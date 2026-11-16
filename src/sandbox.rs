//! Fixed, operator-installed isolation contract. Workloads cannot select a runtime.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{collections::HashSet, path::Path};

pub const RUNTIME: &str = "hal-gvisor";

pub fn profile() -> Value {
    serde_json::from_str(include_str!("gvisor-runtime.json")).expect("built-in sandbox profile")
}

pub fn validate_daemon(info: &Value) -> Result<()> {
    let spec = profile();
    let runtime = &info["Runtimes"][RUNTIME];
    ensure!(runtime["path"] == spec["path"] && runtime["runtimeArgs"] == spec["runtimeArgs"],
        "required gVisor per-user runtime is missing or differs from the approved profile; run python -m hal_fleet.gvisor setup on the execution VM (no fallback)");
    Ok(())
}

/// Expected values come from the trusted launcher, never from worker messages.
pub struct ContainerPolicy<'a> {
    pub image: &'a str,
    pub tenant: &'a str,
    pub session: &'a str,
    pub root: &'a Path,
    pub cpus: usize,
    pub memory_mib: usize,
    pub pids: usize,
    pub storage_mib: usize,
}

pub fn tmpfs_options(storage_mib: usize) -> [(&'static str, String); 2] {
    [
        ("/tmp", "rw,nosuid,nodev,noexec,size=16m,mode=1777".into()),
        (
            "/state",
            format!("rw,nosuid,nodev,noexec,size={storage_mib}m,uid=65532,gid=65532,mode=0700"),
        ),
    ]
}

fn absent_or_empty(value: &Value) -> bool {
    value.is_null()
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(serde_json::Map::is_empty)
}

/// Verify Docker's actual launch configuration before any job is dispatched.
/// This trusts the enclosing VM and daemon; it is not hardware attestation or
/// evidence that the worker remains uncompromised after launch.
pub fn validate_container(info: &Value, expected: &ContainerPolicy<'_>) -> Result<()> {
    let host = &info["HostConfig"];
    let config = &info["Config"];
    ensure!(
        host["Runtime"] == RUNTIME,
        "worker was not created with the required gVisor runtime"
    );
    ensure!(
        info["Image"] == expected.image && info["State"]["Running"] == true,
        "worker image differs from the approved image or container is not running"
    );
    ensure!(
        config["Labels"]["hal.tenant"] == expected.tenant
            && config["Labels"]["hal.broker"] == expected.session,
        "worker ownership differs from this broker"
    );
    ensure!(
        config["User"] == "65532:65532"
            && config["Entrypoint"] == json!(["/usr/local/bin/hal-on-demand"])
            && config["Cmd"] == json!(["--container-worker-config", "/config/worker.json"]),
        "worker user or entrypoint differs from the approved configuration"
    );
    for (field, required) in [
        ("ReadonlyRootfs", json!(true)),
        ("Privileged", json!(false)),
        ("NetworkMode", json!("none")),
        ("IpcMode", json!("private")),
        ("CgroupnsMode", json!("private")),
        ("PidMode", json!("")),
        ("UTSMode", json!("")),
        ("UsernsMode", json!("")),
        ("Init", json!(true)),
        ("PublishAllPorts", json!(false)),
        ("NanoCpus", json!(expected.cpus as u64 * 1_000_000_000)),
        ("Memory", json!(expected.memory_mib as u64 * 1024 * 1024)),
        (
            "MemorySwap",
            json!(expected.memory_mib as u64 * 1024 * 1024),
        ),
        ("PidsLimit", json!(expected.pids)),
    ] {
        ensure!(
            host[field] == required,
            "worker {field} differs from the approved configuration"
        );
    }
    ensure!(
        host["CapDrop"] == json!(["ALL"]),
        "worker must drop all capabilities"
    );
    for field in [
        "CapAdd",
        "Devices",
        "DeviceRequests",
        "DeviceCgroupRules",
        "Binds",
        "VolumesFrom",
        "PortBindings",
        "Links",
    ] {
        ensure!(
            absent_or_empty(&host[field]),
            "worker has forbidden {field}"
        );
    }
    let options = host["SecurityOpt"]
        .as_array()
        .context("worker security options missing")?;
    ensure!(
        options.len() == 1
            && matches!(
                options[0].as_str(),
                Some("no-new-privileges" | "no-new-privileges:true" | "no-new-privileges=true")
            ),
        "worker must enforce no-new-privileges without security overrides"
    );
    ensure!(
        host["LogConfig"]["Type"] == "none",
        "worker logging must not provide unbounded host storage"
    );
    let limits = host["Ulimits"]
        .as_array()
        .context("worker ulimits missing")?;
    for (name, maximum) in [("core", 0), ("nofile", 1024)] {
        let matches: Vec<_> = limits.iter().filter(|v| v["Name"] == name).collect();
        ensure!(
            matches.len() == 1 && matches[0]["Soft"] == maximum && matches[0]["Hard"] == maximum,
            "worker {name} limit differs from the approved configuration"
        );
    }
    let networks = info["NetworkSettings"]["Networks"]
        .as_object()
        .context("worker networks missing")?;
    ensure!(
        networks.len() == 1 && networks.contains_key("none"),
        "worker has an unexpected network attachment"
    );

    // No host cache or credential directory is allowed. Writable storage is
    // private tmpfs. The worker IPC directory is locked after socket creation.
    let tmpfs = host["Tmpfs"]
        .as_object()
        .context("worker private tmpfs mounts missing")?;
    ensure!(tmpfs.len() == 2, "worker has unexpected tmpfs mounts");
    for (destination, options) in tmpfs_options(expected.storage_mib) {
        let actual = tmpfs
            .get(destination)
            .and_then(Value::as_str)
            .context("worker tmpfs options missing")?;
        let actual: HashSet<_> = actual.split(',').collect();
        let wanted: HashSet<_> = options.split(',').collect();
        ensure!(
            actual == wanted,
            "worker {destination} tmpfs differs from the approved configuration"
        );
    }
    let mounts = info["Mounts"].as_array().context("worker mounts missing")?;
    let mut seen = HashSet::new();
    for mount in mounts {
        let destination = mount["Destination"]
            .as_str()
            .context("worker mount destination missing")?;
        ensure!(
            seen.insert(destination),
            "worker has a duplicate mount destination"
        );
        let (directory, writable) = match destination {
            "/config" => ("config", false),
            "/run/broker" => ("broker", false),
            "/run/worker" => ("worker", true),
            // Some Docker versions also list --tmpfs mounts here. Their exact
            // bounded options were checked above, independently of this list.
            "/tmp" | "/state" => {
                ensure!(
                    mount["Type"] == "tmpfs"
                        && mount["RW"] == true
                        && matches!(mount["Source"].as_str(), Some("")),
                    "worker tmpfs replaced by a host mount"
                );
                continue;
            }
            _ => anyhow::bail!("worker has a mount outside the approved private directories"),
        };
        ensure!(
            mount["Type"] == "bind"
                && mount["Source"].as_str() == expected.root.join(directory).to_str()
                && mount["RW"] == writable
                && mount["Propagation"] == "rprivate",
            "worker {destination} mount differs from the approved configuration"
        );
    }
    ensure!(
        ["/config", "/run/broker", "/run/worker"]
            .iter()
            .all(|p| seen.contains(p)),
        "worker private mounts missing"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_must_match_entire_profile() {
        let spec = profile();
        assert_eq!(spec["runtime"], RUNTIME);
        let valid = json!({"Runtimes": {RUNTIME: {
            "path": spec["path"], "runtimeArgs": spec["runtimeArgs"]}}});
        validate_daemon(&valid).unwrap();
        for changed in [json!({}), json!({"Runtimes": {"runc": {}}})] {
            assert!(validate_daemon(&changed).is_err());
        }
        let mut changed = valid.clone();
        changed["Runtimes"][RUNTIME]["path"] = json!("/usr/bin/runc");
        assert!(validate_daemon(&changed).is_err());
        let mut changed = valid;
        changed["Runtimes"][RUNTIME]["runtimeArgs"]
            .as_array_mut()
            .unwrap()
            .push(json!("--allow-flag-override=true"));
        assert!(validate_daemon(&changed).is_err());
    }

    fn policy() -> ContainerPolicy<'static> {
        ContainerPolicy {
            image: "sha256:approved",
            tenant: "alice",
            session: "broker-session",
            root: Path::new("/run/hal/alice"),
            cpus: 2,
            memory_mib: 1024,
            pids: 128,
            storage_mib: 64,
        }
    }

    fn inspected() -> Value {
        json!({
            "Image":"sha256:approved", "State":{"Running":true},
            "Config":{"User":"65532:65532", "Labels":{"hal.tenant":"alice","hal.broker":"broker-session"},
                "Entrypoint":["/usr/local/bin/hal-on-demand"], "Cmd":["--container-worker-config","/config/worker.json"]},
            "HostConfig":{"Runtime":"hal-gvisor", "ReadonlyRootfs":true, "Privileged":false,
                "NetworkMode":"none", "IpcMode":"private", "CgroupnsMode":"private",
                "PidMode":"", "UTSMode":"", "UsernsMode":"", "Init":true, "PublishAllPorts":false,
                "NanoCpus":2000000000_u64, "Memory":1073741824, "MemorySwap":1073741824, "PidsLimit":128,
                "CapDrop":["ALL"], "SecurityOpt":["no-new-privileges:true"], "LogConfig":{"Type":"none"},
                "Ulimits":[{"Name":"core","Soft":0,"Hard":0},{"Name":"nofile","Soft":1024,"Hard":1024}],
                "Tmpfs":{"/tmp":"rw,nosuid,nodev,noexec,size=16m,mode=1777",
                    "/state":"rw,nosuid,nodev,noexec,size=64m,uid=65532,gid=65532,mode=0700"}},
            "NetworkSettings":{"Networks":{"none":{}}},
            "Mounts":[
                {"Type":"bind","Source":"/run/hal/alice/config","Destination":"/config","RW":false,"Propagation":"rprivate"},
                {"Type":"bind","Source":"/run/hal/alice/broker","Destination":"/run/broker","RW":false,"Propagation":"rprivate"},
                {"Type":"bind","Source":"/run/hal/alice/worker","Destination":"/run/worker","RW":true,"Propagation":"rprivate"}]
        })
    }

    fn rejects(pointer: &str, replacement: Value) {
        let mut actual = inspected();
        *actual.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            validate_container(&actual, &policy()).is_err(),
            "accepted changed {pointer}"
        );
    }

    #[test]
    fn approves_private_worker_with_supported_docker_representations() {
        validate_container(&inspected(), &policy()).unwrap();
        let mut actual = inspected();
        actual["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"Type":"tmpfs","Source":"","Destination":"/state","RW":true}));
        actual["HostConfig"]["Tmpfs"]["/tmp"] = json!("size=16m,noexec,nodev,nosuid,rw,mode=1777");
        actual["HostConfig"]["SecurityOpt"] = json!(["no-new-privileges=true"]);
        actual["HostConfig"]["CapAdd"] = json!([]);
        actual["HostConfig"]["PortBindings"] = json!({});
        validate_container(&actual, &policy()).unwrap();
    }

    #[test]
    fn rejects_wrong_runtime_image_user_or_broker_ownership() {
        for runtime in ["", "runc", "runsc"] {
            rejects("/HostConfig/Runtime", json!(runtime));
        }
        for (pointer, value) in [
            ("/Image", json!("sha256:other")),
            ("/State/Running", json!(false)),
            ("/Config/User", json!("0:0")),
            ("/Config/Labels/hal.tenant", json!("bob")),
            ("/Config/Labels/hal.broker", json!("previous-broker")),
            ("/Config/Entrypoint", json!(["/bin/sh"])),
            ("/Config/Cmd", json!(["--help"])),
        ] {
            rejects(pointer, value);
        }
        assert!(validate_container(&json!({"HostConfig":{"Runtime":RUNTIME}}), &policy()).is_err());
    }

    #[test]
    fn rejects_privilege_namespace_network_and_device_expansion() {
        for (pointer, value) in [
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/IpcMode", json!("host")),
            ("/HostConfig/PidMode", json!("container:bob")),
            ("/HostConfig/UTSMode", json!("host")),
            ("/HostConfig/CgroupnsMode", json!("host")),
            ("/HostConfig/PublishAllPorts", json!(true)),
            ("/HostConfig/CapDrop", json!([])),
            (
                "/HostConfig/SecurityOpt",
                json!(["no-new-privileges:false"]),
            ),
            (
                "/HostConfig/SecurityOpt",
                json!(["no-new-privileges:true", "seccomp=unconfined"]),
            ),
            ("/NetworkSettings/Networks", json!({"none":{}, "bridge":{}})),
        ] {
            rejects(pointer, value);
        }
        for field in [
            "CapAdd",
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "Binds",
            "VolumesFrom",
            "PortBindings",
            "Links",
        ] {
            let mut actual = inspected();
            actual["HostConfig"][field] = json!(["unexpected access"]);
            assert!(validate_container(&actual, &policy()).is_err(), "{field}");
        }
    }

    #[test]
    fn rejects_missing_or_weaker_resource_limits() {
        for field in ["NanoCpus", "Memory", "MemorySwap", "PidsLimit"] {
            for value in [Value::Null, json!(0), json!(-1), json!(999999999999_u64)] {
                rejects(&format!("/HostConfig/{field}"), value);
            }
        }
        rejects("/HostConfig/Ulimits/0/Hard", json!(-1));
        rejects("/HostConfig/Ulimits/1/Soft", json!(65536));
        rejects("/HostConfig/LogConfig/Type", json!("json-file"));
        for value in [
            json!("rw,size=64m"),
            json!("rw,nosuid,nodev,exec,size=64m"),
            json!("rw,nosuid,nodev,noexec,size=4096m,uid=65532,gid=65532,mode=0700"),
        ] {
            rejects("/HostConfig/Tmpfs/~1state", value);
        }
    }

    #[test]
    fn rejects_cross_user_credential_cache_and_control_socket_mounts() {
        rejects("/Mounts/0/Source", json!("/run/hal/bob/config"));
        rejects("/Mounts/0/RW", json!(true));
        rejects("/Mounts/1/Propagation", json!("rshared"));
        for source in [
            "/var/run/docker.sock",
            "/root/.ssh",
            "/run/agent-secrets",
            "/shared/compiled-cache",
        ] {
            let mut actual = inspected();
            actual["Mounts"]
                .as_array_mut()
                .unwrap()
                .push(json!({"Type":"bind","Source":source,
                "Destination":"/extra","RW":false,"Propagation":"rprivate"}));
            assert!(validate_container(&actual, &policy()).is_err(), "{source}");
        }
        rejects("/Mounts/2/Destination", json!("/config"));
        let mut actual = inspected();
        actual["Mounts"].as_array_mut().unwrap().pop();
        assert!(validate_container(&actual, &policy()).is_err());
        actual = inspected();
        actual["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(json!({"Type":"bind","Source":"/shared/cache",
            "Destination":"/state","RW":true,"Propagation":"rprivate"}));
        assert!(validate_container(&actual, &policy()).is_err());
    }
}
