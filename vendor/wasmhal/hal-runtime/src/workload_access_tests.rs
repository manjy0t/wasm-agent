use crate::elastic::hal::{crypto, storage};
use crate::*;
use wasmtime::{component::Component, Store};

fn store(runtime: &HalRuntime, operations: &[&str], calls: u64) -> Store<RuntimeState> {
    let mut s = runtime
        .create_job_store(
            HalHost::for_restricted_job(true).unwrap(),
            8 * 1024 * 1024,
            100_000,
            100,
        )
        .unwrap();
    s.data_mut()
        .enforce_workload_policy(
            "alice",
            &"a".repeat(64),
            &[
                "crypto".into(),
                "random".into(),
                "clock".into(),
                "storage".into(),
            ],
        )
        .unwrap();
    s.data_mut()
        .enforce_access_profile(&WorkloadProfile {
            version: 1,
            artifact_sha256: "a".repeat(64),
            operations: operations.iter().map(|s| s.to_string()).collect(),
            max_host_calls: calls,
            max_buffer_bytes: 64,
        })
        .unwrap();
    s
}

#[tokio::test]
async fn access_tests_hash_permission_does_not_allow_signing_or_key_generation() {
    let runtime = HalRuntime::new().unwrap();
    let mut s = store(&runtime, &["crypto.hash.sha256"], 10);
    let actual = crypto::Host::hash(s.data_mut(), b"abc".to_vec(), crypto::HashAlgorithm::Sha256)
        .await
        .unwrap();
    assert_eq!(
        hex::encode(actual),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(
        crypto::Host::hash(s.data_mut(), vec![0], crypto::HashAlgorithm::Sha512)
            .await
            .unwrap_err()
            .contains("profile denied")
    );
    assert!(crypto::Host::sign(s.data_mut(), vec![], vec![])
        .await
        .unwrap_err()
        .contains("profile denied"));
    assert!(crypto::Host::generate_keypair(s.data_mut())
        .await
        .unwrap_err()
        .contains("profile denied"));
    assert!(
        crypto::Host::hash(s.data_mut(), vec![0; 65], crypto::HashAlgorithm::Sha256)
            .await
            .unwrap_err()
            .contains("buffer limit")
    );
}

struct ReadOnlyFixture {
    large: bool,
}
impl JobStorage for ReadOnlyFixture {
    fn open_container(&self, _: &str) -> Result<u64, String> {
        Ok(1)
    }
    fn close_container(&self, _: u64) -> Result<(), String> {
        panic!("delete reached storage")
    }
    fn write_object(&self, _: u64, _: &str, _: &[u8]) -> Result<u64, String> {
        panic!("write reached storage")
    }
    fn read_object(&self, _: u64, _: &str) -> Result<Vec<u8>, String> {
        Ok(if self.large {
            vec![0; 1_048_577]
        } else {
            b"private".to_vec()
        })
    }
    fn delete_object(&self, _: u64, _: &str) -> Result<(), String> {
        panic!("delete reached storage")
    }
    fn list_objects(&self, _: u64) -> Result<Vec<String>, String> {
        Ok(vec!["key".into()])
    }
}

#[tokio::test]
async fn access_tests_storage_read_does_not_allow_write_or_delete() {
    let runtime = HalRuntime::new().unwrap();
    let mut s = store(
        &runtime,
        &["storage.open-container", "storage.retrieve-object"],
        10,
    );
    s.data_mut()
        .restrict_to_job(std::sync::Arc::new(ReadOnlyFixture { large: false }));
    let handle = storage::Host::open_container(s.data_mut(), "own".into())
        .await
        .unwrap();
    assert_eq!(
        storage::Host::retrieve_object(s.data_mut(), handle, "key".into())
            .await
            .unwrap(),
        b"private"
    );
    assert!(
        storage::Host::store_object(s.data_mut(), handle, "key".into(), vec![1])
            .await
            .is_err()
    );
    assert!(
        storage::Host::delete_object(s.data_mut(), handle, "key".into())
            .await
            .is_err()
    );
    assert!(storage::Host::delete_container(s.data_mut(), handle)
        .await
        .is_err());
}

#[tokio::test]
async fn access_tests_storage_buffer_refinement_preserves_unprofiled_rules() {
    let runtime = HalRuntime::new().unwrap();
    let mut legacy = runtime
        .create_store_with_host(HalHost::for_restricted_job(true).unwrap())
        .unwrap();
    legacy
        .data_mut()
        .enforce_workload_policy("alice", &"a".repeat(64), &["storage".into()])
        .unwrap();
    legacy
        .data_mut()
        .restrict_to_job(std::sync::Arc::new(ReadOnlyFixture { large: true }));
    assert_eq!(
        storage::Host::retrieve_object(legacy.data_mut(), 1, "key".into())
            .await
            .unwrap()
            .len(),
        1_048_577
    );
    let mut narrow = store(&runtime, &["storage.retrieve-object"], 10);
    narrow
        .data_mut()
        .restrict_to_job(std::sync::Arc::new(ReadOnlyFixture { large: true }));
    assert!(
        storage::Host::retrieve_object(narrow.data_mut(), 1, "key".into())
            .await
            .unwrap_err()
            .contains("buffer limit")
    );
}

fn probe(runtime: &HalRuntime, interface: &str, method: &str) -> Component {
    Component::new(
        runtime.engine(),
        format!(
            r#"(component
        (import "{interface}" (instance $i (export "{method}" (func (result u64)))))
        (alias export $i "{method}" (func $call))
        (core func $lower (canon lower (func $call)))
        (core module $m
            (import "host" "call" (func $call (result i64)))
            (func (export "probe") (result i64) call $call))
        (core instance $m (instantiate $m (with "host" (instance (export "call" (func $lower))))))
        (func (export "probe") (result u64) (canon lift (core func $m "probe"))))"#
        ),
    )
    .unwrap()
}

#[tokio::test]
async fn access_tests_wasi_calls_cannot_bypass_rule_and_profile() {
    let runtime = HalRuntime::new().unwrap();
    let linker = runtime.create_linker().unwrap();
    for (interface, method, permission, operation) in [
        (
            "wasi:random/random@0.2.0",
            "get-random-u64",
            "random",
            "wasi.random",
        ),
        (
            "wasi:random/insecure@0.2.3",
            "get-insecure-random-u64",
            "random",
            "wasi.insecure-random",
        ),
        (
            "wasi:clocks/monotonic-clock@0.2.0",
            "now",
            "clock",
            "wasi.clock",
        ),
    ] {
        let component = probe(&runtime, interface, method);
        check_workload_imports(runtime.engine(), &component).unwrap();
        // Broad rule alone denies the alternate WASI route without its category.
        let mut s = runtime
            .create_store_with_host(HalHost::for_restricted_job(true).unwrap())
            .unwrap();
        s.data_mut()
            .enforce_workload_policy("bob", &"b".repeat(64), &[])
            .unwrap();
        let i = linker.instantiate_async(&mut s, &component).await.unwrap();
        let f = i.get_typed_func::<(), (u64,)>(&mut s, "probe").unwrap();
        assert!(format!("{:#}", f.call_async(&mut s, ()).await.unwrap_err())
            .contains("disabled by the agent policy"));
        // Category allowed, finer profile denied.
        let mut s = store(&runtime, &[], 2);
        let i = linker.instantiate_async(&mut s, &component).await.unwrap();
        let f = i.get_typed_func::<(), (u64,)>(&mut s, "probe").unwrap();
        assert!(
            format!("{:#}", f.call_async(&mut s, ()).await.unwrap_err()).contains("profile denied")
        );
        // Explicit permission works; the next call exceeds the per-instance budget.
        let mut s = store(&runtime, &[operation], 1);
        let i = linker.instantiate_async(&mut s, &component).await.unwrap();
        let f = i.get_typed_func::<(), (u64,)>(&mut s, "probe").unwrap();
        f.call_async(&mut s, ()).await.unwrap();
        f.post_return_async(&mut s).await.unwrap();
        assert!(f.call_async(&mut s, ()).await.is_err(), "{permission}");
        // Reusing compiled code has neither inherited authority nor spent budget.
        let mut fresh = store(&runtime, &[operation], 1);
        let i = linker
            .instantiate_async(&mut fresh, &component)
            .await
            .unwrap();
        i.get_typed_func::<(), (u64,)>(&mut fresh, "probe")
            .unwrap()
            .call_async(&mut fresh, ())
            .await
            .unwrap();
    }
}

#[test]
fn access_tests_unknown_interfaces_and_profile_rebinding_fail_closed() {
    let runtime = HalRuntime::new().unwrap();
    let component = probe(&runtime, "attacker:host/admin@1.0.0", "run");
    assert!(check_workload_imports(runtime.engine(), &component).is_err());
    let mut s = store(&runtime, &[], 1);
    let profile = WorkloadProfile {
        version: 1,
        artifact_sha256: "b".repeat(64),
        operations: vec![],
        max_host_calls: 1,
        max_buffer_bytes: 64,
    };
    assert!(s.data_mut().enforce_access_profile(&profile).is_err());
    assert!(s
        .data_mut()
        .enforce_workload_policy("bob", &"b".repeat(64), &[])
        .is_err());
}
