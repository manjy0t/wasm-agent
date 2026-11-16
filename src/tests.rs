//! Resource/instance semantics, with real component execution in software mode.
use super::*;
use executor::Prepared;
use wasmtime::component::Component;

fn shared(path: &std::path::Path) -> Arc<Shared> {
    shared_mode(path, "wasm")
}

fn shared_mode(path: &std::path::Path, mode: &str) -> Arc<Shared> {
    let args = Args::parse_from([
        "test",
        "--mode",
        mode,
        "--file-server",
        "http://127.0.0.1:1/",
        "--token-file",
        "unused",
        "--cache-dir",
        path.to_str().unwrap(),
        "--allow-non-tee",
        "--workload-fuel",
        "50000",
        "--compile-opt-level",
        "none",
    ]);
    Shared::new(args).unwrap()
}

fn component(shared: &Shared, body: &str) -> Prepared {
    let wat = format!(
        r#"(component
        (core module $m
            (memory (export "memory") 1)
            (global $counter (mut i32) (i32.const 0))
            (func (export "run") (result i32) {body}))
        (core instance $i (instantiate $m))
        (func $run (result (list u8))
            (canon lift (core func $i "run") (memory (core memory $i "memory"))))
        (instance $exports (export "run" (func $run)))
        (export "elastic:hal/run@0.1.0" (instance $exports)))"#
    );
    Prepared {
        tenant: "legacy".into(),
        sha: "0".repeat(64),
        component: Component::new(shared.runtime.engine(), wat).unwrap(),
        size: 0,
        preparation: json!({}),
        expires: None,
    }
}

#[tokio::test]
async fn compiled_reuse_does_not_reuse_guest_memory_or_globals() {
    let directory = tempfile::tempdir().unwrap();
    let shared = shared(&directory.path().join("cache"));
    let prepared = component(
        &shared,
        r#"
        (global.set $counter (i32.add (global.get $counter) (i32.const 1)))
        (i32.store8 (i32.const 0) (global.get $counter))
        (i32.store (i32.const 16) (i32.const 0))
        (i32.store (i32.const 20) (i32.const 1))
        (i32.const 16)"#,
    );
    for _ in 0..3 {
        let mut record = json!({"timings_ms": {}});
        let bytes = shared
            .execute(&job(), &prepared, &mut record)
            .await
            .unwrap();
        assert_eq!(
            bytes,
            vec![1],
            "a reused instance would return 2 and then 3"
        );
    }
}

#[tokio::test]
async fn infinite_wasm_is_stopped_by_fuel_and_next_job_works() {
    let directory = tempfile::tempdir().unwrap();
    let shared = shared(&directory.path().join("cache"));
    let prepared = component(&shared, "(loop br 0) (i32.const 0)");
    let mut record = json!({"timings_ms": {}});
    let error = shared
        .execute(&job(), &prepared, &mut record)
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("fuel"), "{error:#}");
    let good = component(&shared, "(i32.const 0)");
    assert_eq!(
        shared.execute(&job(), &good, &mut record).await.unwrap(),
        Vec::<u8>::new()
    );
}

#[tokio::test]
async fn attestation_import_is_explicitly_disabled() {
    let runtime = hal_runtime::HalRuntime::new().unwrap();
    let hal = hal_runtime::HalHost::with_platform(elastic_tee_hal::platform::PlatformType::AmdSev)
        .unwrap();
    let mut store = runtime.create_store_with_host(hal).unwrap();
    let result =
        hal_runtime::elastic::hal::attestation::Host::attestation(store.data_mut(), vec![1, 2])
            .await;
    assert!(result.unwrap_err().contains("disabled"));
}

#[tokio::test]
async fn oversized_wasm_memory_growth_is_denied() {
    let directory = tempfile::tempdir().unwrap();
    let shared = shared(&directory.path().join("cache"));
    let prepared = component(
        &shared,
        r#"
        (i32.store8 (i32.const 0)
            (i32.eq (memory.grow (i32.const 1000000)) (i32.const -1)))
        (i32.store (i32.const 16) (i32.const 0))
        (i32.store (i32.const 20) (i32.const 1))
        (i32.const 16)"#,
    );
    let mut record = json!({"timings_ms": {}});
    assert_eq!(
        shared
            .execute(&job(), &prepared, &mut record)
            .await
            .unwrap(),
        vec![1]
    );
}

#[tokio::test]
async fn native_engine_reuse_keeps_independent_job_state() {
    let directory = tempfile::tempdir().unwrap();
    let shared = shared_mode(&directory.path().join("unused-cache"), "native");
    for _ in 0..3 {
        // Each request compiles its own component against the same live engine.
        let prepared = component(
            &shared,
            r#"
            (global.set $counter (i32.add (global.get $counter) (i32.const 1)))
            (i32.store8 (i32.const 0) (global.get $counter))
            (i32.store (i32.const 16) (i32.const 0))
            (i32.store (i32.const 20) (i32.const 1))
            (i32.const 16)"#,
        );
        let mut request = job();
        request.reuse = false;
        let mut record = json!({"timings_ms": {}});
        assert_eq!(
            shared
                .execute(&request, &prepared, &mut record)
                .await
                .unwrap(),
            vec![1],
            "a previous job's mutable state must not survive"
        );
    }
    assert_eq!(shared.stats()["executions"], 3);
    assert_eq!(shared.stats()["compiled_entries"], 0);
    assert!(!directory.path().join("unused-cache").exists());
}

#[tokio::test]
async fn native_memory_limits_apply_with_reused_engine() {
    let directory = tempfile::tempdir().unwrap();
    let shared = shared_mode(&directory.path().join("unused-cache"), "native");
    let prepared = component(
        &shared,
        r#"
        (i32.store8 (i32.const 0)
            (i32.eq (memory.grow (i32.const 1024)) (i32.const -1)))
        (i32.store (i32.const 16) (i32.const 0))
        (i32.store (i32.const 20) (i32.const 1))
        (i32.const 16)"#,
    );
    let mut request = job();
    request.reuse = false;
    let mut record = json!({"timings_ms": {}});
    // One initial page plus 1,024 more exceeds the configured 64 MiB limit.
    assert_eq!(
        shared
            .execute(&request, &prepared, &mut record)
            .await
            .unwrap(),
        vec![1]
    );
}

#[tokio::test]
async fn dedicated_compiler_contains_nested_parallelism() {
    use rayon::prelude::*;
    let compiler = compiler::Compiler::new(3, Some(2)).unwrap();
    let (threads, _) = compiler
        .run(|| {
            Ok((0..256)
                .into_par_iter()
                .map(|_| rayon::current_num_threads())
                .collect::<Vec<_>>())
        })
        .await
        .unwrap();
    assert!(threads.iter().all(|n| *n == 2));
}

#[tokio::test]
async fn cancelled_compiler_keeps_its_slot_until_real_work_finishes() {
    for threads in [None, Some(2)] {
        let compiler = Arc::new(compiler::Compiler::new(1, threads).unwrap());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task_compiler = compiler.clone();
        let task = tokio::spawn(async move {
            task_compiler
                .run(move || {
                    let _ = started.send(());
                    let _ = wait.recv();
                    Ok(())
                })
                .await
        });
        ready.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(compiler.stats()["occupied_slots"], 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), compiler.run(|| Ok(())))
                .await
                .is_err()
        );
        assert_eq!(compiler.stats()["submitted"], 1);
        release.send(()).unwrap();
        let (value, _) = tokio::time::timeout(Duration::from_secs(5), compiler.run(|| Ok(42)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(compiler.stats()["finished"], 2);
    }
}

#[tokio::test]
async fn compiler_panic_does_not_kill_pool_or_leak_slot() {
    let compiler = compiler::Compiler::new(1, Some(2)).unwrap();
    let error = compiler
        .run(|| -> anyhow::Result<()> { panic!("test panic") })
        .await;
    assert!(error
        .err()
        .unwrap()
        .to_string()
        .contains("compiler task panicked"));
    assert_eq!(compiler.run(|| Ok(7)).await.unwrap().0, 7);
}

fn job() -> Job {
    Job {
        ticket: None,
        id: "test".into(),
        name: "test.wasm".into(),
        sha: "0".repeat(64),
        size: 8,
        reuse: true,
        tenant: "legacy".into(),
    }
}

#[tokio::test]
async fn agent_hal_permissions_and_host_buffer_limits_are_enforced() {
    use hal_runtime::elastic::hal::{clock, crypto, random, storage};
    use hal_runtime::{HalHost, HalRuntime};
    let runtime = HalRuntime::new().unwrap();
    let hal = HalHost::for_restricted_job(true).unwrap();
    let mut store = runtime.create_store_with_host(hal).unwrap();
    store.data_mut().restrict_agent_permissions(&[]);
    let denied = crypto::Host::hash(store.data_mut(), vec![], crypto::HashAlgorithm::Sha256).await;
    assert!(denied.unwrap_err().contains("disabled by the agent policy"));
    assert!(random::Host::get_random_bytes(store.data_mut(), 32)
        .await
        .is_err());
    assert!(
        storage::Host::open_container(store.data_mut(), "test".into())
            .await
            .is_err()
    );
    assert!(clock::Host::get_system_time(store.data_mut())
        .await
        .is_err());
    // Grant changes need a fresh Store; an existing Store can only lose rights.
    store
        .data_mut()
        .restrict_agent_permissions(&["random".into()]);
    assert!(random::Host::get_random_bytes(store.data_mut(), 32)
        .await
        .is_err());
    let hal = HalHost::for_restricted_job(true).unwrap();
    let mut store = runtime.create_store_with_host(hal).unwrap();
    store.data_mut().restrict_agent_permissions(&[
        "random".into(),
        "clock".into(),
        "crypto".into(),
    ]);
    assert_eq!(
        random::Host::get_random_bytes(store.data_mut(), 32)
            .await
            .unwrap()
            .len(),
        32
    );
    assert!(random::Host::get_secure_random(store.data_mut(), u32::MAX)
        .await
        .unwrap_err()
        .contains("buffer"));
    assert!(crypto::Host::hash(
        store.data_mut(),
        vec![0; 1024 * 1024 + 1],
        crypto::HashAlgorithm::Sha256
    )
    .await
    .unwrap_err()
    .contains("buffer"));
    assert!(clock::Host::sleep(store.data_mut(), u64::MAX)
        .await
        .unwrap_err()
        .contains("sleep"));
}

#[test]
fn result_policy_rejects_malformed_or_wrong_values() {
    use agent_policy::validate;
    assert!(validate(
        &json!({"kind":"clock"}),
        br#"{"seconds":1,"nanoseconds":999999999}"#
    )
    .is_ok());
    for bytes in [
        br#"{"seconds":-1,"nanoseconds":1}"#.as_slice(),
        br#"{"seconds":1,"nanoseconds":1000000000}"#,
        br#"{"seconds":1,"nanoseconds":0,"extra":true}"#,
        b"not json",
    ] {
        assert!(validate(&json!({"kind":"clock"}), bytes).is_err());
    }
    assert!(validate(
        &json!({"kind":"utf8_contains","value":"IntelTdx|"}),
        b"IntelTdx|0.1.0"
    )
    .is_ok());
    assert!(validate(
        &json!({"kind":"utf8_contains","value":"IntelTdx|"}),
        b"AmdSev|0.1.0"
    )
    .is_err());
    assert!(validate(&json!({"kind":"hex","value":"00"}), &[1]).is_err());
    assert!(validate(&json!({"kind":"length","value":32}), &[0; 31]).is_err());
    assert!(validate(&json!({"kind":"unknown"}), &[]).is_err());
}

fn storage_scope(root: &std::path::Path, sha: &str, bytes: u64) -> Arc<storage::PrivateStorage> {
    cache::private_directory(root).unwrap();
    let budget = Arc::new(storage::Budget {
        root: root.into(),
        bytes,
        entries: 100,
        lock: std::sync::Mutex::new(()),
    });
    Arc::new(storage::PrivateStorage::new(budget, sha).unwrap())
}

#[test]
fn private_storage_separates_tenants_artifacts_and_sessions() {
    use hal_runtime::JobStorage;
    let directory = tempfile::tempdir().unwrap();
    let a = storage_scope(&directory.path().join("alice"), &"a".repeat(64), 100);
    let b = storage_scope(&directory.path().join("bob"), &"a".repeat(64), 100);
    let c = storage_scope(&directory.path().join("alice"), &"b".repeat(64), 100);
    let handle = a.open_container("account").unwrap();
    a.write_object(handle, "secret", b"alice-data").unwrap();
    for scope in [&b, &c] {
        let other = scope.open_container("account").unwrap();
        assert!(scope.read_object(other, "secret").is_err());
    }
    let next = a.session();
    assert!(
        next.read_object(handle, "secret").is_err(),
        "handles are local to an execution"
    );
    let own = next.open_container("account").unwrap();
    assert_eq!(next.read_object(own, "secret").unwrap(), b"alice-data");
    next.close_container(own).unwrap();
    assert!(next.read_object(own, "secret").is_err());
    // A new backend after restart locates the same container by its name, not allocation order.
    let restarted = storage_scope(&directory.path().join("alice"), &"a".repeat(64), 100);
    restarted.open_container("unrelated").unwrap();
    let own = restarted.open_container("account").unwrap();
    assert_eq!(restarted.read_object(own, "secret").unwrap(), b"alice-data");
}

#[test]
fn storage_rejects_traversal_symlinks_and_oversized_objects() {
    use hal_runtime::JobStorage;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    let sha = "a".repeat(64);
    let a = storage_scope(&root, &sha, 100);
    let handle = a.open_container("data").unwrap();
    for key in ["../outside", "/tmp/outside", "..", "a/b", "a\\b", ""] {
        assert!(a.write_object(handle, key, b"secret").is_err(), "{key}");
    }
    assert!(a
        .write_object(handle, "too-big", &vec![0; 1024 * 1024 + 1])
        .is_err());
    let outside = directory.path().join("outside");
    std::fs::write(&outside, b"protected").unwrap();
    let link = root.join(&sha).join(cache::hash(b"data")).join("link.obj");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    assert!(a.read_object(handle, "link").is_err());
    assert!(a.write_object(handle, "link", b"overwrite").is_err());
    assert!(a.delete_object(handle, "link").is_err());
    assert_eq!(std::fs::read(outside).unwrap(), b"protected");
}

#[test]
fn storage_quota_is_atomic_across_workloads_and_counts_existing_files() {
    use hal_runtime::JobStorage;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    cache::private_directory(&root).unwrap();
    let budget = Arc::new(storage::Budget {
        root: root.clone(),
        bytes: 10,
        entries: 100,
        lock: std::sync::Mutex::new(()),
    });
    let a = Arc::new(storage::PrivateStorage::new(budget.clone(), &"a".repeat(64)).unwrap());
    let b = Arc::new(storage::PrivateStorage::new(budget, &"b".repeat(64)).unwrap());
    let handles = [
        a.open_container("data").unwrap(),
        b.open_container("data").unwrap(),
    ];
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = [a.clone(), b.clone()]
        .into_iter()
        .zip(handles)
        .map(|(s, h)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                s.write_object(h, "value", b"123456")
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|t| t.join().unwrap().is_ok() as usize)
            .sum::<usize>(),
        1
    );
    let restarted = storage_scope(&root, &"c".repeat(64), 10);
    let h = restarted.open_container("data").unwrap();
    assert!(restarted.write_object(h, "value", b"123456").is_err());
}

#[tokio::test]
async fn restricted_wit_uses_private_storage_and_denies_ambient_services() {
    use hal_runtime::elastic::hal::{
        communication, gpu, resources, sockets, storage as wit_storage,
    };
    let directory = tempfile::tempdir().unwrap();
    let storage = storage_scope(&directory.path().join("storage"), &"a".repeat(64), 100);
    let runtime = hal_runtime::HalRuntime::new().unwrap();
    let hal = hal_runtime::HalHost::for_restricted_job(true).unwrap();
    let mut store = runtime.create_store_with_host(hal).unwrap();
    store.data_mut().restrict_to_job(storage);
    let h = wit_storage::Host::create_container(store.data_mut(), "data".into())
        .await
        .unwrap();
    wit_storage::Host::store_object(store.data_mut(), h, "key".into(), vec![7])
        .await
        .unwrap();
    assert_eq!(
        wit_storage::Host::retrieve_object(store.data_mut(), h, "key".into())
            .await
            .unwrap(),
        vec![7]
    );
    let error = sockets::Host::create_socket(store.data_mut(), sockets::Protocol::Tcp)
        .await
        .unwrap_err();
    assert!(error.contains("disabled by the tenant policy"));
    assert!(gpu::Host::list_adapters(store.data_mut()).await.is_err());
    assert!(
        resources::Host::query_available(store.data_mut(), resources::ResourceType::Memory)
            .await
            .is_err()
    );
    // Other communication methods are guarded at their generated WIT entry points too.
    let _ = std::mem::size_of::<communication::Message>();
}

#[test]
fn storage_entry_quota_bounds_empty_objects_and_containers() {
    use hal_runtime::JobStorage;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("storage");
    cache::private_directory(&root).unwrap();
    let budget = Arc::new(storage::Budget {
        root,
        bytes: 10,
        entries: 3,
        lock: std::sync::Mutex::new(()),
    });
    let storage = storage::PrivateStorage::new(budget, &"a".repeat(64)).unwrap();
    let h = storage.open_container("first").unwrap();
    storage.write_object(h, "empty", &[]).unwrap();
    assert!(storage.write_object(h, "another", &[]).is_err());
    assert!(storage.open_container("second").is_err());
    storage.delete_object(h, "empty").unwrap();
    storage.write_object(h, "replacement", &[1]).unwrap();
}

#[test]
fn tenant_policy_rejects_ambiguous_identities_credentials_and_zero_quotas() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("alice.token"), "a".repeat(64)).unwrap();
    std::fs::write(directory.path().join("bob.token"), "b".repeat(64)).unwrap();
    let row = json!({"id":"alice", "token_file":"alice.token", "artifacts":[{
        "component":"function.wasm", "sha256":"1".repeat(64), "artifact_bytes":8}]});
    let file = directory.path().join("policy.json");
    let load = |value: Value| {
        std::fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
        tenancy::Policy::load(&file, &"c".repeat(64), 1024, 16)
    };
    assert!(load(json!({"version":1,"tenants":[row.clone()]})).is_ok());
    for (field, value) in [
        ("id", json!("../bob")),
        ("id", json!("Alice")),
        ("cache_bytes", json!(0)),
        ("storage_entries", json!(1)),
        ("max_inflight", json!(17)),
    ] {
        let mut invalid = row.clone();
        invalid[field] = value;
        assert!(load(json!({"version":1,"tenants":[invalid]})).is_err());
    }
    let mut duplicate = row.clone();
    duplicate["id"] = json!("bob");
    assert!(load(json!({"version":1,"tenants":[row, duplicate]})).is_err());
}
