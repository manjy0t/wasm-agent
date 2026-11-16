//! Exercise Python-generated policies using Trustee v0.22.0's actual Rego engine.
use serde_json::{json, Value};
use std::{path::Path, process::Command};

fn fixture(platform: &str) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let python = std::env::var("HAL_TEST_PYTHON").unwrap_or("python3".into());
    let output = Command::new(python)
        .current_dir(root)
        .args(["-B", "tests/trustee_policy_fixture.py", platform])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn evaluate(source: &str, claims: &Value) -> Value {
    let mut engine = regorus::Engine::new();
    engine
        .add_policy("hal_cpu.rego".into(), source.into())
        .unwrap();
    engine.set_input_json(&claims.to_string()).unwrap();
    let result = engine.eval_rule("data.policy.trust_claims".into()).unwrap();
    serde_json::from_str(&result.to_json_str().unwrap()).unwrap()
}

#[test]
fn generated_tdx_policy_checks_all_measurements_debug_and_collateral() {
    let test = fixture("tdx");
    let source = test["policy"].as_str().unwrap();
    let input = &test["claims"];
    assert_eq!(evaluate(source, input)["hardware"], 2);
    for field in ["mr_td", "rtmr_0", "rtmr_1", "rtmr_2", "rtmr_3"] {
        let mut changed = input.clone();
        changed["tdx"]["quote"]["body"][field] = json!("f".repeat(96));
        assert_eq!(evaluate(source, &changed)["executables"], 33);
    }
    for (field, value) in [
        ("tcb_status", json!("OutOfDate")),
        ("collateral_expiration_status", json!("1")),
        ("td_attributes", json!({"debug": true})),
    ] {
        let mut changed = input.clone();
        changed["tdx"][field] = value;
        assert_eq!(evaluate(source, &changed)["hardware"], 97);
    }
    assert_eq!(evaluate(source, &json!({}))["configuration"], 36);
}

#[test]
fn generated_snp_policy_checks_measurement_migration_and_each_tcb_component() {
    let test = fixture("snp");
    let source = test["policy"].as_str().unwrap();
    let input = &test["claims"];
    assert_eq!(evaluate(source, input)["executables"], 3);
    for field in [
        "reported_tcb_bootloader",
        "reported_tcb_tee",
        "reported_tcb_snp",
        "reported_tcb_microcode",
    ] {
        let mut changed = input.clone();
        changed["snp"][field] = json!(-1);
        assert_eq!(evaluate(source, &changed)["hardware"], 97);
    }
    for (field, value) in [
        ("policy_debug_allowed", json!(true)),
        ("policy_migrate_ma", json!(true)),
        ("measurement", json!("f".repeat(96))),
    ] {
        let mut changed = input.clone();
        changed["snp"][field] = value;
        assert_eq!(evaluate(source, &changed)["configuration"], 36);
    }
    assert_eq!(evaluate(source, &json!({"sample": {}}))["hardware"], 97);
}
