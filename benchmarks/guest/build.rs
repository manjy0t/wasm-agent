fn main() {
    println!("cargo:rerun-if-env-changed=HAL_WORKLOAD_INDEX");
    let index: usize = std::env::var("HAL_WORKLOAD_INDEX").unwrap_or("0".into()).parse().unwrap();
    assert!(index < 15);
    std::fs::write(std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("selection.rs"),
                   format!("const INDEX: usize = {index};")).unwrap();
}
