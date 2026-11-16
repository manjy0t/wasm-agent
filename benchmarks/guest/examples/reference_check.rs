fn main() {
    for index in 0..15 {
        println!("{}", hal_benchmark_workload::algorithms::execute(index));
    }
}
