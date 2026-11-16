//! Deterministic inputs and observable outputs; black_box prevents constant folding.
//! The ABI currently has no arguments, so every case generates its input inside Wasm.
use sha2::{Digest, Sha256};
use std::hint::black_box;

pub const NAMES: [&str; 15] = ["matrix-multiply", "integer-sort", "prime-sieve", "dijkstra", "floyd-warshall",
    "knapsack", "edit-distance", "kmeans", "nbody-integer", "image-convolution", "pagerank",
    "json-aggregation", "rle-roundtrip", "merkle-tree", "pbkdf2-sha256"];

struct Rng(u32);
impl Rng {
    fn new() -> Self { Self(black_box(0x12345678)) }
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1664525).wrapping_add(1013904223);
        self.0
    }
}
fn checksum(values: impl IntoIterator<Item=u64>) -> u64 {
    values.into_iter().fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(b))
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

pub fn execute(index: usize) -> String {
    let mut rng = Rng::new();
    let value = match index {
        0 => {
            let n = black_box(96);
            let a: Vec<u64> = (0..n*n).map(|_| (rng.next() % 100) as u64).collect();
            let b: Vec<u64> = (0..n*n).map(|_| (rng.next() % 100) as u64).collect();
            let mut c = vec![0u64; n*n];
            for i in 0..n { for k in 0..n { for j in 0..n {
                c[i*n+j] += a[i*n+k] * b[k*n+j];
            }}}
            checksum(c).to_string()
        }
        1 => {
            let mut values: Vec<u32> = (0..black_box(32768)).map(|_| rng.next()).collect();
            values.sort_unstable();
            checksum(values.into_iter().map(u64::from)).to_string()
        }
        2 => {
            let n = black_box(500000);
            let mut prime = vec![true; n+1];
            prime[0] = false; prime[1] = false;
            for p in 2..=n { if prime[p] && p <= n/p {
                for k in (p*p..=n).step_by(p) { prime[k] = false; }
            }}
            let count = prime.iter().filter(|&&p| p).count();
            let sum: u64 = prime.iter().enumerate().filter(|(_, p)| **p).map(|(i, _)| i as u64).sum();
            format!("{count},{sum}")
        }
        3 => {
            let n = black_box(384);
            let mut graph = vec![Vec::new(); n];
            for edges in &mut graph { for _ in 0..8 {
                let node = rng.next() as usize % n;
                let weight = (rng.next() % 100 + 1) as u64;
                edges.push((node, weight));
            }}
            let mut distance = vec![1_000_000u64; n];
            let mut used = vec![false; n];
            distance[0] = 0;
            for _ in 0..n {
                let u = (0..n).filter(|&i| !used[i]).min_by_key(|&i| (distance[i], i)).unwrap();
                used[u] = true;
                for &(v, w) in &graph[u] { distance[v] = distance[v].min(distance[u] + w); }
            }
            checksum(distance).to_string()
        }
        4 => {
            let n = black_box(96);
            let mut d: Vec<u64> = (0..n*n).map(|_| (rng.next() % 1000 + 1) as u64).collect();
            for i in 0..n { d[i*n+i] = 0; }
            for k in 0..n { for i in 0..n { for j in 0..n {
                d[i*n+j] = d[i*n+j].min(d[i*n+k] + d[k*n+j]);
            }}}
            checksum(d).to_string()
        }
        5 => {
            let capacity = black_box(20000);
            let mut best = vec![0u64; capacity+1];
            for _ in 0..200 {
                let weight = (rng.next() % 400 + 1) as usize;
                let value = (rng.next() % 1000 + 1) as u64;
                for c in (weight..=capacity).rev() { best[c] = best[c].max(best[c-weight] + value); }
            }
            best[capacity].to_string()
        }
        6 => {
            let n = black_box(1024);
            let a: Vec<u32> = (0..n).map(|_| rng.next() % 23).collect();
            let b: Vec<u32> = (0..n).map(|_| rng.next() % 23).collect();
            let mut prev: Vec<u64> = (0..=n as u64).collect();
            let mut current = vec![0; n+1];
            for i in 1..=n {
                current[0] = i as u64;
                for j in 1..=n { current[j] = (prev[j] + 1).min(current[j-1] + 1)
                    .min(prev[j-1] + u64::from(a[i-1] != b[j-1])); }
                std::mem::swap(&mut prev, &mut current);
            }
            prev[n].to_string()
        }
        7 => {
            let points: Vec<(i64, i64)> = (0..black_box(4096)).map(|_| ((rng.next()%10000) as i64, (rng.next()%10000) as i64)).collect();
            let mut centers = points[..8].to_vec();
            for _ in 0..12 {
                let mut sums = [(0i64, 0i64, 0i64); 8];
                for &(x, y) in &points {
                    let k = (0..8).min_by_key(|&k| ((x-centers[k].0).pow(2) + (y-centers[k].1).pow(2), k)).unwrap();
                    sums[k].0 += x; sums[k].1 += y; sums[k].2 += 1;
                }
                for k in 0..8 { if sums[k].2 > 0 { centers[k] = (sums[k].0/sums[k].2, sums[k].1/sums[k].2); }}
            }
            checksum(centers.into_iter().flat_map(|(x,y)| [x as u64, y as u64])).to_string()
        }
        8 => {
            let n = black_box(128);
            let mut points: Vec<(i64, i64)> = (0..n).map(|_| ((rng.next()%10000) as i64, (rng.next()%10000) as i64)).collect();
            let mut velocity = vec![(0i64, 0i64); n];
            for _ in 0..30 {
                let mut acceleration = vec![(0i64, 0i64); n];
                for i in 0..n { for j in 0..n { if i != j {
                    let dx = points[j].0 - points[i].0; let dy = points[j].1 - points[i].1;
                    let d = dx.abs() + dy.abs() + 100;
                    acceleration[i].0 += dx * 100 / d;
                    acceleration[i].1 += dy * 100 / d;
                }}}
                for i in 0..n {
                    velocity[i].0 = (velocity[i].0 + acceleration[i].0 / 100).clamp(-50, 50);
                    velocity[i].1 = (velocity[i].1 + acceleration[i].1 / 100).clamp(-50, 50);
                    points[i].0 += velocity[i].0; points[i].1 += velocity[i].1;
                }
            }
            checksum(points.into_iter().flat_map(|(x,y)| [x as u64, y as u64])).to_string()
        }
        9 => {
            let n = black_box(256);
            let pixels: Vec<u64> = (0..n*n).map(|_| (rng.next()%256) as u64).collect();
            let weights = [1u64, 4, 6, 4, 1];
            let mut out = Vec::new();
            for y in 2..n-2 { for x in 2..n-2 {
                let mut value = 0;
                for ky in 0..5 { for kx in 0..5 { value += pixels[(y+ky-2)*n+x+kx-2]*weights[ky]*weights[kx]; }}
                out.push(value / 256);
            }}
            checksum(out).to_string()
        }
        10 => {
            let n = black_box(512);
            let graph: Vec<Vec<usize>> = (0..n).map(|_| (0..8).map(|_| rng.next() as usize % n).collect()).collect();
            let mut ranks = vec![1_000_000_000u64 / n as u64; n];
            for _ in 0..30 {
                let mut next = vec![150_000_000u64 / n as u64; n];
                for i in 0..n { let amount = ranks[i]*85/100/8;
                    for &j in &graph[i] { next[j] += amount; }
                }
                ranks = next;
            }
            checksum(ranks).to_string()
        }
        11 => {
            let mut records = Vec::new();
            for i in 0..black_box(12000) {
                records.push(serde_json::json!({"region":rng.next()%64, "amount":rng.next()%100000,
                                               "active":i%3 != 0, "id":i}));
            }
            let encoded = serde_json::to_vec(&records).unwrap();
            let parsed: Vec<serde_json::Value> = serde_json::from_slice(black_box(&encoded)).unwrap();
            let mut sums = [0u64; 64];
            for record in parsed { if record["active"].as_bool().unwrap() {
                sums[record["region"].as_u64().unwrap() as usize] += record["amount"].as_u64().unwrap();
            }}
            checksum(sums).to_string()
        }
        12 => {
            let n = black_box(65536);
            let mut input = Vec::new();
            while input.len() < n {
                let byte = (rng.next()%256) as u8;
                let count = (rng.next()%32 + 1) as usize;
                for _ in 0..count.min(n-input.len()) { input.push(byte); }
            }
            let mut packed = Vec::new();
            let mut i = 0;
            while i < input.len() {
                let mut count = 1usize;
                while i+count < input.len() && input[i+count] == input[i] && count < 255 { count += 1; }
                packed.push((count as u8, input[i])); i += count;
            }
            let mut decoded = Vec::new();
            for &(count, byte) in &packed { decoded.extend(std::iter::repeat_n(byte, count as usize)); }
            assert_eq!(input, decoded);
            format!("{},{}", packed.len()*2, checksum(decoded.into_iter().map(u64::from)))
        }
        13 => {
            let mut nodes = Vec::new();
            for _ in 0..black_box(1024) {
                let block: Vec<u8> = (0..1024).map(|_| (rng.next() >> 24) as u8).collect();
                nodes.push(Sha256::digest(&block).to_vec());
            }
            while nodes.len() > 1 {
                nodes = nodes.chunks_exact(2).map(|p| { let mut hasher = Sha256::new();
                    hasher.update(&p[0]); hasher.update(&p[1]); hasher.finalize().to_vec() }).collect();
            }
            hex(&nodes[0])
        }
        14 => {
            fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
                let mut inner = [0x36u8; 64]; let mut outer = [0x5cu8; 64];
                for (i, &b) in key.iter().enumerate() { inner[i] ^= b; outer[i] ^= b; }
                let mut h = Sha256::new(); h.update(inner); h.update(data);
                let temp = h.finalize(); let mut h = Sha256::new(); h.update(outer); h.update(temp);
                h.finalize().to_vec()
            }
            let password = black_box(b"hal-benchmark-password");
            let mut salt = b"hal-benchmark-salt".to_vec(); salt.extend([0,0,0,1]);
            let mut u = hmac(password, &salt); let mut result = u.clone();
            for _ in 1..black_box(10000) {
                u = hmac(password, &u);
                for (r, &b) in result.iter_mut().zip(&u) { *r ^= b; }
            }
            hex(&result)
        }
        _ => panic!("unknown workload"),
    };
    format!("{}:{}", NAMES[index], value)
}
