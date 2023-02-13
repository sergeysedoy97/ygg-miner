use ed25519_dalek::{SecretKey, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH};
use rdrand::{ErrorCode, RdRand};
use std::thread::{spawn, JoinHandle};

const NTHREADS: u8 = 8;
const NZEROS: u8 = 9;

fn main() {
    let mut children: Vec<JoinHandle<_>> = vec![];
    for _ in 0..NTHREADS {
        children.push(spawn(move || {
            let result: Result<RdRand, ErrorCode> = RdRand::new();
            if result.is_err() {
                panic!("{}", result.err().unwrap());
            }
            let mut csprng: RdRand = result.ok().unwrap();
            let mut zero_count: u8 = 0;
            loop {
                let signing_key: SigningKey = SigningKey::generate(&mut csprng);
                let verifying_key: VerifyingKey = signing_key.verifying_key();
                let verifying_key_bytes: &[u8; PUBLIC_KEY_LENGTH] = verifying_key.as_bytes();
                for x in verifying_key_bytes {
                    if *x == 0 {
                        zero_count += 1;
                    } else {
                        break;
                    }
                }
                if zero_count >= NZEROS {
                    let secret_key: SecretKey = signing_key.to_bytes();
                    println!(
                        "public: {:x?}\nsecret: {:x?}\n",
                        verifying_key_bytes, secret_key
                    );
                }
                zero_count = 0;
            }
        }));
    }
    for child in children {
        let _ = child.join();
    }
}
