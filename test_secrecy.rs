use secrecy::SecretVec;

fn main() {
    let mut vec = vec![1, 2, 3];
    let secret = SecretVec::new(vec);
}
