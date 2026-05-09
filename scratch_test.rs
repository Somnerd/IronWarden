fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        std::thread::spawn(move || {
            let _tx = tx;
            panic!("disk error");
        });
        
        let res = rx.await;
        println!("Result: {:?}", res);
    });
}
