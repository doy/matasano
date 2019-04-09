use rand::RngCore;
use serde_derive::Deserialize;

#[derive(Deserialize)]
struct Info {
    file: String,
    signature: String,
}

fn gen_key() -> Vec<u8> {
    let mut key = [0u8; 80];
    rand::thread_rng().fill_bytes(&mut key);
    key.to_vec()
}

fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    true
}

fn index(
    info: actix_web::Query<Info>,
    key: &[u8],
) -> actix_web::Result<String> {
    let hmac = matasano::sha1_hmac(&info.file.clone().into_bytes(), key);
    println!("hmac for {} is {}", info.file, hex::encode(hmac));
    if insecure_compare(
        &hex::decode(info.signature.clone()).unwrap(),
        &hmac[..],
    ) {
        Ok("ok".to_string())
    } else {
        Err(actix_web::error::ErrorBadRequest("hmac failed"))
    }
}

fn main() {
    let sys = actix::System::new("timing_attack");

    let key = gen_key();
    println!("{}", hex::encode(&key));

    actix_web::server::HttpServer::new(move || {
        let key = key.clone();
        actix_web::App::new().resource("/", |r| {
            r.method(actix_web::http::Method::GET)
                .with(move |info| index(info, &key))
        })
    })
    .bind("127.0.0.1:9000")
    .unwrap()
    .start();

    let _ = sys.run();
}
