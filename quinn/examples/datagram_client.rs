use anyhow::anyhow;
use bytes::Bytes;
use std::{fs, io, net::ToSocketAddrs, sync::Arc, time::Instant};
use tracing::{error, info};

fn main() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish(),
    )
    .unwrap();
    let code = {
        if let Err(e) = run() {
            eprintln!("ERROR: {}", e);
            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run() -> anyhow::Result<()> {
    const HOST: &'static str = "127.0.0.1";
    let remote = (HOST, 4433)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;
    let mut roots = rustls::RootCertStore::empty();
    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    match fs::read(dirs.data_local_dir().join("cert.der")) {
        Ok(cert) => {
            println!("{:?}", cert);
            roots.add(&rustls::Certificate(cert))?;
        }
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            info!("local server certificate not found");
        }
        Err(e) => {
            error!("failed to open local server certificate: {}", e);
        }
    }

    let client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

    let start = Instant::now();
    eprintln!("connecting to {}", remote);
    let conn = endpoint
        .connect(remote, "localhost")?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    eprintln!("connected at {:?}", start.elapsed());

    let mut datagram_id = 0;
    loop {
        match conn.send_datagram(Bytes::from(format!("datagram #{}", datagram_id))) {
            Ok(()) => {}
            Err(e) => break Err(anyhow!(e)),
        }
        println!("sent datagram #{}", datagram_id);
        datagram_id += 1;
    }
}
