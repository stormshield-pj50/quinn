use anyhow::{anyhow, bail, Context};
use futures::{stream::FuturesUnordered, FutureExt, StreamExt};
use std::{fs, io, net::ToSocketAddrs, sync::Arc};
use tracing::{error, info};

mod common;

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
    let listen = (HOST, 4433)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("couldn't resolve to an address"))?;

    let dirs = directories_next::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
    let path = dirs.data_local_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            info!("generating self-signed certificate");
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            fs::create_dir_all(&path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };

    let key = rustls::PrivateKey(key);
    let certs = vec![rustls::Certificate(cert)];

    let server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    let endpoint = quinn::Endpoint::server(server_config, listen)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        info!("connection incoming");
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connecting) -> anyhow::Result<()> {
    let conn = conn.await?;
    info!("established");

    let mut fuo = FuturesUnordered::new();
    for i in 0..2 {
        let conn_clone = conn.clone();
        fuo.push(
            async move {
                loop {
                    match conn_clone.read_datagram().await {
                        Ok(datagram) => println!("fut #{} recv datagram {:?}", i, datagram),
                        Err(e) => {
                            break Err(anyhow!(e))
                        }
                    }
                }
            }
            .boxed(),
        );
    }

    match fuo.next().await {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(e),
        None => unreachable!(),
    }
}
