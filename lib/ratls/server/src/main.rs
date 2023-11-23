use std::{sync::Arc, io::Read, vec, fs::File};

use clap::Parser;
use log::info;
use ratls::{RaTlsServer, ChainVerifier};
use veraison_verifier::VeraisonTokenVerifer;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RaTls server bind address
    #[arg(short = 'b', long, default_value = "0.0.0.0:1337")]
    server_bind_address: String,

    /// Path to server cert
    #[arg(short = 'c', long)]
    server_cert: String,

    /// Path to server private key
    #[arg(short = 'k', long)]
    server_privkey: String,

    /// Veraison verification service host
    #[arg(short = 'v', long, default_value = "http://localhost:8080")]
    veraison_url: String,

    /// Veraisons public key to verify attestation results
    #[arg(short = 'p', long)]
    veraison_pubkey: String
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    ratls::init_logger();
    let args = Args::parse();

    let mut pubkey = String::new();
    let mut file = File::open(args.veraison_pubkey)?;
    file.read_to_string(&mut pubkey)?;

    let server = RaTlsServer::new(ratls::ServerMode::AttestedClient {
        client_token_verifier: Arc::new(ChainVerifier::new(vec![
            Arc::new(VeraisonTokenVerifer::new(args.veraison_url, pubkey))
        ])),
        server_certificate_path: args.server_cert,
        server_privatekey_path: args.server_privkey
    })?;

    for connection in server.connections(args.server_bind_address)? {
        if let Ok(mut conn) = connection {
            info!("New connection accepted");
            let mut buf = Vec::new();
            buf.resize(0x100, 0u8);

            while let Ok(len) = conn.stream().read(&mut buf) {
                info!("Message from client: {:?}", String::from_utf8(buf[0..len].to_vec())?);
            }

            info!("Connection closed");
        }
    }

    Ok(())
}
