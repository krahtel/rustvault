use axum::{routing::get, Router};

use std::net::SocketAddr;

mod crypto;
mod vault;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health));

    let address = SocketAddr::from(([127, 0, 0, 1], 8080));

    println!("=================================");
    println!("          RustVault");
    println!("   Decentralized Web Vault");
    println!("=================================");
    println!();
    println!("Server: http://{}", address);

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("Failed to bind server");

    axum::serve(listener, app).await.expect("Server error");
}

async fn index() -> &'static str {
    "Welcome to RustVault 🔐"
}

async fn health() -> &'static str {
    "RustVault is healthy"
}
