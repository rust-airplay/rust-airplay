// SPDX-License-Identifier: GPL-3.0-or-later

// Tests report what they measured; the library itself never prints.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! What the receiver's own answers cost, phase by phase.
//!
//! "Connecting takes a while" can be a client's decision, a network's delay, or a server
//! that is slow to answer. Only the last is this crate's to fix, so it is measured apart
//! from the others: a real TCP connection to a real [`Server`], one request at a time, with
//! each answer timed.
//!
//! The test asserts nothing about speed — a threshold in a test is a number that gets
//! raised until it passes — and prints what it saw. Run it next to a slow connection:
//!
//! ```powershell
//! cargo test --release -p airplay-core --test handshake_cost -- --ignored --nocapture
//! ```
//!
//! If these are milliseconds, the time is somewhere this crate cannot see: the client
//! deciding, the sink bringing up a window, or the network between them.

use std::time::Instant;

use rust_airplay::server::{RouteHandlers, Server, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Sends one request and reads one answer, returning how long the answer took.
async fn ask(stream: &mut TcpStream, request: &[u8], pending: &mut Vec<u8>) -> std::time::Duration {
    let started = Instant::now();
    stream
        .write_all(request)
        .await
        .expect("the request is sent");
    // The answers here are small enough to arrive in one read; a body is drained by its
    // length so that the next request does not read the previous answer's tail.
    loop {
        if let Some(end) = pending.windows(4).position(|run| run == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&pending[..end]).to_ascii_lowercase();
            let declared = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if pending.len() >= end + 4 + declared {
                pending.drain(..end + 4 + declared);
                return started.elapsed();
            }
        }
        let mut chunk = [0u8; 4096];
        let read = stream.read(&mut chunk).await.expect("an answer arrives");
        assert!(read > 0, "the server closed the connection");
        pending.extend_from_slice(&chunk[..read]);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measures rather than asserts; run with --ignored --nocapture"]
async fn what_each_answer_costs() {
    let server = Server::bind(ServerConfig {
        bind: "127.0.0.1:0".parse().expect("address"),
        ..ServerConfig::default()
    })
    .await
    .expect("bind");
    let address = server.local_addr().expect("address");
    let identity = RouteHandlers::new(rust_airplay::server::DeviceIdentity::new(
        "AA:BB:CC:DD:EE:FF",
        "handshake-cost",
        vec![0u8; 32],
    ))
    .identity()
    .clone();
    let serving = tokio::spawn(async move {
        server
            .run(move || {
                let mut handlers = RouteHandlers::new(identity.clone());
                handlers.set_feedback_callback(|| {});
                handlers
            })
            .await
    });

    // Connecting is part of what a client waits for, so it is timed too.
    let connecting = Instant::now();
    let mut stream = TcpStream::connect(address).await.expect("connect");
    let connected = connecting.elapsed();

    let mut pending = Vec::new();
    let requests: &[(&str, &[u8])] = &[
        (
            "OPTIONS",
            b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: AirPlay/900\r\n\r\n",
        ),
        (
            "GET /info",
            b"GET /info RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: AirPlay/900\r\n\r\n",
        ),
    ];
    let mut costs = vec![("TCP connect", connected)];
    for (name, request) in requests {
        costs.push((*name, ask(&mut stream, request, &mut pending).await));
    }

    for (name, cost) in &costs {
        println!("  {name:<14} {cost:?}");
    }
    serving.abort();
    stream.shutdown().await.ok();

    // Said plainly, because the numbers only mean something next to the complaint: these
    // are what this receiver adds to a connection.
    let total: std::time::Duration = costs.iter().map(|(_, cost)| *cost).sum();
    println!(
        "  {:<14} {total:?}   (the receiver's own share of a connection)",
        "total"
    );
}
