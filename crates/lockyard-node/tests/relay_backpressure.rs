// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.

//! Real loopback relay regression: inbound event backpressure must not block writes or shutdown.
use futures_util::{SinkExt, StreamExt};
use lockyard_node::{
    relay::{RelayClient, RelayConfig, RelayEvent},
    wire::{RelayControl, RelayMessage, new_id},
};
use std::time::Duration;
use tokio::{net::TcpListener, sync::oneshot};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{
        Message,
        handshake::server::{ErrorResponse, Request, Response},
    },
};

#[allow(clippy::result_large_err)]
fn handshake(request: &Request, mut response: Response) -> Result<Response, ErrorResponse> {
    assert_eq!(request.uri().path(), "/api/v1/nodes/connect");
    assert_eq!(request.uri().query(), Some("node_id=controller"));
    assert_eq!(
        request.headers().get("X-Lockyard-Session").unwrap(),
        "controller"
    );
    assert_eq!(
        request.headers().get("Authorization").unwrap(),
        "Bearer test-credential"
    );
    response.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "lockyard-node.v1".parse().unwrap(),
    );
    Ok(response)
}

fn ack(id: String) -> RelayMessage {
    RelayMessage::Control(RelayControl::Ack { v: 1, id })
}

fn ack_id(event: RelayEvent) -> String {
    match event {
        RelayEvent::Message(RelayMessage::Control(RelayControl::Ack { v: 1, id })) => id,
        _ => panic!("expected the next relay acknowledgement"),
    }
}

#[tokio::test]
async fn inbound_event_backpressure_does_not_block_outbound_ack_and_preserves_order() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let expected: Vec<_> = (0..64).map(|_| new_id().unwrap()).collect();
        let emitted = expected.clone();
        let outbound_id = new_id().unwrap();
        let server_expected = outbound_id.clone();
        let (burst_done, burst_received) = oneshot::channel();
        let (seen_ack, ack_received) = oneshot::channel();
        let (drained, wait_for_drain) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_hdr_async(stream, handshake).await.unwrap();
            for id in emitted {
                socket
                    .send(Message::Text(
                        serde_json::to_string(&ack(id)).unwrap().into(),
                    ))
                    .await
                    .unwrap();
            }
            burst_done.send(()).unwrap();
            loop {
                match socket.next().await.unwrap().unwrap() {
                    Message::Text(text) => {
                        match serde_json::from_str::<RelayMessage>(&text).unwrap() {
                            RelayMessage::Control(RelayControl::Ack { v: 1, id }) => {
                                assert_eq!(id, server_expected)
                            }
                            _ => panic!("unexpected outbound message"),
                        }
                        seen_ack.send(()).unwrap();
                        break;
                    }
                    Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                    _ => {}
                }
            }
            let _ = wait_for_drain.await;
        });
        let mut client = RelayClient::spawn(
            RelayConfig::new(&url, "controller".into(), "test-credential".into()).unwrap(),
        )
        .unwrap();
        let mut sender = client.sender();
        sender.wait_connected(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(client.recv().await, Some(RelayEvent::Connected)));
        burst_received.await.unwrap();
        // Let the bounded queue fill, then consume exactly one item as Host does
        // before waiting for its outbound ACK. No further inbound event is consumed
        // until the write has completed and the peer has observed it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(ack_id(client.recv().await.unwrap()), expected[0]);
        tokio::time::sleep(Duration::from_millis(100)).await;
        tokio::time::timeout(Duration::from_secs(2), sender.send(&ack(outbound_id)))
            .await
            .expect("outbound ACK stalled behind a full inbound event queue")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), ack_received)
            .await
            .expect("peer did not receive the outbound ACK")
            .unwrap();
        for id in expected.iter().skip(1) {
            assert_eq!(&ack_id(client.recv().await.unwrap()), id);
        }
        drained.send(()).unwrap();
        client.shutdown().await;
        server.await.unwrap();
    })
    .await
    .expect("relay backpressure regression timed out");
}

#[tokio::test]
async fn shutdown_interrupts_full_inbound_event_queue() {
    check_shutdown_with_backpressure(false).await;
}

#[tokio::test]
async fn shutdown_interrupts_reconnect_while_event_queue_is_full() {
    check_shutdown_with_backpressure(true).await;
}

async fn check_shutdown_with_backpressure(request_reconnect: bool) {
    tokio::time::timeout(Duration::from_secs(8), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (burst_done, burst_received) = oneshot::channel();
        let (release, wait_for_release) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_hdr_async(stream, handshake).await.unwrap();
            for _ in 0..64 {
                socket
                    .send(Message::Text(
                        serde_json::to_string(&ack(new_id().unwrap()))
                            .unwrap()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            burst_done.send(()).unwrap();
            let _ = wait_for_release.await;
        });
        let mut client = RelayClient::spawn(
            RelayConfig::new(&url, "controller".into(), "test-credential".into()).unwrap(),
        )
        .unwrap();
        let mut sender = client.sender();
        sender.wait_connected(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(client.recv().await, Some(RelayEvent::Connected)));
        burst_received.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        if request_reconnect {
            sender.request_reconnect();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::timeout(Duration::from_secs(2), client.shutdown())
            .await
            .expect("relay shutdown stalled behind a full inbound event queue");
        let _ = release.send(());
        server.await.unwrap();
    })
    .await
    .expect("relay shutdown regression timed out");
}

#[tokio::test]
async fn reconnect_keeps_already_parsed_event_before_disconnect() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let expected: Vec<_> = (0..64).map(|_| new_id().unwrap()).collect();
        let emitted = expected.clone();
        let (burst_done, burst_received) = oneshot::channel();
        let (release, wait_for_release) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_hdr_async(stream, handshake).await.unwrap();
            for id in emitted {
                socket
                    .send(Message::Text(
                        serde_json::to_string(&ack(id)).unwrap().into(),
                    ))
                    .await
                    .unwrap();
            }
            burst_done.send(()).unwrap();
            while let Some(Ok(message)) = socket.next().await {
                if matches!(message, Message::Close(_)) {
                    break;
                }
            }
            let (stream, _) = listener.accept().await.unwrap();
            let _socket = accept_hdr_async(stream, handshake).await.unwrap();
            let _ = wait_for_release.await;
        });
        let mut client = RelayClient::spawn(
            RelayConfig::new(&url, "controller".into(), "test-credential".into()).unwrap(),
        )
        .unwrap();
        let mut sender = client.sender();
        sender.wait_connected(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(client.recv().await, Some(RelayEvent::Connected)));
        burst_received.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        sender.request_reconnect();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut received = 0;
        loop {
            match client.recv().await.unwrap() {
                RelayEvent::Message(RelayMessage::Control(RelayControl::Ack { v: 1, id })) => {
                    assert_eq!(id, expected[received]);
                    received += 1;
                }
                RelayEvent::Disconnected { code } => {
                    assert_eq!(code, "relay_reconnect_requested");
                    break;
                }
                _ => panic!("unexpected event before disconnect"),
            }
        }
        assert!(
            received >= 17,
            "the event already read beyond the 16-slot queue was lost"
        );
        assert!(matches!(client.recv().await, Some(RelayEvent::Connected)));
        let _ = release.send(());
        client.shutdown().await;
        server.await.unwrap();
    })
    .await
    .expect("relay reconnect ordering timed out");
}
