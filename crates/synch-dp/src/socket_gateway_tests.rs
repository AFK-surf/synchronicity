// Included in writes::tests to reuse the managed-tunnel and node fixtures.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[tokio::test]
async fn socket_gateway_streams_remote_bytes_and_cancels_on_tunnel_loss() {
    let (_data, node) = tenant().await;
    let (_remote_data, remote) = tenant().await;
    let source = tempfile::tempdir().unwrap();
    let elf = synch_cc::compile(
        include_str!("../../synch-sock/examples/echo.c"),
        "echo.c",
        &[("synch.h", synch_sock::sdk::HEADER)],
        &[],
    )
    .unwrap();
    std::fs::write(source.path().join("echo.o"), elf).unwrap();
    remote.add_filesystem_source("code", source.path()).unwrap();
    remote
        .socket_activate(&synch_store::SocketActivation::new(
            "echo",
            "code",
            "echo.o",
            synch_core::now_ns(),
        ))
        .unwrap();
    remote.scan_and_publish().unwrap();
    for (caller, peer) in [(&node, &remote), (&remote, &node)] {
        caller
            .store()
            .put_binding(&synch_store::Binding {
                origin: peer.origin().clone(),
                node_id: peer.node_id(),
                source: synch_store::BindingSource::Static,
                domain: None,
                issuer: None,
                spaces: vec![],
                note: None,
                added_at: 0,
                expires_at: None,
            })
            .unwrap();
        caller.remember_peer(&peer.net().direct_addr()).unwrap();
    }
    let (down, mut up, task) = session(&node, limits());
    down.send(down_msg(&Down::SocketList {
        id: 1,
        origin: remote.origin().canonical(),
    }))
    .unwrap();
    match next_up(&mut up).await {
        Up::SocketList {
            controller,
            sockets,
            ..
        } => {
            assert_eq!(controller, node.node_id().to_z32());
            assert_eq!(sockets[0]["name"], "echo");
        }
        other => panic!("expected listing, got {other:?}"),
    }
    down.send(down_msg(&Down::SocketOpen {
        id: 2,
        origin: remote.origin().canonical(),
        socket: "echo".into(),
    }))
    .unwrap();
    assert!(matches!(
        next_up(&mut up).await,
        Up::SocketOpened { id: 2, .. }
    ));
    let bytes = b"binary\0\xffthrough managed tunnel";
    down.send(Message::Binary(encode_chunk(2, 0, bytes).into()))
        .unwrap();
    let mut credit = false;
    let mut echoed = Vec::new();
    while !credit || echoed.len() < bytes.len() {
        match tokio::time::timeout(Duration::from_secs(10), up.recv())
            .await
            .unwrap()
            .unwrap()
        {
            Message::Binary(frame) => {
                let (id, _, data) = decode_chunk(&frame).unwrap();
                assert_eq!(id, 2);
                echoed.extend_from_slice(data);
                down.send(down_msg(&Down::SocketAck { id: 2 })).unwrap();
            }
            Message::Text(body) => match serde_json::from_str::<Up>(&body).unwrap() {
                Up::Credit { id: 2, n: 1 } => credit = true,
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(echoed, bytes);
    down.send(down_msg(&Down::SocketEof { id: 2 })).unwrap();
    assert!(matches!(next_up(&mut up).await, Up::SocketEof { id: 2 }));
    assert!(matches!(
        next_up(&mut up).await,
        Up::SocketClosed { id: 2, .. }
    ));
    down.send(down_msg(&Down::SocketOpen {
        id: 3,
        origin: remote.origin().canonical(),
        socket: "echo".into(),
    }))
    .unwrap();
    assert!(matches!(
        next_up(&mut up).await,
        Up::SocketOpened { id: 3, .. }
    ));
    down.send(down_msg(&Down::Cancel { id: 3 })).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !remote.socket_ps(None).is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("explicit cancel must end the remote invocation");
    down.send(down_msg(&Down::SocketOpen {
        id: 4,
        origin: remote.origin().canonical(),
        socket: "echo".into(),
    }))
    .unwrap();
    assert!(matches!(
        next_up(&mut up).await,
        Up::SocketOpened { id: 4, .. }
    ));
    // The peer ends its invocation while CP still owns one input credit.
    // Input already in flight must not take down the shared managed tunnel.
    assert!(remote.socket_kill(remote.socket_ps(None)[0].id));
    assert!(matches!(next_up(&mut up).await, Up::SocketEof { id: 4 }));
    assert!(matches!(
        next_up(&mut up).await,
        Up::SocketClosed { id: 4, .. }
    ));
    down.send(Message::Binary(
        encode_chunk(4, 0, b"late valid input").into(),
    ))
    .unwrap();
    down.send(down_msg(&Down::SocketOpen {
        id: 5,
        origin: remote.origin().canonical(),
        socket: "echo".into(),
    }))
    .unwrap();
    loop {
        match next_up(&mut up).await {
            Up::Err { id: Some(4), .. } => continue,
            Up::SocketOpened { id: 5, .. } => break,
            other => panic!("late input damaged a different request: {other:?}"),
        }
    }
    drop(down);
    task.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !remote.socket_ps(None).is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("tunnel loss must cancel remote invocation");
    node.shutdown().await.unwrap();
    remote.shutdown().await.unwrap();
}
