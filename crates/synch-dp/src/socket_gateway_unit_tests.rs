use super::*;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn output_waits_for_credit_and_completion_does_not_wait_for_client_eof() {
    let (caller, mut peer) = tokio::io::duplex(MAX_CHUNK * 4);
    let (read, write) = tokio::io::split(caller);
    let (_input, receiver) = mpsc::channel(1);
    let (writes, mut output) = mpsc::channel(8);
    let permits = Arc::new(Semaphore::new(1));
    let pending = Arc::new(AtomicBool::new(false));
    let (done, completion) = tokio::sync::oneshot::channel();
    let task_permits = permits.clone();
    let task = tokio::spawn(async move {
        pump(
            read,
            write,
            receiver,
            async { completion.await.map_err(|e| e.to_string()) },
            Flow {
                writes: &writes,
                id: 7,
                credit: Arc::new(AtomicBool::new(true)),
                pending,
                permits: task_permits,
            },
        )
        .await
    });
    peer.write_all(&vec![42; MAX_CHUNK * 2]).await.unwrap();
    peer.shutdown().await.unwrap();
    let first = output.recv().await.unwrap();
    assert!(matches!(first, Message::Binary(_)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), output.recv())
            .await
            .is_err(),
        "a stalled receiver must not receive a second uncredited chunk"
    );
    permits.add_permits(1);
    assert!(matches!(output.recv().await.unwrap(), Message::Binary(_)));
    permits.add_permits(1);
    let Message::Text(eof) = output.recv().await.unwrap() else {
        panic!("expected eof")
    };
    assert!(matches!(
        serde_json::from_str::<Up>(&eof).unwrap(),
        Up::SocketEof { id: 7 }
    ));
    assert!(
        !task.is_finished(),
        "a half-close is not invocation completion"
    );
    done.send(synch_core::SockStatus::Deadline).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        synch_core::SockStatus::Deadline
    );
    // Input sender still exists: completion cancels the blocked upload.
}
