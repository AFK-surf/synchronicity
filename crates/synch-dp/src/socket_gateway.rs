//! Generic socket streams carried by the managed tunnel, never the browse tunnel.
//! One credit in either direction bounds buffering even when the consumer stalls.
use crate::writes::{encode_chunk, text, Up, MAX_CHUNK};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use synch_core::OriginId;
use synch_engine::{sockets::SocketConnection, Node};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, Semaphore},
};

const MAX_SOCKETS: usize = 32;
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct Gateway {
    streams: HashMap<u32, Stream>,
}

struct Stream {
    input: mpsc::Sender<Vec<u8>>,
    input_credit: Arc<AtomicBool>,
    output_pending: Arc<AtomicBool>,
    output_credit: Arc<Semaphore>,
    eof: bool,
    seq: u32,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    pub(crate) fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub(crate) fn open(
        &mut self,
        node: &Node,
        writes: &mpsc::Sender<tokio_tungstenite::tungstenite::Message>,
        id: u32,
        origin: String,
        socket: Option<String>,
    ) -> crate::Result<Option<tokio_tungstenite::tungstenite::Message>> {
        self.streams.retain(|_, stream| !stream.task.is_finished());
        if self.streams.contains_key(&id) || self.streams.len() >= MAX_SOCKETS {
            // The tunnel owns at most one pending refusal and pauses reads until
            // writer capacity returns. A full queue is not a failed connection.
            return Ok(Some(text(&Up::Err {
                id: Some(id),
                code: "busy".into(),
                message: "too many or duplicate socket requests".into(),
            })?));
        }
        let (input, receiver) = mpsc::channel(1);
        let input_credit = Arc::new(AtomicBool::new(false));
        let output_pending = Arc::new(AtomicBool::new(false));
        let output_credit = Arc::new(Semaphore::new(1));
        let (node, writes) = (node.clone(), writes.clone());
        let (credit, pending, permits) = (
            input_credit.clone(),
            output_pending.clone(),
            output_credit.clone(),
        );
        let task = tokio::spawn(async move {
            let result = async {
                let origin: OriginId = if origin.is_empty() {
                    node.origin().clone()
                } else {
                    origin.parse().map_err(|e| format!("invalid origin: {e}"))?
                };
                let controller = node.node_id().to_z32();
                match socket {
                    None => {
                        let sockets =
                            tokio::time::timeout(OPEN_TIMEOUT, node.list_sockets(&origin))
                                .await
                                .map_err(|_| "socket listing timed out".to_string())?
                                .map_err(|e| e.to_string())?;
                        send(
                            &writes,
                            Up::SocketList {
                                id,
                                controller,
                                origin: node.origin().canonical(),
                                sockets: serde_json::to_value(sockets)
                                    .map_err(|e| e.to_string())?,
                            },
                        )
                        .await
                    }
                    Some(socket) => {
                        let connection = tokio::time::timeout(
                            OPEN_TIMEOUT,
                            node.connect_socket(&origin, &socket, vec![]),
                        )
                        .await
                        .map_err(|_| "socket open timed out".to_string())?
                        .map_err(|e| e.to_string())?;
                        credit.store(true, Ordering::Release);
                        send(
                            &writes,
                            Up::SocketOpened {
                                id,
                                controller,
                                origin: node.origin().canonical(),
                            },
                        )
                        .await?;
                        let status = match connection {
                            SocketConnection::Remote {
                                client,
                                mut control,
                                stream,
                            } => {
                                // Both are retained for the entire byte stream. Dropping the client
                                // cancels the remote invocation even if the peer stopped sending.
                                let _client = client;
                                pump(
                                    stream.recv,
                                    stream.send,
                                    receiver,
                                    async move {
                                        synch_net::frame::read_frame::<synch_core::SockClosed>(
                                            &mut control,
                                        )
                                        .await
                                        .map(|closed| closed.status)
                                        .map_err(|e| e.to_string())
                                    },
                                    Flow {
                                        writes: &writes,
                                        id,
                                        credit,
                                        pending,
                                        permits,
                                    },
                                )
                                .await?
                            }
                            SocketConnection::Local {
                                stream, completion, ..
                            } => {
                                let (read, write) = tokio::io::split(stream);
                                pump(
                                    read,
                                    write,
                                    receiver,
                                    async move { completion.await.map_err(|e| e.to_string()) },
                                    Flow {
                                        writes: &writes,
                                        id,
                                        credit,
                                        pending,
                                        permits,
                                    },
                                )
                                .await?
                            }
                        };
                        send(&writes, Up::SocketClosed { id, status }).await
                    }
                }
            }
            .await;
            if let Err(message) = result {
                let _ = send(
                    &writes,
                    Up::Err {
                        id: Some(id),
                        code: "unavailable".into(),
                        message,
                    },
                )
                .await;
            }
        });
        self.streams.insert(
            id,
            Stream {
                input,
                input_credit,
                output_pending,
                output_credit,
                eof: false,
                seq: 0,
                task,
            },
        );
        Ok(None)
    }

    pub(crate) fn cancel(&mut self, id: u32) {
        self.streams.remove(&id);
    }

    pub(crate) fn contains(&self, id: u32) -> bool {
        self.streams.contains_key(&id)
    }

    pub(crate) fn chunk(&mut self, id: u32, seq: u32, data: &[u8]) -> crate::Result<()> {
        let Some(stream) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        if stream.eof
            || seq != stream.seq
            || data.is_empty()
            || data.len() > MAX_CHUNK
            || !stream.input_credit.swap(false, Ordering::AcqRel)
        {
            return Err(crate::DpError::Control(
                "invalid socket input or input without credit".into(),
            ));
        }
        stream.seq = stream.seq.wrapping_add(1);
        // At most one data frame is in flight; the sender is dropped on EOF.
        stream
            .input
            .try_send(data.to_vec())
            .map_err(|_| crate::DpError::Control("socket input is closed".into()))
    }

    pub(crate) fn eof(&mut self, id: u32) {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.eof = true;
            let (closed, _) = mpsc::channel(1);
            // Drop the actual sender: queued input drains before write shutdown.
            stream.input = closed;
        }
    }

    pub(crate) fn ack(&self, id: u32) -> crate::Result<()> {
        if let Some(stream) = self.streams.get(&id) {
            if !stream.output_pending.swap(false, Ordering::AcqRel) {
                return Err(crate::DpError::Control(
                    "socket output credit without a chunk".into(),
                ));
            }
            stream.output_credit.add_permits(1);
        }
        Ok(())
    }
}

async fn send(
    writes: &mpsc::Sender<tokio_tungstenite::tungstenite::Message>,
    frame: Up,
) -> Result<(), String> {
    writes
        .send(text(&frame).map_err(|e| e.to_string())?)
        .await
        .map_err(|_| "tunnel closed".into())
}

struct Flow<'a> {
    writes: &'a mpsc::Sender<tokio_tungstenite::tungstenite::Message>,
    id: u32,
    credit: Arc<AtomicBool>,
    pending: Arc<AtomicBool>,
    permits: Arc<Semaphore>,
}

async fn pump(
    mut read: impl AsyncRead + Unpin,
    mut write: impl AsyncWrite + Unpin,
    mut input: mpsc::Receiver<Vec<u8>>,
    completion: impl std::future::Future<Output = Result<synch_core::SockStatus, String>>,
    flow: Flow<'_>,
) -> Result<synch_core::SockStatus, String> {
    let upload = async {
        while let Some(data) = input.recv().await {
            write.write_all(&data).await.map_err(|e| e.to_string())?;
            flow.credit.store(true, Ordering::Release);
            send(flow.writes, Up::Credit { id: flow.id, n: 1 }).await?;
        }
        write.shutdown().await.map_err(|e| e.to_string())
    };
    let download = async {
        let mut seq = 0;
        let mut buf = vec![0; MAX_CHUNK];
        loop {
            let permit = flow.permits.acquire().await.map_err(|e| e.to_string())?;
            permit.forget();
            let n = read.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return send(flow.writes, Up::SocketEof { id: flow.id }).await;
            }
            flow.pending.store(true, Ordering::Release);
            flow.writes
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    encode_chunk(flow.id, seq, &buf[..n]).into(),
                ))
                .await
                .map_err(|_| "tunnel closed".to_string())?;
            seq = seq.wrapping_add(1);
        }
    };
    let closing = async {
        download.await?;
        completion.await
    };
    tokio::pin!(upload, closing);
    tokio::select! {
        result = &mut upload => { result?; closing.await }
        result = &mut closing => result,
    }
}

#[cfg(test)]
#[path = "socket_gateway_unit_tests.rs"]
mod tests;
