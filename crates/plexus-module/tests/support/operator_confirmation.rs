//! A test-only supervisor peer that answers confirmation without an OS prompt.
//! Authentication, registration, routing, and all other frames reach the daemon.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use subc_protocol::session::{OperatorConfirmReply, OperatorConfirmRequest};
use subc_protocol::{Frame, FrameType};
use subc_transport::auth::{authenticate_client, authenticate_server};
use subc_transport::frame_io::{read_frame, write_frame};
use subc_transport::ConnectionInfo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};

pub struct ConfirmationPeer {
    task: JoinHandle<()>,
    approvals: Arc<AtomicUsize>,
}

impl ConfirmationPeer {
    pub fn spawn(listener: TcpListener, connection: ConnectionInfo) -> Self {
        let approvals = Arc::new(AtomicUsize::new(0));
        let count = approvals.clone();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.expect("confirmation peer accept");
                        sessions.spawn(forward(stream, connection.clone(), count.clone()));
                    }
                    Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                        result.expect("confirmation peer session");
                    }
                }
            }
        });
        Self { task, approvals }
    }

    pub fn approvals(&self) -> usize {
        self.approvals.load(Ordering::SeqCst)
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for ConfirmationPeer {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn forward(mut module: TcpStream, connection: ConnectionInfo, approvals: Arc<AtomicUsize>) {
    authenticate_server(
        &mut module,
        &connection.key,
        &connection.daemon_id,
        &connection.daemon_ver,
        Duration::from_secs(5),
    )
    .await
    .expect("authenticate module at fake confirmation peer");
    let endpoint = &connection.endpoints[0];
    let mut daemon = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .expect("connect confirmation peer to daemon");
    authenticate_client(&mut daemon, &connection, Duration::from_secs(5))
        .await
        .expect("authenticate confirmation peer at daemon");
    let (mut module_read, module_write) = module.into_split();
    let (mut daemon_read, mut daemon_write) = daemon.into_split();
    let module_write = Mutex::new(module_write);

    let to_daemon = async {
        while let Ok(Some(frame)) = read_frame(&mut module_read).await {
            if frame.header.channel == 0
                && frame.header.ty == FrameType::Request
                && serde_json::from_slice::<OperatorConfirmRequest>(&frame.body).is_ok()
            {
                let request: OperatorConfirmRequest = serde_json::from_slice(&frame.body).unwrap();
                assert!(
                    plexus_module::operator_confirmation::valid_summary(&request.summary),
                    "invalid operator summary: {}",
                    request.summary
                );
                let reply = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Response,
                    plexus_module::wire::control_flags(),
                    0,
                    0,
                    frame.header.corr,
                    serde_json::to_vec(&OperatorConfirmReply::confirmed()).unwrap(),
                )
                .unwrap();
                approvals.fetch_add(1, Ordering::SeqCst);
                if write_frame(&mut *module_write.lock().await, &reply)
                    .await
                    .is_err()
                {
                    break;
                }
            } else if write_frame(&mut daemon_write, &frame).await.is_err() {
                break;
            }
        }
    };
    let to_module = async {
        while let Ok(Some(frame)) = read_frame(&mut daemon_read).await {
            if write_frame(&mut *module_write.lock().await, &frame)
                .await
                .is_err()
            {
                break;
            }
        }
    };
    tokio::select! {
        () = to_daemon => {},
        () = to_module => {},
    }
}
