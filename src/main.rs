use anyhow::Result;
use qls_proto_utils::{quic::parse_quic_payload, tls::sni::parse_sni_inner};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        RwLock,
    },
};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = Arc::new(UdpSocket::bind("0.0.0.0:8443").await?);
    let tunnel_map: TunnelMapTest = Arc::new(RwLock::new(HashMap::new()));

    let mut recv_buf = [0; 65536];
    while let Ok((client, addr)) = server_test(&listener, &mut recv_buf, &tunnel_map).await {
        //println!("new client: {addr:?}");

        let listener = listener.clone();
        tokio::task::spawn(async move {
            let res = handle_client(client, addr, listener).await;
            if let Err(e) = res {
                println!("handle_client_err: {e:?}");
            }
        });
    }

    Ok(())
}

async fn handle_client(
    mut client: UdpClient,
    addr: SocketAddr,
    listener: Arc<UdpSocket>,
) -> Result<()> {
    println!("handle_client: {addr}");

    let recv_buf = client
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("client_recv_err"))?;

    let mut recv_buf_copy = recv_buf.clone();
    let quic_header = qls_proto_utils::quic::parse_quic_header(&recv_buf_copy)
        .ok_or_else(|| anyhow::anyhow!("Quic header parse error (bytes 0-5)"))?;

    //println!("qh: {quic_header:?}");
    if quic_header.header_form != 1 || quic_header.packet_type != 0 {
        return Err(anyhow::anyhow!("Not an initial packet!"));
    }

    let quic_frame = parse_quic_payload(&mut recv_buf_copy);
    //println!("quic_frame: {quic_frame:02X?}");
    if let Some(quic_frame) = quic_frame {
        if quic_frame.frame_type == 6 {
            //println!("INITIAL FRAME: {quic_frame:02X?}");
            let sni_res = parse_sni_inner(&quic_frame.decoded_data).unwrap_or("");
            println!("{sni_res:?}");
        }
    } else {
        return Err(anyhow::anyhow!("No sni in initial quic packet (tls)!"));
    }

    let local_sock = UdpSocket::bind("0.0.0.0:0").await?;
    local_sock.connect("127.0.0.1:443").await?;
    local_sock.send(&recv_buf).await?;
    client.copy_bidirectional(&listener, local_sock).await?;

    Ok(())
}

type TunnelMapTest = Arc<RwLock<HashMap<SocketAddr, UnboundedSender<Vec<u8>>>>>;
async fn server_test(
    listener: &Arc<UdpSocket>,
    recv_buf: &mut [u8],
    tunnel_map: &TunnelMapTest,
) -> Result<(UdpClient, SocketAddr)> {
    loop {
        let (n, addr) = listener.recv_from(recv_buf).await?;
        let rx = {
            let mut tunnel_map_rw = tunnel_map.write().await;
            if let Some(sock) = tunnel_map_rw.get_mut(&addr) {
                if sock.is_closed() {
                    let (tx, rx) = unbounded_channel();
                    *sock = tx;
                    sock.send(recv_buf[..n].to_vec())?;

                    return Ok((UdpClient::new(tunnel_map, rx, addr), addr));
                }

                sock.send(recv_buf[..n].to_vec())?;
                continue;
            } else {
                let (tx, rx) = unbounded_channel();
                tx.send(recv_buf[..n].to_vec())?;
                tunnel_map_rw.insert(addr, tx);

                rx
            }
        };

        return Ok((UdpClient::new(tunnel_map, rx, addr), addr));
    }
}

struct UdpClient {
    tunnel_map: TunnelMapTest,
    rx: UnboundedReceiver<Vec<u8>>,
    addr: SocketAddr,
}

impl UdpClient {
    pub fn new(
        tunnel_map: &TunnelMapTest,
        rx: UnboundedReceiver<Vec<u8>>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            tunnel_map: tunnel_map.clone(),
            rx,
            addr,
        }
    }

    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let timeout = tokio::time::timeout(Duration::from_secs(45), self.rx.recv()).await;
        match timeout {
            Ok(recv) => recv,
            Err(_) => {
                self.remove().await;
                println!("recv timeout!");
                None
            }
        }
    }

    pub async fn copy_bidirectional(
        &mut self,
        listener: &Arc<UdpSocket>,
        sock: UdpSocket,
    ) -> Result<()> {
        let mut recv_buf = [0; 65536];
        loop {
            tokio::select! {
                res = self.recv() => {
                    match res {
                        Some(res) => sock.send(&res).await?,
                        None => break
                    };
                }
                res = sock.recv(&mut recv_buf) => {
                    let n = res?;
                    listener.send_to(&recv_buf[..n], self.addr).await?;
                }
            }
        }

        Ok(())
    }

    async fn remove(&self) {
        self.tunnel_map.write().await.remove(&self.addr);
    }
}
