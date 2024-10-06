use anyhow::Result;
use qls_proto_utils::{quic::parse_quic_payload, tls::sni::parse_sni_inner};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Notify, RwLock,
    },
    time::{Instant, Interval},
};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = Arc::new(UdpSocket::bind("0.0.0.0:8443").await?);
    let tunnel_map: TunnelMapTest = Arc::new(RwLock::new(HashMap::new()));

    let mut recv_buf = [0; 65536];
    while let Ok((mut client, addr)) = server_test(&listener, &mut recv_buf, &tunnel_map).await {
        println!("new client: {addr:?}");

        let listener = listener.clone();
        tokio::task::spawn(async move {
            let recv_buf = client.recv().await.unwrap();
            let mut recv_buf_copy = recv_buf.clone();
            let quic_header = qls_proto_utils::quic::parse_quic_header(&recv_buf_copy).unwrap();
            println!("qh: {quic_header:?}");
            if quic_header.header_form != 1 || quic_header.packet_type != 0 {
                println!("Not initial packet!");
                return;
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
                println!("no sni");
                return;
            }

            let local_sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            local_sock.connect("127.0.0.1:443").await.unwrap();
            local_sock.send(&recv_buf).await.unwrap();

            let mut recv_buf = [0; 65536];
            loop {
                tokio::select! {
                    res = client.recv() => {
                        match res {
                            Some(res) => local_sock.send(&res).await.unwrap(),
                            None => break
                        };
                    }
                    res = local_sock.recv(&mut recv_buf) => {
                        let n = res.unwrap();
                        listener.send_to(&recv_buf[..n], addr).await.unwrap();
                    }
                }
            }
        });
    }

    Ok(())
}

type TunnelMapTest = Arc<RwLock<HashMap<SocketAddr, (Instant, UnboundedSender<Vec<u8>>)>>>;
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
                if (Instant::now() - sock.0).as_secs() > 45 || sock.1.is_closed() {
                    println!("Keep alive drop!");
                    tunnel_map_rw.remove(&addr);
                    continue;
                }

                sock.0 = Instant::now();
                sock.1.send(recv_buf[..n].to_vec())?;
                continue;
            } else {
                let (tx, rx) = unbounded_channel();
                tx.send(recv_buf[..n].to_vec())?;
                tunnel_map_rw.insert(addr, (Instant::now(), tx));

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

    async fn remove(&self) {
        self.tunnel_map.write().await.remove(&self.addr);
    }
}
