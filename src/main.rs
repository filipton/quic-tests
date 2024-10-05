use anyhow::Result;
use qls_proto_utils::{quic::parse_quic_payload, tls::sni::parse_sni_inner};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        RwLock,
    },
    time::Instant,
};

#[tokio::main]
async fn main() -> Result<()> {
    let listener = Arc::new(UdpSocket::bind("0.0.0.0:8443").await?);
    let tunnel_map: Arc<RwLock<HashMap<SocketAddr, UnboundedSender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let mut recv_buf = [0; 65536];
    loop {
        let (n, addr) = listener.recv_from(&mut recv_buf).await?;
        //println!("recv: {n}bytes from: {addr}");

        let (tx, mut rx) = unbounded_channel();
        {
            let mut tunnel_map_rw = tunnel_map.write().await;
            if let Some(sock) = tunnel_map_rw.get(&addr) {
                sock.send(recv_buf[..n].to_vec())?;
                continue;
            } else {
                tunnel_map_rw.insert(addr, tx);
            }
        }

        let quic_frame = parse_quic_payload(&recv_buf[..n]);
        //println!("quic_frame: {quic_frame:02X?}");
        if let Some(quic_frame) = quic_frame {
            if quic_frame.frame_type == 6 {
                //println!("INITIAL FRAME: {quic_frame:02X?}");
                let sni_res = parse_sni_inner(&quic_frame.decoded_data);
                println!("{sni_res:?}");
            }
        }

        let listener = listener.clone();
        tokio::task::spawn(async move {
            let local_sock = UdpSocket::bind("0.0.0.0:0").await.unwrap();
            local_sock.connect("127.0.0.1:443").await.unwrap();
            local_sock.send(&recv_buf[..n]).await.unwrap();

            let mut recv_buf = [0; 65536];
            let mut keep_alive = tokio::time::interval_at(
                Instant::now() + Duration::from_secs(45),
                Duration::from_secs(45),
            );

            loop {
                tokio::select! {
                    Some(res) = rx.recv() => {
                        keep_alive.reset();
                        local_sock.send(&res).await.unwrap();
                    }
                    res = local_sock.recv(&mut recv_buf) => {
                        keep_alive.reset();
                        //println!("{res:?}");
                        let n = res.unwrap();
                        listener.send_to(&recv_buf[..n], addr).await.unwrap();
                    }
                    _ = keep_alive.tick() => {
                        println!("Keep alive drop");
                        break;
                    }
                }
            }
        });
    }
}
