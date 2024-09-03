use anyhow::Result;
use qls_proto_utils::{quic::parse_quic_payload, tls::sni::parse_sni_inner};
use std::net::UdpSocket;

fn main() -> Result<()> {
    let listener = UdpSocket::bind("0.0.0.0:8443")?;

    let mut recv_buf = [0; 65536];
    loop {
        let (n, addr) = listener.recv_from(&mut recv_buf)?;
        println!("recv: {n}bytes from: {addr}");

        let quic_frame = parse_quic_payload(&recv_buf[..n]);
        if let Some(quic_frame) = quic_frame {
            if quic_frame.frame_type == 6 {
                println!("INITIAL FRAME: {quic_frame:02X?}");
                let sni_res = parse_sni_inner(&quic_frame.decoded_data);
                println!("{sni_res:?}");
            }
        }
    }
}
