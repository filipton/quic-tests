use std::net::UdpSocket;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::{aead::AeadMutInPlace, Aes128Gcm};
use anyhow::Result;
use hex_literal::hex;
use hkdf::Hkdf;
use sha2::Sha256;

const INITIAL_SALT: [u8; 20] = hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const CLIENT_IN: [u8; 19] = hex!("00200f746c73313320636c69656e7420696e00");
const QUIC_KEY: [u8; 18] = hex!("00100e746c7331332071756963206b657900");
const QUIC_IV: [u8; 17] = hex!("000c0d746c733133207175696320697600");
const QUIC_HP: [u8; 17] = hex!("00100d746c733133207175696320687000");

#[derive(Debug)]
pub struct QuicFrameData {
    pub frame_type: u8,
    pub offset: u8,
    pub length: usize,
    pub decoded_frame: Vec<u8>,
}

pub fn parse_quic_frame(data: &[u8]) -> Option<QuicFrameData> {
    let mut data = data.to_vec();
    let dest_conn_len = *data.get(5)? as usize;
    let dcid = data.get(6..6 + dest_conn_len)?;

    let mut offset = 6 + dest_conn_len;
    let src_conn_len = *data.get(offset)? as usize;
    offset += src_conn_len + 1;

    let token_len = *data.get(offset)? as usize;
    offset += token_len + 1;

    //let payload_len = u16::from_be_bytes([*data.get(offset)?, *data.get(offset + 1)?]) & 0x0fff;
    offset += 2;

    let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dcid);
    let mut client_initial_secret = [0; 32];
    hk.expand(&CLIENT_IN, &mut client_initial_secret).ok()?;

    let hk = Hkdf::<Sha256>::from_prk(&client_initial_secret).ok()?;
    let mut quic_hp_key = [0; 16];
    hk.expand(&QUIC_KEY, &mut quic_hp_key).ok()?;

    let mut quic_hp_iv = [0; 12];
    hk.expand(&QUIC_IV, &mut quic_hp_iv).ok()?;

    let mut quic_hp_secret = [0; 16];
    hk.expand(&QUIC_HP, &mut quic_hp_secret).ok()?;

    let cipher = aes::Aes128::new_from_slice(&quic_hp_secret).ok()?;
    let mut sample = data.get((offset + 4)..(offset + 20))?.to_vec();
    let mut block = aes::Block::from_mut_slice(&mut sample);
    cipher.encrypt_block(&mut block);
    let mask = &block[..5];

    data[0] ^= mask[0] & 0x0f;
    let packet_number_len = (data[0] & 0b00000011) as usize + 1;
    offset += packet_number_len; // payload starts here
    let mut packet_data = Vec::from(&data[offset..]);

    let header = data.get_mut(0..offset)?;
    let mut mask_i = 1;
    for i in 18..(22.min(header.len())) {
        header[i] ^= mask[mask_i];
        mask_i += 1;
    }

    let mut i = 0;
    while i < packet_number_len {
        quic_hp_iv[quic_hp_iv.len() - i - 1] ^= header[header.len() - i - 1];
        i += 1;
    }

    let mut cipher = Aes128Gcm::new_from_slice(&quic_hp_key).ok()?;
    cipher
        .decrypt_in_place(&quic_hp_iv.try_into().ok()?, &header, &mut packet_data)
        .ok()?;

    let frame_type = packet_data[0];
    let offset = packet_data[1];
    let length = (u16::from_be_bytes([packet_data[2], packet_data[3]]) & 0x0fff) as usize;

    packet_data.drain(0..4);
    Some(QuicFrameData {
        frame_type,
        offset,
        length,
        decoded_frame: packet_data,
    })
}

fn main() -> Result<()> {
    let listener = UdpSocket::bind("0.0.0.0:8443")?;

    let mut recv_buf = [0; 65536];
    loop {
        let (n, addr) = listener.recv_from(&mut recv_buf)?;
        println!("recv: {n}bytes from: {addr}");

        let quic_frame = parse_quic_frame(&recv_buf[..n]);
        if let Some(quic_frame) = quic_frame {
            if quic_frame.frame_type == 6 {
                println!("INITIAL FRAME: {quic_frame:02X?}");
                let sni_res = parse_sni_inner(&quic_frame.decoded_frame);
                println!("{sni_res:?}");
            }
        }
    }
}

// from fkm-proxy
pub fn parse_sni_inner(buf: &[u8]) -> Option<String> {
    let handshake_type = *buf.get(0)?; // 1byte
    if handshake_type != 1 {
        return None;
    }

    let session_id_length = *buf.get(38)? as usize; // 1byte
    let cipher_suites_len: u16 = u16::from_be_bytes([
        *buf.get(39 + session_id_length + 0)?,
        *buf.get(39 + session_id_length + 1)?,
    ]); // 2bytes

    let mut offset: usize = 39 + session_id_length + 2 + cipher_suites_len as usize;
    let compression_methods_len = *buf.get(offset)? as usize; // 1byte
    offset += 1 + compression_methods_len;

    let mut extensions_len: u16 = u16::from_be_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]); // 2bytes
    offset += 2;

    while extensions_len > 0 {
        let ext_type: u16 = u16::from_be_bytes([*buf.get(offset)?, *buf.get(offset + 1)?]);
        let ext_len: u16 = u16::from_be_bytes([*buf.get(offset + 2)?, *buf.get(offset + 3)?]);
        offset += 4;

        if ext_type == 0 {
            let server_name_type = *buf.get(offset + 2)?;
            let server_name_length: u16 =
                u16::from_be_bytes([*buf.get(offset + 3)?, *buf.get(offset + 4)?]);

            let server_name = &buf.get((offset + 5)..(offset + 5 + server_name_length as usize))?;
            let server_name = core::str::from_utf8(server_name).ok()?;

            if server_name_type == 0 {
                return Some(server_name.to_string());
            }
        }

        offset += ext_len as usize;
        extensions_len -= 4 + ext_len;
    }

    None
}
