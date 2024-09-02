use ::hkdf::Hkdf;
use aes::cipher::{
    block_padding::{NoPadding, Pkcs7},
    BlockDecryptMut, BlockEncryptMut, KeyInit,
};
use anyhow::Result;
use hex_literal::hex;
//use hkdf::Hkdf;
use ring::{aead::AES_128_GCM, hkdf, hmac};
use s2n_quic_core::crypto::{HeaderKey, InitialKey as _, Key};
use s2n_quic_crypto::initial::InitialKey;
use sha2::Sha256;

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

fn main() -> Result<()> {
    let mut payload = hex::decode(std::fs::read_to_string("./encrypted-packet.txt")?.trim())?;
    let dest_conn_len = payload[5] as usize;
    let dcid = &payload[6..6 + dest_conn_len];
    println!("dcid: {dcid:02X?}");

    let mut offset = 6 + dest_conn_len;
    let src_conn_len = payload[offset] as usize;
    offset += src_conn_len + 1;

    let token_len = payload[offset] as usize;
    offset += token_len + 1;

    let payload_len: u16 = u16::from_be_bytes([payload[offset], payload[offset + 1]]) & 0x0fff;
    println!("payload_len: {payload_len}");
    offset += 2; // we are on packet_number, but we dont know its length

    let sample = &payload[(offset + 4)..(offset + 20)];
    println!("sample: {:02X?}", &sample);

    let initial_salt = hex!("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
    let client_in = hex!("00200f746c73313320636c69656e7420696e00");
    //let quic_key = hex!("00100e746c7331332071756963206b657900");
    //let quic_iv = hex!("000c0d746c733133207175696320697600");
    let quic_hp = hex!("00100d746c733133207175696320687000");

    let hk = Hkdf::<Sha256>::new(Some(&initial_salt), &dcid);
    let mut client_initial_secret = [0; 32];
    hk.expand(&client_in, &mut client_initial_secret).unwrap();
    println!("client_initial_secret: {client_initial_secret:02X?}");

    let hk = Hkdf::<Sha256>::from_prk(&client_initial_secret).unwrap();
    let mut quic_hp_secret = [0; 16];
    hk.expand(&quic_hp, &mut quic_hp_secret).unwrap();
    println!("quic_hp_secret: {quic_hp_secret:02X?}");

    /*
    let mut client_initial_secret = [0; 32];
    let hk = Hkdf::<Sha256>::new(Some(&initial_salt), &dcid);
    hk.expand(&client_in, &mut client_initial_secret).unwrap();
    println!("client_initial_secret: {client_initial_secret:02X?}");

    let hk = Hkdf::<Sha256>::new(Some(&client_initial_secret), &[]);
    let mut quic_hp_secret = [0; 16];
    hk.expand(&quic_key, &mut quic_hp_secret).unwrap();
    println!("quic_hp_secret: {quic_hp_secret:02X?}");

    let mut buf = [0; 16];
    buf.copy_from_slice(&sample);
    let pt = Aes128EcbDec::new(&quic_hp_secret.try_into()?)
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .unwrap();

    let mask = &pt[..4];
    println!("mask: {mask:02X?}");
    */

    /*
    let (key, header) = InitialKey::new_server(&dcid);
    let mask = header.opening_header_protection_mask(sample);
    println!("mask: {mask:02X?}");

    let header = &mut payload.clone()[0..22];
    header[0] ^= mask[0] & 0x0f;
    header[18] ^= mask[1];
    header[19] ^= mask[2];
    header[20] ^= mask[3];
    header[21] ^= mask[4];

    println!("{header:02X?}");

    let mut payload = &mut payload[22..];
    key.decrypt(0, &header, &mut payload).unwrap();

    println!("{payload:02X?}");
    */

    // test quic parsing
    //let quic_packet = std::fs::read("/home/notpilif/Downloads/quic-initial.bin")?;
    //let packet_header = PacketHeader::from_bytes(&quic_packet, 8)?;
    //println!("{packet_header:?}");

    Ok(())
}
