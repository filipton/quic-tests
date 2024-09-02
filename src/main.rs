use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit};
use anyhow::Result;
use s2n_quic_core::crypto::{HeaderKey, InitialKey as _, Key};
use s2n_quic_crypto::initial::InitialKey;

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

    /*
    let mut buf = [0; 100];
    let pt = Aes128EcbDec::new(&key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .unwrap();
    */

    let (key, header) = InitialKey::new_server(&dcid);
    println!("sample {:02X?}", &payload[22..38]);
    let mask = header.opening_header_protection_mask(&payload[22..38]);
    println!("mask {mask:02X?}");

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

    /*
    let initial_salt = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];

    let client_in = [
        0x00, 0x20, 0x0f, 0x74, 0x6c, 0x73, 0x31, 0x33, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
        0x20, 0x69, 0x6e, 0x00,
    ];

    let hk = Hkdf::<Sha256>::new(Some(&initial_salt), &dcid);

    let mut client_initial_secret = [0; 32];
    hk.expand(&client_in, &mut client_initial_secret).unwrap();

    println!("{client_initial_secret:02X?}");
    */

    // test quic parsing
    //let quic_packet = std::fs::read("/home/notpilif/Downloads/quic-initial.bin")?;
    //let packet_header = PacketHeader::from_bytes(&quic_packet, 8)?;
    //println!("{packet_header:?}");

    Ok(())
}
