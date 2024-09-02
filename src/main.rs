use anyhow::Result;
use s2n_quic_core::crypto::{HeaderKey, InitialKey as _, Key};
use s2n_quic_crypto::initial::InitialKey;

fn main() -> Result<()> {
    let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]; // read from packet
    let mut payload = hex::decode(std::fs::read_to_string("./encrypted-packet.txt")?.trim())?;

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
    key.decrypt(2, &header, &mut payload).unwrap();

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
