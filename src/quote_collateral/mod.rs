use alloc::borrow::Cow;

pub struct QuoteCollateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: Vec<u8>,
    pub pck_crl: Vec<u8>,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
}

// impl QuoteCollateral {
//     pub fn parse(raw_collateral: &[u8]) -> Result<Self, ParseError> {
//         if raw_quote.len() < QUOTE_MIN_BYTE_LEN {
//             return Err(ParseError::Invalid);
//         }
//
//         let raw_header = &raw_quote[..HEADER_BYTE_LEN];
//         let header = Header::from_slice(raw_header).expect("Parse error");
//
//         let raw_enclave_report = &raw_quote[HEADER_BYTE_LEN..(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN)];
//         let enclave_report = EnclaveReport::from_slice(raw_enclave_report).expect("Parse error");
//
//         let auth_data_size = LittleEndian::read_u32(&raw_quote[(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN)..(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + 4)]) as usize;
//         let raw_signed_data = &raw_quote[(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + 4)..(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + 4 + auth_data_size)];
//         let signed_data = QuoteAuthData::<'a>::from_slice(header.clone().attestation_key_type, raw_signed_data).expect("Parse error");
//
//         println!("auth_data_size: {}", auth_data_size);
//
//         Ok(
//             Self {
//                 header,
//                 enclave_report,
//                 signed_data,
//             }
//         )
//     }
// }
