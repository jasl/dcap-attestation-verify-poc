use core::result::Result;
use core::fmt::Debug;
use byteorder::{ByteOrder, LittleEndian};
use ecdsa::Signature;

const ENCLAVE_REPORT_BYTE_LEN: usize = 384;

const HEADER_BYTE_LEN: usize = 48;
const AUTH_DATA_SIZE_BYTE_LEN: usize = 4;

const ECDSA_SIGNATURE_BYTE_LEN: usize = 64;
const ECDSA_PUBKEY_BYTE_LEN: usize = 64;
const QE_REPORT_BYTE_LEN: usize = ENCLAVE_REPORT_BYTE_LEN;
const QE_REPORT_SIG_BYTE_LEN: usize = ECDSA_SIGNATURE_BYTE_LEN;
const CERTIFICATION_DATA_TYPE_BYTE_LEN: usize = 2;
const CERTIFICATION_DATA_SIZE_BYTE_LEN: usize = 4;
const QE_AUTH_DATA_SIZE_BYTE_LEN: usize = 2;
const QE_CERT_DATA_TYPE_BYTE_LEN: usize = 2;
const QE_CERT_DATA_SIZE_BYTE_LEN: usize = 4;

const AUTH_DATA_MIN_BYTE_LEN: usize =
    ECDSA_SIGNATURE_BYTE_LEN +
    ECDSA_PUBKEY_BYTE_LEN +
    QE_REPORT_BYTE_LEN +
    QE_REPORT_SIG_BYTE_LEN +
    QE_AUTH_DATA_SIZE_BYTE_LEN +
    QE_CERT_DATA_TYPE_BYTE_LEN +
    QE_CERT_DATA_SIZE_BYTE_LEN;

const QUOTE_MIN_BYTE_LEN: usize = // Actual minimal size is a Quote V3 with Enclave report
    HEADER_BYTE_LEN +
    ENCLAVE_REPORT_BYTE_LEN +
    AUTH_DATA_SIZE_BYTE_LEN +
    AUTH_DATA_MIN_BYTE_LEN;

const INTEL_QE_VENDOR_ID: [u8; 16] = [0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07];

#[derive(Debug)]
pub enum ParseError {
    Invalid,
    Unexpected { field: String, message: String },
    UnsupportedValue { field: String },
    InvalidValue { field: String },
    MissingField { field: String }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum QuoteVersion {
    V3, // Doc said always this
    Unsupported { raw: u16 },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AttestationKeyType {
    ECDSA256WithP256Curve, // Doc said always this
    ECDSA384WithP384Curve,
    Unsupported { raw: u16 },
}

#[derive(Clone)]
pub struct Header {
    pub version: QuoteVersion,
    pub attestation_key_type: AttestationKeyType,
    pub tee_type: u32, // Doc said this is reserved, but implementation is this, it's 0 as doc said.
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

impl Header {
    pub fn from_slice(raw_header: &[u8]) -> Result<Self, ParseError> {
        if raw_header.len() != HEADER_BYTE_LEN {
            return Err(ParseError::Invalid)
        }

        let version = LittleEndian::read_u16(&raw_header[..2]);
        let attestation_key_type = LittleEndian::read_u16(&raw_header[2..4]);
        let tee_type = LittleEndian::read_u32(&raw_header[4..8]);
        let qe_svn = LittleEndian::read_u16(&raw_header[8..10]);
        let pce_svn = LittleEndian::read_u16(&raw_header[10..12]);
        let qe_vendor_id: [u8; 16] = raw_header[12..28].try_into().unwrap();
        let user_data: [u8; 20] = raw_header[28..48].try_into().unwrap();

        println!("- Quote header -");
        println!("version: {}", version);
        println!("attestation key type: {}", attestation_key_type);
        println!("tee type: {}", tee_type);
        println!("qe svn: {}", qe_svn);
        println!("pce svn: {}", pce_svn);
        println!("qe vendor id: 0x{}", hex::encode(qe_vendor_id));
        println!("user data: 0x{}", hex::encode(user_data));
        println!("----------------");

        let version = match version {
            3 => QuoteVersion::V3,
            _ => QuoteVersion::Unsupported { raw: version }
        };
        if !matches!(version, QuoteVersion::V3) {
            return Err(ParseError::Invalid)
        }

        let attestation_key_type = match attestation_key_type {
            2 => AttestationKeyType::ECDSA256WithP256Curve,
            3 => AttestationKeyType::ECDSA384WithP384Curve,
            _ => AttestationKeyType::Unsupported { raw: attestation_key_type }
        };
        if !matches!(attestation_key_type, AttestationKeyType::ECDSA256WithP256Curve) {
            return Err(ParseError::Invalid)
        }

        // TODO: Validate TEE type, version 3 must be TEE_TYPE_SGX
        
        if qe_vendor_id != INTEL_QE_VENDOR_ID {
            return Err(ParseError::Invalid)
        }

        Ok(
            Self {
                version,
                attestation_key_type,
                tee_type,
                qe_svn,
                pce_svn,
                qe_vendor_id,
                user_data
            }
        )
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EnclaveReport {
    pub cpu_svn: [u8; 16],
    pub misc_select: u32,
    // pub reserved1: [u8; 28],
    pub attributes: [u8; 16],
    pub mr_enclave: [u8; 32],
    // pub reserved2: [u8; 32],
    pub mr_signer: [u8; 32],
    // pub reserved_3: [u8; 96],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    // pub reserved5: [u8; 60],
    pub report_data: [u8; 64],
}

impl EnclaveReport {
    pub fn from_slice(raw_report: &[u8]) -> Result<Self, ParseError> {
        if raw_report.len() != ENCLAVE_REPORT_BYTE_LEN {
            return Err(ParseError::Invalid)
        }

        let cpu_svn: [u8; 16] = raw_report[..16].try_into().unwrap();
        let misc_select = LittleEndian::read_u32(&raw_report[16..20]);
        // let _reserved: [u8; 28] = raw_report[20..48].try_into().unwrap();
        let attributes: [u8; 16] = raw_report[48..64].try_into().unwrap();
        let mr_enclave: [u8; 32] = raw_report[64..96].try_into().unwrap();
        // let _reserved: [u8; 32] = raw_report[96..128].try_into().unwrap();
        let mr_signer: [u8; 32] = raw_report[128..160].try_into().unwrap();
        // let _reserved: [u8; 96] = raw_report[160..256].try_into().unwrap();
        let isv_prod_id = LittleEndian::read_u16(&raw_report[256..258]);
        let isv_svn = LittleEndian::read_u16(&raw_report[258..260]);
        // let _reserved: [u8; 60] = raw_report[260..320].try_into().unwrap();
        let report_data: [u8; 64] = raw_report[320..384].try_into().unwrap();

        println!("- Quote enclave report -");
        println!("cpu svn: 0x{}", hex::encode(cpu_svn));
        println!("misc select: {}", misc_select);
        println!("attributes: 0x{}", hex::encode(attributes));
        println!("mr enclave: 0x{}", hex::encode(mr_enclave));
        println!("mr signer: 0x{}", hex::encode(mr_signer));
        println!("isv prod id: {}", isv_prod_id);
        println!("isv svn: {}", isv_svn);
        println!("report data: {}", core::str::from_utf8(&report_data).unwrap_or(format!("0x{}", hex::encode(report_data)).as_str()));
        println!("------------------------");

        Ok(
            Self {
                cpu_svn,
                misc_select,
                attributes,
                mr_enclave,
                mr_signer,
                isv_prod_id,
                isv_svn,
                report_data
            }
        )
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CertificationData {
    pub data_type: u16,
    pub data_size: usize,
    pub data: Vec<u8>,
}

impl CertificationData {
    pub fn from_slice(raw_data: &[u8]) -> Result<CertificationData, ParseError> {
        if raw_data.len() <= CERTIFICATION_DATA_SIZE_BYTE_LEN + CERTIFICATION_DATA_TYPE_BYTE_LEN {
            return Err(ParseError::Invalid)
        }

        let data_type = LittleEndian::read_u16(&raw_data[..2]);
        // TODO: guard type
        let data_size = LittleEndian::read_u32(&raw_data[2..6]) as usize;
        // TODO: guard size

        let data = raw_data[6..(6 + data_size)].to_vec();

        println!("- Certification data -");
        println!("data type: {}", data_type);
        println!("data_size: {}", data_size);
        println!("----------------------");

        Ok(
            Self {
                data_type,
                data_size,
                data
            }
        )
    }
}

pub type Ecdsa256BitSignature = p256::ecdsa::Signature;
pub type Ecdsa256BitPubkey = p256::ecdsa::VerifyingKey;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum QuoteAuthData {
    Ecdsa256Bit {
        signature: Ecdsa256BitSignature,
        attestation_key: Ecdsa256BitPubkey,
        qe_report: EnclaveReport,
        qe_report_signature: Ecdsa256BitSignature,
        qe_auth_data: Vec<u8>,
        certification_data: CertificationData
    },
    // TODO: V4
    Unsupported,
}

impl QuoteAuthData {
    pub fn from_slice(attestation_key_type: AttestationKeyType, raw_data: &[u8]) -> Result<Self, ParseError> {
        match attestation_key_type {
            AttestationKeyType::ECDSA256WithP256Curve => {
                Self::new_ecdsa256_with_p256_curve(raw_data)
            },
            _ => {
                Err(ParseError::Invalid)
            }
        }
    }

    fn new_ecdsa256_with_p256_curve(raw_data: &[u8]) -> Result<Self, ParseError> {
        let raw_signature = &raw_data[..64];
        let signature = Ecdsa256BitSignature::from_bytes(raw_signature.into()).expect("Parse error");

        let raw_attestation_key = &raw_data[64..128];
        let encoded_point = p256::EncodedPoint::from_untagged_bytes(raw_attestation_key.into());
        let attestation_key = Ecdsa256BitPubkey::from_encoded_point(&encoded_point).expect("Parse error");

        let raw_qe_report = &raw_data[128..512];
        let qe_report = EnclaveReport::from_slice(raw_qe_report).expect("Parse error");

        let raw_qe_report_signature = &raw_data[512..576];
        let qe_report_signature = Ecdsa256BitSignature::from_bytes(raw_qe_report_signature.into()).expect("Parse error");

        let qe_auth_data_size = LittleEndian::read_u16(&raw_data[576..578]) as usize;
        let qe_auth_data = raw_data[578..(578 + qe_auth_data_size)].to_vec();

        let raw_certification_data = &raw_data[(578 + qe_auth_data_size)..];
        let certification_data = CertificationData::from_slice(raw_certification_data).expect("Parse error");

        println!("- ECDSA 256-bit Quote Signature -");
        println!("signature: {}", signature);
        println!("attestation_key: {}", attestation_key.to_encoded_point(true));
        println!("qe report signature: {}", qe_report_signature);
        println!("qe auth data size: {}", qe_auth_data_size);
        println!("qe auth data: 0x{}", hex::encode(qe_auth_data.clone()));
        println!("---------------------------------");

        Ok(
            Self::Ecdsa256Bit {
                signature,
                attestation_key,
                qe_report,
                qe_report_signature,
                qe_auth_data,
                certification_data,
            }
        )
    }
}

pub struct Quote {
    pub header: Header,
    pub enclave_report: EnclaveReport,
    pub auth_data_size: usize, // Doc calls it `Quote Signature Data Len`
    pub signed_data: QuoteAuthData, // Doc calls it `Quote Signature Data`

    // Ecdsa256BitQuoteV3AuthData authDataV3{};
    // Ecdsa256BitQuoteV4AuthData authDataV4{};
    // std::array<uint8_t, constants::ECDSA_SIGNATURE_BYTE_LEN> qeReportSignature{};
    // EnclaveReport qeReport{};
    // std::array<uint8_t, constants::ECDSA_PUBKEY_BYTE_LEN> attestKeyData{};
    // std::vector<uint8_t> qeAuthData{};
    // CertificationData certificationData{};
    // std::array<uint8_t, constants::ECDSA_SIGNATURE_BYTE_LEN> quoteSignature{};
}

impl Quote {
    pub fn parse(raw_quote: &[u8]) -> Result<Self, ParseError> {
        if raw_quote.len() < QUOTE_MIN_BYTE_LEN {
            return Err(ParseError::Invalid)
        }

        let raw_header = &raw_quote[..HEADER_BYTE_LEN];
        let header = Header::from_slice(raw_header).expect("Parse error");

        let raw_enclave_report = &raw_quote[HEADER_BYTE_LEN..(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN)];
        let enclave_report = EnclaveReport::from_slice(raw_enclave_report).expect("Parse error");

        let auth_data_size = LittleEndian::read_u32(&raw_quote[(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN)..(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + 4)]) as usize;
        let raw_signed_data = &raw_quote[(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + 4)..(HEADER_BYTE_LEN + ENCLAVE_REPORT_BYTE_LEN + 4 + auth_data_size)];
        let signed_data = QuoteAuthData::from_slice(header.clone().attestation_key_type, raw_signed_data).expect("Parse error");

        println!("auth_data_size: {}", auth_data_size);

        Ok(
            Self {
                header,
                enclave_report,
                auth_data_size,
                signed_data
            }
        )
    }
}
