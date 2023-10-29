extern crate alloc;
extern crate core;

use core::time::Duration;
use webpki::types::CertificateDer;
use base64::{engine::general_purpose, Engine as _};
use const_oid::ObjectIdentifier;
use x509_cert::Certificate;

use crate::quote::{AttestationKeyType, Quote, QuoteAuthData, QuoteVersion};
use crate::quote_collateral::QuoteCollateral;

// mod quote_verifier;
mod tcb;
mod quote;
mod qe_identity;
mod quote_collateral;

/// The needed code for a trust anchor can be extracted using `webpki` with something like this:
/// println!("{:?}", webpki::TrustAnchor::try_from_cert_der(&root_cert));
#[allow(clippy::zero_prefixed_literal)]
pub static DCAP_SERVER_ROOTS: &[webpki::types::TrustAnchor<'static>; 1] = &[
	webpki::types::TrustAnchor {
		subject: webpki::types::Der::from_slice(&[
			49, 26, 48, 24, 06, 03, 85, 04, 03, 12, 17, 73, 110, 116, 101, 108, 32, 83, 71, 88, 32,
			82, 111, 111, 116, 32, 67, 65, 49, 26, 48, 24, 06, 03, 85, 04, 10, 12, 17, 73, 110,
			116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 20, 48, 18,
			06, 03, 85, 04, 07, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11, 48,
			09, 06, 03, 85, 04, 08, 12, 02, 67, 65, 49, 11, 48, 09, 06, 03, 85, 04, 06, 19, 02, 85,
			83,
		]),
		subject_public_key_info: webpki::types::Der::from_slice(&[
			48, 19, 06, 07, 42, 134, 72, 206, 61, 02, 01, 06, 08, 42, 134, 72, 206, 61, 03, 01, 07,
			03, 66, 00, 04, 11, 169, 196, 192, 192, 200, 97, 147, 163, 254, 35, 214, 176, 44, 218,
			16, 168, 187, 212, 232, 142, 72, 180, 69, 133, 97, 163, 110, 112, 85, 37, 245, 103,
			145, 142, 46, 220, 136, 228, 13, 134, 11, 208, 204, 78, 226, 106, 172, 201, 136, 229,
			05, 169, 83, 85, 140, 69, 63, 107, 09, 04, 174, 115, 148,
		]),
		name_constraints: None,
	}
];

pub type MrSigner = [u8; 32];
pub type MrEnclave = [u8; 32];
pub type Fmspc = [u8; 6];
pub type CpuSvn = [u8; 16];
pub type PceSvn = u16;

#[derive(Default, Clone, PartialEq, Eq)]
pub enum TcbStatus {
	#[default]
	Unknown,
	UpToDate,
	SWHardeningNeeded,
	ConfigurationAndSWHardeningNeeded,
	OutOfDate,
	OutOfDateConfigurationNeeded,
	Revoked,
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct TcbVersionStatus {
	pub cpusvn: CpuSvn,
	pub pcesvn: PceSvn,
	pub tcb_status: TcbStatus,
}

impl TcbVersionStatus {
	pub fn new(cpusvn: CpuSvn, pcesvn: PceSvn, tcb_status: TcbStatus) -> Self {
		Self { cpusvn, pcesvn, tcb_status }
	}

	/// verifies if CpuSvn and PceSvn are considered valid
	/// this function should be called by recent TcbInfo from Intel with the DUT enclave
	/// TCB info from the DCAP quote as argument
	pub fn verify_examinee(&self, examinee: &TcbVersionStatus) -> bool {
		for (v, r) in self.cpusvn.iter().zip(examinee.cpusvn.iter()) {
			log::debug!("verify_examinee: v={:?},r={:?}", v, r);
			if *v > *r {
				return false;
			}
		}
		log::debug!(
            "verify_examinee: self.pcesvn={:?},examinee.pcesvn={:?}",
            &self.pcesvn,
            &examinee.pcesvn
        );
		self.pcesvn <= examinee.pcesvn
	}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("UnknownMREnclave")]
	UnknownMREnclave,
	#[error("UnknownMRSigner")]
	UnknownMRSigner,
	#[error("UnsupportedDCAPQuoteVersion")]
	UnsupportedDCAPQuoteVersion,
	#[error("UnsupportedDCAPAttestationKeyType")]
	UnsupportedDCAPAttestationKeyType,
	#[error("UnsupportedQuoteAuthData")]
	UnsupportedQuoteAuthData,
	#[error("UnsupportedDCAPPckCertFormat")]
	UnsupportedDCAPPckCertFormat,
	#[error("EnclaveRejectedByQE")]
	EnclaveRejectedByQE,
	#[error("LeafCertificateParsingError")]
	LeafCertificateParsingError,
	#[error("IntermediateCertificateParsingError")]
	IntermediateCertificateParsingError,
	#[error("CertificateChainIsInvalid")]
	CertificateChainIsInvalid,
	#[error("CertificateChainIsTooShort")]
	CertificateChainIsTooShort,
	#[error("IntelExtensionCertificateDecodingError")]
	IntelExtensionCertificateDecodingError,
	#[error("IntelExtensionAmbiguity")]
	IntelExtensionAmbiguity,
	#[error("FmspcOidIsMissing")]
	FmspcOidIsMissing,
	#[error("FmspcLengthMismatch")]
	FmspcLengthMismatch,
	#[error("FmspcDecodingError")]
	FmspcDecodingError,
	#[error("CpuSvnOidIsMissing")]
	CpuSvnOidIsMissing,
	#[error("CpuSvnLengthMismatch")]
	CpuSvnLengthMismatch,
	#[error("CpuSvnDecodingError")]
	CpuSvnDecodingError,
	#[error("PceSvnOidIsMissing")]
	PceSvnOidIsMissing,
	#[error("PceSvnDecodingError")]
	PceSvnDecodingError,
	#[error("PceSvnLengthMismatch")]
	PceSvnLengthMismatch,
	#[error("QEReportHashMismatch")]
	QEReportHashMismatch,
	#[error("IsvEnclaveReportSignatureIsInvalid")]
	IsvEnclaveReportSignatureIsInvalid,
}

/// See document "Intel® Software Guard Extensions: PCK Certificate and Certificate Revocation List Profile Specification"
/// https://download.01.org/intel-sgx/dcap-1.2/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.1.pdf
const INTEL_SGX_EXTENSION_OID: ObjectIdentifier =
	ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
const OID_FMSPC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");
const OID_PCESVN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.17");
const OID_CPUSVN: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.18");

fn safe_indexing_one(data: &[u8], idx: usize) -> Result<usize, &'static str> {
	let elt = data.get(idx).ok_or("Index out of bounds")?;
	Ok(*elt as usize)
}

pub fn length_from_raw_data(data: &[u8], offset: &mut usize) -> Result<usize, &'static str> {
	let mut len = safe_indexing_one(data, *offset)?;
	if len > 0x80 {
		len = (safe_indexing_one(data, *offset + 1)?) * 0x100 +
			(safe_indexing_one(data, *offset + 2)?);
		*offset += 2;
	}
	Ok(len)
}

pub fn extract_tcb_info(cert: &[u8]) -> Result<(Fmspc, TcbVersionStatus), Error> {
	let extension_section = get_intel_extension(cert)?;

	let fmspc = get_fmspc(&extension_section)?;
	let cpusvn = get_cpusvn(&extension_section)?;
	let pcesvn = get_pcesvn(&extension_section)?;

	Ok((fmspc, TcbVersionStatus::new(cpusvn, pcesvn, TcbStatus::Unknown)))
}

fn get_intel_extension(der_encoded: &[u8]) -> Result<Vec<u8>, Error> {
	let cert: Certificate = der::Decode::from_der(der_encoded)
		.map_err(|_| Error::IntelExtensionCertificateDecodingError)?;
	let mut extension_iter = cert
		.tbs_certificate
		.extensions
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.filter(|e| e.extn_id == INTEL_SGX_EXTENSION_OID)
		.map(|e| e.extn_value.clone());

	let extension = extension_iter.next();
	if !(extension.is_some() && extension_iter.next().is_none()) {
		//"There should only be one section containing Intel extensions"
		return Err(Error::IntelExtensionAmbiguity);
	}
	// SAFETY: Ensured above that extension.is_some() == true
	Ok(extension.unwrap().into_bytes())
}

fn get_fmspc(der: &[u8]) -> Result<Fmspc, Error> {
	let bytes_oid = OID_FMSPC.as_bytes();
	let mut offset = der
		.windows(bytes_oid.len())
		.position(|window| window == bytes_oid)
		.ok_or(Error::FmspcOidIsMissing)?;
	offset += 12; // length oid (10) + asn1 tag (1) + asn1 length10 (1)

	let fmspc_size = core::mem::size_of::<Fmspc>() / core::mem::size_of::<u8>();
	let data = der.get(offset..offset + fmspc_size).ok_or(Error::FmspcLengthMismatch)?;
	data.try_into().map_err(|_| Error::FmspcDecodingError)
}

fn get_cpusvn(der: &[u8]) -> Result<CpuSvn, Error> {
	let bytes_oid = OID_CPUSVN.as_bytes();
	let mut offset = der
		.windows(bytes_oid.len())
		.position(|window| window == bytes_oid)
		.ok_or(Error::CpuSvnOidIsMissing)?;
	offset += 13; // length oid (11) + asn1 tag (1) + asn1 length10 (1)

	// CPUSVN is specified to have length 16
	let len = 16;
	let data = der.get(offset..offset + len).ok_or(Error::CpuSvnLengthMismatch)?;
	data.try_into().map_err(|_| Error::CpuSvnDecodingError)
}

fn get_pcesvn(der: &[u8]) -> Result<PceSvn, Error> {
	let bytes_oid = OID_PCESVN.as_bytes();
	let mut offset = der
		.windows(bytes_oid.len())
		.position(|window| window == bytes_oid)
		.ok_or(Error::PceSvnOidIsMissing)?;
	// length oid + asn1 tag (1 byte)
	offset += bytes_oid.len() + 1;
	// PCESVN can be 1 or 2 bytes
	let len = length_from_raw_data(der, &mut offset).map_err(|_| Error::PceSvnDecodingError)?;
	offset += 1; // length_from_raw_data does not move the offset when the length is encoded in a single byte
	if !(len == 1 || len == 2) {
		return Err(Error::PceSvnLengthMismatch);
	}
	let data = der.get(offset..offset + len).ok_or(Error::PceSvnLengthMismatch)?;
	if data.len() == 1 {
		Ok(u16::from(data[0]))
	} else {
		// Unwrap is fine here as we check the length above
		// DER integers are encoded in big endian
		Ok(u16::from_be_bytes(data.try_into().unwrap()))
	}
}

/// Extract a list of certificates from a byte vec. The certificates must be separated by
/// `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` markers
pub fn extract_certs(cert_chain: &[u8]) -> Vec<Vec<u8>> {
	// The certificates should be valid UTF-8 but if not we skip the invalid cert. The certificate verification
	// will fail at a later point.
	let certs_concat = String::from_utf8_lossy(cert_chain);
	let certs_concat = certs_concat.replace('\n', "");
	let certs_concat = certs_concat.replace("-----BEGIN CERTIFICATE-----", "");
	// Use the end marker to split the string into certificates
	let parts = certs_concat.split("-----END CERTIFICATE-----");
	parts.filter(|p| !p.is_empty()).filter_map(|p| general_purpose::STANDARD.decode(p).ok()).collect()
}

// pub fn verify_certificate_chain<'a>(
//     raw_leaf_cert: &'a [u8],
//     raw_intermediate_certs: &[&[u8]],
//     verification_time: u64,
// ) -> Result<webpki::EndEntityCert<'a>, Error> {
//     let leaf_cert_der = webpki::types::CertificateDer::from(raw_leaf_cert);
//     let leaf_cert: webpki::EndEntityCert =
//         webpki::EndEntityCert::try_from(&leaf_cert_der).map_err(|_| Error::LeafCertificateParsingError)?;
//     let intermediate_certs = raw_intermediate_certs.into_iter().map(|raw_cert| {
//         webpki::types::CertificateDer::from(*raw_cert)
//     }).collect::<Vec<_>>();
//
//     let time = webpki::types::UnixTime::since_unix_epoch(Duration::from_secs(verification_time / 1000));
//     let sig_algs = &[webpki::ring::ECDSA_P256_SHA256];
//     leaf_cert
//         .verify_for_usage(
//             sig_algs,
//             DCAP_SERVER_ROOTS,
//             intermediate_certs.as_slice(),
//             time,
//             webpki::KeyUsage::server_auth(),
//             None,
//             None
//         )
//         .map_err(|e| {
//             Error::CertificateChainIsInvalid
//         })?;
//
//     Ok(leaf_cert)
// }

/// Verifies that the `leaf_cert` in combination with the `intermediate_certs` establishes
/// a valid certificate chain that is rooted in one of the trust anchors that was compiled into to the pallet
pub fn verify_certificate_chain<'a>(
	leaf_cert: &webpki::EndEntityCert,
	intermediate_certs: &[CertificateDer],
	verification_time: u64,
) -> Result<(), Error> {
	let time = webpki::types::UnixTime::since_unix_epoch(Duration::from_secs(verification_time / 1000));
	let sig_algs = &[webpki::ring::ECDSA_P256_SHA256];
	leaf_cert
		.verify_for_usage(
            sig_algs,
            DCAP_SERVER_ROOTS,
            intermediate_certs,
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
		.map_err(|e| {
			Error::CertificateChainIsInvalid
		})?;

	Ok(())
}

fn main() -> Result<(), Error> {
	let quote_collateral = QuoteCollateral {
		major_version: 3,
		minor_version: 0,
		tee_type: 0,
		pck_crl_issuer_chain: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/pck_crl_issuer_chain")).to_string(),
		root_ca_crl: include_bytes!("../sample/quote_collateral/root_ca_crl").to_vec(),
		pck_crl: include_bytes!("../sample/quote_collateral/pck_crl").to_vec(),
		tcb_info_issuer_chain: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/tcb_info_issuer_chain")).to_string(),
		tcb_info: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/tcb_info")).to_string(),
		qe_identity_issuer_chain: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/qe_identity_issuer_chain")).to_string(),
		qe_identity: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/qe_identity")).to_string(),
	};

	let now = 1698266494000u64;
	let mr_enclave: [u8; 32] = hex::decode("9b62c246eaff2b5493a5c74941d4eb70b700a19edb005cc91fda286a62934048").expect("Hex decodable").try_into().expect("into");
	let mr_signer: [u8; 32] = hex::decode("815f42f11cf64430c30bab7816ba596a1da0130c3b028b673133a66cf9a3e0e6").expect("Hex decodable").try_into().expect("into");

	println!("= Test parsing TCB info from collateral =");
	let _ = tcb::TCBInfo::from_json_str(&quote_collateral.tcb_info);
	println!("==========================================");

	println!("= Test parsing quote =");
	let raw_quote = include_bytes!("../sample/quote").to_vec();
	let quote = Quote::parse(&raw_quote).expect("Quote decodable");
	println!("======================");

	// let current_time: u64 = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();
	// quote_verifier::sgx_qv_verify_quote(&quote, quote_collateral, current_time);

	if quote.header.version != QuoteVersion::V3 {
		return Err(Error::UnsupportedDCAPQuoteVersion);
	}
	if quote.header.attestation_key_type != AttestationKeyType::ECDSA256WithP256Curve {
		return Err(Error::UnsupportedDCAPAttestationKeyType);
	}

	let QuoteAuthData::Ecdsa256Bit {
		signature,
		attestation_key,
		qe_report,
		qe_report_signature,
		qe_auth_data,
		certification_data,
	} = quote.signed_data else {
		return Err(Error::UnsupportedQuoteAuthData);
	};
	if certification_data.data_type != 5 {
		return Err(Error::UnsupportedDCAPPckCertFormat);
	}

	if quote.enclave_report.mr_enclave != mr_enclave {
		return Err(Error::UnknownMREnclave);
	}
	if quote.enclave_report.mr_signer != mr_signer {
		return Err(Error::UnknownMRSigner);
	}

	// Seems we verify MR_ENCLAVE and MR_SIGNER is enough

	// verify_misc_select_field
	// for i in 0..self.misc_select.len() {
	//     if (self.misc_select[i] & o.miscselect_mask[i]) !=
	//         (o.miscselect[i] & o.miscselect_mask[i])
	//     {
	//         return false
	//     }
	// }

	// verify_attributes_field
	// let attributes_flags = self.attributes.flags;
	//
	// let quoting_enclave_attributes_mask = o.attributes_flags_mask_as_u64();
	// let quoting_enclave_attributes_flags = o.attributes_flags_as_u64();
	//
	// (attributes_flags & quoting_enclave_attributes_mask) == quoting_enclave_attributes_flags

	// for tcb in &o.tcb {
	//     // If the enclave isvsvn is bigger than one of the
	//     if self.isv_svn >= tcb.isvsvn {
	//         return true
	//     }
	// }
	// // ensure!(quote.quote_signature_data.qe_report.verify(qe), Error::QeHasRejectedEnclave); //"Enclave rejected by quoting enclave"

	let certs = extract_certs(&certification_data.data);
	if certs.len() < 2 {
		return Err(Error::CertificateChainIsTooShort);
	}
	let intermediate_certificate_slices: Vec<&[u8]> =
		certs[1..].iter().map(Vec::as_slice).collect();
	let intermediate_certs = intermediate_certificate_slices.into_iter().map(|raw_cert| {
		webpki::types::CertificateDer::from(raw_cert)
	}).collect::<Vec<_>>();

	let leaf_cert_der = webpki::types::CertificateDer::from(certs[0].clone());
	let leaf_cert: webpki::EndEntityCert =
		webpki::EndEntityCert::try_from(&leaf_cert_der).map_err(|_| Error::LeafCertificateParsingError)?;

	if let Err(err) = verify_certificate_chain(&leaf_cert, &intermediate_certs, now) {
		return Err(err);
	}

	// TODO: Uncomment this, Rust plugin crash in below lines
	// const ATTESTATION_KEY_SIZE: usize = 64;
	// const AUTHENTICATION_DATA_SIZE: usize = 32;
	//
	// let mut qe_hash_data = [0u8; ATTESTATION_KEY_SIZE + AUTHENTICATION_DATA_SIZE];
	// qe_hash_data[0..ATTESTATION_KEY_SIZE].copy_from_slice(
	// 	&attestation_key.to_encoded_point(false).as_bytes()[1..]
	// );
	// qe_hash_data[ATTESTATION_KEY_SIZE..].copy_from_slice(
	// 	&qe_auth_data
	// );
	// let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
	// if qe_hash.as_ref() != &qe_report.report_data[0..32] {
	// 	return Err(Error::QEReportHashMismatch)
	// }

	// let (fmspc, tcb_info) = extract_tcb_info(&certs[0])?;

	// if quote.enclave_report.report_data[0..32] != signature.to_vec() {
	// 	return Err(Error::QEReportHashMismatch);
	// }

	Ok(())
}
