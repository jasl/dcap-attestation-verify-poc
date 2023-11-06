extern crate alloc;
extern crate core;

mod error;
mod utils;
// mod quote_verifier;
mod tcb;
mod quote;
mod qe_identity;
mod quote_collateral;

use const_oid::ObjectIdentifier;
use scale_codec::Decode;
use x509_cert::Certificate;

use crate::quote::{AttestationKeyType, Quote, QuoteAuthData, QuoteVersion};
use crate::quote_collateral::QuoteCollateral;

use crate::utils::*;
use error::Error;
use crate::tcb::TCBInfo;

pub type MrSigner = [u8; 32];
pub type MrEnclave = [u8; 32];
pub type Fmspc = [u8; 6];
pub type CpuSvn = [u8; 16];
pub type PceSvn = u16;

#[derive(Default, Clone, PartialEq, Eq, Debug)]
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

#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct TcbVersionStatus {
	pub cpu_svn: CpuSvn,
	pub pce_svn: PceSvn,
	pub tcb_status: TcbStatus,
}

impl TcbVersionStatus {
	pub fn new(cpu_svn: CpuSvn, pce_svn: PceSvn, tcb_status: TcbStatus) -> Self {
		Self { cpu_svn, pce_svn, tcb_status }
	}

	/// verifies if CpuSvn and PceSvn are considered valid
	/// this function should be called by recent TcbInfo from Intel with the DUT enclave
	/// TCB info from the DCAP quote as argument
	pub fn verify_examinee(&self, examinee: &TcbVersionStatus) -> bool {
		for (v, r) in self.cpu_svn.iter().zip(examinee.cpu_svn.iter()) {
			log::debug!("verify_examinee: v={:?},r={:?}", v, r);
			if *v > *r {
				return false;
			}
		}
		log::debug!(
            "verify_examinee: self.pcesvn={:?},examinee.pcesvn={:?}",
            &self.pce_svn,
            &examinee.pce_svn
        );
		self.pce_svn <= examinee.pce_svn
	}
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
	let cpu_svn = get_cpu_svn(&extension_section)?;
	let pce_svn = get_pce_svn(&extension_section)?;

	Ok((fmspc, TcbVersionStatus::new(cpu_svn, pce_svn, TcbStatus::Unknown)))
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

fn get_cpu_svn(der: &[u8]) -> Result<CpuSvn, Error> {
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

fn get_pce_svn(der: &[u8]) -> Result<PceSvn, Error> {
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

fn main() -> Result<(), Error> {
	let mut raw_quote_collateral = include_bytes!("../sample/quote_collateral").to_vec();
	let quote_collateral = QuoteCollateral::decode(&mut raw_quote_collateral.as_slice()).unwrap();

	println!("= Test parsing TCB info from collateral =");
	let tcb_info = TCBInfo::from_json_str(&quote_collateral.tcb_info).unwrap();
	println!("{:?}", tcb_info);
	println!("==========================================");

	let now = 1699301000000u64;
	let mr_enclave: [u8; 32] = hex::decode("33d8736db756ed4997e04ba358d27833188f1932ff7b1d156904d3f560452fbb").expect("Hex decodable").try_into().expect("into");
	let mr_signer: [u8; 32] = hex::decode("815f42f11cf64430c30bab7816ba596a1da0130c3b028b673133a66cf9a3e0e6").expect("Hex decodable").try_into().expect("into");

	println!("= Test parsing quote =");
	let raw_quote = include_bytes!("../sample/quote").to_vec();
	let quote = Quote::parse(&raw_quote).expect("Quote decodable");
	println!("======================");

	let leaf_certs = extract_certs(quote_collateral.tcb_info_issuer_chain.as_bytes());
	if leaf_certs.len() < 2 {
		return Err(Error::CertificateChainIsTooShort);
	}
	let leaf_cert: webpki::EndEntityCert =
		webpki::EndEntityCert::try_from(&leaf_certs[0]).map_err(|_| Error::LeafCertificateParsingError)?;
	let intermediate_certs = &leaf_certs[1..];
	if let Err(err) = verify_certificate_chain(&leaf_cert, &intermediate_certs, now) {
		return Err(err);
	}
	let asn1_signature = encode_as_der(&quote_collateral.tcb_info_signature)?;
	if leaf_cert.verify_signature(webpki::ring::ECDSA_P256_SHA256, &quote_collateral.tcb_info.as_bytes(), &asn1_signature).is_err() {
		return Err(Error::RsaSignatureIsInvalid)
	}

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

	println!("{}", hex::encode(&quote.enclave_report.mr_enclave));
	if quote.enclave_report.mr_enclave != mr_enclave {
		return Err(Error::UnknownMREnclave);
	}
	println!("{}", hex::encode(&quote.enclave_report.mr_signer));
	if quote.enclave_report.mr_signer != mr_signer {
		return Err(Error::UnknownMRSigner);
	}

	let parsed_qe_report = crate::quote::EnclaveReport::from_slice(&qe_report).map_err(|_err| Error::ParseError)?;

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

	let leaf_cert: webpki::EndEntityCert =
		webpki::EndEntityCert::try_from(&certification_data.certs[0]).map_err(|_| Error::LeafCertificateParsingError)?;
	let intermediate_certs = &certification_data.certs[1..];
	if let Err(err) = verify_certificate_chain(&leaf_cert, &intermediate_certs, now) {
		return Err(err);
	}

	// if let Err(err) = verify_certificate_chain(&certification_data.leaf_cert, &certification_data.intermediate_certs, now) {
	// 	return Err(err);
	// }

	const ATTESTATION_KEY_LEN: usize = 64;
	const AUTHENTICATION_DATA_LEN: usize = 32;

	let mut qe_hash_data = [0u8; ATTESTATION_KEY_LEN + AUTHENTICATION_DATA_LEN];
	qe_hash_data[0..ATTESTATION_KEY_LEN].copy_from_slice(
		&attestation_key
	);
	qe_hash_data[ATTESTATION_KEY_LEN..].copy_from_slice(
		&qe_auth_data
	);
	let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
	if qe_hash.as_ref() != &parsed_qe_report.report_data[0..32] {
		return Err(Error::QEReportHashMismatch)
	}

	let asn1_signature = encode_as_der(&qe_report_signature)?;
	if leaf_cert.verify_signature(webpki::ring::ECDSA_P256_SHA256, &qe_report, &asn1_signature).is_err() {
		return Err(Error::RsaSignatureIsInvalid)
	}

	let mut pub_key = [0x04u8; 65]; //Prepend 0x04 to specify uncompressed format
	pub_key[1..].copy_from_slice(&attestation_key);

	let peer_public_key =
		ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pub_key);
	// Verify that the enclave data matches the signature generated by the trusted attestation key.
	// This establishes trust into the data of the enclave we actually want to verify
	peer_public_key
		.verify(&raw_quote[..(quote::HEADER_BYTE_LEN + quote::ENCLAVE_REPORT_BYTE_LEN)], &signature)
		.map_err(|_| Error::IsvEnclaveReportSignatureIsInvalid)?;

	let (fmspc, tcb_info) = extract_tcb_info(&certification_data.certs[0])?;
	println!("fmspc: {}", hex::encode(fmspc));
	println!("tcb_info: {:?}", tcb_info);


	// if quote.enclave_report.report_data[0..32] != signature.to_vec() {
	// 	return Err(Error::QEReportHashMismatch);
	// }

	Ok(())
}
