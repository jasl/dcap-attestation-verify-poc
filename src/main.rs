extern crate alloc;
extern crate core;

mod error;
mod utils;
mod tcb;
mod quote;
mod quote_collateral;

use scale_codec::Decode;

use crate::quote::{AttestationKeyType, Quote, QuoteAuthData, QuoteVersion};
use crate::quote_collateral::QuoteCollateral;

use crate::utils::*;
use crate::error::Error;
use crate::tcb::TCBInfo;

// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf
fn main() -> Result<(), Error> {
	// Mock data

	let now = 1699301000000u64;
	let mr_enclave: [u8; 32] = hex::decode("33d8736db756ed4997e04ba358d27833188f1932ff7b1d156904d3f560452fbb").expect("Hex decodable").try_into().expect("into");
	let mr_signer: [u8; 32] = hex::decode("815f42f11cf64430c30bab7816ba596a1da0130c3b028b673133a66cf9a3e0e6").expect("Hex decodable").try_into().expect("into");

	let raw_quote_collateral = include_bytes!("../sample/quote_collateral").to_vec();
	let raw_quote = include_bytes!("../sample/quote").to_vec();

	// Parse data

	let quote = Quote::parse(&raw_quote).expect("Quote decodable");
	// For quick deny invalid quote
	// Check MR enclave
	if quote.enclave_report.mr_enclave != mr_enclave {
		return Err(Error::UnknownMREnclave);
	}
	// Check MR signer
	if quote.enclave_report.mr_signer != mr_signer {
		return Err(Error::UnknownMRSigner);
	}

	let quote_collateral = QuoteCollateral::decode(&mut raw_quote_collateral.as_slice()).unwrap();
	let tcb_info = TCBInfo::from_json_str(&quote_collateral.tcb_info).unwrap();

	// Verify enclave

	// Seems we verify MR_ENCLAVE and MR_SIGNER is enough
	// skip verify_misc_select_field
	// skip verify_attributes_field

	// Verify integrity

	// Check TCB info cert chain and signature
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

	// Check quote fields
	if quote.header.version != QuoteVersion::V3 {
		return Err(Error::UnsupportedDCAPQuoteVersion);
	}
	// We only support ECDSA256 with P256 curve
	if quote.header.attestation_key_type != AttestationKeyType::ECDSA256WithP256Curve {
		return Err(Error::UnsupportedDCAPAttestationKeyType);
	}

	// Extract Auth data from quote
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

	// We only support 5 -Concatenated PCK Cert Chain (PEM formatted).
	if certification_data.data_type != 5 {
		return Err(Error::UnsupportedDCAPPckCertFormat);
	}
	// Check certification_data
	let leaf_cert: webpki::EndEntityCert =
		webpki::EndEntityCert::try_from(&certification_data.certs[0]).map_err(|_| Error::LeafCertificateParsingError)?;
	let intermediate_certs = &certification_data.certs[1..];
	if let Err(err) = verify_certificate_chain(&leaf_cert, &intermediate_certs, now) {
		return Err(err);
	}

	// Check QE signature
	let asn1_signature = encode_as_der(&qe_report_signature)?;
	if leaf_cert.verify_signature(webpki::ring::ECDSA_P256_SHA256, &qe_report, &asn1_signature).is_err() {
		return Err(Error::RsaSignatureIsInvalid)
	}

	// Extract QE report from quote
	let parsed_qe_report = crate::quote::EnclaveReport::from_slice(&qe_report).map_err(|_err| Error::ParseError)?;

	// Check QE hash
	let mut qe_hash_data = [0u8; quote::QE_HASH_DATA_BYTE_LEN];
	qe_hash_data[0..quote::ATTESTATION_KEY_LEN].copy_from_slice(
		&attestation_key
	);
	qe_hash_data[quote::ATTESTATION_KEY_LEN..].copy_from_slice(
		&qe_auth_data
	);
	let qe_hash = ring::digest::digest(&ring::digest::SHA256, &qe_hash_data);
	if qe_hash.as_ref() != &parsed_qe_report.report_data[0..32] {
		return Err(Error::QEReportHashMismatch)
	}

	// Check signature from auth data
	let mut pub_key = [0x04u8; 65]; //Prepend 0x04 to specify uncompressed format
	pub_key[1..].copy_from_slice(&attestation_key);
	let peer_public_key =
		ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, pub_key);
	peer_public_key
		.verify(&raw_quote[..(quote::HEADER_BYTE_LEN + quote::ENCLAVE_REPORT_BYTE_LEN)], &signature)
		.map_err(|_| Error::IsvEnclaveReportSignatureIsInvalid)?;

	// Extract information from the quote

	let extension_section = get_intel_extension(&certification_data.certs[0])?;
	let cpu_svn = get_cpu_svn(&extension_section)?;
	let pce_svn = get_pce_svn(&extension_section)?;

	// TCB status and advisory ids
	let mut tcb_status = tcb::TCBStatus::Unrecognized { status: None };
	let mut advisory_ids = Vec::<String>::new();
	for tcb_level in &tcb_info.tcb_levels {
		if pce_svn >= tcb_level.pce_svn {
			let mut selected = true;
			for i in 0..15 { // constant?
				// println!("[{}] QE SVN: {}, TCB LEVEL SVN: {}", i, parsed_qe_report.cpu_svn[i], tcb_level.components[i]);

				if cpu_svn[i] < tcb_level.components[i] {
					selected = false;
					break;
				}
			}
			if !selected {
				continue;
			}

			tcb_status = tcb_level.tcb_status.clone();
			tcb_level.advisory_ids.iter().for_each(|id| advisory_ids.push(id.clone()));

			break;
		}
	}

	println!("TCB status: {}", tcb_status);
	println!("Advisory IDs: {:?}", advisory_ids);

	Ok(())
}
