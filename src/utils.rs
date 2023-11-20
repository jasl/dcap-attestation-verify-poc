use core::time::Duration;
use base64::{engine::general_purpose, Engine as _};
use webpki::types::CertificateDer;
use const_oid::ObjectIdentifier;
use x509_cert::Certificate;

use crate::quote::{CpuSvn, Svn};
use crate::error::Error;

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

/// See document "Intel® Software Guard Extensions: PCK Certificate and Certificate Revocation List Profile Specification"
/// https://download.01.org/intel-sgx/sgx-dcap/1.19/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf
const INTEL_SGX_EXTENSION_OID: ObjectIdentifier =
	ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
// const OID_FMSPC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");
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

pub fn get_intel_extension(der_encoded: &[u8]) -> Result<Vec<u8>, Error> {
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

// pub fn get_fmspc(der: &[u8]) -> Result<Fmspc, Error> {
// 	let bytes_oid = OID_FMSPC.as_bytes();
// 	let mut offset = der
// 		.windows(bytes_oid.len())
// 		.position(|window| window == bytes_oid)
// 		.ok_or(Error::FmspcOidIsMissing)?;
// 	offset += 12; // length oid (10) + asn1 tag (1) + asn1 length10 (1)
//
// 	let fmspc_size = core::mem::size_of::<Fmspc>() / core::mem::size_of::<u8>();
// 	let data = der.get(offset..offset + fmspc_size).ok_or(Error::FmspcLengthMismatch)?;
// 	data.try_into().map_err(|_| Error::FmspcDecodingError)
// }

pub fn get_cpu_svn(der: &[u8]) -> Result<CpuSvn, Error> {
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

pub fn get_pce_svn(der: &[u8]) -> Result<Svn, Error> {
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
pub fn extract_raw_certs(cert_chain: &[u8]) -> Vec<Vec<u8>> {
	// The certificates should be valid UTF-8 but if not we skip the invalid cert. The certificate verification
	// will fail at a later point.
	let certs_concat = String::from_utf8_lossy(cert_chain);
	let certs_concat = certs_concat.replace('\n', "");
	let certs_concat = certs_concat.replace("-----BEGIN CERTIFICATE-----", "");
	// Use the end marker to split the string into certificates
	let parts = certs_concat.split("-----END CERTIFICATE-----");
	parts.filter(|p| !p.is_empty()).filter_map(|p| general_purpose::STANDARD.decode(p).ok()).collect()
}

pub fn extract_certs<'a>(cert_chain: &'a [u8]) -> Vec<CertificateDer<'a>> {
	let mut certs = Vec::<CertificateDer<'a>>::new();

	let raw_certs = extract_raw_certs(cert_chain);
	for raw_cert in raw_certs.iter() {
		let cert = webpki::types::CertificateDer::<'a>::from(raw_cert.to_vec());
		certs.push(cert);
	}

	certs
}

/// Encode two 32-byte values in DER format
/// This is meant for 256 bit ECC signatures or public keys
pub fn encode_as_der(data: &[u8]) -> Result<Vec<u8>, Error> {
	if data.len() != 64 {
		return Result::Err(Error::KeyLengthIsInvalid)
	}
	let mut sequence = der::asn1::SequenceOf::<der::asn1::UintRef, 2>::new();
	sequence
		.add(der::asn1::UintRef::new(&data[0..32]).map_err(|_| Error::PublicKeyIsInvalid)?)
		.map_err(|_| Error::PublicKeyIsInvalid)?;
	sequence
		.add(der::asn1::UintRef::new(&data[32..]).map_err(|_| Error::PublicKeyIsInvalid)?)
		.map_err(|_| Error::PublicKeyIsInvalid)?;
	// 72 should be enough in all cases. 2 + 2 x (32 + 3)
	let mut asn1 = vec![0u8; 72];
	let mut writer = der::SliceWriter::new(&mut asn1);
	writer.encode(&sequence).map_err(|_| Error::DerEncodingError)?;
	Ok(writer.finish().map_err(|_| Error::DerEncodingError)?.to_vec())
}

/// Verifies that the `leaf_cert` in combination with the `intermediate_certs` establishes
/// a valid certificate chain that is rooted in one of the trust anchors that was compiled into to the pallet
pub fn verify_certificate_chain(
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
		.map_err(|_e| {
			Error::CertificateChainIsInvalid
		})?;

	Ok(())
}
