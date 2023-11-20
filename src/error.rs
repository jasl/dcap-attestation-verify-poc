#[derive(thiserror::Error, Debug)]
pub enum Error {
	#[error("ParseError")]
	ParseError,
	#[error("RawDataInvalid")]
	RawDataInvalid,
	#[error("MissingField: {field}")]
	MissingField { field: String },
	#[error("InvalidField: {field}")]
	InvalidFieldValue { field: String },
	#[error("UnsupportedFieldValue: {field}")]
	UnsupportedFieldValue { field: String },
	#[error("KeyLengthIsInvalid")]
	KeyLengthIsInvalid,
	#[error("PublicKeyIsInvalid")]
	PublicKeyIsInvalid,
	#[error("RsaSignatureIsInvalid")]
	RsaSignatureIsInvalid,
	#[error("DerEncodingError")]
	DerEncodingError,
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
	#[error("LeafCertificateParsingError")]
	LeafCertificateParsingError,
	#[error("CertificateChainIsInvalid")]
	CertificateChainIsInvalid,
	#[error("CertificateChainIsTooShort")]
	CertificateChainIsTooShort,
	#[error("IntelExtensionCertificateDecodingError")]
	IntelExtensionCertificateDecodingError,
	#[error("IntelExtensionAmbiguity")]
	IntelExtensionAmbiguity,
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
