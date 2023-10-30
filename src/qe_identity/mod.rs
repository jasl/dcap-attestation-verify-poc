use core::result::Result;
use core::fmt;
use chrono::{
    DateTime, FixedOffset
};

use crate::tcb::{TCBStatus, ParseError};

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EnclaveIdentityVersion {
    V2,
    // V3, // TODO: QVE says there has V3, but it's hard-coded class name V2
    Unsupported { version: u32 },
}

impl fmt::Display for EnclaveIdentityVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EnclaveIdentityVersion::V2 => write!(f, "2"),
            EnclaveIdentityVersion::Unsupported { version } => write!(f, "{}", version)
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EnclaveId {
    QE,
    QVE,
    TdQE,
    Unknown { id: String },
}

impl fmt::Display for EnclaveId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EnclaveId::QE => write!(f, "QE"),
            EnclaveId::QVE => write!(f, "QVE"),
            EnclaveId::TdQE => write!(f, "TD_QE"),
            EnclaveId::Unknown { id } => write!(f, "{}", id)
        }
    }
}

#[derive(Clone)]
pub struct TCBLevel {
    pub tcb_status: TCBStatus,
    pub tcb_date: DateTime<FixedOffset>,
    pub isv_svn: u32,
}

impl TCBLevel {
    pub fn from_json_value(json: &serde_json::Value) -> Result<TCBLevel, ParseError> {
        let tcb_level = json.as_object().expect("TCB level should be a JSON object");

        let tcb_date = tcb_level.get("tcbDate").expect("TCB Info JSON should has [tcbDate] field");
        let tcb_date = tcb_date.as_str().expect("Could not parse [tcbDate] field of TCB info JSON to string");
        let tcb_date = chrono::DateTime::parse_from_rfc3339(tcb_date).expect("[tcbDate] should be ISO formatted date");

        let tcb_status = {
            let raw_tcb_status = tcb_level
                .get("tcbStatus")
                .expect("TCB Info JSON should has [tcbStatus] field")
                .as_str()
                .expect("Could not parse [tcbStatus] field of TCB info JSON to string");
            match raw_tcb_status {
                "UpToDate" => TCBStatus::UpToDate,
                "OutOfDate" => TCBStatus::OutOfDate,
                "ConfigurationNeeded" => TCBStatus::ConfigurationNeeded,
                "Revoked" => TCBStatus::Revoked,
                "OutOfDateConfigurationNeeded" => TCBStatus::OutOfDateConfigurationNeeded,
                "SWHardeningNeeded" => TCBStatus::SWHardeningNeeded,
                "ConfigurationAndSWHardeningNeeded" => TCBStatus::ConfigurationAndSWHardeningNeeded,
                _ => TCBStatus::Unrecognized { status: raw_tcb_status.to_owned() }
            }
        };
        if matches!(tcb_status, TCBStatus::Unrecognized { .. }) {
            return Err(
                ParseError::InvalidValue { field: "tcbStatus".to_owned() }
            )
        }

        let tcb = tcb_level.get("tcb").expect("Missing [tcb] field of TCB info JSON");
        let tcb = tcb.as_object().expect("TCB should be a JSON object");

        let isv_svn = tcb.get("isvsvn").expect("TCB Info JSON should has [isvsvn] field");
        let isv_svn = isv_svn.as_u64().expect("Could not parse [isvsvn] field of TCB info JSON to integer") as u32;

        println!("- Parsed TCB Level -");
        println!("TCB Status: {}", tcb_status);
        println!("TCB Date: {}", tcb_date);
        println!("ISV SVN: {}", isv_svn);
        println!("---------------------");

        Ok(
            Self {
                tcb_status,
                tcb_date,
                isv_svn,
            }
        )
    }
}

// EnclaveIdentityV2
#[derive(Clone)]
pub struct EnclaveIdentity {
    pub signature: String,
    // std::vector<uint8_t> body;

    pub misc_select: Vec<u8>,
    pub misc_select_mask: Vec<u8>,
    pub attributes: Vec<u8>,
    pub attributes_mask: Vec<u8>,
    pub mr_signer: Vec<u8>,
    pub issue_date: DateTime<FixedOffset>,
    pub next_update: DateTime<FixedOffset>,
    pub isv_prod_id: u32,
    pub version: EnclaveIdentityVersion,
    pub id: EnclaveId,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TCBLevel>,

    // status
    //     STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_FORMAT,
    //     STATUS_SGX_ENCLAVE_IDENTITY_INVALID,
    //     STATUS_SGX_ENCLAVE_IDENTITY_UNSUPPORTED_VERSION,
}

impl EnclaveIdentity {
    pub fn from_json_str(json_str: &str) -> Result<Self, ParseError> {
        let enclave_identity_json: serde_json::Value = serde_json::from_str(json_str).expect("Could not parse EnclaveIdentity JSON");
        let enclave_identity_json = enclave_identity_json.as_object().expect("EnclaveIdentity JSON should be an object");

        let enclave_identity = enclave_identity_json.get("enclaveIdentity").expect("Missing [enclaveIdentity] field of EnclaveIdentity JSON");
        let enclave_identity = enclave_identity.as_object().expect("EnclaveIdentity JSON should be an object");

        let signature = enclave_identity_json.get("signature").expect("Missing [signature] field of EnclaveIdentity JSON");
        let signature = signature.as_str().expect("Could not parse [signature] field of EnclaveIdentity JSON to string");
        let signature = signature.to_owned();
        // TODO: validate length

        let misc_select = enclave_identity.get("miscselect").expect("Missing [miscselect] field of EnclaveIdentity JSON");
        let misc_select = misc_select.as_str().expect("Could not parse [miscselect] field of EnclaveIdentity JSON to string");
        let misc_select = hex::decode(misc_select).expect("Could not parse [miscselect] field of EnclaveIdentity JSON to hex");

        let misc_select_mask = enclave_identity.get("miscselectMask").expect("Missing [miscselectMask] field of EnclaveIdentity JSON");
        let misc_select_mask = misc_select_mask.as_str().expect("Could not parse [miscselectMask] field of EnclaveIdentity JSON to string");
        let misc_select_mask = hex::decode(misc_select_mask).expect("Could not parse [miscselectMask] field of EnclaveIdentity JSON to hex");

        let attributes = enclave_identity.get("attributes").expect("Missing [attributes] field of EnclaveIdentity JSON");
        let attributes = attributes.as_str().expect("Could not parse [attributes] field of EnclaveIdentity JSON to string");
        let attributes = hex::decode(attributes).expect("Could not parse [attributes] field of EnclaveIdentity JSON to hex");

        let attributes_mask = enclave_identity.get("attributesMask").expect("Missing [attributesMask] field of EnclaveIdentity JSON");
        let attributes_mask = attributes_mask.as_str().expect("Could not parse [attributesMask] field of EnclaveIdentity JSON to string");
        let attributes_mask = hex::decode(attributes_mask).expect("Could not parse [attributesMask] field of EnclaveIdentity JSON to hex");

        let mr_signer = enclave_identity.get("mrsigner").expect("Missing [mrsigner] field of EnclaveIdentity JSON");
        let mr_signer = mr_signer.as_str().expect("Could not parse [mrsigner] field of EnclaveIdentity JSON to string");
        let mr_signer = hex::decode(mr_signer).expect("Could not parse [mrsigner] field of EnclaveIdentity JSON to hex");

        let isv_prod_id = enclave_identity.get("isvprodid").expect("EnclaveIdentity JSON should has [isvprodid] field");
        let isv_prod_id = isv_prod_id.as_u64().expect("Could not parse [isvprodid] field of EnclaveIdentity JSON to integer") as u32;

        let tcb_evaluation_data_number = enclave_identity.get("tcbEvaluationDataNumber").expect("EnclaveIdentity JSON should has [tcbEvaluationDataNumber] field");
        let tcb_evaluation_data_number = tcb_evaluation_data_number.as_u64().expect("Could not parse [tcbEvaluationDataNumber] field of EnclaveIdentity JSON to integer") as u32;

        let version = {
            let raw_version = enclave_identity
                .get("version")
                .expect("TCB Info JSON should has [version] field")
                .as_u64()
                .expect("Could not parse [version] field of TCB info JSON to integer") as u32;
            match raw_version {
                2 => EnclaveIdentityVersion::V2,
                _ => EnclaveIdentityVersion::Unsupported { version: raw_version }
            }
        };
        if matches!(version, EnclaveIdentityVersion::Unsupported { .. }) {
            return Err(
                ParseError::InvalidValue {
                    field: "version".to_owned(),
                }
            )
        }

        let id = {
            let raw_id = enclave_identity
                .get("id")
                .expect("EnclaveIdentity JSON should has [id] field")
                .as_str()
                .expect("Could not parse [id] field of EnclaveIdentity JSON string");
            match raw_id {
                "QE" => EnclaveId::QE,
                "QVE" => EnclaveId::QVE,
                "TD_QE" => EnclaveId::TdQE,
                _ => EnclaveId::Unknown { id: raw_id.to_owned() },
            }
        };

        if matches!(id, EnclaveId::Unknown { .. }) {
            return Err(
                ParseError::InvalidValue { field: "id".to_owned() }
            )
        }

        let issue_date = enclave_identity.get("issueDate").expect("TCB Info JSON should has [issueDate] field");
        let issue_date = issue_date.as_str().expect("Could not parse [issueDate] field of TCB info JSON to string");
        let issue_date = chrono::DateTime::parse_from_rfc3339(issue_date).expect("[issueDate] should be ISO formatted date");

        let next_update = enclave_identity.get("nextUpdate").expect("TCB Info JSON should has [nextUpdate] field");
        let next_update = next_update.as_str().expect("Could not parse [nextUpdate] field of TCB info JSON to string");
        let next_update = chrono::DateTime::parse_from_rfc3339(next_update).expect("[nextUpdate] should be ISO formatted date");

        println!("= Parsed EnclaveIdentity =");
        println!("Signature: {}", signature);
        println!("Version: {}", version);
        println!("Id: {}", id);
        println!("Issue date: {}", issue_date);
        println!("Next update: {}", next_update);
        println!("TCB Evaluation Data Number: {}", tcb_evaluation_data_number);
        println!("MISC select: {}", hex::encode_upper(misc_select.clone()));
        println!("MISC select mask: {}", hex::encode_upper(misc_select_mask.clone()));
        println!("Attributes: {}", hex::encode_upper(attributes.clone()));
        println!("Attributes mask: {}", hex::encode_upper(attributes_mask.clone()));
        println!("MR Signer: {}", hex::encode_upper(mr_signer.clone()));
        println!("ISV prod id: {}", isv_prod_id);
        println!("===================");

        let raw_tcb_levels = enclave_identity.get("tcbLevels").expect("Missing [tcbLevels] field of TCB info JSON");
        let raw_tcb_levels = raw_tcb_levels.as_array().expect("[tcbLevels] field of TCB info JSON should be an array");
        if raw_tcb_levels.is_empty() {
            return Err(
                ParseError::InvalidValue { field: "InvalidValue".to_owned() }
            )
        }

        let mut tcb_levels: Vec<TCBLevel> = Vec::new();
        for raw_tcb_level in raw_tcb_levels {
            let tcb_level = TCBLevel::from_json_value(raw_tcb_level).expect("Can't parse TCBLevel");
            tcb_levels.push(tcb_level)
        }

        Ok(
            Self {
                signature,
                version,
                id,
                issue_date,
                next_update,
                tcb_evaluation_data_number,
                misc_select,
                misc_select_mask,
                attributes,
                attributes_mask,
                mr_signer,
                isv_prod_id,
                tcb_levels
            }
        )
    }
}
