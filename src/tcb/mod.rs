use core::result::Result;
use core::fmt;
use chrono::{
    DateTime, FixedOffset
};

const SGX_ID: &str = "SGX";
const TDX_ID: &str = "TDX";

pub const FMSPC_SIZE: usize = 6;
pub const PCE_ID_SIZE: usize = 2;
pub const CPU_SVN_SIZE: usize = 16;
pub const SGX_TCB_SVN_COMP_SIZE: usize = 16;

#[derive(Debug)]
pub enum ParseError {
    Unexpected { field: String, message: String },
    UnsupportedValue { field: String },
    InvalidValue { field: String },
    MissingField { field: String }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::Unexpected { field, message } => {
                write!(f, "`{}`: {}", field, message)
            },
            ParseError::UnsupportedValue { field } => {
                write!(f, "`{}`", field)
            },
            ParseError::InvalidValue { field } => {
                write!(f, "`{}`", field)
            },
            ParseError::MissingField { field } => {
                write!(f, "`{}`", field)
            },
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TCBVersion {
    V2,
    V3,
    Unsupported { version: u8 }
}

impl fmt::Display for TCBVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TCBVersion::V2 => write!(f, "2"),
            TCBVersion::V3 => write!(f, "3"),
            TCBVersion::Unsupported { version } => write!(f, "{}", version)
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TCBId {
    TDX,
    SGX,
    Unsupported { id: String }
}

impl fmt::Display for TCBId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TCBId::TDX => write!(f, "TDX"),
            TCBId::SGX => write!(f, "SGX"),
            TCBId::Unsupported { id } => write!(f, "{}", id)
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TCBStatus {
    UpToDate,
    OutOfDate,
    ConfigurationNeeded,
    Revoked,
    OutOfDateConfigurationNeeded,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    Unrecognized { status: String }
}

impl fmt::Display for TCBStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TCBStatus::UpToDate => write!(f, "UpToDate"),
            TCBStatus::OutOfDate => write!(f, "OutOfDate"),
            TCBStatus::ConfigurationNeeded => write!(f, "ConfigurationNeeded"),
            TCBStatus::Revoked => write!(f, "Revoked"),
            TCBStatus::OutOfDateConfigurationNeeded => write!(f, "OutOfDateConfigurationNeeded"),
            TCBStatus::SWHardeningNeeded => write!(f, "SWHardeningNeeded"),
            TCBStatus::ConfigurationAndSWHardeningNeeded => write!(f, "ConfigurationAndSWHardeningNeeded"),
            TCBStatus::Unrecognized { status } => write!(f, "{}", status),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TCBInfo {
    pub signature: String,
    pub version: TCBVersion,
    pub id: TCBId,
    pub issue_date: DateTime<FixedOffset>,
    pub next_update: DateTime<FixedOffset>,
    pub fmspc: Vec<u8>,
    pub pce_id: Vec<u8>,
    pub tcb_type: u32,
    pub tcb_evaluation_data_number: u32,
    pub tcb_levels: Vec<TCBLevel>
    // TODO: tdxModule, we won't support TDX for now
}

impl TCBInfo {
    pub fn from_json_str(json_str: &str) -> Result<Self, ParseError> {
        let tcb_info_json: serde_json::Value = serde_json::from_str(json_str).expect("Could not parse TCB info JSON");
        let tcb_info_json = tcb_info_json.as_object().expect("TCB info JSON should be an object");

        let tcb_info = tcb_info_json.get("tcbInfo").expect("Missing [tcbInfo] field of TCB info JSON");
        let tcb_info = tcb_info.as_object().expect("TCB info JSON should be an object");

        let signature = tcb_info_json.get("signature").expect("Missing [signature] field of TCB info JSON");
        let signature = signature.as_str().expect("Could not parse [signature] field of TCB info JSON to string");
        let signature = signature.to_owned();
        // TODO: validate length

        let version = {
            let raw_version = tcb_info
                .get("version")
                .expect("TCB Info JSON should has [version] field")
                .as_u64()
                .expect("Could not parse [version] field of TCB info JSON to integer") as u8;
            match raw_version {
                2 => TCBVersion::V2,
                3 => TCBVersion::V3,
                _ => TCBVersion::Unsupported { version: raw_version }
            }
        };
        if matches!(version, TCBVersion::Unsupported { .. }) {
            return Err(
                ParseError::InvalidValue {
                    field: "version".to_owned(),
                }
            )
        }
        let id = {
            let raw_id = {
                if version == TCBVersion::V3 {
                    tcb_info
                        .get("id")
                        .expect("TCB Info JSON should has [id] field")
                        .as_str()
                        .expect("Could not parse [id] field of TCB info JSON to string")
                } else {
                    SGX_ID
                }
            };

            match raw_id {
                SGX_ID => TCBId::SGX,
                TDX_ID => TCBId::TDX,
                _ => TCBId::Unsupported { id: raw_id.to_owned() }
            }
        };

        if matches!(id, TCBId::Unsupported { .. }) {
            return Err(
                ParseError::InvalidValue { field: "id".to_owned() }
            )
        } else if id == TCBId::TDX {
            // TODO: We won't support TDX for now
            return Err(
                ParseError::UnsupportedValue { field: "id".to_owned() }
            )
        }

        let mut tcb_type = 0u32;
        let mut tcb_evaluation_data_number = 0u32;
        if version == TCBVersion::V2 {
            tcb_type = tcb_info
                .get("tcbType")
                .expect("TCB Info JSON should has [tcbType] field")
                .as_u64()
                .expect("Could not parse [tcbType] field of TCB info JSON to integer") as u32;
            tcb_evaluation_data_number = tcb_info
                .get("tcbEvaluationDataNumber")
                .expect("TCB Info JSON should has [tcbEvaluationDataNumber] field")
                .as_u64()
                .expect("Could not parse [tcbEvaluationDataNumber] field of TCB info JSON to integer") as u32;
        } else if version == TCBVersion::V3 {
            // TODO: V3 looks for TDX which we won't support yet
        }

        let issue_date = tcb_info.get("issueDate").expect("TCB Info JSON should has [issueDate] field");
        let issue_date = issue_date.as_str().expect("Could not parse [issueDate] field of TCB info JSON to string");
        let issue_date = chrono::DateTime::parse_from_rfc3339(issue_date).expect("[issueDate] should be ISO formatted date");

        let next_update = tcb_info.get("nextUpdate").expect("TCB Info JSON should has [nextUpdate] field");
        let next_update = next_update.as_str().expect("Could not parse [nextUpdate] field of TCB info JSON to string");
        let next_update = chrono::DateTime::parse_from_rfc3339(next_update).expect("[nextUpdate] should be ISO formatted date");

        let fmspc = tcb_info.get("fmspc").expect("TCB Info JSON should has [fmspc] field");
        let fmspc = fmspc.as_str().expect("Could not parse [fmspc] field of TCB info JSON to string");
        let fmspc = hex::decode(fmspc).expect("Could not parse [fmspc] field of TCB info JSON to bytes");

        let pce_id = tcb_info.get("pceId").expect("TCB Info JSON should has [pceId] field");
        let pce_id = pce_id.as_str().expect("Could not parse [pceId] field of TCB info JSON to string");
        let pce_id = hex::decode(pce_id).expect("Could not parse [pceId] field of TCB info JSON to bytes");

        println!("= Parsed TCB info =");
        println!("Signature: {}", signature);
        println!("Version: {}", version);
        println!("Id: {}", id);
        println!("Issue date: {}", issue_date);
        println!("Next update: {}", next_update);
        println!("FMSPC: {}", hex::encode(fmspc.clone()));
        println!("PCE Id: {}", hex::encode(pce_id.clone()));
        println!("===================");

        let raw_tcb_levels = tcb_info.get("tcbLevels").expect("Missing [tcbLevels] field of TCB info JSON");
        let raw_tcb_levels = raw_tcb_levels.as_array().expect("[tcbLevels] field of TCB info JSON should be an array");
        if raw_tcb_levels.is_empty() {
            return Err(
                ParseError::InvalidValue { field: "InvalidValue".to_owned() }
            )
        }

        let mut tcb_levels: Vec<TCBLevel> = Vec::new();
        for raw_tcb_level in raw_tcb_levels {
            let tcb_level = TCBLevel::from_json_value(raw_tcb_level, &version).expect("Can't parse TCBLevel");
            tcb_levels.push(tcb_level)
        }

        Ok(
            Self {
                signature,
                version,
                id,
                issue_date,
                next_update,
                fmspc,
                pce_id,
                tcb_type,
                tcb_evaluation_data_number,
                tcb_levels
            }
        )
    }
}

#[derive(Clone, Debug)]
pub struct TCBLevel {
    pub tcb_status: TCBStatus,
    pub tcb_date: DateTime<FixedOffset>,
    pub pce_svn: u32,
    pub advisory_ids: Vec<String>,
    pub components: [u8; 16],
}

impl TCBLevel {
    pub fn from_json_value(json: &serde_json::Value, version: &TCBVersion) -> Result<TCBLevel, ParseError> {
        let tcb_level = json.as_object().expect("TCB level should be a JSON object");

        let tcb_date = tcb_level.get("tcbDate").expect("TCB Info JSON should has [tcbDate] field");
        let tcb_date = tcb_date.as_str().expect("Could not parse [tcbDate] field of TCB info JSON to string");
        let tcb_date = chrono::DateTime::parse_from_rfc3339(tcb_date).expect("[tcbDate] should be ISO formatted date");

        let advisory_ids = tcb_level.get("advisoryIDs").expect("TCB Info JSON should has [advisoryIDs] field");
        let advisory_ids = advisory_ids.as_array().expect("[advisoryIDs] should be string array");
        let advisory_ids = advisory_ids.iter().filter_map(|i| i.as_str().map(|i| i.to_string())).collect();

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

        let pce_svn = tcb.get("pcesvn").expect("TCB Info JSON should has [pcesvn] field");
        let pce_svn = pce_svn.as_u64().expect("Could not parse [pcesvn] field of TCB info JSON to integer") as u32;

        let tcb_components = tcb.get("sgxtcbcomponents").expect("TCB Info JSON should has [sgxtcbcomponents] field");
        let tcb_components = tcb_components.as_array().expect("[sgxtcbcomponents] should be an array");
        let tcb_components: Vec<_> = tcb_components
            .iter()
            .map(|i| {
                let Some(i) = i.as_object() else {
                    return None
                };
                let Some(i) = i.get("svn") else {
                    return None
                };
                let Some(i) = i.as_u64() else {
                    return None
                };
                Some(i as u8)
            }).collect();
        let mut components = [0u8; 16];
        for i in 0..15 {
            match &tcb_components[i] {
                Some(svn) => {
                    components[i] = *svn;
                },
                None => {
                    return Err(
                        ParseError::InvalidValue { field: "sgxtcbcomponents".to_owned() }
                    )
                }
            };
        }

        println!("- Parsed TCB Level -");
        println!("TCB Status: {}", tcb_status);
        println!("TCB Date: {}", tcb_date);
        println!("PCE SVN: {}", pce_svn);
        println!("Components: {:?}", components);
        println!("---------------------");

        Ok(
            Self {
                tcb_status,
                tcb_date,
                advisory_ids,
                pce_svn,
                components
            }
        )
    }
}
