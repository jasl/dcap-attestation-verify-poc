use intel_tee_quote_verification_sys as qvl_sys;
use intel_tee_quote_verification_rs as qvl;
use std::{fs, time};
use intel_tee_quote_verification_rs::QuoteCollateral;

pub struct QuoteBag {
    // TODO: Version of the bag
    pub quote: Vec<u8>,
    pub quote_collateral: QuoteCollateral,
}

pub fn create_quote_bag(data: &[u8]) -> QuoteBag {
    // TODO: DCAP-only for now, should determine which RA type via `/dev/attestation/attestation_type`
    fs::write("/dev/attestation/user_report_data", data).expect("Write user report data error");
    let quote = fs::read("/dev/attestation/quote").expect("Create quote error");

    println!("Quote hex:");
    println!("0x{}", hex::encode(quote.clone()));

    let quote_collateral = match qvl::tee_qv_get_collateral(&quote) {
        Ok(r) => r,
        Err(e) => panic!("Error: tee_qv_get_collateral failed: {:#04x}", e as u32)
    };

    // TODO: may requires to free collateral

    QuoteBag {
        quote,
        quote_collateral
    }
}

#[allow(dead_code)]
pub fn quote_verification(quote: &[u8], quote_collateral: &QuoteCollateral) {
    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time: u64 = time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();

    // call DCAP quote verify library for quote verification
    // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
    // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    let mut quote_verification_result = qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
    let mut collateral_expiration_status = 1u32;

    match qvl::tee_verify_quote(
        &quote,
        Some(quote_collateral),
        current_time as i64,
        None,
        None,
    ) {
        Ok((colla_exp_stat, qv_result)) => {
            collateral_expiration_status = colla_exp_stat;
            quote_verification_result = qv_result;
            println!("\tInfo: App: tee_verify_quote successfully returned.");
        }
        Err(e) => println!("\tError: App: tee_verify_quote failed: {:#04x}", e as u32),
    }
    // check verification result

    match quote_verification_result {
        qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if collateral_expiration_status == 0 {
                println!("\tInfo: App: Verification completed successfully.");
            } else {
                println!("\tWarning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            println!("\tWarning: App: Verification completed with Non-terminal result: {:x}", quote_verification_result as u32);
        }
        qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_INVALID_SIGNATURE
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_REVOKED
        | qvl_sys::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED
        | _ => {
            println!("\tError: App: Verification completed with Terminal result: {:x}", quote_verification_result as u32);
        }
    }
}
