use std::ffi::CStr;
use std::fs;

mod quote_generator;

use scale_codec::{Encode, Decode};
use scale_info::TypeInfo;

#[derive(Encode, Decode, TypeInfo, Clone, Debug)]
pub struct QuoteCollateral {
    pub major_version: u16,
    pub minor_version: u16,
    pub tee_type: u32,
    pub pck_crl_issuer_chain: String,
    pub root_ca_crl: String,
    pub pck_crl: String,
    pub tcb_info_issuer_chain: String,
    pub tcb_info: String,
    pub tcb_info_signature: Vec<u8>,
    pub qe_identity_issuer_chain: String,
    pub qe_identity: String,
    pub qe_identity_signature: Vec<u8>,
}

fn main() {
    let quote_bag = quote_generator::create_quote_bag("Hello, world!".as_bytes());

    // DCAP SGX still trying to get supplemental from enclave!
    // quote_generator::quote_verification(&quote_bag.quote, &quote_bag.quote_collateral);

    let quote_collateral = quote_bag.quote_collateral;

    println!("Collateral Version:");
    let major_version = quote_collateral.major_version;
    let minor_version = quote_collateral.minor_version;
    println!("{}.{}", major_version, minor_version);

    println!("Collateral TEE type:");
    let tee_type = quote_collateral.tee_type;
    println!("{}", tee_type);

    println!("Collateral PCK CRL issuer chain size:");
    println!("{}", quote_collateral.pck_crl_issuer_chain.len());
    println!("Collateral PCK CRL issuer chain data:");
    let pck_crl_issuer_chain = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.pck_crl_issuer_chain.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("Collateral PCK CRL issuer chain should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("{}", pck_crl_issuer_chain);

    println!("Collateral ROOT CA CRL size:");
    println!("{}", quote_collateral.root_ca_crl.len());
    println!("Collateral ROOT CA CRL data:");
    let root_ca_crl = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.root_ca_crl.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("ROOT CA CRL should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("0x{}", hex::encode(root_ca_crl.clone()));

    println!("Collateral PCK CRL size:");
    println!("{}", quote_collateral.pck_crl.len());
    println!("Collateral PCK CRL data:");
    let pck_crl = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.pck_crl.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("PCK CRL should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("0x{}", hex::encode(pck_crl.clone()));

    println!("Collateral TCB info issuer chain size:");
    println!("{}", quote_collateral.tcb_info_issuer_chain.len());
    println!("Collateral TCB info issuer chain data:");
    let tcb_info_issuer_chain = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.tcb_info_issuer_chain.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("TCB Info issuer should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("{}", tcb_info_issuer_chain);

    println!("Collateral TCB info size:");
    println!("{}", quote_collateral.tcb_info.len());
    println!("Collateral TCB info data:");
    let raw_tcb_info = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.tcb_info.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("TCB Info should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("{}", raw_tcb_info);
    let tcb_info_json: serde_json::Value = serde_json::from_str(raw_tcb_info.as_str()).expect("TCB Info should a JSON");
    let tcb_info = tcb_info_json["tcbInfo"].to_string();
    let tcb_info_signature = tcb_info_json["signature"].as_str().expect("TCB Info signature should a hex string");
    let tcb_info_signature = hex::decode(tcb_info_signature).expect("TCB Info signature should a hex string");
    println!("{tcb_info}");
    println!("{}", hex::encode(&tcb_info_signature));

    println!("Collateral QE identity issuer chain size:");
    println!("{}", quote_collateral.qe_identity_issuer_chain.len());
    println!("Collateral QE identity issuer chain data:");
    let qe_identity_issuer_chain = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.qe_identity_issuer_chain.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("QE Identity issuer chain should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("{}", qe_identity_issuer_chain);

    println!("Collateral QE Identity size:");
    println!("{}", quote_collateral.qe_identity.len());
    println!("Collateral QE identity data:");
    let raw_qe_identity = {
        let c_str: &CStr = unsafe { CStr::from_ptr(quote_collateral.qe_identity.as_ptr()) };
        let str_slice: &str = c_str.to_str().expect("QE Identity should an UTF-8 string");
        str_slice.to_owned()
    };
    println!("{}", raw_qe_identity);
    let qe_identity_json: serde_json::Value = serde_json::from_str(raw_qe_identity.as_str()).expect("QE Identity should a JSON");
    let qe_identity = qe_identity_json["enclaveIdentity"].to_string();
    let qe_identity_signature = qe_identity_json["signature"].as_str().expect("QE Identity signature should a hex string");
    let qe_identity_signature = hex::decode(qe_identity_signature).expect("QE Identity signature should a hex string");
    println!("{qe_identity}");
    println!("{}", hex::encode(&qe_identity_signature));

    fs::write(
        "/data/storage_files/quote",
        &quote_bag.quote
    ).unwrap();

    // fs::create_dir_all("/data/storage_files/quote_collateral").unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/version",
    //     format!("{major_version}.{minor_version}")
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/tee_type",
    //     format!("{tee_type}")
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/pck_crl_issuer_chain",
    //     pck_crl_issuer_chain.clone()
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/root_ca_crl",
    //     root_ca_crl.clone()
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/pck_crl",
    //     pck_crl.clone()
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/tcb_info_issuer_chain",
    //     tcb_info_issuer_chain.clone()
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/tcb_info",
    //     tcb_info.clone()
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/qe_identity_issuer_chain",
    //     qe_identity_issuer_chain.clone()
    // ).unwrap();
    // fs::write(
    //     "/data/storage_files/quote_collateral/qe_identity",
    //     qe_identity.clone()
    // ).unwrap();

    let quote_collateral = QuoteCollateral {
        major_version,
        minor_version,
        tee_type,
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
    };

    let encoded = quote_collateral.encode();
    // println!("0x{}", hex::encode(&encoded));
    fs::write(
        "/data/storage_files/quote_collateral",
        &encoded
    ).unwrap();

    println!("Done");
}
