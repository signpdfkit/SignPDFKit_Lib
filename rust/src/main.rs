use std::collections::HashMap;
use reqwest::blocking::Client;
use serde_json::Value;
use anyhow::{anyhow, Result};

mod signpdfkit; // assume the converted Rust FFI wrapper is in this file
use signpdfkit::{SignPDFKitSign, SignPDFKitVerify, SignArgs, SignatureType, Subfilter, Visibility, DSS};

fn sign_digest_function(digest: &str, options: &HashMap<String, String>) -> Result<String> {
    let url = "https://signpdfkit.com/api/sign";

    let client = Client::builder()
        .danger_accept_invalid_certs(true) // allow self-signed certs like PHP's CURLOPT_SSL_VERIFYPEER=false
        .build()?;

    let payload = serde_json::json!({
        "digest": digest,
        "email": options.get("email").cloned().unwrap_or_default(),
        "passcode": options.get("passcode").cloned().unwrap_or_default(),
    });

    let res = client
        .post(url)
        .json(&payload)
        .send()?;

    if !res.status().is_success() {
        return Err(anyhow!("HTTP Error: {} - {:?}", res.status(), res.text()?));
    }

    let json: Value = res.json()?;
    if let Some(cms) = json.get("cms").and_then(|v| v.as_str()) {
        Ok(cms.to_string())
    } else {
        Err(anyhow!("Invalid response: {:?}", json))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lib_dir = "../lib";

    let mut options = HashMap::new();
    options.insert("email".to_string(), "user@signpdfkit.com".to_string());
    options.insert("passcode".to_string(), "123456".to_string());

    // Initialize signer
    let signer = SignPDFKitSign::new(
        lib_dir,
        |digest, opts| sign_digest_function(digest, opts),
        options,
    )?;

    // Call signing
    let args = SignArgs {
        input_path: "../assets/input/sample.pdf".to_string(),
        output_path: "../assets/output/rust.pdf".to_string(),
        image_path: "../assets/input/visualization.png".to_string(),
        url: "signpdfkit.com".to_string(),
        location: "Jakarta".to_string(),
        reason: "Need to sign".to_string(),
        contact_info: "signpdfkit@gmail.com".to_string(),
        field_id: "SignPDFKit".to_string(),
        character: "#".to_string(),
        signature_type: SignatureType::Signature,
        page: 1,
        field_type: Subfilter::Adbe,
        visibility: Visibility::Invisible,
        x: 0.0,
        y: 0.0,
        width: 50.0,
        height: 50.0,
        dss: DSS::Yes,
    };

    let result = signer.sign_pdf(args)?;
    println!("Result: {}", result);

    // Example: Verify PDF
    let verifier = SignPDFKitVerify::new(lib_dir)?;
    let verify_result = verifier.verify("/Users/pusopskamsinas/Documents/Pribadi/Rust/signpdfkit/assets/output/rust.pdf")?;
    println!("Verify result: {}", verify_result.unwrap());

    Ok(())
}
