// example.js
const {
  Visibility,
  Subfilter,
  SignatureType,
  DSS,
  SignPDFKitSign,
  SignPDFKitVerify,
} = require("./signpdfkit");

const options = {
  email: "user@signpdfkit.com",
  passcode: "123456",
};

const libDir = '../lib';

// Equivalent of PHP's sign_digest_function
async function signDigestFunction(digest, optionsParams) {
  const url = "https://signpdfkit.com/api/sign";
  const payload = {
    digest,
    email: optionsParams.email,
    passcode: optionsParams.passcode,
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`HTTP Error: ${res.status} - ${text}`);
  }

  const data = await res.json();
  if (!data.cms) {
    throw new Error("Invalid response: " + JSON.stringify(data));
  }

  return data.cms;
}

(async () => {
  try {
    const signer = new SignPDFKitSign(libDir, signDigestFunction, options);

    const result = await signer.sign_pdf({
      input_path: "../assets/input/sample.pdf",
      output_path: "../assets/output/javascript.pdf",
      image_path: "../assets/input/visualization.png",
      url: "https://example.com",
      location: "Jakarta",
      reason: "Need to Approve",
      contact_info: "karyadi.dk@gmail.com",
      field_id: "SignPDFKit",
      character: "#",
      signature_type: SignatureType.SIGNATURE,
      page: 1,
      field_type: Subfilter.ADBE,
      visibility: Visibility.VISIBLE_IMAGE,
      x: 100.0,
      y: 200.0,
      width: 100.0,
      height: 100.0,
      dss: DSS.YES
  });

    console.log(result);

  } catch (err) {
    console.error("Error:", err.message);
  }

  // Verify part stays sync
  try {
    const verifier = new SignPDFKitVerify(libDir);
    const verifyResult = verifier.verify(
      "../assets/output/javascript.pdf"
    );
    console.log("Verify Result:", verifyResult);
  } catch (err) {
    console.error("Verification error:", err.message);
  }
})();
