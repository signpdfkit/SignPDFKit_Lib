<?php

require_once './signpdfkit.php'; // Assuming the previous classes are in this file

$options = [
    "email" => "user@signpdfkit.com",
    "passcode" => "123456"
];

$lib_dir = '../lib';

function sign_digest_function($digest, $options_params) {
    // 1) Send POST request to PHP API
    $url = "https://signpdfkit.com/api/sign";
    
    $headers = ["Content-Type: application/json"];
    $payload = [
        "digest" => $digest,
        "email" => $options_params["email"],
        "passcode" => $options_params["passcode"]
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    // Raise error if not 2xx
    if ($httpCode < 200 || $httpCode >= 300) {
        throw new Exception("HTTP Error: {$httpCode} - {$response}");
    }

    // 2) Parse JSON response from PHP
    $data = json_decode($response, true);
    
    if (!isset($data['cms'])) {
        throw new Exception("Invalid response: " . $response);
    }

    return $data['cms'];
}

// Example usage of Sign PDF
try {
    $signer = new SignPDFKitSign($lib_dir, 'sign_digest_function', $options);

    $result = $signer->sign_pdf(
        input_path: "../assets/input/php.pdf", // input pdf
        output_path: "../assets/output/php.pdf", // output pdf
        image_path: "../assets/input/visualization.png", // visualization image
        url: "https://example.com", // url for qrcode
        location: "Jakarta", // location
        reason: "Need to Approve", // reason
        contact_info: "karyadi.dk@gmail.com", // contact info
        field_id: "SignPDFKit", // field id
        character: "#",  // Character
        signature_type: SignatureType::SIGNATURE, // signature type
        page: 1, // page
        field_type: Subfilter::ADBE, // is pades
        visibility: Visibility::INVISIBLE, // type
        x: 100.0, // x (float)
        y: 200.0, // y (float)
        width: 100.0, // width (float)
        height: 100.0,  // height (float)
        dss: DSS::YES
    );

    echo $result;
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}

// Example usage of Verify PDF
try {
    $verifier = new SignPDFKitVerify($lib_dir);
    $result = $verifier->verify("../assets/output/php.pdf");
    echo $result . "\n";
} catch (Exception $e) {
    echo "Verification error: " . $e->getMessage() . "\n";
}
