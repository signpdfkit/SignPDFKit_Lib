package com.signpdfkit;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.signpdfkit.SignPDFKit.DSS;
import com.signpdfkit.SignPDFKit.Sign;
import com.signpdfkit.SignPDFKit.SignatureType;
import com.signpdfkit.SignPDFKit.Subfilter;
import com.signpdfkit.SignPDFKit.Visibility;
import com.signpdfkit.SignPDFKit.Verify;
import com.signpdfkit.SignPDFKit.Sign.SignPdfOptions;

public class Main {

    // Example usage
    public static void main(String[] args) {
        // Example usage

        BiFunction<String, Map<String, Object>, String> signFunction = (digest, options) -> {
            try {

                // API endpoint
                String url = "https://signpdfkit.com/api/sign";

                // Build payload
                ObjectMapper mapper = new ObjectMapper();
                String jsonPayload = mapper.writeValueAsString(Map.of(
                        "digest", digest,
                        "email", options.get("email"),
                        "passcode", options.get("passcode")
                ));

                // Build request
                HttpClient client = HttpClient.newHttpClient();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                        .build();

                // Send request
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new RuntimeException("HTTP Error: " + response.statusCode() + " - " + response.body());
                }

                // Parse JSON response
                Map<String, Object> data = mapper.readValue(response.body(), Map.class);

                if (!data.containsKey("cms")) {
                    throw new RuntimeException("Invalid response: " + response.body());
                }

                return data.get("cms").toString();

            } catch (Exception e) {
                throw new RuntimeException("Error signing digest", e);
            }
        };

        Map<String, Object> options = new HashMap<>();
        options.put("email", "user@signpdfkit.com");
        options.put("passcode", "123456");

        String libDir = "../lib";

        SignPdfOptions signerOptions = new SignPdfOptions(
            "../assets/output/sample.pdf",
            "../assets/output/java.pdf"
        ).imagePath("../assets/input/visualization.png")
        .url("example.com")
        .location("Jakarta")
        .reason("Need to Sign")
        .contactInfo("user@signpdfkit.com")
        .fieldId("SignPDFKit")
        .character("#")
        .signatureType(SignatureType.SIGNATURE)
        .page(1)
        .fieldType(Subfilter.PADES)
        .visibility(Visibility.INVISIBLE)
        .x(100.0)
        .y(100.0)
        .width(150.0)
        .height(50.0)
        .dss(DSS.NO);

        try {
            Sign signer = SignPDFKit.createSigner(libDir, signFunction, options);
            String result = signer.signPdf(signerOptions);
            System.out.println("Sign result: " + result);

            Verify verifier = SignPDFKit.createVerifier(libDir);
            String verifyResult = verifier.verify("/Users/pusopskamsinas/Documents/Pribadi/Rust/signpdfkit/assets/output/java.pdf");
            System.out.println("Verify result: " + verifyResult);

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}