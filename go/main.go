package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func main() {
	options := map[string]string{
		"email":    "user@example.com",
		"passcode": "123456",
	}

	libDir := "../lib"

	signFn := func(digest string, options map[string]string) string {
		url := "https://signpdfkit.com/api/sign"

		// Prepare payload
		payload := map[string]string{
			"digest":   digest,
			"email":    options["email"],
			"passcode": options["passcode"],
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return ""
		}

		// Create POST request
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
		if err != nil {
			return ""
		}
		req.Header.Set("Content-Type", "application/json")

		// Disable TLS verification (⚠️ not recommended for production)
		client := &http.Client{
			Transport: &http.Transport{
				// InsecureSkipVerify disables SSL verification like CURLOPT_SSL_VERIFYPEER=false
				// Import "crypto/tls" if you want to allow this
				TLSClientConfig: nil,
			},
		}

		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return ""
		}

		// Raise error if HTTP status not 2xx
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return ""
		}

		// Parse JSON response
		var responseData map[string]interface{}
		if err := json.Unmarshal(body, &responseData); err != nil {
			return ""
		}

		// Validate response contains "cms"
		cms, ok := responseData["cms"].(string)
		if !ok || cms == "" {
			return ""
		}

		return cms
	}

	// Create the wrapper with the callback function
	signer, _ := SignPDFKitSign(signFn, options, libDir)

	signResult := signer.SignPDF(SignArgs{
		InputPath:     "../assets/input/sample.pdf",
		OutputPath:    "../assets/output/go.pdf",
		ImagePath:     strPtr("../assets/input/visualization.png"),
		URL:           strPtr("https://example.com/file/1234567"),
		Location:      strPtr("Jakarta"),
		Reason:        strPtr("Need to sign"),
		ContactInfo:   strPtr("example@gmail.com"),
		FieldID:       strPtr("SignPDFKit"),
		Character:     strPtr("@"),
		SignatureType: intPtr(SIGNATURE),
		Page:          intPtr(1),
		FieldType:     intPtr(ADBE),
		Visibility:    intPtr(Invisible),
		X:             floatPtr(100.0),
		Y:             floatPtr(200.0),
		Width:         floatPtr(100.0),
		Height:        floatPtr(100.0),
		DSS:           intPtr(DSS_YES),
	})

	fmt.Println("Sign result:", signResult)

	verifier, _ := SignPDFKitVerify(libDir)
	verificationResult := verifier.Verify("/Users/pusopskamsinas/Documents/Pribadi/Rust/signpdfkit/assets/output/go.pdf")
	fmt.Println("Verification result:", verificationResult)
}
