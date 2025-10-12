package main

/*
#include <stdlib.h>
#include <dlfcn.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

// Function pointer types
typedef char* (*calculate_digest_func)(
    const char*, const char*, const char*, const char*, const char*,
    const char*, const char*, const char*, int, int, int, int,
    double, double, double, double, int
);

typedef char* (*get_revocation_parameters_func)(const char*);
typedef int (*embed_cms_func)(const char*, const char*, const char*);
typedef char* (*verify_func)(const char*);
typedef void (*free_c_string_func)(char*);

// Global function pointers
calculate_digest_func calculate_digest_ptr = NULL;
get_revocation_parameters_func get_revocation_parameters_ptr = NULL;
embed_cms_func embed_cms_ptr = NULL;
verify_func verify_ptr = NULL;
free_c_string_func free_c_string_ptr = NULL;

#ifdef _WIN32
HMODULE lib_handle = NULL;
#else
void* lib_handle = NULL;
#endif

int load_library(const char* lib_path) {
    #ifdef _WIN32
    lib_handle = LoadLibraryA(lib_path);
    if (!lib_handle) {
        return 0;
    }

    calculate_digest_ptr = (calculate_digest_func)GetProcAddress(lib_handle, "calculate_digest");
    get_revocation_parameters_ptr = (get_revocation_parameters_func)GetProcAddress(lib_handle, "get_revocation_parameters");
    embed_cms_ptr = (embed_cms_func)GetProcAddress(lib_handle, "embed_cms");
    verify_ptr = (verify_func)GetProcAddress(lib_handle, "verify");
    free_c_string_ptr = (free_c_string_func)GetProcAddress(lib_handle, "free_c_string");
    #else
    lib_handle = dlopen(lib_path, RTLD_LAZY);
    if (!lib_handle) {
        return 0;
    }

    calculate_digest_ptr = (calculate_digest_func)dlsym(lib_handle, "calculate_digest");
    get_revocation_parameters_ptr = (get_revocation_parameters_func)dlsym(lib_handle, "get_revocation_parameters");
    embed_cms_ptr = (embed_cms_func)dlsym(lib_handle, "embed_cms");
    verify_ptr = (verify_func)dlsym(lib_handle, "verify");
    free_c_string_ptr = (free_c_string_func)dlsym(lib_handle, "free_c_string");
    #endif

    if (!calculate_digest_ptr || !get_revocation_parameters_ptr ||
        !embed_cms_ptr || !verify_ptr || !free_c_string_ptr) {
        return 0;
    }

    return 1;
}

void unload_library() {
    #ifdef _WIN32
    if (lib_handle) {
        FreeLibrary(lib_handle);
        lib_handle = NULL;
    }
    #else
    if (lib_handle) {
        dlclose(lib_handle);
        lib_handle = NULL;
    }
    #endif

    calculate_digest_ptr = NULL;
    get_revocation_parameters_ptr = NULL;
    embed_cms_ptr = NULL;
    verify_ptr = NULL;
    free_c_string_ptr = NULL;
}

char* calculate_digest(
    const char* input_path, const char* image_path, const char* url,
    const char* location, const char* reason, const char* contact_info,
    const char* field_id, const char* character, int signature_type,
    int page, int field_type, int typ, double x, double y,
    double width, double height, int dss
) {
    if (calculate_digest_ptr) {
        return calculate_digest_ptr(
            input_path, image_path, url, location, reason,
            contact_info, field_id, character, signature_type,
            page, field_type, typ, x, y, width, height, dss
        );
    }
    return NULL;
}

char* get_revocation_parameters(const char* cms) {
    if (get_revocation_parameters_ptr) {
        return get_revocation_parameters_ptr(cms);
    }
    return NULL;
}

int embed_cms(const char* pre_calculate, const char* cms, const char* output_path) {
    if (embed_cms_ptr) {
        return embed_cms_ptr(pre_calculate, cms, output_path);
    }
    return -1;
}

char* verify(const char* input_path) {
    if (verify_ptr) {
        return verify_ptr(input_path);
    }
    return NULL;
}

void free_c_string(char* s) {
    if (free_c_string_ptr) {
        free_c_string_ptr(s);
    }
}
*/
import "C"

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"unsafe"
)

// Constants
const (
	Invisible = iota
	VisibleImage
	VisibleQR
	VisibleImageFromChar
	VisibleQRFromChar
)

const (
	ADBE = iota
	PAdES
)

const (
	SIGNATURE = iota
	SEAL
)

const (
	DSS_NO = iota
	DSS_YES
)

// Types
type (
	DataStruct struct {
		Br1              int    `json:"br1"`
		Br2              int    `json:"br2"`
		Br3              int    `json:"br3"`
		Br4              int    `json:"br4"`
		CatalogObjNumber int    `json:"catalog_obj_number"`
		CatalogObjString string `json:"catalog_obj_string"`
		Digest           string `json:"digest"`
		IsDss            int    `json:"is_dss"`
		IsTrailerStream  int    `json:"is_trailer_stream"`
		NewStartxref     int    `json:"new_startxref"`
		ObjSize          int    `json:"obj_size"`
		Pdf              string `json:"pdf"`
	}

	PreSignData struct {
		ResponseCode   int        `json:"response_code"`
		ResponseStatus string     `json:"response_status"`
		Data           DataStruct `json:"data"`
	}

	RevocationItem struct {
		Type    string `json:"type"`
		URL     string `json:"url"`
		Request string `json:"request,omitempty"`
	}

	RevocationData struct {
		CMS  string   `json:"cms"`
		OCSP []string `json:"ocsp"`
		CRL  []string `json:"crl"`
	}

	LibSignPDF struct {
		signFn     func(string, map[string]string) string
		options    map[string]string
		httpClient *http.Client
		libPath    string
		libLoaded  bool
	}

	VerifyPDF struct {
		libPath   string
		libLoaded bool
	}
)

// GetLibraryPath calculates the library path based on platform
func GetLibraryPath(libDir string) (string, error) {
	system := runtime.GOOS
	machine := runtime.GOARCH

	platformMappings := map[string]map[string][]string{
		"darwin": {
			"amd64": {"macos_x86_64", "libsignpdfkit.dylib"},
			"arm64": {"macos_arm64", "libsignpdfkit.dylib"},
		},
		"linux": {
			"amd64": {"linux_x86_64", "libsignpdfkit.so"},
			"386":   {"linux_i686", "libsignpdfkit.so"},
			"arm64": {"linux_arm64", "libsignpdfkit.so"},
			"arm":   {"linux_armv7", "libsignpdfkit.so"},
		},
		"windows": {
			"amd64": {"windows_x64", "libsignpdfkit.dll"},
			"386":   {"windows_x86", "libsignpdfkit.dll"},
			"arm64": {"windows_arm64", "libsignpdfkit.dll"},
		},
	}

	// Normalize system name
	osKey := strings.ToLower(system)
	if osKey == "darwin" {
		osKey = "darwin"
	} else if strings.Contains(osKey, "linux") {
		osKey = "linux"
	} else if strings.Contains(osKey, "windows") {
		osKey = "windows"
	}

	if platform, ok := platformMappings[osKey]; ok {
		if pathInfo, ok := platform[machine]; ok {
			return fmt.Sprintf("%s/%s/%s", libDir, pathInfo[0], pathInfo[1]), nil
		}
	}

	return "", fmt.Errorf("unsupported platform: %s %s", osKey, machine)
}

// Create a reusable HTTP client
func createHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:      10,
			IdleConnTimeout:   30,
			DisableKeepAlives: false,
		},
	}
}

func SignPDFKitSign(
	signFn func(string, map[string]string) string,
	options map[string]string,
	libDir string,
) (*LibSignPDF, error) {
	libPath, err := GetLibraryPath(libDir)
	if err != nil {
		return nil, err
	}

	lib := &LibSignPDF{
		signFn:     signFn,
		options:    options,
		httpClient: createHTTPClient(),
		libPath:    libPath,
		libLoaded:  false,
	}

	// Load the library
	if success := C.load_library(C.CString(libPath)); success == 0 {
		return nil, fmt.Errorf("failed to load library: %s", libPath)
	}
	lib.libLoaded = true

	return lib, nil
}

func (lib *LibSignPDF) Close() {
	if lib.libLoaded {
		C.unload_library()
		lib.libLoaded = false
	}
}

func (lib *LibSignPDF) getRevocation(cms string, dss int) (string, error) {
	cmsC := C.CString(cms)
	defer C.free(unsafe.Pointer(cmsC))

	result := C.get_revocation_parameters(cmsC)
	if result == nil {
		return "", nil
	}
	defer C.free_c_string(result)

	resultStr := C.GoString(result)
	if resultStr == "" {
		return "", nil
	}

	var items []RevocationItem
	if err := json.Unmarshal([]byte(resultStr), &items); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	jsonData := RevocationData{
		CMS:  cms,
		OCSP: []string{},
		CRL:  []string{},
	}

	if dss == DSS_YES {
		lib.processRevocationData(items, &jsonData)
	}

	finalJSON, err := json.Marshal(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal jsonData: %w", err)
	}
	return string(finalJSON), nil
}

func (lib *LibSignPDF) processRevocationData(items []RevocationItem, jsonData *RevocationData) {
	for _, item := range items {
		switch item.Type {
		case "ocsp":
			lib.processOCSPItem(item, jsonData)
		case "crl":
			lib.processCRLItem(item, jsonData)
		}
	}
}

func (lib *LibSignPDF) processOCSPItem(item RevocationItem, jsonData *RevocationData) {
	ocspReq, err := base64.StdEncoding.DecodeString(item.Request)
	if err != nil {
		fmt.Println("Error decoding OCSP request:", err)
		return
	}

	resp, err := lib.httpClient.Post(item.URL, "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		fmt.Println("OCSP request failed:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Error OCSP: HTTP %d\n", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading OCSP response:", err)
		return
	}

	jsonData.OCSP = append(jsonData.OCSP, base64.StdEncoding.EncodeToString(body))
}

func (lib *LibSignPDF) processCRLItem(item RevocationItem, jsonData *RevocationData) {
	resp, err := lib.httpClient.Get(item.URL)
	if err != nil {
		fmt.Println("CRL request failed:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("Error fetching CRL: HTTP %d\n", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading CRL response:", err)
		return
	}

	crlDer := extractCRLDER(body)
	jsonData.CRL = append(jsonData.CRL, base64.StdEncoding.EncodeToString(crlDer))
}

func extractCRLDER(content []byte) []byte {
	str := string(content)
	if !strings.Contains(str, "BEGIN X509 CRL") {
		return content
	}

	lines := strings.Split(str, "\n")
	var pemBody strings.Builder
	for _, line := range lines {
		if !strings.HasPrefix(line, "---") {
			pemBody.WriteString(strings.TrimSpace(line))
		}
	}

	if der, err := base64.StdEncoding.DecodeString(pemBody.String()); err == nil {
		return der
	}
	return content
}

type SignArgs struct {
	InputPath     string // required
	OutputPath    string // required
	ImagePath     *string
	URL           *string
	Location      *string
	Reason        *string
	ContactInfo   *string
	FieldID       *string
	Character     *string
	SignatureType *int
	Page          *int
	FieldType     *int
	Visibility    *int
	X             *float64
	Y             *float64
	Width         *float64
	Height        *float64
	DSS           *int
}

// ===== Options with defaults =====
type SignOptions struct {
	ImagePath     string
	URL           string
	Location      string
	Reason        string
	ContactInfo   string
	FieldID       string
	Character     string
	SignatureType int
	Page          int
	FieldType     int
	Visibility    int
	X             float64
	Y             float64
	Width         float64
	Height        float64
	DSS           int
}

func strPtr(s string) *string     { return &s }
func intPtr(i int) *int           { return &i }
func floatPtr(f float64) *float64 { return &f }

func DefaultSignOptions() SignOptions {
	return SignOptions{
		ImagePath:     "example.png",
		URL:           "signpdfkit.com",
		Location:      "Jakarta",
		Reason:        "Need to sign",
		ContactInfo:   "signpdfkit@gmail.com",
		FieldID:       "SignPDFKit",
		Character:     "#",
		SignatureType: SIGNATURE,
		Page:          1,
		FieldType:     ADBE,
		Visibility:    Invisible,
		X:             0.0,
		Y:             0.0,
		Width:         50.0,
		Height:        50.0,
		DSS:           DSS_NO,
	}
}

func (lib *LibSignPDF) SignPDF(
	args SignArgs,
) string {
	opts := DefaultSignOptions()

	// Override only if not nil
	if args.ImagePath != nil {
		opts.ImagePath = *args.ImagePath
	}
	if args.URL != nil {
		opts.URL = *args.URL
	}
	if args.Location != nil {
		opts.Location = *args.Location
	}
	if args.Reason != nil {
		opts.Reason = *args.Reason
	}
	if args.ContactInfo != nil {
		opts.ContactInfo = *args.ContactInfo
	}
	if args.FieldID != nil {
		opts.FieldID = *args.FieldID
	}
	if args.Character != nil {
		opts.Character = *args.Character
	}
	if args.SignatureType != nil {
		opts.SignatureType = *args.SignatureType
	}
	if args.Page != nil {
		opts.Page = *args.Page
	}
	if args.FieldType != nil {
		opts.FieldType = *args.FieldType
	}
	if args.Visibility != nil {
		opts.Visibility = *args.Visibility
	}
	if args.X != nil {
		opts.X = *args.X
	}
	if args.Y != nil {
		opts.Y = *args.Y
	}
	if args.Width != nil {
		opts.Width = *args.Width
	}
	if args.Height != nil {
		opts.Height = *args.Height
	}
	if args.DSS != nil {
		opts.DSS = *args.DSS
	}

	jsonData := map[string]interface{}{
		"response_code":   0,
		"response_status": "success",
	}

	// Validate input/output paths
	if args.InputPath == "" || args.OutputPath == "" ||
		!strings.HasSuffix(strings.ToLower(args.InputPath), ".pdf") ||
		!strings.HasSuffix(strings.ToLower(args.OutputPath), ".pdf") {
		jsonData["response_code"] = 3
		jsonData["response_status"] = "Input parameters are incorrect"
		b, _ := json.Marshal(jsonData)
		return string(b)
	}

	// Convert strings to C
	cInput := C.CString(args.InputPath)
	cImage := C.CString(opts.ImagePath)
	cURL := C.CString(opts.URL)
	cLocation := C.CString(opts.Location)
	cReason := C.CString(opts.Reason)
	cContact := C.CString(opts.ContactInfo)
	cField := C.CString(opts.FieldID)
	cChar := C.CString(opts.Character)
	cOutput := C.CString(args.OutputPath)

	defer func() {
		C.free(unsafe.Pointer(cInput))
		C.free(unsafe.Pointer(cImage))
		C.free(unsafe.Pointer(cURL))
		C.free(unsafe.Pointer(cLocation))
		C.free(unsafe.Pointer(cReason))
		C.free(unsafe.Pointer(cContact))
		C.free(unsafe.Pointer(cField))
		C.free(unsafe.Pointer(cChar))
		C.free(unsafe.Pointer(cOutput))
	}()

	preSign := C.calculate_digest(
		cInput, cImage, cURL, cLocation, cReason,
		cContact, cField, cChar,
		C.int(opts.SignatureType), C.int(opts.Page), C.int(opts.FieldType), C.int(opts.Visibility),
		C.double(opts.X), C.double(opts.Y), C.double(opts.Width), C.double(opts.Height), C.int(opts.DSS),
	)

	if preSign == nil {
		jsonData["response_code"] = 4
		jsonData["response_status"] = "Failed when processing PDF"
		b, _ := json.Marshal(jsonData)
		return string(b)
	}
	defer C.free_c_string(preSign)

	preSignStr := C.GoString(preSign)
	if preSignStr == "" {
		jsonData["response_code"] = 4
		jsonData["response_status"] = "Failed when processing PDF"
		b, _ := json.Marshal(jsonData)
		return string(b)
	}

	var data PreSignData
	if err := json.Unmarshal([]byte(preSignStr), &data); err != nil {
		jsonData["response_code"] = 4
		jsonData["response_status"] = "Failed to parse JSON"
		b, _ := json.Marshal(jsonData)
		return string(b)
	}

	// Handle based on response code
	switch data.ResponseCode {
	case 0:
		cms := lib.signFn(data.Data.Digest, lib.options)
		responseStr, _ := lib.getRevocation(cms, opts.DSS)

		cPreSign := C.CString(preSignStr)
		cResponse := C.CString(responseStr)
		defer func() {
			C.free(unsafe.Pointer(cPreSign))
			C.free(unsafe.Pointer(cResponse))
		}()

		result := C.embed_cms(cPreSign, cResponse, cOutput)

		if result == 0 {
			b, _ := json.Marshal(jsonData)
			return string(b)
		} else {
			jsonData["response_code"] = 4
			jsonData["response_status"] = "Failed when processing PDF"
		}

	case 1:
		jsonData["response_code"] = 1
		jsonData["response_status"] = "Failed to open/read document"
	case 4:
		jsonData["response_code"] = 4
		jsonData["response_status"] = "Failed when processing PDF"
	case 5:
		jsonData["response_code"] = 5
		jsonData["response_status"] = "PDF File not found"
	case 6:
		jsonData["response_code"] = 6
		jsonData["response_status"] = "Visualization Image not found"
	default:
		jsonData["response_code"] = 4
		jsonData["response_status"] = "Failed when processing PDF"
	}

	b, _ := json.Marshal(jsonData)
	return string(b)
}

func SignPDFKitVerify(libDir string) (*VerifyPDF, error) {
	libPath, err := GetLibraryPath(libDir)
	if err != nil {
		return nil, err
	}

	verifyLib := &VerifyPDF{
		libPath:   libPath,
		libLoaded: false,
	}

	// Load the library
	if success := C.load_library(C.CString(libPath)); success == 0 {
		return nil, fmt.Errorf("failed to load library: %s", libPath)
	}
	verifyLib.libLoaded = true

	return verifyLib, nil
}

func (lib *VerifyPDF) Close() {
	if lib.libLoaded {
		C.unload_library()
		lib.libLoaded = false
	}
}

func (lib *VerifyPDF) Verify(inputPath string) string {
	if !lib.libLoaded {
		return ""
	}

	cInput := C.CString(inputPath)
	defer C.free(unsafe.Pointer(cInput))

	result := C.verify(cInput)
	defer C.free_c_string(result)

	return C.GoString(result)
}
