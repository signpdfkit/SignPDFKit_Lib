use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use libloading::{Library, Symbol};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_double, c_int};
use std::path::{Path, PathBuf};

/// Enums mirroring PHP constants
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Visibility {
    Invisible = 0,
    VisibleImage = 1,
    VisibleQr = 2,
    VisibleImageFromChar = 3,
    VisibleQrFromChar = 4,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum Subfilter {
    Adbe = 0,
    Pades = 1,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum SignatureType {
    Signature = 0,
    Seal = 1,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum DSS {
    No = 0,
    Yes = 1,
}

/// Represents the native API symbols we expect
struct NativeApi {
    _lib: Library, // keep library alive
    calculate_digest:
        Symbol<'static, unsafe extern "C" fn(*const c_char, *const c_char, *const c_char, *const c_char,
                                            *const c_char, *const c_char, *const c_char, *const c_char,
                                            c_int, c_int, c_int, c_int,
                                            c_double, c_double, c_double, c_double,
                                            c_int) -> *mut c_char>,
    get_revocation_parameters: Symbol<'static, unsafe extern "C" fn(*const c_char) -> *mut c_char>,
    embed_cms: Symbol<'static, unsafe extern "C" fn(*const c_char, *const c_char, *const c_char) -> c_int>,
    free_c_string: Symbol<'static, unsafe extern "C" fn(*mut c_char)>,
    verify: Option<Symbol<'static, unsafe extern "C" fn(*const c_char) -> *mut c_char>>,
}

impl NativeApi {
    /// Load library and bind symbols
    unsafe fn load(lib_path: &Path) -> Result<Self> {
        let lib = unsafe { Library::new(lib_path)
            .with_context(|| format!("Failed to open library {}", lib_path.display()))? };

        // Define the function types for clarity
        type CalculateDigestFn = unsafe extern "C" fn(
            *const c_char, *const c_char, *const c_char, *const c_char,
            *const c_char, *const c_char, *const c_char, *const c_char,
            c_int, c_int, c_int, c_int,
            c_double, c_double, c_double, c_double,
            c_int,
        ) -> *mut c_char;
        
        type GetRevocationParamsFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
        type EmbedCmsFn = unsafe extern "C" fn(*const c_char, *const c_char, *const c_char) -> c_int;
        type FreeCStringFn = unsafe extern "C" fn(*mut c_char);
        type VerifyFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

        // Get symbols with explicit type annotations
        let calculate_digest: Symbol<CalculateDigestFn> = unsafe { lib.get(b"calculate_digest\0")? };
        let get_revocation_parameters: Symbol<GetRevocationParamsFn> = unsafe { lib.get(b"get_revocation_parameters\0")? };
        let embed_cms: Symbol<EmbedCmsFn> = unsafe { lib.get(b"embed_cms\0")? };
        let free_c_string: Symbol<FreeCStringFn> = unsafe { lib.get(b"free_c_string\0")? };

        // Transmute to 'static lifetime
        let calculate_digest = unsafe { std::mem::transmute::<_, Symbol<'static, CalculateDigestFn>>(calculate_digest) };
        let get_revocation_parameters = unsafe { std::mem::transmute::<_, Symbol<'static, GetRevocationParamsFn>>(get_revocation_parameters) };
        let embed_cms = unsafe { std::mem::transmute::<_, Symbol<'static, EmbedCmsFn>>(embed_cms) };
        let free_c_string = unsafe { std::mem::transmute::<_, Symbol<'static, FreeCStringFn>>(free_c_string) };

        // verify() may or may not exist
        let verify = match unsafe { lib.get::<VerifyFn>(b"verify\0") } {
            Ok(s) => Some( unsafe { std::mem::transmute::<_, Symbol<'static, VerifyFn>>(s) }),
            Err(_) => None,
        };

        Ok(Self {
            _lib: lib,
            calculate_digest,
            get_revocation_parameters,
            embed_cms,
            free_c_string,
            verify,
        })
    }
}

/// Helper: convert *mut c_char returned from native to Rust String, then free via free_c_string
unsafe fn cstr_to_string_and_free(ptr: *mut c_char, free_fn: &Symbol<'static, unsafe extern "C" fn(*mut c_char)>) -> Result<String> {
    if ptr.is_null() {
        return Err(anyhow!("Received null pointer from native function"));
    }
    let s = unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned();
    // free allocated C string returned by native code
    unsafe { free_fn(ptr) };
    Ok(s)
}

/// Base object that loads the library and provides an HTTP client
pub struct SignPDFKitBase {
    api: NativeApi,
    http_client: Client,
}

impl SignPDFKitBase {
    /// Determine library path (similar to PHP calculateLibraryPath)
    fn calculate_library_path(lib_dir: &str) -> Result<PathBuf> {
        let os_name = env::consts::OS; // "macos", "linux", "windows"
        let arch = env::consts::ARCH; // "x86", "x86_64", "aarch64", "arm"

        let lib_dir = Path::new(lib_dir).to_path_buf();

        let mut mapping: HashMap<&str, HashMap<&str, (&str, &str)>> = HashMap::new();

        mapping.insert("macos", {
            let mut m = HashMap::new();
            m.insert("x86_64", ("macos_x86_64", "libsignpdfkit.dylib"));
            m.insert("aarch64", ("macos_arm64", "libsignpdfkit.dylib"));
            m.insert("arm64", ("macos_arm64", "libsignpdfkit.dylib"));
            m
        });

        mapping.insert("linux", {
            let mut m = HashMap::new();
            m.insert("x86_64", ("linux_x86_64", "libsignpdfkit.so"));
            m.insert("i686", ("linux_x86", "libsignpdfkit.so"));
            m.insert("aarch64", ("linux_arm64", "libsignpdfkit.so"));
            m.insert("arm64", ("linux_arm64", "libsignpdfkit.so"));
            m.insert("armv7l", ("linux_armv7", "libsignpdfkit.so"));
            m
        });

        mapping.insert("windows", {
            let mut m = HashMap::new();
            m.insert("amd64", ("win64", "libsignpdfkit.dll"));
            m.insert("x86_64", ("win64", "libsignpdfkit.dll"));
            m.insert("x86", ("win32", "libsignpdfkit.dll"));
            m.insert("i686", ("win32", "libsignpdfkit.dll"));
            m.insert("arm64", ("win64", "libsignpdfkit.dll"));
            m
        });

        let os_key = match os_name {
            "macos" => "macos",
            "linux" => "linux",
            "windows" => "windows",
            other => other,
        };

        // normalize arch keys
        let arch_key = match arch {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            "arm" => "arm64",
            "armv7" => "armv7l",
            "i386" => "i686",
            other => other,
        };

        if let Some(osmap) = mapping.get(os_key) {
            if let Some((dir, file)) = osmap.get(arch_key) {
                let full = lib_dir.join(dir).join(file);
                return Ok(full);
            }
        }

        Err(anyhow!("Unsupported platform: {} {}", os_key, arch_key))
    }

    /// Create new base by loading native library and building HTTP client
    pub fn new(lib_dir: &str) -> Result<Self> {
        let lib_path = Self::calculate_library_path(lib_dir)?;
        // load native api
        let api = unsafe { NativeApi::load(&lib_path)? };

        // build HTTP client (skip TLS verify to mimic PHP example)
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?;

        Ok(SignPDFKitBase { api, http_client: client })
    }
}

/// Struct for revocation items returned by native lib
#[derive(Debug, Deserialize)]
struct RevocationItem {
    #[serde(rename = "type")]
    rtype: String,
    url: String,
    #[serde(default)]
    request: Option<String>, // base64 OCSP request maybe
}

/// Sign struct accepts a boxed callback for producing CMS from digest
pub struct SignPDFKitSign<'a> {
    base: SignPDFKitBase,
    custom_fn: Box<dyn Fn(&str, &HashMap<String, String>) -> Result<String> + Send + Sync + 'a>,
    options: HashMap<String, String>,
}

pub struct SignArgs {
    pub input_path: String,
    pub output_path: String,
    pub image_path: String,
    pub url: String,
    pub location: String,
    pub reason: String,
    pub contact_info: String,
    pub field_id: String,
    pub character: String,
    pub signature_type: SignatureType,
    pub page: i32,
    pub field_type: Subfilter,
    pub visibility: Visibility,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub dss: DSS,
}

impl<'a> SignPDFKitSign<'a> {
    pub fn new<F>(lib_dir: &str, custom_fn: F, options: HashMap<String, String>) -> Result<Self>
    where
        F: Fn(&str, &HashMap<String, String>) -> Result<String> + Send + Sync + 'a,
    {
        let base = SignPDFKitBase::new(lib_dir)?;
        Ok(Self {
            base,
            custom_fn: Box::new(custom_fn),
            options,
        })
    }

    /// Call native get_revocation_parameters and (optionally) fetch ocsp/crl data
    pub fn get_revocation(&self, cms: &str, dss: DSS) -> Result<Option<String>> {
        let c_cms = CString::new(cms)?;
        let raw = unsafe { (self.base.api.get_revocation_parameters)(c_cms.as_ptr()) };
        if raw.is_null() {
            return Ok(None);
        }
        // convert and free pointer
        let raw_str = unsafe { CStr::from_ptr(raw).to_string_lossy().into_owned() };
        unsafe { (self.base.api.free_c_string)(raw) };

        if raw_str.trim().is_empty() {
            return Ok(None);
        }

        let items: Vec<RevocationItem> = serde_json::from_str(&raw_str)
            .map_err(|e| anyhow!("Failed to parse revocation JSON: {}", e))?;

        let mut json_data = serde_json::json!({
            "cms": cms,
            "ocsp": [],
            "crl": []
        });

        if let DSS::Yes = dss {
            for item in items {
                match item.rtype.as_str() {
                    "ocsp" => {
                        if let Some(req_b64) = item.request {
                            if let Ok(req_bytes) = general_purpose::STANDARD.decode(req_b64) {
                                let resp = self.base.http_client.post(&item.url)
                                    .header("Content-Type", "application/ocsp-request")
                                    .header("Accept", "application/ocsp-response")
                                    .body(req_bytes)
                                    .send();

                                if let Ok(r) = resp {
                                    if r.status().is_success() {
                                        if let Ok(bytes) = r.bytes() {
                                            let b64 = general_purpose::STANDARD.encode(bytes);
                                            json_data["ocsp"].as_array_mut().unwrap().push(Value::String(b64));
                                        }
                                    } else {
                                        // log, ignore
                                    }
                                }
                            }
                        }
                    }
                    "crl" => {
                        let resp = self.base.http_client.get(&item.url).send();
                        if let Ok(r) = resp {
                            if r.status().is_success() {
                                if let Ok(bytes) = r.bytes() {
                                    let txt = String::from_utf8_lossy(&bytes).to_string();
                                    let der = Self::extract_crl_der(&txt, &bytes);
                                    let b64 = general_purpose::STANDARD.encode(der);
                                    json_data["crl"].as_array_mut().unwrap().push(Value::String(b64));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(Some(serde_json::to_string(&json_data)?))
    }

    fn extract_crl_der(pem_or_bytes: &str, raw_bytes: &[u8]) -> Vec<u8> {
        if pem_or_bytes.contains("BEGIN X509 CRL") {
            let mut body = String::new();
            let mut inside = false;
            for line in pem_or_bytes.lines() {
                if line.contains("BEGIN X509 CRL") {
                    inside = true;
                    continue;
                } else if line.contains("END X509 CRL") {
                    break;
                }

                if inside {
                    if !line.starts_with("---") {
                        body.push_str(line.trim());
                    }
                }
            }
            if !body.is_empty() {
                if let Ok(decoded) = general_purpose::STANDARD.decode(body) {
                    return decoded;
                }
            }
            raw_bytes.to_vec()
        } else {
            raw_bytes.to_vec()
        }
    }

    /// Main sign_pdf equivalent. Returns JSON string like PHP.
    pub fn sign_pdf(&self, args: SignArgs) -> Result<String> {
        let mut json_data = serde_json::json!({
            "response_code": 0,
            "response_status": "success"
        });

        // basic validation
        if args.input_path.is_empty() || args.output_path.is_empty()
            || !args.input_path.to_lowercase().ends_with(".pdf")
            || !args.output_path.to_lowercase().ends_with(".pdf")
        {
            json_data["response_code"] = Value::from(3);
            json_data["response_status"] = Value::from("Input parameters is incorrect");
            return Ok(serde_json::to_string(&json_data)?);
        }

        // prepare C strings
        let c_input = CString::new(args.input_path)?;
        let c_image = CString::new(args.image_path)?;
        let c_url = CString::new(args.url)?;
        let c_location = CString::new(args.location)?;
        let c_reason = CString::new(args.reason)?;
        let c_contact = CString::new(args.contact_info)?;
        let c_field_id = CString::new(args.field_id)?;
        let c_character = CString::new(args.character)?;

        // call native calculate_digest
        let raw_ptr = unsafe {
            (self.base.api.calculate_digest)(
                c_input.as_ptr(),
                c_image.as_ptr(),
                c_url.as_ptr(),
                c_location.as_ptr(),
                c_reason.as_ptr(),
                c_contact.as_ptr(),
                c_field_id.as_ptr(),
                c_character.as_ptr(),
                args.signature_type as c_int,
                args.page,
                args.field_type as c_int,
                args.visibility as c_int,
                args.x as c_double,
                args.y as c_double,
                args.width as c_double,
                args.height as c_double,
                args.dss as c_int,
            )
        };

        if raw_ptr.is_null() {
            json_data["response_code"] = Value::from(4);
            json_data["response_status"] = Value::from("Failed when process PDF");
            return Ok(serde_json::to_string(&json_data)?);
        }

        // copy string and free native
        let pre_sign_str = unsafe { cstr_to_string_and_free(raw_ptr, &self.base.api.free_c_string)? };

        if pre_sign_str.trim().is_empty() {
            json_data["response_code"] = Value::from(4);
            json_data["response_status"] = Value::from("Failed when process PDF");
            return Ok(serde_json::to_string(&json_data)?);
        }

        let v: Value = serde_json::from_str(&pre_sign_str).context("parse pre-sign JSON")?;
        let response_code = v["response_code"].as_i64().unwrap_or(-1);
        if response_code == 0 {
            let digest = v["data"]["digest"].as_str().ok_or_else(|| anyhow!("no digest in pre-sign"))?;
            let cms = (self.custom_fn)(digest, &self.options)?;
            let response_str = match self.get_revocation(&cms, args.dss)? {
                Some(s) => s,
                None => String::new(),
            };

            let c_pre_sign = CString::new(pre_sign_str)?;
            let c_response = CString::new(response_str)?;
            let c_output = CString::new(args.output_path)?;

            let res = unsafe { (self.base.api.embed_cms)(c_pre_sign.as_ptr(), c_response.as_ptr(), c_output.as_ptr()) };

            if res == 0 {
                return Ok(serde_json::to_string(&json_data)?);
            } else {
                json_data["response_code"] = Value::from(4);
                json_data["response_status"] = Value::from("Failed when process PDF");
                return Ok(serde_json::to_string(&json_data)?);
            }
        } else {
            // map other codes like PHP
            let status_text = match response_code {
                1 => "Failed to open/read document",
                4 => "Failed when process PDF",
                5 => "PDF File not found",
                6 => "Visualization Image not found",
                _ => "Failed when process PDF",
            };
            json_data["response_code"] = Value::from(response_code);
            json_data["response_status"] = Value::from(status_text);
            return Ok(serde_json::to_string(&json_data)?);
        }
    }
}

/// Verify wrapper
pub struct SignPDFKitVerify {
    base: SignPDFKitBase,
}

impl SignPDFKitVerify {
    pub fn new(lib_dir: &str) -> Result<Self> {
        let base = SignPDFKitBase::new(lib_dir)?;
        Ok(Self { base })
    }

    pub fn verify(&self, input_path: &str) -> Result<Option<String>> {
        if let Some(verify_fn) = &self.base.api.verify {
            let c_input = CString::new(input_path)?;
            let raw = unsafe { verify_fn(c_input.as_ptr()) };
            if raw.is_null() {
                return Ok(None);
            }
            let s = unsafe { cstr_to_string_and_free(raw, &self.base.api.free_c_string)? };
            Ok(Some(s))
        } else {
            Err(anyhow!("verify symbol not available in native library"))
        }
    }
}

// -----------------------------
// Example usage (main)
// -----------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn instantiate_and_call_dummy() {
        // NOTE: This test demonstrates construction only and will fail if the real native lib isn't present.
        let lib_dir = "../lib"; // change to your lib folder root
        let opts: HashMap<String, String> = HashMap::from([
            ("email".to_string(), "user@example.com".to_string()),
            ("passcode".to_string(), "123456".to_string()),
        ]);

        // Example callback that POSTs to remote sign API (synchronous)
        let callback = |digest: &str, options: &HashMap<String, String>| -> Result<String> {
            // Here you should implement an HTTP call to your signing service that returns JSON { "cms": "..." }
            // For demo we return a dummy value:
            Ok(format!("dummy-cms-for-{}", &digest[..std::cmp::min(8, digest.len())]))
        };

        // If you actually run this you need the native library files under ../lib/<platform>/
        if Path::new(lib_dir).exists() {
            let signer = SignPDFKitSign::new(lib_dir, callback, opts).expect("create signer");
            // signer.sign_pdf(...) // call when native library present
        } else {
            // Just ensure code compiles in CI environments without native lib
            eprintln!("skipping runtime call, lib_dir doesn't exist: {:?}", lib_dir);
        }
    }
}
