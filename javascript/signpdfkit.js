const ffi = require('ffi-napi');

// Enums
const Visibility = {
    INVISIBLE: 0,
    VISIBLE_IMAGE: 1,
    VISIBLE_QR: 2,
    VISIBLE_IMAGE_FROM_CHAR: 3,
    VISIBLE_QR_FROM_CHAR: 4
};

const Subfilter = {
    PADES: 1,
    ADBE: 0
};

const SignatureType = {
    SIGNATURE: 0,
    SEAL: 1
};

const DSS = {
    NO: 0,
    YES: 1
};

// Platform detection utilities
class PlatformUtils {
    static getPlatformInfo() {
        const platform = process.platform;
        const arch = process.arch;
        
        const platformMappings = {
            'darwin': {
                'x64': ['macos_x86_64', 'libsignpdfkit.dylib'],
                'arm64': ['macos_arm64', 'libsignpdfkit.dylib']
            },
            'linux': {
                'x64': ['linux_x86_64', 'libsignpdfkit.so'],
                'ia32': ['linux_x86', 'libsignpdfkit.so'],
                'arm64': ['linux_arm64', 'libsignpdfkit.so'],
                'arm': ['linux_armv7', 'libsignpdfkit.so']
            },
            'win32': {
                'x64': ['win64', 'libsignpdfkit.dll'],
                'ia32': ['win32', 'libsignpdfkit.dll'],
                'arm64': ['win64', 'libsignpdfkit.dll']
            }
        };

        if (platformMappings[platform] && platformMappings[platform][arch]) {
            return platformMappings[platform][arch];
        }

        throw new Error(`Unsupported platform: ${platform} ${arch}`);
    }

    static getLibraryPath(libDir) {
        const [platformDir, libraryName] = PlatformUtils.getPlatformInfo();
        return `${libDir}/${platformDir}/${libraryName}`;
    }
}

// Base class
class SignPDFKitBase {
    constructor() {
        this.ffi = null;
    }

    initializeFFI(libDir, cdef) {
        const libraryPath = PlatformUtils.getLibraryPath(libDir);
        
        // For Node.js using node-ffi-napi or similar
        try {
            // Using node-ffi-napi approach
            this.ffi = ffi.Library(libraryPath, {
                // Function definitions would be mapped here
                calculate_digest: ['string', ['string', 'string', 'string', 'string', 'string', 
                    'string', 'string', 'string', 'int', 'int', 'int', 
                    'int', 'double', 'double', 'double', 'double', 'int']],
                get_revocation_parameters: ['string', ['string']],
                embed_cms: ['int', ['string', 'string', 'string']],
                free_c_string: ['void', ['string']],
                verify: ['string', ['string']]
            });
        } catch (error) {
            console.error('FFI initialization failed:', error);
            throw error;
        }
    }
}

// Sign class
class SignPDFKitSign extends SignPDFKitBase {
    constructor(libDir, signDigestFunc, kwargs) {
        super();
        this.libDir = libDir;
        this.customFunction = signDigestFunc;
        this.options = kwargs;
        this.initializeFFI(this.libDir);
    }

    // Ubah method _process_revocation_data menjadi async
    async _process_revocation_data(data, jsonData) {
        const promises = [];
        
        data.forEach(item => {
            if (item.type === 'ocsp') {
                promises.push(this._process_ocsp_item(item, jsonData));
            } else if (item.type === 'crl') {
                promises.push(this._process_crl_item(item, jsonData));
            }
        });
        
        // Tunggu semua proses HTTP request selesai
        await Promise.all(promises);
    }

    // Ubah method get_revocation untuk menangani async process
    async get_revocation(cms, dss) {
        try {
            const result = this.ffi.get_revocation_parameters(cms);
            
            if (!result || result === '') {
                return null;
            }
            
            const data = JSON.parse(result);
            
            const jsonData = {
                'cms': cms,
                'ocsp': [],
                'crl': []
            };
            
            if (dss === DSS.YES) {
                // Tunggu proses revocation data selesai
                await this._process_revocation_data(data, jsonData);
            }
            
            return JSON.stringify(jsonData);
        } catch (error) {
            console.error('Error in get_revocation:', error);
            return null;
        }
    }

    // Method _process_ocsp_item
    async _process_ocsp_item(item, jsonData) {
        const ocspRequestDer = Buffer.from(item.request, 'base64');
        const url = item.url;
        
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/ocsp-request',
                    'Accept': 'application/ocsp-response',
                },
                body: ocspRequestDer
            });

            if (response.ok) {
                const buffer = await response.arrayBuffer();
                const ocspResponseB64 = Buffer.from(buffer).toString('base64');
                jsonData.ocsp.push(ocspResponseB64);
            } else {
                console.error(`OCSP request failed with status: ${response.status}`);
            }
        } catch (error) {
            console.error("OCSP request failed:", error.message);
        }
    }

    // Method _process_crl_item
    async _process_crl_item(item, jsonData) {
        const url = item.url;
        
        try {
            const response = await fetch(url, {
                method: 'GET'
            });

            if (response.ok) {
                const buffer = await response.arrayBuffer();
                const content = Buffer.from(buffer);
                const crlDer = this._extract_crl_der(content);
                const crlB64 = crlDer.toString('base64');
                jsonData.crl.push(crlB64);
            } else {
                console.error(`CRL request failed with status: ${response.status}`);
            }
        } catch (error) {
            console.error("CRL request failed:", error.message);
        }
    }

    _extract_crl_der(content) {
        const contentStr = content.toString();
        
        if (contentStr.includes('BEGIN X509 CRL')) {
            const lines = contentStr.split('\n');
            let pemBody = '';
            
            for (const line of lines) {
                if (!line.startsWith('---')) {
                    pemBody += line.trim();
                }
            }
            
            return Buffer.from(pemBody, 'base64');
        }
        
        return content;
    }

    async sign_pdf({
        input_path,
        output_path,
        image_path = 'example.png',
        url = 'signpdfkit.com',
        location = 'Jakarta',
        reason = 'Need to sign',
        contact_info = 'signpdfkit@gmail.com',
        field_id = 'SignPDFKit',
        character = '#',
        signature_type = SignatureType.SIGNATURE,
        page = 1,
        field_type = Subfilter.ADBE,
        visibility = Visibility.INVISIBLE,
        x = 0.0,
        y = 0.0,
        width = 50.0,
        height = 50.0,
        dss = DSS.NO
    }) {
        const jsonData = {
            response_code: 0,
            response_status: 'success'
        };

        if (
            !input_path ||
            !output_path ||
            !input_path.toLowerCase().endsWith('.pdf') ||
            !output_path.toLowerCase().endsWith('.pdf')
        ) {
            jsonData.response_code = 3;
            jsonData.response_status = 'Input parameters is incorrect';
            return JSON.stringify(jsonData);
        }

        try {
            const pre_sign = this.ffi.calculate_digest(
                input_path, image_path, url, location, reason,
                contact_info, field_id, character, signature_type,
                page, field_type, visibility, x, y, width, height, dss
            );
            
            if (!pre_sign || pre_sign === '') {
                jsonData.response_code = 4;
                jsonData.response_status = 'Failed when process PDF';
                return JSON.stringify(jsonData);
            }
            
            const data = JSON.parse(pre_sign);
            
            if (data.response_code === 0) {
                const cms = await this.customFunction(data.data.digest, this.options);
                const response_str = await this.get_revocation(cms, dss);
                // console.log(response_str);
                
                const result = this.ffi.embed_cms(pre_sign, response_str, output_path);

                if (result === 0) {
                    return JSON.stringify(jsonData);
                } else {
                    jsonData.response_code = result;
                    jsonData.response_status = 'Failed when process PDF';
                }
                
            } else {
                jsonData.response_code = data.response_code;
                switch (data.response_code) {
                    case 1:
                        jsonData.response_status = 'Failed to open/read document';
                        break;
                    case 4:
                        jsonData.response_status = 'Failed when process PDF';
                        break;
                    case 5:
                        jsonData.response_status = 'PDF File not found';
                        break;
                    case 6:
                        jsonData.response_status = 'Visualization Image not found';
                        break;
                    default:
                        jsonData.response_status = 'Failed when process PDF';
                }
            }
            
            return JSON.stringify(jsonData);
            
        } catch (error) {
            jsonData.response_code = 4;
            jsonData.response_status = `Failed when process PDF: ${error.message}`;
            return JSON.stringify(jsonData);
        }
    }
}

// Verify class
class SignPDFKitVerify extends SignPDFKitBase {
    constructor(libDir) {
        super();
        this.libDir = libDir;
        this.initializeFFI(this.libDir);
    }
    
    verify(input_path) {
        try {
            const result = this.ffi.verify(input_path);
            
            if (!result || result === '') {
                return null;
            }
            
            return result;
        } catch (error) {
            console.error('Verification failed:', error);
            return null;
        }
    }
}

// Export classes
module.exports = {
    Visibility,
    Subfilter,
    SignatureType,
    DSS,
    SignPDFKitSign,
    SignPDFKitVerify
};