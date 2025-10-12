import ctypes
import json
import base64
import os
import platform
import requests
from enum import Enum
from typing import Optional, Dict, Any, Callable, Union


# Constants as classes
class Visibility:
    INVISIBLE = 0
    VISIBLE_IMAGE = 1
    VISIBLE_QR = 2
    VISIBLE_IMAGE_FROM_CHAR = 3
    VISIBLE_QR_FROM_CHAR = 4

class Subfilter:
    PADES = 1
    ADBE = 0

class SignatureType:
    SIGNATURE = 0
    SEAL = 1

class DSS:
    NO = 0
    YES = 1


class SignPDFKitBase:
    """Base class dengan configurable lib_dir"""
    
    def __init__(self, lib_dir: str):
        self.lib_dir = lib_dir
        self._library_path_cache = None
        self.lib = None
    
    def get_library_path(self) -> str:
        """Mendapatkan path library dengan caching"""
        if self._library_path_cache is None:
            self._library_path_cache = self._calculate_library_path()
        return self._library_path_cache
    
    def _calculate_library_path(self) -> str:
        """Menghitung path library berdasarkan sistem operasi dan arsitektur"""
        system = platform.system().lower()
        machine = platform.machine()

        # Normalize system name like PHP does
        os_key = ""
        if "darwin" in system:
            os_key = "darwin"
        elif "linux" in system:
            os_key = "linux"
        elif "win" in system:
            os_key = "winnt"
        else:
            os_key = system

        # Mapping untuk sistem dan arsitektur
        platform_mappings = {
            "darwin": {
                "x86_64": ("macos_x86_64", "libsignpdfkit.dylib"),
                "arm64": ("macos_arm64", "libsignpdfkit.dylib")
            },
            "linux": {
                "x86_64": ("linux_x86_64", "libsignpdfkit.so"),
                "i686": ("linux_x86", "libsignpdfkit.so"),
                "aarch64": ("linux_arm64", "libsignpdfkit.so"),
                "arm64": ("linux_arm64", "libsignpdfkit.so"),
                "armv7l": ("linux_armv7", "libsignpdfkit.so")
            },
            "winnt": {
                "amd64": ("win64", "libsignpdfkit.dll"),
                "x86_64": ("win64", "libsignpdfkit.dll"),
                "x86": ("win32", "libsignpdfkit.dll"),
                "i686": ("win32", "libsignpdfkit.dll"),
                "arm64": ("win64", "libsignpdfkit.dll")
            }
        }

        if os_key in platform_mappings and machine in platform_mappings[os_key]:
            path_info = platform_mappings[os_key][machine]
            return os.path.join(self.lib_dir, path_info[0], path_info[1])
        
        raise ValueError(f"Unsupported platform: {os_key} {machine}")
    
    def _load_library(self):
        """Load shared library"""
        if self.lib is None:
            lib_path = self.get_library_path()
            self.lib = ctypes.CDLL(lib_path)


class SignPDFKitSign(SignPDFKitBase):
    """Kelas untuk menangani penandatanganan PDF"""
    
    def __init__(self, lib_dir: str, sign_digest_func: Callable, kwargs: Dict[str, Any]):
        super().__init__(lib_dir)
        # Store custom function and options
        self.custom_function = sign_digest_func
        self.options = kwargs

        # Load library and setup function prototypes
        self._load_library()
        self._setup_function_prototypes()

    def _setup_function_prototypes(self):
        """Menyiapkan prototype fungsi dari library native"""
        # calculate_digest function
        self.lib.calculate_digest.argtypes = [
            ctypes.c_char_p,  # input_path
            ctypes.c_char_p,  # image_path
            ctypes.c_char_p,  # url
            ctypes.c_char_p,  # location
            ctypes.c_char_p,  # reason
            ctypes.c_char_p,  # contact_info
            ctypes.c_char_p,  # field_id
            ctypes.c_char_p,  # character
            ctypes.c_int,     # signature_type
            ctypes.c_int,     # page
            ctypes.c_int,     # field_type
            ctypes.c_int,     # typ
            ctypes.c_double,  # x
            ctypes.c_double,  # y
            ctypes.c_double,  # width
            ctypes.c_double,  # height
            ctypes.c_int      # dss
        ]
        self.lib.calculate_digest.restype = ctypes.c_char_p

        # get_revocation_parameters function
        self.lib.get_revocation_parameters.argtypes = [ctypes.c_char_p]
        self.lib.get_revocation_parameters.restype = ctypes.c_char_p

        # embed_cms function
        self.lib.embed_cms.argtypes = [
            ctypes.c_char_p,  # pre_sign
            ctypes.c_char_p,  # response_str
            ctypes.c_char_p   # output_path
        ]
        self.lib.embed_cms.restype = ctypes.c_int
        
        self.lib.free_c_string.restype = None
        self.lib.free_c_string.argtypes = [ctypes.c_char_p]

    def get_revocation(self, cms: str, dss: int) -> Optional[str]:
        """Mendapatkan informasi revocation (OCSP/CRL) untuk CMS"""
        result_ptr = self.lib.get_revocation_parameters(cms.encode("utf-8"))

        if not result_ptr:  # NULL pointer check
            return None

        # Convert C string to Python string
        message = ctypes.string_at(result_ptr).decode("utf-8")
        data = json.loads(message)

        # Prepare response container
        json_data = {
            "cms": cms,   # already base64
            "ocsp": [],   # collect all ocsp responses
            "crl": []     # collect all crl responses
        }

        if dss == DSS.YES:
            self._process_revocation_data(data, json_data)

        return json.dumps(json_data)

    def _process_revocation_data(self, data, json_data):
        """Memproses data revocation (OCSP/CRL)"""
        for item in data:
            if item["type"] == "ocsp":
                self._process_ocsp_item(item, json_data)
            elif item["type"] == "crl":
                self._process_crl_item(item, json_data)

    def _process_ocsp_item(self, item, json_data):
        """Memproses item OCSP"""
        ocsp_request_der = base64.b64decode(item["request"])
        headers = {
            "Content-Type": "application/ocsp-request",
            "Accept": "application/ocsp-response"
        }
        
        try:
            # Disable SSL verification like PHP does
            response = requests.post(item["url"], data=ocsp_request_der, 
                                   headers=headers, timeout=10, verify=False)
            
            if response.status_code == 200:
                ocsp_response_b64 = base64.b64encode(response.content).decode("ascii")
                json_data["ocsp"].append(ocsp_response_b64)
            else:
                print(f"Error OCSP: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"OCSP request failed: {e}")

    def _process_crl_item(self, item, json_data):
        """Memproses item CRL"""
        try:
            # Disable SSL verification like PHP does
            response = requests.get(item["url"], timeout=10, verify=False)
            
            if response.status_code == 200:
                content = response.content
                crl_der = self._extract_crl_der(content)
                crl_b64 = base64.b64encode(crl_der).decode("ascii")
                json_data["crl"].append(crl_b64)
            else:
                print(f"Error fetching CRL: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"CRL request failed: {e}")

    def _extract_crl_der(self, content):
        """Mengekstrak CRL DER dari konten response"""
        if b"BEGIN X509 CRL" in content:
            # Extract PEM body and decode Base64 → binary DER
            pem_body = b"".join(
                line.strip()
                for line in content.splitlines()
                if not line.startswith(b"---")
            )
            return base64.b64decode(pem_body)
        else:
            # Assume already DER
            return content

    def sign_pdf(
        self,
        input_path: str,
        output_path: str,
        image_path: str = "example.png",
        url: str = "signpdfkit.com",
        location: str = "Jakarta",
        reason: str = "Need to sign",
        contact_info: str = "signpdfkit@gmail.com",
        field_id: str = "SignPDFKit",
        character: str = "#",
        signature_type: int = SignatureType.SIGNATURE,
        page: int = 1,
        field_type: int = Subfilter.ADBE,
        visibility: int = Visibility.INVISIBLE,
        x: float = 0.0,
        y: float = 0.0,
        width: float = 50.0,
        height: float = 50.0,
        dss: int = DSS.NO
    ) -> str:
        """Menandatangani PDF dengan parameter yang diberikan"""
        # Input validation like PHP
        json_data = {
            "response_code": 0,
            "response_status": "success"
        }

        if (
            not input_path or
            not output_path or
            not input_path.lower().endswith('.pdf') or
            not output_path.lower().endswith('.pdf')
        ):
            json_data["response_code"] = 3
            json_data["response_status"] = "Input parameters is in correct"
            return json.dumps(json_data)

        pre_sign_ptr = self.lib.calculate_digest(
            input_path.encode('utf-8'),
            image_path.encode('utf-8'),
            url.encode('utf-8'),
            location.encode('utf-8'),
            reason.encode('utf-8'),
            contact_info.encode('utf-8'),
            field_id.encode('utf-8'),
            character.encode('utf-8'),
            signature_type,
            page,
            field_type,
            visibility,
            x,
            y,
            width,
            height,
            dss
        )
        
        if not pre_sign_ptr:
            json_data["response_code"] = 4
            json_data["response_status"] = "Failed when process PDF"
            return json.dumps(json_data)
            
        pre_sign = ctypes.string_at(pre_sign_ptr).decode('utf-8')
        data = json.loads(pre_sign)
        
        if data["response_code"] == 0:
            cms = self.custom_function(data["data"]["digest"], self.options)
            response_str = self.get_revocation(cms, dss)
            
            result = self.lib.embed_cms(
                pre_sign.encode('utf-8'), 
                response_str.encode('utf-8') if response_str else None, 
                output_path.encode('utf-8')
            )

            if result == 0:
                return json.dumps(json_data)
            else:
                json_data["response_code"] = 4
                json_data["response_status"] = "Failed when process PDF"

        else:
            # Map error codes like PHP
            if data["response_code"] == 1:
                json_data["response_code"] = 1
                json_data["response_status"] = "Failed to open/read document"
            elif data["response_code"] == 4:
                json_data["response_code"] = 4
                json_data["response_status"] = "Failed when process PDF"
            elif data["response_code"] == 5:
                json_data["response_code"] = 5
                json_data["response_status"] = "PDF File not found"
            elif data["response_code"] == 6:
                json_data["response_code"] = 6
                json_data["response_status"] = "Visualization Image not found"
            else:
                json_data["response_code"] = 4
                json_data["response_status"] = "Failed when process PDF"
            
        return json.dumps(json_data)


class SignPDFKitVerify(SignPDFKitBase):
    """Kelas untuk memverifikasi tanda tangan PDF"""
    
    def __init__(self, lib_dir: str):
        super().__init__(lib_dir)
        # Load library and setup function prototypes
        self._load_library()
        self._setup_function_prototypes()

    def _setup_function_prototypes(self):
        """Menyiapkan prototype fungsi dari library native"""
        # Configure verify function prototype
        self.lib.verify.argtypes = [ctypes.c_char_p]
        self.lib.verify.restype = ctypes.c_char_p
        
        self.lib.free_c_string.restype = None
        self.lib.free_c_string.argtypes = [ctypes.c_char_p]

    def verify(self, input_path: str) -> Optional[str]:
        """Memverifikasi tanda tangan pada PDF"""
        result_ptr = self.lib.verify(input_path.encode('utf-8'))
        
        if not result_ptr:
            return None
            
        result = ctypes.string_at(result_ptr).decode('utf-8')
        
        return result