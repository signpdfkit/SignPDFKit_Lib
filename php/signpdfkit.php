<?php

class Visibility
{
    const INVISIBLE = 0;
    const VISIBLE_IMAGE = 1;
    const VISIBLE_QR = 2;
    const VISIBLE_IMAGE_FROM_CHAR = 3;
    const VISIBLE_QR_FROM_CHAR = 4;
}

class Subfilter
{
    const PADES = 1;
    const ADBE = 0;
}

class SignatureType
{
    const SIGNATURE = 0;
    const SEAL = 1;
}

class DSS
{
    const NO = 0;
    const YES = 1;
}

abstract class SignPDFKitBase
{
    protected $ffi;
    private static $libraryPathCache = null;
    
    protected static function getLibraryPath($libDir)
    {
        if (self::$libraryPathCache === null) {
            self::$libraryPathCache = self::calculateLibraryPath($libDir);
        }
        return self::$libraryPathCache;
    }
    
    private static function calculateLibraryPath($libDir)
    {
        $system = strtolower(PHP_OS);
        $machine = php_uname('m');
        $currentDir = dirname(__FILE__);
        
        $platformMappings = [
            'darwin' => [
                'x86_64' => ['macos_x86_64', 'libsignpdfkit.dylib'],
                'arm64' => ['macos_arm64', 'libsignpdfkit.dylib']
            ],
            'linux' => [
                'x86_64' => ['linux_x86_64', 'libsignpdfkit.so'],
                'i686' => ['linux_x86', 'libsignpdfkit.so'],
                'aarch64' => ['linux_arm64', 'libsignpdfkit.so'],
                'arm64' => ['linux_arm64', 'libsignpdfkit.so'],
                'armv7l' => ['linux_armv7', 'libsignpdfkit.so']
            ],
            'winnt' => [
                'amd64' => ['win64', 'libsignpdfkit.dll'],
                'x86_64' => ['win64', 'libsignpdfkit.dll'],
                'x86' => ['win32', 'libsignpdfkit.dll'],
                'i686' => ['win32', 'libsignpdfkit.dll'],
                'arm64' => ['win64', 'libsignpdfkit.dll']
            ],
            'windows' => [
                'amd64' => ['win64', 'libsignpdfkit.dll'],
                'x86_64' => ['win64', 'libsignpdfkit.dll'],
                'x86' => ['win32', 'libsignpdfkit.dll'],
                'i686' => ['win32', 'libsignpdfkit.dll'],
                'arm64' => ['win64', 'libsignpdfkit.dll']
            ]
        ];
        
        // Normalize system name
        $osKey = '';
        if (strpos($system, 'darwin') !== false) {
            $osKey = 'darwin';
        } elseif (strpos($system, 'linux') !== false) {
            $osKey = 'linux';
        } elseif (strpos($system, 'win') !== false) {
            $osKey = 'winnt';
        } else {
            $osKey = $system;
        }
        
        if (isset($platformMappings[$osKey]) && isset($platformMappings[$osKey][$machine])) {
            $pathInfo = $platformMappings[$osKey][$machine];
            return $libDir . '/' . $pathInfo[0] . '/' . $pathInfo[1];
        }
        
        throw new Exception("Unsupported platform: {$osKey} {$machine}");
    }
    
    protected function initializeFFI($libDir, $cdef)
    {
        $libraryPath = self::getLibraryPath($libDir);
        $this->ffi = FFI::cdef($cdef, $libraryPath);
    }
}

class SignPDFKitSign extends SignPDFKitBase
{
    private $libDir;
    private $customFunction;
    private $options;
    
    public function __construct(string $libDir, callable $sign_digest_func, array $kwargs)
    {
        $this->libDir = $libDir;
        $this->customFunction = $sign_digest_func;
        $this->options = $kwargs;
        $this->initializeFFI($this->libDir, "
            char* calculate_digest(const char*, const char*, const char*, const char*, const char*, 
                                  const char*, const char*, const char*, int, int, int, 
                                  int, double, double, double, double, int);
            char* get_revocation_parameters(const char*);
            int embed_cms(const char*, const char*, const char*);
            void free_c_string(char* ptr);
        ");
    }
    
    public function get_revocation($cms, $dss)
    {
        $result = $this->ffi->get_revocation_parameters($cms);
        
        // Convert FFI\CData to string
        $resultStr = FFI::string($result);
        
        if ($resultStr === null || $resultStr === '') {
            return null;
        }
        
        $data = json_decode($resultStr, true);
        
        $jsonData = [
            'cms' => $cms,
            'ocsp' => [],
            'crl' => []
        ];
        
        if ($dss == DSS::YES) {
            $this->_process_revocation_data($data, $jsonData);
        }

        $this->ffi->free_c_string($result);
        
        return json_encode($jsonData);
    }
    
    private function _process_revocation_data($data, &$jsonData)
    {
        foreach ($data as $item) {
            if ($item['type'] == 'ocsp') {
                $this->_process_ocsp_item($item, $jsonData);
            } elseif ($item['type'] == 'crl') {
                $this->_process_crl_item($item, $jsonData);
            }
        }
    }
    
    private function _process_ocsp_item($item, &$jsonData)
    {
        $ocspRequestDer = base64_decode($item['request']);
        $url = $item['url'];
        $parsedUrl = parse_url($url);
        
        $host = $parsedUrl['host'];
        $port = $parsedUrl['port'] ?? ($parsedUrl['scheme'] == 'https' ? 443 : 80);
        $path = $parsedUrl['path'] ?? '/';
        
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/ocsp-request\r\nAccept: application/ocsp-response",
                'content' => $ocspRequestDer,
                'ignore_errors' => true
            ]
        ]);
        
        try {
            $response = file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $ocspResponseB64 = base64_encode($response);
                $jsonData['ocsp'][] = $ocspResponseB64;
            } else {
                error_log("Error OCSP: Failed to fetch response");
            }
        } catch (Exception $e) {
            error_log("OCSP request failed: " . $e->getMessage());
        }
    }
    
    private function _process_crl_item($item, &$jsonData)
    {
        $url = $item['url'];
        
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
            'http' => [
                'method' => 'GET',
                'ignore_errors' => true
            ]
        ]);
        
        try {
            $response = file_get_contents($url, false, $context);
            
            if ($response !== false) {
                $crlDer = $this->_extract_crl_der($response);
                $crlB64 = base64_encode($crlDer);
                $jsonData['crl'][] = $crlB64;
            } else {
                error_log("Error fetching CRL: Failed to fetch response");
            }
        } catch (Exception $e) {
            error_log("CRL request failed: " . $e->getMessage());
        }
    }
    
    private function _extract_crl_der($content)
    {
        if (strpos($content, 'BEGIN X509 CRL') !== false) {
            // Extract PEM body and decode Base64
            $lines = explode("\n", $content);
            $pemBody = '';
            
            foreach ($lines as $line) {
                if (!preg_match('/^---/', $line)) {
                    $pemBody .= trim($line);
                }
            }
            
            return base64_decode($pemBody);
        }
        
        return $content;
    }
    
    public function sign_pdf(
        string $input_path,
        string $output_path,
        string $image_path = 'example.png',
        string $url = 'signpdfkit.com',
        string $location = 'Jakarta',
        string $reason = 'Need to sign',
        string $contact_info = 'signpdfkit@gmail.com',
        string $field_id = 'SignPDFKit',
        string $character = '#',
        string $signature_type = SignatureType::SIGNATURE,
        int $page = 1,
        string $field_type = Subfilter::ADBE,
        string $visibility = Visibility::INVISIBLE,
        float $x = 0.0,
        float $y = 0.0,
        float $width = 50.0,
        float $height = 50.0,
        bool $dss = DSS::NO
    ){
        $jsonData = [
            'response_code' => 0,
            'response_status' => 'success'
        ];

        if (
            empty($input_path) ||
            empty($output_path) ||
            strtolower(substr($input_path, -4)) !== '.pdf' ||
            strtolower(substr($output_path, -4)) !== '.pdf'
        ) {
            $jsonData['response_code'] = 3;
            $jsonData['response_status'] = 'Input parameters is in correct';
            return json_encode($jsonData);
        }

        $pre_sign = $this->ffi->calculate_digest(
            $input_path, $image_path, $url, $location, $reason,
            $contact_info, $field_id, $character, $signature_type,
            $page, $field_type, $visibility, $x, $y, $width, $height, $dss
        );
        
        // Convert FFI\CData to string
        $pre_sign_str = FFI::string($pre_sign);
        
        if ($pre_sign_str === null || $pre_sign_str === '') {
            $jsonData['response_code'] = 4;
            $jsonData['response_status'] = 'Failed when process PDF';
            return json_encode($jsonData);
        }
        
        $data = json_decode($pre_sign_str, true);
        
        if ($data['response_code'] == 0) {
            $customFunction = $this->customFunction;
            $cms = $customFunction($data['data']['digest'], $this->options);
            $response_str = $this->get_revocation($cms, $dss);
            
            $result = $this->ffi->embed_cms($pre_sign_str, $response_str, $output_path);

            $this->ffi->free_c_string($pre_sign);

            if ($result == 0) {
                return json_encode($jsonData);
            } else {
                $jsonData['response_code'] = 4;
                $jsonData['response_status'] = 'Failed when process PDF';
            }

        } else if ($data['response_code'] == 1) {
            $jsonData['response_code'] = 1;
            $jsonData['response_status'] = 'Failed to open/read document';
        } else if ($data['response_code'] == 4) {
            $jsonData['response_code'] = 4;
            $jsonData['response_status'] = 'Failed when process PDF';
        } else if ($data['response_code'] == 5) {
            $jsonData['response_code'] = 5;
            $jsonData['response_status'] = 'PDF File not found';
        } else if ($data['response_code'] == 6) {
            $jsonData['response_code'] = 6;
            $jsonData['response_status'] = 'Visualization Image not found';
        } else {
            $jsonData['response_code'] = 4;
            $jsonData['response_status'] = 'Failed when process PDF';
        }

        return json_encode($jsonData);
    }
}

class SignPDFKitVerify extends SignPDFKitBase
{
    private $libDir;

    public function __construct(string $libDir)
    {
        $this->libDir = $libDir;

        $this->initializeFFI($this->libDir, "
            char* verify(const char*);
            void free_c_string(char* ptr);
        ");
    }
    
    public function verify($input_path)
    {
        $result = $this->ffi->verify($input_path);
        
        // Convert FFI\CData to string
        $resultStr = FFI::string($result);
        
        if ($resultStr === null || $resultStr === '') {
            return null;
        }

        $this->ffi->free_c_string($result);
        
        return $resultStr;
    }
}