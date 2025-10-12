require 'ffi'
require 'json'
require 'base64'
require 'open3'
require 'net/http'
require 'uri'

module Visibility
  INVISIBLE = 0
  VISIBLE_IMAGE = 1
  VISIBLE_QR = 2
  VISIBLE_IMAGE_FROM_CHAR = 3
  VISIBLE_QR_FROM_CHAR = 4
end

module Subfilter
  PADES = 1
  ADBE = 0
end

module SignatureType
  SIGNATURE = 0
  SEAL = 1
end

module DSS
  NO = 0
  YES = 1
end

module SignPDFKitBase
  def self.included(base)
    base.extend ClassMethods
  end

  module ClassMethods
    @@library_path_cache = {}

    def get_library_path(lib_dir)
      @@library_path_cache[lib_dir] ||= calculate_library_path(lib_dir)
    end

    private

    def calculate_library_path(lib_dir)
      system = RbConfig::CONFIG['host_os'].downcase
      machine = RbConfig::CONFIG['host_cpu']
      
      platform_mappings = {
        'darwin' => {
          'x86_64' => ['macos_x86_64', 'libsignpdfkit.dylib'],
          'arm64' => ['macos_arm64', 'libsignpdfkit.dylib']
        },
        'linux' => {
          'x86_64' => ['linux_x86_64', 'libsignpdfkit.so'],
          'i686' => ['linux_x86', 'libsignpdfkit.so'],
          'aarch64' => ['linux_arm64', 'libsignpdfkit.so'],
          'arm64' => ['linux_arm64', 'libsignpdfkit.so'],
          'armv7l' => ['linux_armv7', 'libsignpdfkit.so']
        },
        'mswin' => {
          'amd64' => ['win64', 'libsignpdfkit.dll'],
          'x86_64' => ['win64', 'libsignpdfkit.dll'],
          'x86' => ['win32', 'libsignpdfkit.dll'],
          'i686' => ['win32', 'libsignpdfkit.dll'],
          'arm64' => ['win64', 'libsignpdfkit.dll']
        },
        'mingw' => {
          'amd64' => ['win64', 'libsignpdfkit.dll'],
          'x86_64' => ['win64', 'libsignpdfkit.dll'],
          'x86' => ['win32', 'libsignpdfkit.dll'],
          'i686' => ['win32', 'libsignpdfkit.dll'],
          'arm64' => ['win64', 'libsignpdfkit.dll']
        }
      }

      # Normalize system name
      os_key = if system.include?('darwin')
                 'darwin'
               elsif system.include?('linux')
                 'linux'
               elsif system.include?('mswin') || system.include?('mingw')
                 'mswin'
               else
                 system
               end

      if platform_mappings.key?(os_key) && platform_mappings[os_key].key?(machine)
        path_info = platform_mappings[os_key][machine]
        return File.join(lib_dir, path_info[0], path_info[1])
      end

      raise "Unsupported platform: #{os_key} #{machine}"
    end
  end
end

class SignPDFKitSign
  extend FFI::Library
  include SignPDFKitBase

  attr_reader :lib_dir, :custom_function, :options

  def initialize(lib_dir, sign_digest_func, kwargs)
    @lib_dir = lib_dir
    @custom_function = sign_digest_func
    @options = kwargs
    
    # Load the library at class level
    library_path = self.class.get_library_path(lib_dir)
    self.class.ffi_lib library_path

    # Define function prototypes at class level
    self.class.attach_function :calculate_digest, [:string, :string, :string, :string, :string, 
                                       :string, :string, :string, :int, :int, :int, 
                                       :int, :double, :double, :double, :double, :int], :string
    self.class.attach_function :get_revocation_parameters, [:string], :string
    self.class.attach_function :embed_cms, [:string, :string, :string], :int
    self.class.attach_function :free_c_string, [:string], :void
  end

  def get_revocation(cms, dss)
    result = self.class.get_revocation_parameters(cms)

    return nil if result.nil? || result.empty?

    data = JSON.parse(result)

    json_data = {
      'cms' => cms,
      'ocsp' => [],
      'crl' => []
    }

    if dss == DSS::YES
      _process_revocation_data(data, json_data)
    end

    JSON.generate(json_data)
  end

  def _process_revocation_data(data, json_data)
    data.each do |item|
      if item['type'] == 'ocsp'
        _process_ocsp_item(item, json_data)
      elsif item['type'] == 'crl'
        _process_crl_item(item, json_data)
      end
    end
  end

  def _process_ocsp_item(item, json_data)
    ocsp_request_der = Base64.decode64(item['request'])
    uri = URI.parse(item['url'])
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    
    request = Net::HTTP::Post.new(uri.request_uri)
    request['Content-Type'] = 'application/ocsp-request'
    request['Accept'] = 'application/ocsp-response'
    request.body = ocsp_request_der

    begin
      response = http.request(request)
      
      if response.code == '200'
        ocsp_response_b64 = Base64.strict_encode64(response.body)
        json_data['ocsp'] << ocsp_response_b64
      else
        puts "Error OCSP: #{response.code} - #{response.body}"
      end
    rescue => e
      puts "OCSP request failed: #{e.message}"
    end
  end

  def _process_crl_item(item, json_data)
    uri = URI.parse(item['url'])
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    
    request = Net::HTTP::Get.new(uri.request_uri)

    begin
      response = http.request(request)
      
      if response.code == '200'
        content = response.body
        crl_der = _extract_crl_der(content)
        crl_b64 = Base64.strict_encode64(crl_der)
        json_data['crl'] << crl_b64
      else
        puts "Error fetching CRL: #{response.code} - #{response.body}"
      end
    rescue => e
      puts "CRL request failed: #{e.message}"
    end
  end

  def _extract_crl_der(content)
    if content.include?('BEGIN X509 CRL')
      # Extract PEM body and decode Base64
      pem_body = content.lines
                        .reject { |line| line.start_with?('---') }
                        .map { |line| line.strip }
                        .join
      Base64.decode64(pem_body)
    else
      content
    end
  end

  def sign_pdf(input_path, output_path, image_path = 'example.png', url = 'signpdfkit.com', 
               location = 'Jakarta', reason = 'Need to sign', contact_info = 'signpdfkit@gmail.com', 
               field_id = 'SignPDFKit', character = '#', signature_type = SignatureType::SIGNATURE, 
               page = 1, field_type = Subfilter::ADBE, visibility = Visibility::INVISIBLE, 
               x = 0.0, y = 0.0, width = 50.0, height = 50.0, dss = DSS::NO)
    
    # Input validation like in PHP
    json_data = {
      'response_code' => 0,
      'response_status' => 'success'
    }

    if input_path.empty? || output_path.empty? ||
       !input_path.downcase.end_with?('.pdf') || !output_path.downcase.end_with?('.pdf')
      json_data['response_code'] = 3
      json_data['response_status'] = 'Input parameters is incorrect'
      return JSON.generate(json_data)
    end

    pre_sign = self.class.calculate_digest(
      input_path, image_path, url, location, reason,
      contact_info, field_id, character, signature_type,
      page, field_type, visibility, x, y, width, height, dss
    )
    
    if pre_sign.nil? || pre_sign.empty?
      json_data['response_code'] = 4
      json_data['response_status'] = 'Failed when process PDF'
      return JSON.generate(json_data)
    end
    
    data = JSON.parse(pre_sign)
    
    case data['response_code']
    when 0
      cms = @custom_function.call(data['data']['digest'], @options)
      response_str = get_revocation(cms, dss)
      
      result = self.class.embed_cms(pre_sign, response_str, output_path)
      
      return JSON.generate(json_data)
    when 1
      json_data['response_code'] = 1
      json_data['response_status'] = 'Failed to open/read document'
    when 4
      json_data['response_code'] = 4
      json_data['response_status'] = 'Failed when process PDF'
    when 5
      json_data['response_code'] = 5
      json_data['response_status'] = 'PDF File not found'
    when 6
      json_data['response_code'] = 6
      json_data['response_status'] = 'Visualization Image not found'
    else
      json_data['response_code'] = 4
      json_data['response_status'] = 'Failed when process PDF'
    end

    JSON.generate(json_data)
  end
end

class SignPDFKitVerify
  extend FFI::Library
  include SignPDFKitBase

  attr_reader :lib_dir

  def initialize(lib_dir)
    @lib_dir = lib_dir
    
    # Load the library at class level
    library_path = self.class.get_library_path(lib_dir)
    self.class.ffi_lib library_path

    # Define function prototypes at class level
    self.class.attach_function :verify, [:string], :string
    self.class.attach_function :free_c_string, [:string], :void
  end

  def verify(input_path)
    result = self.class.verify(input_path)
    
    if result.nil? || result.empty?
      return nil
    end
    
    # result_str = result.dup
    
    result_str
  end
end