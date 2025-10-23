require_relative './signpdfkit'  # Assuming the previous code is in signpdfkit.rb
require 'json'
require 'base64'
require 'net/http'
require 'uri'

# Define the path to your lib directory containing the platform-specific libraries
LIB_DIR = "../lib"  # Change this to your actual lib directory path

options = {
  "email" => "user@signpdfkit.com",
  "passcode" => "123456"
}

def sign_digest_function(digest, options_params)
  # 1) Send POST request to PHP API
  url = "https://signpdfkit.com/api/sign"
  uri = URI.parse(url)
  
  headers = {"Content-Type" => "application/json"}
  payload = {
    "digest" => digest,
    "email" => options_params["email"],
    "passcode" => options_params["passcode"]
  }

  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  
  request = Net::HTTP::Post.new(uri.request_uri, headers)
  request.body = payload.to_json

  response = http.request(request)
  
  # Raise error if not 2xx
  unless response.code.start_with?('2')
    raise "HTTP Error: #{response.code} - #{response.body}"
  end

  # 2) Parse JSON response from PHP
  data = JSON.parse(response.body)

  unless data.key?("cms")
    raise "Invalid response: #{data}"
  end

  data["cms"]
end

# Example usage of Sign PDF
# Now pass LIB_DIR as the first parameter
signer = SignPDFKitSign.new(LIB_DIR, method(:sign_digest_function), options)

result = signer.sign_pdf(
  input_path = "../assets/input/sample.pdf",
  output_path = "../assets/output/ruby.pdf",
  image_path = "../assets/input/visualization.png",
  url = "https://example.com",
  location = "Jakarta",
  reason = "Need to Approve",
  contact_info = "karyadi.dk@gmail.com",
  field_id = "SignPDFKit",
  character = "#",
  signature_type = SignatureType::SIGNATURE,
  page = 1,
  field_type = Subfilter::ADBE,
  visibility = Visibility::VISIBLE_IMAGE,
  x = 100.0,
  y = 200.0,
  width = 100.0,
  height = 100.0,
  dss = DSS::YES
)

# The result is now a JSON string, not an integer
result_data = JSON.parse(result)

if result_data['response_code'] == 0
  puts "Signing success"
else
  puts "Signing failed: #{result_data['response_status']} (Code: #{result_data['response_code']})"
end

# Example usage of Verify PDF
# Now pass LIB_DIR as the first parameter
verifier = SignPDFKitVerify.new(LIB_DIR)
result = verifier.verify("../assets/output/ruby.pdf")
if result
  puts "Verification result:"
  puts result
else
  puts "Verification failed or no result returned"
end
