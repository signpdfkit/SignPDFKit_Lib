from signpdfkit import SignPDFKitSign, SignPDFKitVerify, Visibility, Subfilter, SignatureType, DSS
import requests  # pip install requests

options = {
    "email": "user@signpdfkit.com",
    "passcode": "123456"
}

def sign_digest_function(digest, options_params):
# You can provide the cms here by sign the digest

    # 1) Send POST request to PHP API
    url = "https://signpdfkit.com/api/sign"
    headers = {"Content-Type": "application/json"}
    payload = {
        "digest": digest,
        "email": options_params["email"],
        "passcode": options_params["passcode"]
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()  # will throw if not 2xx

    # 2) Parse JSON response from PHP
    data = response.json()

    if "cms" not in data:
        raise ValueError(f"Invalid response: {data}")

    cms = data["cms"]

    return cms

# Location of shared library
libDir = "../lib"
    
# Example usage of Sign PDF
signer = SignPDFKitSign(libDir, sign_digest_function, options)

resultSign = signer.sign_pdf(
    input_path = "../assets/input/sample.pdf", # input pdf
    output_path = "../assets/output/py.pdf", # output pdf
    image_path = "../assets/input/visualization.png", # visualization image
    url = "https://example.com", # url for qrcode
    location = "Jakarta", # location
    reason = "Need to Approve", # reason
    contact_info = "karyadi.dk@gmail.com", # contact info
    field_id = "SignPDFKit", # field id
    character = "#",  # Character
    signature_type = SignatureType.SIGNATURE, # signature type
    page = 1, # page
    field_type = Subfilter.ADBE, # is pades
    visibility = Visibility.VISIBLE_IMAGE, # type
    x = 100.0, # x (float)
    y = 200.0, # y (float)
    width = 100.0, # width (float)
    height = 100.0,  # height (float)
    dss = DSS.YES
)
print(resultSign)

# # Example usage of Verify PDF
verifier = SignPDFKitVerify(libDir)
resultVerify = verifier.verify("../assets/output/py.pdf")
print(resultVerify)
