package com.signpdfkit;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import java.io.File;
import java.nio.file.Paths;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * SignPDFKit - Java implementation of PDF signing and verification
 */
public class SignPDFKit {

    // Constants
    public static class Visibility {
        public static final int INVISIBLE = 0;
        public static final int VISIBLE_IMAGE = 1;
        public static final int VISIBLE_QR = 2;
        public static final int VISIBLE_IMAGE_FROM_CHAR = 3;
        public static final int VISIBLE_QR_FROM_CHAR = 4;
    }

    public static class Subfilter {
        public static final int PADES = 1;
        public static final int ADBE = 0;
    }

    public static class SignatureType {
        public static final int SIGNATURE = 0;
        public static final int SEAL = 1;
    }

    public static class DSS {
        public static final int NO = 0;
        public static final int YES = 1;
    }

    // Base class
    private static abstract class SignPDFKitBase {
        protected interface SignPDFLibrary extends Library {
            Pointer calculate_digest(String input_path, String image_path, String url, String location, 
                                   String reason, String contact_info, String field_id, String character, 
                                   int signature_type, int page, int field_type, int visibility, 
                                   double x, double y, double width, double height, int dss);
            
            Pointer get_revocation_parameters(String cms);
            int embed_cms(String pre_sign, String response_str, String output_path);
            void free_c_string(Pointer ptr);
            Pointer verify(String input_path);
        }
        
        protected SignPDFLibrary lib;
        private static String libraryPathCache = null;
        protected Gson gson = new Gson();
        
        protected static String getLibraryPath(String libDir) {
            if (libraryPathCache == null) {
                libraryPathCache = calculateLibraryPath(libDir);
            }
            return libraryPathCache;
        }
        
        private static String calculateLibraryPath(String libDir) {
            String osName = System.getProperty("os.name").toLowerCase();
            String arch = System.getProperty("os.arch");
            
            Map<String, Map<String, String[]>> platformMappings = new HashMap<>();
            
            // Darwin (macOS) mappings
            Map<String, String[]> darwinMap = new HashMap<>();
            darwinMap.put("x86_64", new String[]{"macos_x86_64", "libsignpdfkit.dylib"});
            darwinMap.put("amd64", new String[]{"macos_x86_64", "libsignpdfkit.dylib"});
            darwinMap.put("aarch64", new String[]{"macos_arm64", "libsignpdfkit.dylib"});
            darwinMap.put("arm64", new String[]{"macos_arm64", "libsignpdfkit.dylib"});
            platformMappings.put("darwin", darwinMap);
            
            // Linux mappings
            Map<String, String[]> linuxMap = new HashMap<>();
            linuxMap.put("x86_64", new String[]{"linux_x86_64", "libsignpdfkit.so"});
            linuxMap.put("amd64", new String[]{"linux_x86_64", "libsignpdfkit.so"});
            linuxMap.put("i686", new String[]{"linux_x86", "libsignpdfkit.so"});
            linuxMap.put("i386", new String[]{"linux_x86", "libsignpdfkit.so"});
            linuxMap.put("aarch64", new String[]{"linux_arm64", "libsignpdfkit.so"});
            linuxMap.put("arm64", new String[]{"linux_arm64", "libsignpdfkit.so"});
            linuxMap.put("armv7l", new String[]{"linux_armv7", "libsignpdfkit.so"});
            platformMappings.put("linux", linuxMap);
            
            // Windows mappings
            Map<String, String[]> windowsMap = new HashMap<>();
            windowsMap.put("amd64", new String[]{"win64", "libsignpdfkit.dll"});
            windowsMap.put("x86_64", new String[]{"win64", "libsignpdfkit.dll"});
            windowsMap.put("x86", new String[]{"win32", "libsignpdfkit.dll"});
            windowsMap.put("i686", new String[]{"win32", "libsignpdfkit.dll"});
            windowsMap.put("i386", new String[]{"win32", "libsignpdfkit.dll"});
            windowsMap.put("arm64", new String[]{"win64", "libsignpdfkit.dll"});
            platformMappings.put("winnt", windowsMap);
            platformMappings.put("windows", windowsMap);
            
            // Normalize OS name
            String osKey;
            if (osName.contains("mac") || osName.contains("darwin")) {
                osKey = "darwin";
            } else if (osName.contains("linux")) {
                osKey = "linux";
            } else if (osName.contains("win")) {
                osKey = "winnt";
            } else {
                osKey = osName;
            }
            
            // Normalize architecture
            String normalizedArch = arch;
            if (arch.equals("x86_64") || arch.equals("amd64")) {
                normalizedArch = "x86_64";
            } else if (arch.equals("i386") || arch.equals("i686")) {
                normalizedArch = "i686";
            } else if (arch.equals("aarch64")) {
                normalizedArch = "arm64";
            }
            
            if (platformMappings.containsKey(osKey) && 
                platformMappings.get(osKey).containsKey(normalizedArch)) {
                
                String[] pathInfo = platformMappings.get(osKey).get(normalizedArch);
                return Paths.get(libDir, pathInfo[0], pathInfo[1]).toString();
            }
            
            throw new RuntimeException("Unsupported platform: " + osKey + " " + arch);
        }
        
        protected void initializeFFI(String libDir) {
            String libraryPath = getLibraryPath(libDir);
            File libFile = new File(libraryPath);
            
            if (!libFile.exists()) {
                throw new RuntimeException("Native library not found: " + libraryPath);
            }
            
            // Load the library using JNA
            lib = Native.load(libraryPath, SignPDFLibrary.class);
        }
    }

    // Sign class
    public static class Sign extends SignPDFKitBase {
        private String libDir;
        private BiFunction<String, Map<String, Object>, String> customFunction;
        private Map<String, Object> options;
        private HttpClient httpClient;
        
        public Sign(String libDir, BiFunction<String, Map<String, Object>, String> signDigestFunc, 
                   Map<String, Object> kwargs) {
            this.libDir = libDir;
            this.customFunction = signDigestFunc;
            this.options = kwargs;
            this.httpClient = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .build();
            this.initializeFFI(this.libDir);
        }
        
        // SignPDFKit.java - Updated getRevocation method
        public String getRevocation(String cms, int dss) {
            try {
                Pointer resultPtr = lib.get_revocation_parameters(cms);
                String resultStr = resultPtr.getString(0);
                lib.free_c_string(resultPtr);
                
                if (resultStr == null || resultStr.isEmpty()) {
                    return null;
                }
                
                System.out.println("Raw revocation response: " + resultStr); // Debug
                
                JsonElement element = gson.fromJson(resultStr, JsonElement.class);
                JsonObject jsonData = new JsonObject();
                jsonData.addProperty("cms", cms);
                jsonData.add("ocsp", new JsonArray());
                jsonData.add("crl", new JsonArray());
                
                if (dss == DSS.YES) {
                    if (element.isJsonArray()) {
                        // Handle JSON array response
                        processRevocationData(element.getAsJsonArray(), jsonData);
                    } else if (element.isJsonObject() && element.getAsJsonObject().has("data")) {
                        // Handle JSON object with data field
                        JsonObject dataObj = element.getAsJsonObject();
                        if (dataObj.get("data").isJsonArray()) {
                            processRevocationData(dataObj.getAsJsonArray("data"), jsonData);
                        }
                    }
                }
                
                return gson.toJson(jsonData);
                
            } catch (Exception e) {
                System.err.println("Error in getRevocation: " + e.getMessage());
                e.printStackTrace();
                return null;
            }
        }
        
        private void processRevocationData(JsonArray data, JsonObject jsonData) {
            for (JsonElement itemElement : data) {
                JsonObject item = itemElement.getAsJsonObject();
                String type = item.get("type").getAsString();
                
                if ("ocsp".equals(type)) {
                    processOcspItem(item, jsonData);
                } else if ("crl".equals(type)) {
                    processCrlItem(item, jsonData);
                }
            }
        }
        
        private void processOcspItem(JsonObject item, JsonObject jsonData) {
            try {
                String requestB64 = item.get("request").getAsString();
                String url = item.get("url").getAsString();
                
                byte[] ocspRequestDer = Base64.getDecoder().decode(requestB64);
                
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .header("Content-Type", "application/ocsp-request")
                        .header("Accept", "application/ocsp-response")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(ocspRequestDer))
                        .build();
                
                HttpResponse<byte[]> response = httpClient.send(request, 
                        HttpResponse.BodyHandlers.ofByteArray());
                
                if (response.statusCode() == 200) {
                    String ocspResponseB64 = Base64.getEncoder().encodeToString(response.body());
                    jsonData.getAsJsonArray("ocsp").add(ocspResponseB64);
                } else {
                    System.err.println("OCSP request failed with status: " + response.statusCode());
                }
                
            } catch (Exception e) {
                System.err.println("OCSP request failed: " + e.getMessage());
            }
        }
        
        private void processCrlItem(JsonObject item, JsonObject jsonData) {
            try {
                String url = item.get("url").getAsString();
                
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .GET()
                        .build();
                
                HttpResponse<byte[]> response = httpClient.send(request, 
                        HttpResponse.BodyHandlers.ofByteArray());
                
                if (response.statusCode() == 200) {
                    byte[] content = response.body();
                    byte[] crlDer = extractCrlDer(content);
                    String crlB64 = Base64.getEncoder().encodeToString(crlDer);
                    jsonData.getAsJsonArray("crl").add(crlB64);
                } else {
                    System.err.println("CRL request failed with status: " + response.statusCode());
                }
                
            } catch (Exception e) {
                System.err.println("CRL request failed: " + e.getMessage());
            }
        }
        
        private byte[] extractCrlDer(byte[] content) {
            String contentStr = new String(content);
            
            if (contentStr.contains("BEGIN X509 CRL")) {
                String[] lines = contentStr.split("\n");
                StringBuilder pemBody = new StringBuilder();
                
                for (String line : lines) {
                    if (!line.startsWith("---")) {
                        pemBody.append(line.trim());
                    }
                }
                
                return Base64.getDecoder().decode(pemBody.toString());
            }
            
            return content;
        }

        public static class SignPdfOptions {
            public String inputPath;
            public String outputPath;
            public String imagePath = "example.png";
            public String url = "signpdfkit.com";
            public String location = "Jakarta";
            public String reason = "Need to sign";
            public String contactInfo = "signpdfkit@gmail.com";
            public String fieldId = "SignPDFKit";
            public String character = "#";
            public int signatureType = SignatureType.SIGNATURE;
            public int page = 1;
            public int fieldType = Subfilter.ADBE;
            public int visibility = Visibility.INVISIBLE;
            public double x = 0.0;
            public double y = 0.0;
            public double width = 50.0;
            public double height = 50.0;
            public int dss = DSS.NO;

            public SignPdfOptions(String inputPath, String outputPath) {
                this.inputPath = inputPath;
                this.outputPath = outputPath;
            }

            // builder-style setters for convenience
            public SignPdfOptions imagePath(String v) { this.imagePath = v; return this; }
            public SignPdfOptions url(String v) { this.url = v; return this; }
            public SignPdfOptions location(String v) { this.location = v; return this; }
            public SignPdfOptions reason(String v) { this.reason = v; return this; }
            public SignPdfOptions contactInfo(String v) { this.contactInfo = v; return this; }
            public SignPdfOptions fieldId(String v) { this.fieldId = v; return this; }
            public SignPdfOptions character(String v) { this.character = v; return this; }
            public SignPdfOptions signatureType(int v) { this.signatureType = v; return this; }
            public SignPdfOptions page(int v) { this.page = v; return this; }
            public SignPdfOptions fieldType(int v) { this.fieldType = v; return this; }
            public SignPdfOptions visibility(int v) { this.visibility = v; return this; }
            public SignPdfOptions x(double v) { this.x = v; return this; }
            public SignPdfOptions y(double v) { this.y = v; return this; }
            public SignPdfOptions width(double v) { this.width = v; return this; }
            public SignPdfOptions height(double v) { this.height = v; return this; }
            public SignPdfOptions dss(int v) { this.dss = v; return this; }
        }

        
        public String signPdf(SignPdfOptions opts) {
            JsonObject jsonData = new JsonObject();
            jsonData.addProperty("response_code", 0);
            jsonData.addProperty("response_status", "success");

            if (opts.inputPath == null || opts.inputPath.isEmpty() ||
                opts.outputPath == null || opts.outputPath.isEmpty() ||
                !opts.inputPath.toLowerCase().endsWith(".pdf") ||
                !opts.outputPath.toLowerCase().endsWith(".pdf")) {

                jsonData.addProperty("response_code", 3);
                jsonData.addProperty("response_status", "Input parameters is incorrect");
                return gson.toJson(jsonData);
            }

            try {
                Pointer preSignPtr = lib.calculate_digest(
                    opts.inputPath,
                    opts.imagePath,
                    opts.url,
                    opts.location,
                    opts.reason,
                    opts.contactInfo,
                    opts.fieldId,
                    opts.character,
                    opts.signatureType,
                    opts.page,
                    opts.fieldType,
                    opts.visibility,
                    opts.x,
                    opts.y,
                    opts.width,
                    opts.height,
                    opts.dss
                );

                String preSignStr = preSignPtr.getString(0);
                lib.free_c_string(preSignPtr);

                if (preSignStr == null || preSignStr.isEmpty()) {
                    jsonData.addProperty("response_code", 4);
                    jsonData.addProperty("response_status", "Failed when process PDF");
                    return gson.toJson(jsonData);
                }

                JsonObject data = gson.fromJson(preSignStr, JsonObject.class);
                int responseCode = data.get("response_code").getAsInt();

                if (responseCode == 0) {
                    JsonObject dataObj = data.getAsJsonObject("data");
                    String digest = dataObj.get("digest").getAsString();

                    String cms = customFunction.apply(digest, options);
                    String responseStr = getRevocation(cms, opts.dss);

                    int result = lib.embed_cms(preSignStr, responseStr, opts.outputPath);

                    if (result == 0) {
                        return gson.toJson(jsonData);
                    } else {
                        jsonData.addProperty("response_code", 4);
                        jsonData.addProperty("response_status", "Failed when process PDF");
                    }
                } else {
                    switch (responseCode) {
                        case 1:
                            jsonData.addProperty("response_code", 1);
                            jsonData.addProperty("response_status", "Failed to open/read document");
                            break;
                        case 4:
                            jsonData.addProperty("response_code", 4);
                            jsonData.addProperty("response_status", "Failed when process PDF");
                            break;
                        case 5:
                            jsonData.addProperty("response_code", 5);
                            jsonData.addProperty("response_status", "PDF File not found");
                            break;
                        case 6:
                            jsonData.addProperty("response_code", 6);
                            jsonData.addProperty("response_status", "Visualization Image not found");
                            break;
                        default:
                            jsonData.addProperty("response_code", 4);
                            jsonData.addProperty("response_status", "Failed when process PDF");
                            break;
                    }
                }
            } catch (Exception e) {
                jsonData.addProperty("response_code", 4);
                jsonData.addProperty("response_status", "Failed when process PDF: " + e.getMessage());
            }

            return gson.toJson(jsonData);
        }

        // // Overloaded method with default parameters
        // public String signPdf(String inputPath, String outputPath) {
        //     return signPdf(
        //         inputPath, outputPath, "example.png", "signpdfkit.com", 
        //         "Jakarta", "Need to sign", "signpdfkit@gmail.com", "SignPDFKit", 
        //         "#", SignatureType.SIGNATURE, 1, Subfilter.ADBE, 
        //         Visibility.INVISIBLE, 0.0, 0.0, 50.0, 50.0, DSS.NO
        //     );
        // }
    }

    // Verify class
    public static class Verify extends SignPDFKitBase {
        
        public Verify(String libDir) {
            this.initializeFFI(libDir);
        }
        
        public String verify(String inputPath) {
            try {
                Pointer resultPtr = lib.verify(inputPath);
                String resultStr = resultPtr.getString(0);
                lib.free_c_string(resultPtr);
                
                if (resultStr == null || resultStr.isEmpty()) {
                    return null;
                }
                
                return resultStr;
                
            } catch (Exception e) {
                System.err.println("Verification failed: " + e.getMessage());
                return null;
            }
        }
    }

    // Utility method for quick initialization
    public static Sign createSigner(String libDir, BiFunction<String, Map<String, Object>, String> signFunction, 
                                  Map<String, Object> options) {
        return new Sign(libDir, signFunction, options);
    }

    public static Verify createVerifier(String libDir) {
        return new Verify(libDir);
    }
}