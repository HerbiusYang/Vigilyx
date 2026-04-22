//! FileMedium Riskdetecthandler

//! detectuser webmail FileMedium UploadContainsSensitiveInfoofFile.
//! Scenario:user HTTP multipart/form-data UploadFile FileMedium,
//! FileName ContentpacketContainsSensitiveInfo.

//! Coremail Process:upload.jsp Use application/octet-stream
//! ConnectUpload2Base/RadixFile,URL ParameterContains attachmentId/func=directdata.

use chrono::Utc;
use vigilyx_core::magic_bytes::{FileTypeRisk, is_encrypted_archive};
use vigilyx_core::security::Evidence;
use vigilyx_core::{
    DataSecurityIncident, DataSecurityIncidentType, DataSecuritySeverity, HttpMethod, HttpSession,
};

use super::dlp;
use super::{DataSecurityDetector, DetectorResult};

/// FileUpload URI mode (smallwritematch)
const UPLOAD_URI_PATTERNS: &[&str] = &[
    "/upload",
    "/file/upload",
    "/netdisk",
    "/attachupload",
    "/attach_upload",
    "/filestation",
    "/file_transit",
    "/filetransit",
    // Coremail FileUpload (API)
    "func=mbox:uploadatt",
    "func=mbox:compose&sid", // compose with attachment upload
    "/coremail/main/netdisk",
    "func=global:netdisk",
    "/coremail/xt5/proxy/upload",
    // Coremail ChunkedUpload (chunked upload via upload.jsp)
    "upload.jsp",
    "func=directdata",
    // Exchange OWA
    "/owa/service.svc",
    // General API
    "/api/file/upload",
    "/api/attachment/upload",
    "/webmail/upload",
    "/cloud/upload",
];

/// HighRiskFileextension (Key/ /data / - FileType emailTransmission)
/// Note: Documentation (.doc/.xlsx/.pdf wait), ofSensitive ByContent DLP
const SENSITIVE_EXTENSIONS: &[&str] = &[
    ".sql",
    ".db",
    ".mdb",
    ".bak",
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".cer",
    ".crt",
];

#[derive(Default)]
pub struct FileTransitDetector;

impl FileTransitDetector {
    pub fn new() -> Self {
        Self
    }

    fn is_upload_uri(uri: &str) -> bool {
        let uri_lower = uri.to_lowercase();
        UPLOAD_URI_PATTERNS
            .iter()
            .any(|pattern| uri_lower.contains(pattern))
    }

    /// CheckFileextensionwhether HighRiskType(Key/ /data wait emailTransmissionofFile)
    fn is_sensitive_extension(filename: &str) -> Option<String> {
        let filename_lower = filename.to_lowercase();
        for &ext in SENSITIVE_EXTENSIONS {
            if filename_lower.ends_with(ext) {
                return Some(format!("HighRiskFileType: {}", ext));
            }
        }
        None
    }

    fn is_multipart(content_type: Option<&str>) -> bool {
        content_type
            .map(|ct| ct.to_lowercase().contains("multipart/form-data"))
            .unwrap_or(false)
    }

    /// Read body from temp file for DLP scan - limited to 50MB to prevent OOM
    fn read_body_for_dlp(path: &str) -> Option<String> {
        const DLP_MAX_READ: usize = 50 * 1024 * 1024;

        // SEC: path validation prevents arbitrary file reads (CWE-22)
        let validated = super::validate_temp_path(path)?;

        let data = match std::fs::read(&validated) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(path = %path, error = %e, "readGet body tempFileFailed (DLP)");
                return None;
            }
        };

        let cap = data.len().min(DLP_MAX_READ);
        let text = String::from_utf8_lossy(&data[..cap]);
        if text.is_empty() {
            return None;
        }
        Some(text.into_owned())
    }

    /// Read raw binary data for document extraction - limited to 50MB
    fn read_body_bytes(session: &HttpSession) -> Vec<u8> {
        const MAX_READ: usize = 50 * 1024 * 1024;

        // priorityFromtempFilereadGet — SEC: path validation (CWE-22)
        if let Some(ref path) = session.body_temp_file
            && let Some(validated) = super::validate_temp_path(path)
        {
            match std::fs::read(&validated) {
                Ok(data) => {
                    let cap = data.len().min(MAX_READ);
                    return data[..cap].to_vec();
                }
                Err(e) => {
                    tracing::warn!(path = %path, error = %e, "readGet body tempFileFailed (DocumentationExtract)");
                }
            }
        }

        // Fallback: FromMemory body readGet
        if let Some(ref body) = session.request_body {
            let cap = body.len().min(MAX_READ);
            return body.as_bytes()[..cap].to_vec();
        }

        Vec::new()
    }
}

impl DataSecurityDetector for FileTransitDetector {
    fn id(&self) -> &str {
        "file_transit_detect"
    }

    fn name(&self) -> &str {
        "File transit risk detection"
    }

    fn analyze(&self, session: &HttpSession) -> DetectorResult {
        // onlyCheck POST Request
        if session.method != HttpMethod::Post {
            return None;
        }

        // URI matchUploadmode
        if !Self::is_upload_uri(&session.uri) {
            return None;
        }

        let mut evidence = Vec::new();
        let mut dlp_matches = Vec::new();
        let mut dlp_for_jrt: Option<dlp::DlpScanResult> = None;

        // Checkwhether FileUpload (multipart FileName Coremail directData)

        // Coremail upload.jsp?func=directData application/octet-stream
        // multipart/form-data, URL
        let uri_lower = session.uri.to_lowercase();
        let is_coremail_direct_upload =
            uri_lower.contains("func=directdata") || uri_lower.contains("func=directdata");
        let has_file = session.uploaded_filename.is_some()
            || Self::is_multipart(session.content_type.as_deref())
            || is_coremail_direct_upload;

        if !has_file {
            return None;
        }

        // 1. Executable fileUploaddetect (magic bytes)

        if let Some(ft) = session.detected_file_type {
            match ft.base_risk() {
                FileTypeRisk::High => {
                    // PE/ELF/MachO/LNK/JavaClass - HighRiskExecutable file
                    dlp_matches.push("executable_upload".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "UploadExecutable file: {} (largesmall: {} Byte)",
                            ft.display_name(),
                            session.request_body_size
                        ),
                        location: Some("magic bytes".to_string()),
                        snippet: None,
                    });
                }
                FileTypeRisk::Medium => {
                    // ZIP/RAR/7z/Gzip/OLE - RecordingFileType
                    evidence.push(Evidence {
                        description: format!(
                            "UploadFileType: {} (largesmall: {} Byte)",
                            ft.display_name(),
                            session.request_body_size
                        ),
                        location: Some("magic bytes".to_string()),
                        snippet: None,
                    });
                }
                _ => {}
            }
        }

        // 2. FileType detect (extension vs magic bytes)

        if let Some(ref mismatch) = session.file_type_mismatch {
            dlp_matches.push("file_type_mismatch".to_string());
            evidence.push(Evidence {
                description: format!("File type disguise: {}", mismatch),
                location: Some("extension mismatch".to_string()),
                snippet: session.uploaded_filename.clone(),
            });
        }

        // 2b. EncryptFiledetect (ZIP/RAR/7z/PDF - DLP Risk)

        {
            // Read full body for encryption detection - no truncation (full-audit mode)
            // SEC: path validation prevents arbitrary file reads via body_temp_file (CWE-22)
            let header_bytes: Option<Vec<u8>> = session
                .request_body
                .as_ref()
                .map(|b| b.as_bytes().to_vec())
                .or_else(|| {
                    session
                        .body_temp_file
                        .as_ref()
                        .and_then(|path| super::validate_temp_path(path))
                        .and_then(|validated| std::fs::read(validated).ok())
                });

            if let Some(ref hdr) = header_bytes {
                // EncryptCompresspacket: ZIP/RAR4/RAR5/7z
                if is_encrypted_archive(hdr) {
                    dlp_matches.push("encrypted_archive".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Uploaded encrypted/compressed archive (may bypass DLP content scan): {} (size: {} bytes)",
                            session.detected_file_type.map(|ft| ft.display_name()).unwrap_or("Unknown"),
                            session.request_body_size
                        ),
                        location: Some("archive header".to_string()),
                        snippet: session.uploaded_filename.clone(),
                    });
                }
                // Password PDF
                if vigilyx_core::magic_bytes::is_encrypted_pdf(hdr) {
                    dlp_matches.push("encrypted_pdf".to_string());
                    evidence.push(Evidence {
                        description: format!(
                            "Uploaded password-protected PDF (content cannot be scanned): size {} bytes",
                            session.request_body_size
                        ),
                        location: Some("PDF header".to_string()),
                        snippet: session.uploaded_filename.clone(),
                    });
                }
            }
        }

        // CheckFileextensionwhether HighRiskType(Key/ /data wait)
        // Note: CheckFileNameKeywords(" Same"/" table"wait),Sensitive ByFileContent DLP
        if let Some(ref filename) = session.uploaded_filename {
            if let Some(reason) = Self::is_sensitive_extension(filename) {
                dlp_matches.push("sensitive_extension".to_string());
                evidence.push(Evidence {
                    description: reason,
                    location: Some("filename".to_string()),
                    snippet: Some(filename.clone()),
                });
            }

            evidence.push(Evidence {
                description: format!(
                    "UploadFile: {} (largesmall: {} Byte)",
                    filename,
                    session.uploaded_file_size.unwrap_or(0)
                ),
                location: Some("file upload".to_string()),
                snippet: None,
            });
        }

        // 3. DLP (UploadFileContent Sensitivedatadetect)

        // strategy:
        // 1. File (DOCX/XLSX/PDF/OLE) -> Decompress/ParseExtractText
        // 2. Plain text body (body_is_binary=false) -> Connect
        // 3. 2Base/RadixFile (PNG/JPEG/EXE/Unknown2Base/Radix) -> hopsText DLP(Byte only)
        {
            let mut scanned = false;

            // : whether 2Base/RadixFile(Used for step 3b And FP-1)
            // unwrap_or(false): UnknownFileTypeDefault (possibly sniffer ofPlain text)
            let is_binary_file = session.body_is_binary
                || session
                    .detected_file_type
                    .map(|ft| !ft.is_text_scannable())
                    .unwrap_or(false);

            // 3a. FileDocumentationExtract (DOCX/XLSX/PPTX/PDF/OLE)
            if session
                .detected_file_type
                .map(|ft| ft.is_extractable_document())
                .unwrap_or(false)
            {
                let raw_bytes = Self::read_body_bytes(session);
                if !raw_bytes.is_empty()
                    && let Some(extracted_text) = super::document_extract::extract_text(
                        &raw_bytes,
                        session.detected_file_type,
                    )
                {
                    scanned = true;
                    let dlp_result = dlp::scan_text(&extracted_text);
                    if !dlp_result.is_empty() {
                        dlp_for_jrt = Some(dlp_result.clone());
                        dlp_matches.extend(dlp_result.matches);
                        for (dtype, values) in &dlp_result.details {
                            let snippet = super::extract_snippet(&extracted_text, values);
                            evidence.push(Evidence {
                                description: format!(
                                    "File content contains {} ({} occurrences): {}",
                                    super::dlp_type_cn(dtype),
                                    values.len(),
                                    values.join(", ")
                                ),
                                location: Some("DocumentationContent".to_string()),
                                snippet,
                            });
                        }
                    }
                }
            }

            // 3b. FileofPlain text DLP
            // 2Base/RadixFileExecuteline: Plain text (body_is_binary=false) And octet-stream Uploadof TXT/CSV
            // 2Base/RadixFile (PNG/JPEG/EXE/Unknown2Base/Radix) Byte only, Connecthops
            if !scanned && !is_binary_file {
                let body_text = session.request_body.clone().or_else(|| {
                    session
                        .body_temp_file
                        .as_ref()
                        .and_then(|path| Self::read_body_for_dlp(path))
                });

                if let Some(ref body) = body_text
                    && !body.is_empty()
                {
                    let dlp_text = dlp::extract_dlp_text(body, &session.uri);
                    let dlp_result = dlp::scan_text(&dlp_text);
                    if !dlp_result.is_empty() {
                        dlp_for_jrt = Some(dlp_result.clone());
                        dlp_matches.extend(dlp_result.matches);
                        for (dtype, values) in &dlp_result.details {
                            let snippet = super::extract_snippet(&dlp_text, values);
                            evidence.push(Evidence {
                                description: format!(
                                    "File content contains {} ({} occurrences): {}",
                                    super::dlp_type_cn(dtype),
                                    values.len(),
                                    values.join(", ")
                                ),
                                location: Some("FileContent".to_string()),
                                snippet,
                            });
                        }
                    }
                }
            }
        }

        // FP-1: swift_code 2Base/RadixFile(Image/PDF Byte/Unknown2Base/Radix)Medium match
        // When swift_code 1 DLP Medium (MediumDescription ContainsSensitivedata)
        // : is_binary_file already step 3 first; step 3a ExtractofDocumentationText Security
        let is_binary_for_fp1 = session.body_is_binary
            || session
                .detected_file_type
                .map(|ft| !ft.is_text_scannable())
                .unwrap_or(true);
        if is_binary_for_fp1
            && dlp_matches.len() == 1
            && dlp_matches.contains(&"swift_code".to_string())
        {
            dlp_matches.clear();
            evidence.retain(|e| {
                e.location.as_deref() != Some("FileContent")
                    && e.location.as_deref() != Some("DocumentationContent")
            });
        }

        // FP-2: employee_info ByFileNameMediumof" bit/ "waitGeneral
        // multipart Uploadof body packetContains filename,DLP body Mediummatch multipart header MediumofFileName
        // if employee_info 1 Medium According to snippet onlyContainsFileNameDistrict,
        if dlp_matches == ["employee_info"] {
            let only_filename_match = evidence.iter().all(|e| {
                if e.location.as_deref() == Some("FileContent") {
                    // snippet MediumContains multipart form-data / filename -> FileName match
                    e.snippet
                        .as_deref()
                        .map(|s| s.contains("filename=") || s.contains("form-data"))
                        .unwrap_or(false)
                } else {
                    true // content Typeof evidence(if file upload)
                }
            });
            if only_filename_match {
                dlp_matches.clear();
                evidence.retain(|e| e.location.as_deref() != Some("FileContent"));
            }
        }

        // if not SensitiveFound,
        if dlp_matches.is_empty() {
            return None;
        }

        // Critical: Executable file/ /EncryptCompresspacket -> High (Securitystrategy)
        // By dataof High JR/T level (JR/T 0197-2020)
        let has_executable = dlp_matches.contains(&"executable_upload".to_string());
        let has_mismatch = dlp_matches.contains(&"file_type_mismatch".to_string());
        let has_encrypted = dlp_matches.contains(&"encrypted_archive".to_string())
            || dlp_matches.contains(&"encrypted_pdf".to_string());
        let severity = if has_executable || has_mismatch || has_encrypted {
            DataSecuritySeverity::High
        } else {
            super::jrt::severity_from_max_jrt_level(&dlp_matches)
        };

        let filename_info = session
            .uploaded_filename
            .as_deref()
            .unwrap_or("UnknownFile");

        let user = dlp::extract_user(session);
        let summary = format!(
            "File transit risk: {} from {} uploaded sensitive file \"{}\"",
            user.as_deref().unwrap_or("Unknownuser"),
            session.client_ip,
            filename_info
        );

        Some((
            DataSecurityIncident {
                id: vigilyx_core::fast_uuid(),
                http_session_id: session.id,
                incident_type: DataSecurityIncidentType::FileTransitAbuse,
                severity,
                confidence: 0.85,
                summary,
                evidence,
                details: None,
                dlp_matches,
                client_ip: session.client_ip.clone(),
                detected_user: dlp::extract_user(session),
                request_url: session.uri.clone(),
                host: session.host.clone(),
                method: session.method.to_string(),
                created_at: Utc::now(),
            },
            dlp_for_jrt,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vigilyx_core::magic_bytes::DetectedFileType;

    fn make_session(uri: &str, filename: Option<&str>, body: Option<&str>) -> HttpSession {
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            uri.to_string(),
        );
        s.content_type = Some("multipart/form-data; boundary=abc".to_string());
        s.uploaded_filename = filename.map(|f| f.to_string());
        s.uploaded_file_size = Some(1024);
        s.request_body = body.map(|b| b.to_string());
        s
    }

    #[test]
    fn test_file_transit_filename_keyword_no_longer_triggers() {
        // FileNameKeywords(" Name ") Alert, Content DLP
        let detector = FileTransitDetector::new();
        let session = make_session("/netdisk/upload", Some("公司客户Name单2026.xlsx"), None);
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "FileNameKeywords不应单独触发Alert，Sensitive性ByContent DLP 决定"
        );
    }

    #[test]
    fn test_file_transit_sensitive_extension_triggers() {
        // HighRiskextension(.sql)
        let detector = FileTransitDetector::new();
        let session = make_session("/netdisk/upload", Some("database_backup.sql"), None);
        let result = detector.analyze(&session);
        assert!(result.is_some(), "HighRiskextension .sql 应触发Alert");
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"sensitive_extension".to_string())
        );
    }

    #[test]
    fn test_file_transit_upload_with_sensitive_content() {
        let detector = FileTransitDetector::new();
        let session = make_session(
            "/file/upload",
            Some("data.txt"),
            // 4532015112830366 is Luhn-valid
            Some("员工Info: 4532015112830366"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
    }

    #[test]
    fn test_file_transit_upload_image_no_alert() {
        let detector = FileTransitDetector::new();
        let session = make_session("/netdisk/upload", Some("vacation_photo.jpg"), None);
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_transit_non_upload_uri_no_alert() {
        let detector = FileTransitDetector::new();
        let session = make_session("/inbox/list", Some("机密合Same.pdf"), None);
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_transit_get_request_no_alert() {
        let mut session = make_session("/netdisk/upload", Some("secret.pdf"), None);
        session.method = HttpMethod::Get;
        let detector = FileTransitDetector::new();
        let result = detector.analyze(&session);
        assert!(result.is_none());
    }

    #[test]
    fn test_file_transit_coremail_binary_chunk_no_alert() {
        // Coremail AttachmentChunkedUpload (application/octet-stream) Alert
        let detector = FileTransitDetector::new();
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/coremail/XT/jsp/upload.jsp?sid=abc&func=directdata&attachmentId=1&composeId=xyz&offset=0".to_string(),
        );
        s.content_type = Some("application/octet-stream".to_string());
        s.request_body_size = 366566;
        // body,DLP
        let result = detector.analyze(&s);
        assert!(
            result.is_none(),
            "Coremail binary chunk upload without sensitive content should NOT alert"
        );
    }

    // Coremail directData ()

    #[test]
    fn test_coremail_directdata_with_sensitive_txt_triggers_alert() {
        // : txt
        // upload.jsp?func=directData + application/octet-stream +
        let detector = FileTransitDetector::new();
        let mut s = HttpSession::new(
            "10.1.141.140".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/coremail/XT/jsp/upload.jsp?sid=BAQkfBKK&func=directData&attachmentId=1&composeId=c%3Anf%3A8628193&offset=0".to_string(),
        );
        s.content_type = Some("application/octet-stream".to_string());
        s.uploaded_filename = Some("DLP测试_敏感数据样本.txt".to_string());
        s.body_is_binary = false;

        // GB 11643-1999
        // 4532015112830366 is Luhn-valid
        s.request_body = Some(
            "客户: 110101199001011237\n\
             信用卡: 4532015112830366\n\
             Password: MyBankP@ss123"
                .to_string(),
        );
        s.request_body_size = s.request_body.as_ref().map(|b| b.len()).unwrap_or(0);

        let result = detector.analyze(&s);
        assert!(
            result.is_some(),
            "Coremail directData upload with sensitive content MUST trigger alert"
        );
        let (incident, dlp_opt) = result.unwrap();
        assert!(
            incident.dlp_matches.contains(&"id_number".to_string()),
            "Should detect Chinese ID numbers"
        );
        assert!(
            incident.dlp_matches.contains(&"credit_card".to_string()),
            "Should detect credit card numbers"
        );
        assert!(
            dlp_opt.is_some(),
            "Should return DLP result for JRT tracking"
        );
    }

    #[test]
    fn test_coremail_directdata_without_filename_still_detects() {
        // uploaded_filename(prepare),
        let detector = FileTransitDetector::new();
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/coremail/XT/jsp/upload.jsp?func=directData&sid=abc&composeId=123&attachmentId=1&offset=0".to_string(),
        );
        s.content_type = Some("application/octet-stream".to_string());
        s.uploaded_filename = None;
        s.body_is_binary = false;
        s.request_body = Some("密码: Test@2026Secure!\nPassword: MyBankP@ss123".to_string());

        let result = detector.analyze(&s);
        assert!(
            result.is_some(),
            "directData without filename but with credentials should still alert"
        );
        let (incident, _) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"credential_leak".to_string())
        );
    }

    #[test]
    fn test_coremail_directdata_clean_content_no_alert() {
        // directData ->
        let detector = FileTransitDetector::new();
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/coremail/XT/jsp/upload.jsp?func=directData&sid=abc&composeId=123&attachmentId=1&offset=0".to_string(),
        );
        s.content_type = Some("application/octet-stream".to_string());
        s.uploaded_filename = Some("会议纪要.txt".to_string());
        s.body_is_binary = false;
        s.request_body = Some("本次会议讨论了下季度工作计划。参会人员达成一致意见。".to_string());

        let result = detector.analyze(&s);
        assert!(
            result.is_none(),
            "directData upload with clean content should NOT alert"
        );
    }

    #[test]
    fn test_coremail_directdata_has_file_gate_passes() {
        // func=directdata URL has_file
        let detector = FileTransitDetector::new();
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/coremail/XT/jsp/upload.jsp?func=directData&sid=abc".to_string(),
        );
        s.content_type = Some("application/octet-stream".to_string());
        s.uploaded_filename = None;
        // multipart, uploaded_filename, URI func=directdata
        // has_file true(is_coremail_direct_upload)
        s.body_is_binary = false;
        // 4532015112830366 is Luhn-valid
        s.request_body = Some("信用卡: 4532015112830366".to_string());

        let result = detector.analyze(&s);
        assert!(
            result.is_some(),
            "func=directdata should pass has_file gate even without multipart/filename"
        );
    }

    #[test]
    fn test_file_transit_normal_office_file_no_alert() {
        let detector = FileTransitDetector::new();
        // FileUpload SensitiveContent -> Alert(FileName)
        let session = make_session("/file/upload", Some("report.xlsx"), None);
        let result = detector.analyze(&session);
        assert!(result.is_none(), "普通办公File无SensitiveContent不应Alert");
    }

    // Executable fileUploaddetectTest

    fn make_session_with_file_type(
        uri: &str,
        filename: Option<&str>,
        file_type: Option<DetectedFileType>,
        mismatch: Option<&str>,
        body_is_binary: bool,
        body: Option<&str>,
    ) -> HttpSession {
        let mut s = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            uri.to_string(),
        );
        s.content_type = Some("multipart/form-data; boundary=abc".to_string());
        s.uploaded_filename = filename.map(|f| f.to_string());
        s.uploaded_file_size = Some(1024);
        s.detected_file_type = file_type;
        s.file_type_mismatch = mismatch.map(|m| m.to_string());
        s.body_is_binary = body_is_binary;
        s.request_body = body.map(|b| b.to_string());
        s.request_body_size = body.map(|b| b.len()).unwrap_or(1024);
        s
    }

    #[test]
    fn test_file_transit_pe_disguised_as_xlsx_high_severity() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("financial_report.xlsx"),
            Some(DetectedFileType::PeExecutable),
            Some("声称 .xlsx But实际  PE Executable"),
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(result.is_some(), "PE disguised as xlsx should be detected");
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"executable_upload".to_string()),
            "Should contain executable_upload"
        );
        assert!(
            incident
                .dlp_matches
                .contains(&"file_type_mismatch".to_string()),
            "Should contain file_type_mismatch"
        );
        assert_eq!(incident.severity, DataSecuritySeverity::High);
    }

    #[test]
    fn test_file_transit_elf_upload_detected() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/netdisk/upload",
            Some("backdoor"),
            Some(DetectedFileType::ElfBinary),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(result.is_some(), "ELF binary upload should be detected");
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"executable_upload".to_string())
        );
    }

    #[test]
    fn test_file_transit_binary_body_skips_dlp() {
        let detector = FileTransitDetector::new();
        // body_is_binary = true request_body = None -> DLP line
        let session = make_session_with_file_type(
            "/file/upload",
            Some("data.bin"),
            Some(DetectedFileType::UnknownBinary),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        // UnknownBinary HighRisk + FileName SensitiveKeywords + DLP -> match -> None
        assert!(
            result.is_none(),
            "Binary body with no sensitive info should not alert"
        );
    }

    #[test]
    fn test_file_transit_text_body_still_does_dlp() {
        let detector = FileTransitDetector::new();
        // body_is_binary = false -> DLP Normal line
        let session = make_session_with_file_type(
            "/file/upload",
            Some("notes.txt"),
            Some(DetectedFileType::PlainText),
            None,
            false,
            // 4532015112830366 is Luhn-valid
            Some("客户信用Card number: 4532015112830366"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Text body with credit card should trigger DLP"
        );
        let (incident, _dlp) = result.unwrap();
        assert!(incident.dlp_matches.contains(&"credit_card".to_string()));
    }

    #[test]
    fn test_file_transit_zip_as_docx_no_alert() {
        let detector = FileTransitDetector::new();
        // ZIP.docx Normalof (OOXML),FileNameContains" Same" Do not trigger(FileNameKeywords)
        let session = make_session_with_file_type(
            "/file/upload",
            Some("合Same草案.docx"),
            Some(DetectedFileType::ZipArchive),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Normal docx Upload不应触发，Sensitive性ByContent DLP 决定"
        );
    }

    #[test]
    fn test_file_transit_jpeg_upload_no_alert() {
        let detector = FileTransitDetector::new();
        // JPEG ImageUpload, SensitiveFileName -> Alert
        let session = make_session_with_file_type(
            "/netdisk/upload",
            Some("vacation.jpg"),
            Some(DetectedFileType::Jpeg),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "JPEG upload with normal filename should not alert"
        );
    }

    #[test]
    fn test_file_transit_pe_disguised_as_jpg_critical() {
        let detector = FileTransitDetector::new();
        // PE jpg -> executable_upload + file_type_mismatch
        let session = make_session_with_file_type(
            "/file/upload",
            Some("photo.jpg"),
            Some(DetectedFileType::PeExecutable),
            Some("声称 .jpg But实际  PE Executable"),
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(result.is_some(), "PE disguised as jpg should be detected");
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"executable_upload".to_string())
        );
        assert!(
            incident
                .dlp_matches
                .contains(&"file_type_mismatch".to_string())
        );
        // 0.5 + 0.35 = 0.85 -> High
        assert_eq!(incident.severity, DataSecuritySeverity::High);
    }

    #[test]
    fn test_file_transit_windows_shortcut_detected() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("readme.lnk"),
            Some(DetectedFileType::WindowsShortcut),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(result.is_some(), "Windows shortcut should be detected");
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"executable_upload".to_string())
        );
    }

    // body_temp_file DLP Test

    #[test]
    fn test_file_transit_dlp_from_temp_file() {
        let detector = FileTransitDetector::new();

        // Create temp file in the allowed base directory so validate_temp_path passes.
        let base = std::path::Path::new("data/tmp/http");
        std::fs::create_dir_all(base).unwrap();
        let file_path = base.join("test_body_dlp.bin");
        // 4532015112830366 is Luhn-valid
        std::fs::write(
            &file_path,
            "Internal data: credit card number 4532015112830366",
        )
        .unwrap();

        let mut session = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/file/upload".to_string(),
        );
        session.content_type = Some("multipart/form-data; boundary=abc".to_string());
        session.uploaded_filename = Some("data.txt".to_string());
        session.uploaded_file_size = Some(512 * 1024);
        session.body_is_binary = false;
        session.request_body = None; // no in-memory body, force temp file read
        session.body_temp_file = Some(file_path.to_string_lossy().to_string());

        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Should detect sensitive content from temp file"
        );
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident.dlp_matches.contains(&"credit_card".to_string()),
            "Should detect credit card from temp file body"
        );
        // Cleanup temp file
        let _ = std::fs::remove_file("data/tmp/http/test_body_dlp.bin");
    }

    #[test]
    fn test_file_transit_dlp_prefers_memory_body() {
        let detector = FileTransitDetector::new();

        // tempFile SensitiveContent
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("empty.bin");
        std::fs::write(&file_path, "nothing here").unwrap();

        let mut session = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/file/upload".to_string(),
        );
        session.content_type = Some("multipart/form-data; boundary=abc".to_string());
        session.uploaded_filename = Some("report.txt".to_string());
        session.uploaded_file_size = Some(1024);
        session.body_is_binary = false;
        // Memory body Sensitivedata
        // 4532015112830366 is Luhn-valid
        session.request_body = Some("信用卡: 4532015112830366".to_string());
        session.body_temp_file = Some(file_path.to_string_lossy().to_string());

        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident.dlp_matches.contains(&"credit_card".to_string()),
            "Should use memory body (has credit card), not temp file"
        );
    }

    // EncryptCompresspacketdetectTest

    #[test]
    fn test_file_transit_encrypted_zip_detected() {
        let detector = FileTransitDetector::new();
        // constructEncrypt ZIP offirst 8 Byte body
        let encrypted_zip_header = "\x50\x4B\x03\x04\x14\x00\x01\x00";
        let mut session = make_session_with_file_type(
            "/file/upload",
            Some("data.zip"),
            Some(DetectedFileType::ZipArchive),
            None,
            false,
            Some(encrypted_zip_header),
        );
        session.body_is_binary = true;
        // request_body Need/RequirepacketContains Byte; String
        // Connect request_body = Some(String) 2Base/RadixHeader
        session.request_body = Some(
            String::from_utf8_lossy(&[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00]).into_owned(),
        );

        let result = detector.analyze(&session);
        assert!(result.is_some(), "Encrypted ZIP upload should be detected");
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"encrypted_archive".to_string()),
            "Should contain encrypted_archive match"
        );
        assert_eq!(incident.severity, DataSecuritySeverity::High);
    }

    #[test]
    fn test_file_transit_unencrypted_zip_no_encrypted_flag() {
        let detector = FileTransitDetector::new();
        let mut session = make_session_with_file_type(
            "/file/upload",
            Some("photos.zip"),
            Some(DetectedFileType::ZipArchive),
            None,
            true,
            None,
        );
        // Set Encryptof ZIP header body
        session.request_body = Some(
            String::from_utf8_lossy(&[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]).into_owned(),
        );

        let result = detector.analyze(&session);
        // FileName SensitiveKeywords, Encrypt -> Alert
        assert!(
            result.is_none(),
            "Unencrypted ZIP with normal filename should not alert"
        );
    }

    #[test]
    fn test_file_transit_coremail_upload_jsp_uri_matches() {
        // Verify upload.jsp is now recognized as upload URI
        assert!(FileTransitDetector::is_upload_uri(
            "/coremail/XT/jsp/upload.jsp?sid=abc&func=directdata"
        ));
        assert!(FileTransitDetector::is_upload_uri(
            "/api?func=directdata&attachmentId=1"
        ));
    }

    // Test: URI match

    #[test]
    fn test_file_transit_uri_case_insensitive() {
        assert!(FileTransitDetector::is_upload_uri("/FILE/UPLOAD"));
        assert!(FileTransitDetector::is_upload_uri("/Netdisk/Upload"));
    }

    #[test]
    fn test_file_transit_non_upload_uri() {
        assert!(!FileTransitDetector::is_upload_uri("/inbox/list"));
        assert!(!FileTransitDetector::is_upload_uri("/compose/send"));
        assert!(!FileTransitDetector::is_upload_uri("/api/mail/read"));
    }

    #[test]
    fn test_file_transit_various_upload_uris() {
        let uris = [
            "/file/upload",
            "/netdisk/upload",
            "/attachment/upload",
            "/webmail/uploadFile",
        ];
        for uri in uris {
            assert!(
                FileTransitDetector::is_upload_uri(uri),
                "URI '{}' should be recognized as upload",
                uri
            );
        }
    }

    // Test: FileTypedetect

    #[test]
    fn test_file_transit_macho_binary_detected() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("app"),
            Some(DetectedFileType::MachOBinary),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(result.is_some(), "Mach-O binary upload should be detected");
        let (incident, _) = result.unwrap();
        assert!(
            incident
                .dlp_matches
                .contains(&"executable_upload".to_string())
        );
    }

    #[test]
    fn test_file_transit_java_class_detected() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("Exploit.class"),
            Some(DetectedFileType::JavaClass),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Java class file upload should be detected"
        );
    }

    #[test]
    fn test_file_transit_pdf_normal_no_alert() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("report.pdf"),
            Some(DetectedFileType::Pdf),
            None,
            true,
            None,
        );
        let result = detector.analyze(&session);
        // PDF HighRiskFileType, DLP Medium Alert
        assert!(
            result.is_none(),
            "Normal PDF upload without DLP content should not alert"
        );
    }

    // Test: DLP Content

    #[test]
    fn test_file_transit_text_with_multiple_dlp() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("data.csv"),
            Some(DetectedFileType::PlainText),
            None,
            false,
            Some("客户: ID card 110101199001011237, Password: admin123"),
        );
        let result = detector.analyze(&session);
        assert!(result.is_some());
        let (incident, dlp_opt) = result.unwrap();
        assert!(incident.dlp_matches.contains(&"id_number".to_string()));
        assert!(
            incident
                .dlp_matches
                .contains(&"credential_leak".to_string())
        );
        assert!(
            dlp_opt.is_some(),
            "Should return DLP result for JRT tracking"
        );
    }

    #[test]
    fn test_file_transit_text_clean_content_no_alert() {
        let detector = FileTransitDetector::new();
        let session = make_session_with_file_type(
            "/file/upload",
            Some("readme.txt"),
            Some(DetectedFileType::PlainText),
            None,
            false,
            Some("这是1普通ofTextFile，not有SensitiveContent。"),
        );
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Text file without sensitive content should not alert"
        );
    }

    #[test]
    fn test_file_transit_get_request_ignored() {
        let detector = FileTransitDetector::new();
        let mut session = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Get,
            "/file/upload".to_string(),
        );
        session.content_type = Some("multipart/form-data".to_string());
        session.uploaded_filename = Some("secret.txt".to_string());
        session.request_body = Some("Password: admin123".to_string());
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "GET request should not trigger file transit detection"
        );
    }

    #[test]
    fn test_file_transit_no_file_at_all_no_alert() {
        // FileUpload(multipart, FileName) -> Do not trigger
        let detector = FileTransitDetector::new();
        let mut session = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/file/upload".to_string(),
        );
        session.content_type = Some("application/json".to_string());
        session.uploaded_filename = None;
        session.request_body = Some("Password: admin123".to_string());
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Non-multipart, no-filename POST should not trigger file transit"
        );
    }

    // 2Base/RadixFilehops Step 3b DLP Test

    #[test]
    fn test_binary_file_with_swift_pattern_skips_dlp() {
        // 2Base/RadixFile body MediumpacketContains match SWIFT Code/DigitofByte -> step 3b hops, DLP
        let detector = FileTransitDetector::new();
        let mut session = make_session_with_file_type(
            "/file/upload",
            Some("image.png"),
            Some(DetectedFileType::Png),
            None,
            true,
            // 2Base/RadixMediumof SWIFT match
            Some("binary header BKCHCNBJ more binary data"),
        );
        session.body_is_binary = true;
        let result = detector.analyze(&session);
        assert!(
            result.is_none(),
            "Binary PNG with SWIFT-like pattern in raw bytes should NOT trigger DLP"
        );
    }

    #[test]
    fn test_unknown_filetype_nonbinary_still_scans() {
        // detected_file_type=None + body_is_binary=false -> possibly ofPlain text, Normal DLP
        let detector = FileTransitDetector::new();
        let mut session = HttpSession::new(
            "192.168.1.100".to_string(),
            12345,
            "10.0.0.1".to_string(),
            80,
            HttpMethod::Post,
            "/file/upload".to_string(),
        );
        session.content_type = Some("multipart/form-data; boundary=abc".to_string());
        session.uploaded_filename = Some("data.csv".to_string());
        session.uploaded_file_size = Some(1024);
        session.detected_file_type = None; // sniffer
        session.body_is_binary = false;
        // 4532015112830366 is Luhn-valid
        session.request_body = Some("客户信用Card number: 4532015112830366".to_string());
        let result = detector.analyze(&session);
        assert!(
            result.is_some(),
            "Unknown file type with body_is_binary=false should still run DLP"
        );
        let (incident, _dlp) = result.unwrap();
        assert!(
            incident.dlp_matches.contains(&"credit_card".to_string()),
            "Should detect credit card in non-binary unknown file"
        );
    }
}
