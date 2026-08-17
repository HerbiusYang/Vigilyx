//! Bounded, format-aware attachment inspection used to validate executable
//! payload claims before YARA evidence is allowed to trigger a hard risk floor.
//!
//! This module never executes or writes untrusted content. It extracts only a
//! bounded set of in-memory PDF streams and ZIP/OOXML members, then validates
//! PE headers structurally inside each decoded byte stream.

use std::io::{Cursor, Read};

use flate2::read::{GzDecoder, ZlibDecoder};
use vigilyx_core::magic_bytes::DetectedFileType;

const MAX_PDF_STREAMS: usize = 128;
const MAX_ARCHIVE_ENTRIES: usize = 128;
const MAX_NESTED_ARCHIVE_DEPTH: usize = 2;
const MAX_LAYER_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_DECODED_BYTES: usize = 64 * 1024 * 1024;
const MAX_PE_CANDIDATES: usize = 4096;
const MAX_PE_FINDINGS_PER_LAYER: usize = 4;

const ONENOTE_MAGIC: &[u8] = &[0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    PdfStream {
        embedded_file: bool,
        automatic_action: bool,
    },
    ArchiveEntry {
        office_container: bool,
        suspicious_name: bool,
        depth: usize,
    },
}

#[derive(Debug, Clone)]
pub struct ScanLayer {
    pub location: String,
    pub data: Vec<u8>,
    pub kind: LayerKind,
}

#[derive(Debug, Clone)]
pub struct CoverageGap {
    pub location: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct StructuralFinding {
    pub rule_name: &'static str,
    pub severity: &'static str,
    pub confidence: f64,
    pub categories: Vec<&'static str>,
    pub description: String,
    pub location: String,
    pub offset: usize,
    pub validation: String,
}

#[derive(Debug, Default)]
pub struct StructuralInspection {
    pub layers: Vec<ScanLayer>,
    pub findings: Vec<StructuralFinding>,
    pub coverage_gaps: Vec<CoverageGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeInfo {
    pub offset: usize,
    pub pe_offset: usize,
    pub machine: u16,
    pub sections: u16,
    pub optional_magic: u16,
    pub is_dll: bool,
}

#[derive(Default)]
struct DecodeBudget {
    decoded_bytes: usize,
}

impl DecodeBudget {
    fn reserve(&mut self, size: usize) -> bool {
        let Some(total) = self.decoded_bytes.checked_add(size) else {
            return false;
        };
        if total > MAX_TOTAL_DECODED_BYTES {
            return false;
        }
        self.decoded_bytes = total;
        true
    }
}

pub fn inspect_attachment(filename: &str, data: &[u8]) -> StructuralInspection {
    let mut inspection = StructuralInspection::default();
    let mut budget = DecodeBudget::default();
    let extension = file_extension(filename);
    let is_pdf = has_pdf_header(data);
    let zip_prefixed = data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06");
    let trailing_eocd = vigilyx_core::magic_bytes::find_trailing_zip_eocd(data);
    // Polyglot: no ZIP magic at offset 0, but a trailing EOCD record means
    // archive tools (7-Zip, Windows Explorer) still unpack the archive from
    // the tail — `cat photo.jpg payload.zip > invoice.jpg` must not sail
    // through as a plain image.
    let zip_polyglot = !zip_prefixed && trailing_eocd.is_some();
    let is_zip = zip_prefixed || zip_polyglot;
    let is_onenote = data.starts_with(ONENOTE_MAGIC);
    let detected_type = vigilyx_core::magic_bytes::detect_file_type(data);

    if is_pdf {
        // Token checks run on the `#hh`-decoded view: `/Encrypt` spelled as
        // `/#45ncrypt` resolves back to the real name in every PDF reader.
        let name_normalized = vigilyx_core::magic_bytes::normalize_pdf_name_escapes(data);
        if contains_pdf_name(&name_normalized, b"/Encrypt") {
            inspection.coverage_gaps.push(CoverageGap {
                location: format!("attachment:{}:pdf", sanitize_component(filename)),
                reason: "encrypted_pdf",
            });
        } else {
            collect_pdf_layers(filename, data, &mut inspection, &mut budget);
        }
    } else if is_zip {
        if let Some(eocd_offset) = trailing_eocd.filter(|_| zip_polyglot) {
            inspection.findings.push(StructuralFinding {
                rule_name: "Polyglot_Zip_Appended_Archive",
                severity: "high",
                confidence: 0.90,
                categories: vec!["polyglot_container", "executable_disguise"],
                description: "Attachment has non-ZIP leading magic but carries a trailing ZIP End Of Central Directory record — a polyglot (e.g. image+archive) that archive tools unpack from the tail".to_string(),
                location: format!("attachment:{}", sanitize_component(filename)),
                offset: eocd_offset,
                validation: format!(
                    "EOCD@{}; archive resolves from the tail while offset-0 magic reads as a different format",
                    eocd_offset
                ),
            });
        }
        let office_container = is_office_zip_extension(extension);
        collect_zip_layers(
            filename,
            data,
            office_container,
            0,
            &mut inspection,
            &mut budget,
        );
    } else if matches!(
        detected_type,
        Some(DetectedFileType::RarArchive | DetectedFileType::SevenZipArchive)
    ) {
        // RAR/7z are recognizable but have no decode path here. Without an
        // explicit coverage-gap marker, an unencrypted invoice.rar carrying
        // a lure document plus payload.exe reported "no anomalies".
        inspection.coverage_gaps.push(CoverageGap {
            location: format!("attachment:{}", sanitize_component(filename)),
            reason: "unsupported_archive_format",
        });
    } else if matches!(detected_type, Some(DetectedFileType::Gzip)) {
        collect_gzip_layer(filename, data, &mut inspection, &mut budget);
    }

    // Direct files and non-container polyglots are validated against their
    // original byte stream. PDF and ZIP compressed bytes are deliberately not
    // scanned as PE candidates; their decoded layers are inspected below.
    // A ZIP polyglot's prefix bytes are NOT compressed container data (an SFX
    // stub or a prepended image), so the raw stream is still scanned to keep
    // pre-existing direct-PE detection strength.
    if !is_pdf && (!is_zip || zip_polyglot) {
        for pe in find_valid_pes(data)
            .into_iter()
            .take(MAX_PE_FINDINGS_PER_LAYER)
        {
            let finding = if is_onenote && pe.offset > 0 {
                StructuralFinding {
                    rule_name: "OneNote_Embedded_PE_Structurally_Valid",
                    severity: "high",
                    confidence: 0.95,
                    categories: vec!["verified_executable_payload", "onenote_embedded_executable"],
                    description: format!(
                        "OneNote attachment contains a structurally valid PE payload at offset {}",
                        pe.offset
                    ),
                    location: format!("attachment:{}", sanitize_component(filename)),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else if pe.offset == 0 && is_executable_extension(extension) {
                StructuralFinding {
                    rule_name: "PE_Attachment_Structurally_Valid",
                    severity: "high",
                    confidence: 0.94,
                    categories: vec!["verified_executable_payload", "executable_attachment"],
                    description: "Attachment is a structurally valid Windows PE executable"
                        .to_string(),
                    location: format!("attachment:{}", sanitize_component(filename)),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else if pe.offset == 0 {
                StructuralFinding {
                    rule_name: "PE_Masquerading_As_Document_Structurally_Valid",
                    severity: "critical",
                    confidence: 0.98,
                    categories: vec![
                        "verified_executable_payload",
                        "executable_disguise",
                        "verified_payload_anchor",
                    ],
                    description: format!(
                        "Structurally valid Windows PE executable is disguised as .{}",
                        if extension.is_empty() {
                            "unknown"
                        } else {
                            extension
                        }
                    ),
                    location: format!("attachment:{}", sanitize_component(filename)),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else {
                StructuralFinding {
                    rule_name: "PE_Polyglot_Structurally_Valid",
                    severity: "high",
                    confidence: 0.96,
                    categories: vec!["verified_executable_payload", "executable_polyglot"],
                    description: format!(
                        "Non-container attachment contains a structurally valid PE at offset {}",
                        pe.offset
                    ),
                    location: format!("attachment:{}", sanitize_component(filename)),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            };
            inspection.findings.push(finding);
        }
    }

    for layer in &inspection.layers {
        for pe in find_valid_pes(&layer.data)
            .into_iter()
            .take(MAX_PE_FINDINGS_PER_LAYER)
        {
            inspection.findings.push(finding_for_layer(layer, pe));
        }
    }

    inspection
}

fn finding_for_layer(layer: &ScanLayer, pe: PeInfo) -> StructuralFinding {
    match layer.kind {
        LayerKind::PdfStream {
            embedded_file,
            automatic_action,
        } => {
            if embedded_file && automatic_action {
                StructuralFinding {
                    rule_name: "PDF_AutoAction_Embedded_PE_Structurally_Valid",
                    severity: "high",
                    confidence: 0.97,
                    categories: vec![
                        "verified_executable_payload",
                        "pdf_embedded_executable",
                        "pdf_active_payload",
                    ],
                    description: "PDF contains both an automatic action and an embedded-file stream with a structurally valid PE payload".to_string(),
                    location: layer.location.clone(),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else if embedded_file {
                StructuralFinding {
                    rule_name: "PDF_Embedded_PE_Structurally_Valid",
                    severity: "high",
                    confidence: 0.95,
                    categories: vec!["verified_executable_payload", "pdf_embedded_executable"],
                    description:
                        "PDF embedded-file stream contains a structurally valid PE payload"
                            .to_string(),
                    location: layer.location.clone(),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else {
                StructuralFinding {
                    rule_name: "PDF_Hidden_PE_Stream_Structurally_Valid",
                    severity: "high",
                    confidence: 0.92,
                    categories: vec![
                        "verified_executable_payload",
                        "pdf_hidden_executable_stream",
                    ],
                    description: "Decoded PDF stream contains a structurally valid PE payload without an EmbeddedFile declaration".to_string(),
                    location: layer.location.clone(),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            }
        }
        LayerKind::ArchiveEntry {
            office_container,
            suspicious_name,
            depth,
        } => {
            if suspicious_name {
                StructuralFinding {
                    rule_name: "Document_Archive_Embedded_PE_Structurally_Valid",
                    severity: "high",
                    confidence: 0.96,
                    categories: vec![
                        "verified_executable_payload",
                        "document_embedded_executable",
                        "verified_payload_anchor",
                    ],
                    description: format!(
                        "Document/archive member contains a structurally valid PE payload (nesting depth {})",
                        depth
                    ),
                    location: layer.location.clone(),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else if office_container {
                StructuralFinding {
                    rule_name: "Office_Container_Embedded_PE_Structurally_Valid",
                    severity: "high",
                    confidence: 0.94,
                    categories: vec![
                        "verified_executable_payload",
                        "document_embedded_executable",
                    ],
                    description: format!(
                        "Office container member contains a structurally valid PE payload (nesting depth {})",
                        depth
                    ),
                    location: layer.location.clone(),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            } else {
                StructuralFinding {
                    rule_name: "Archive_Contains_PE_Structurally_Valid",
                    severity: "medium",
                    confidence: 0.88,
                    categories: vec!["verified_executable_payload", "archive_executable"],
                    description: format!(
                        "Archive member contains a structurally valid PE executable (nesting depth {})",
                        depth
                    ),
                    location: layer.location.clone(),
                    offset: pe.offset,
                    validation: pe_validation_summary(pe),
                }
            }
        }
    }
}

pub fn validate_pe_at(data: &[u8], offset: usize) -> Option<PeInfo> {
    let dos_end = offset.checked_add(0x40)?;
    if dos_end > data.len() || data.get(offset..offset + 2)? != b"MZ" {
        return None;
    }

    let e_lfanew = read_u32(data, offset.checked_add(0x3c)?)? as usize;
    if !(0x40..=0x10_0000).contains(&e_lfanew) {
        return None;
    }
    let pe_offset = offset.checked_add(e_lfanew)?;
    if data.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }

    let machine = read_u16(data, pe_offset.checked_add(4)?)?;
    if !is_known_pe_machine(machine) {
        return None;
    }
    let sections = read_u16(data, pe_offset.checked_add(6)?)?;
    if !(1..=96).contains(&sections) {
        return None;
    }
    let optional_size = read_u16(data, pe_offset.checked_add(20)?)? as usize;
    if !(96..=4096).contains(&optional_size) {
        return None;
    }
    let characteristics = read_u16(data, pe_offset.checked_add(22)?)?;
    if characteristics & 0x0002 == 0 {
        return None;
    }

    let optional_offset = pe_offset.checked_add(24)?;
    let optional_end = optional_offset.checked_add(optional_size)?;
    if optional_end > data.len() {
        return None;
    }
    let optional_magic = read_u16(data, optional_offset)?;
    let minimum_optional_size = match optional_magic {
        0x10b => 96,
        0x20b => 112,
        _ => return None,
    };
    if optional_size < minimum_optional_size {
        return None;
    }

    let size_of_image = read_u32(data, optional_offset.checked_add(56)?)? as usize;
    let size_of_headers = read_u32(data, optional_offset.checked_add(60)?)? as usize;
    if size_of_image == 0
        || size_of_headers == 0
        || size_of_headers > data.len().saturating_sub(offset)
    {
        return None;
    }

    let section_table_end = optional_end.checked_add(sections as usize * 40)?;
    if section_table_end > data.len() {
        return None;
    }
    let mut has_file_backed_section = false;
    for index in 0..sections as usize {
        let section = optional_end.checked_add(index * 40)?;
        let raw_size = read_u32(data, section.checked_add(16)?)? as usize;
        let raw_pointer = read_u32(data, section.checked_add(20)?)? as usize;
        if raw_size == 0 {
            continue;
        }
        let raw_start = offset.checked_add(raw_pointer)?;
        let raw_end = raw_start.checked_add(raw_size)?;
        if raw_pointer < size_of_headers || raw_end > data.len() {
            return None;
        }
        has_file_backed_section = true;
    }
    if !has_file_backed_section {
        return None;
    }

    Some(PeInfo {
        offset,
        pe_offset,
        machine,
        sections,
        optional_magic,
        is_dll: characteristics & 0x2000 != 0,
    })
}

fn find_valid_pes(data: &[u8]) -> Vec<PeInfo> {
    let mut results = Vec::new();
    let mut candidates = 0usize;
    if data.len() < 2 {
        return results;
    }
    for offset in 0..data.len() - 1 {
        if data[offset] != b'M' || data[offset + 1] != b'Z' {
            continue;
        }
        candidates += 1;
        if candidates > MAX_PE_CANDIDATES {
            break;
        }
        if let Some(pe) = validate_pe_at(data, offset) {
            results.push(pe);
            if results.len() >= MAX_PE_FINDINGS_PER_LAYER {
                break;
            }
        }
    }
    results
}

fn collect_pdf_layers(
    filename: &str,
    data: &[u8],
    inspection: &mut StructuralInspection,
    budget: &mut DecodeBudget,
) {
    let name_normalized = vigilyx_core::magic_bytes::normalize_pdf_name_escapes(data);
    let automatic_action = contains_pdf_name(&name_normalized, b"/Launch")
        || contains_pdf_name(&name_normalized, b"/OpenAction")
        || contains_pdf_name(&name_normalized, b"/AA");
    // Active-content tokens visible in the raw byte view are already covered
    // by the YARA PDF rules on the attachment root; only tokens that appear
    // solely inside a decoded stream (e.g. an ObjStm-compressed object, whose
    // decompressed layer no longer carries a %PDF anchor for those rules)
    // are "hidden" and reported here. `/OpenAction` alone stays quiet:
    // legitimate open-at-page actions are common in compressed object
    // streams, and it only counts alongside a hidden JS entry.
    const PDF_JS_ENTRY_TOKENS: &[&[u8]] = &[b"/JavaScript", b"/JS"];
    const PDF_RISKY_ACTION_TOKENS: &[&[u8]] = &[b"/Launch", b"/GoToE", b"/RichMedia"];
    let raw_js_visible = PDF_JS_ENTRY_TOKENS
        .iter()
        .any(|token| contains_pdf_name(&name_normalized, token));
    let raw_action_visible = PDF_RISKY_ACTION_TOKENS
        .iter()
        .any(|token| contains_pdf_name(&name_normalized, token));
    let raw_open_action_visible = contains_pdf_name(&name_normalized, b"/OpenAction");
    let mut hidden_active_content_flagged = false;
    let mut cursor = 0usize;
    let mut streams_seen = 0usize;

    while streams_seen < MAX_PDF_STREAMS {
        let Some(relative) = find_subslice(&data[cursor..], b"stream") else {
            break;
        };
        let stream_word = cursor + relative;
        cursor = stream_word.saturating_add(6);
        if !is_pdf_stream_token(data, stream_word) {
            continue;
        }
        let Some(stream_start) = pdf_stream_data_start(data, cursor) else {
            continue;
        };
        let Some(relative_end) = find_subslice(&data[stream_start..], b"endstream") else {
            inspection.coverage_gaps.push(CoverageGap {
                location: format!("attachment:{}:pdf_stream", sanitize_component(filename)),
                reason: "unterminated_pdf_stream",
            });
            break;
        };
        let stream_end = stream_start + relative_end;
        cursor = stream_end.saturating_add(9);
        streams_seen += 1;

        let dictionary_start = stream_word.saturating_sub(4096);
        let dictionary = &data[dictionary_start..stream_word];
        // Filter/name token checks tolerate `#hh` name escapes; stream offsets
        // still come from the raw bytes below.
        let dict_names = vigilyx_core::magic_bytes::normalize_pdf_name_escapes(dictionary);
        let dict_names = dict_names.as_ref();
        let embedded_file = contains_pdf_name(dict_names, b"/EmbeddedFile")
            || contains_pdf_name(dict_names, b"/FileAttachment");
        let flate = dict_names
            .windows(b"/FlateDecode".len())
            .any(|w| w == b"/FlateDecode");
        let dct = dict_names
            .windows(b"/DCTDecode".len())
            .any(|w| w == b"/DCTDecode")
            || dict_names
                .windows(b"/JPXDecode".len())
                .any(|w| w == b"/JPXDecode");
        let has_other_filter = dict_names
            .windows(b"/Filter".len())
            .any(|w| w == b"/Filter")
            && !flate
            && !dct;
        let object_id = pdf_object_id(dictionary).unwrap_or(streams_seen);
        let location = format!(
            "attachment:{}:pdf_object_{}",
            sanitize_component(filename),
            object_id
        );
        let raw = trim_pdf_stream_end(&data[stream_start..stream_end]);

        if dct && !embedded_file {
            continue;
        }
        if has_other_filter {
            if embedded_file {
                inspection.coverage_gaps.push(CoverageGap {
                    location,
                    reason: "unsupported_pdf_embedded_stream_filter",
                });
            }
            continue;
        }

        let decoded = if flate {
            match read_bounded(ZlibDecoder::new(raw), MAX_LAYER_BYTES) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    if embedded_file {
                        inspection
                            .coverage_gaps
                            .push(CoverageGap { location, reason });
                    }
                    continue;
                }
            }
        } else {
            if raw.len() > MAX_LAYER_BYTES {
                inspection.coverage_gaps.push(CoverageGap {
                    location,
                    reason: "pdf_stream_size_limit",
                });
                continue;
            }
            raw.to_vec()
        };

        if !budget.reserve(decoded.len()) {
            inspection.coverage_gaps.push(CoverageGap {
                location,
                reason: "deep_inspection_total_output_limit",
            });
            break;
        }
        if !hidden_active_content_flagged {
            let layer_names = vigilyx_core::magic_bytes::normalize_pdf_name_escapes(&decoded);
            let layer_names = layer_names.as_ref();
            let mut found_tokens: Vec<&'static str> = Vec::new();
            if !raw_js_visible {
                for token in ["/JavaScript", "/JS"] {
                    if contains_pdf_name(layer_names, token.as_bytes()) {
                        found_tokens.push(token);
                    }
                }
            }
            if !raw_action_visible {
                for token in ["/Launch", "/GoToE", "/RichMedia"] {
                    if contains_pdf_name(layer_names, token.as_bytes()) {
                        found_tokens.push(token);
                    }
                }
            }
            let js_entry = found_tokens
                .iter()
                .any(|token| matches!(*token, "/JavaScript" | "/JS"));
            let risky_action = found_tokens
                .iter()
                .any(|token| matches!(*token, "/Launch" | "/GoToE" | "/RichMedia"));
            let hidden_open_action = !raw_open_action_visible
                && contains_pdf_name(layer_names, b"/OpenAction");
            if hidden_open_action && js_entry {
                found_tokens.push("/OpenAction");
            }
            if js_entry || risky_action {
                inspection.findings.push(StructuralFinding {
                    rule_name: "PDF_Hidden_Active_Content",
                    severity: "high",
                    confidence: 0.85,
                    categories: vec!["pdf_hidden_active_content", "pdf_active_payload"],
                    description: format!(
                        "Decoded PDF stream contains active-content token(s) hidden from the raw byte view: {}",
                        found_tokens.join(", ")
                    ),
                    location: location.clone(),
                    offset: 0,
                    validation: "token visible only after stream decompression (object-stream concealment)"
                        .to_string(),
                });
                hidden_active_content_flagged = true;
            }
        }
        inspection.layers.push(ScanLayer {
            location,
            data: decoded,
            kind: LayerKind::PdfStream {
                embedded_file,
                automatic_action,
            },
        });
    }

    if streams_seen == MAX_PDF_STREAMS && find_subslice(&data[cursor..], b"stream").is_some() {
        inspection.coverage_gaps.push(CoverageGap {
            location: format!("attachment:{}:pdf", sanitize_component(filename)),
            reason: "pdf_stream_count_limit",
        });
    }
}

fn collect_zip_layers(
    container_name: &str,
    data: &[u8],
    office_container: bool,
    depth: usize,
    inspection: &mut StructuralInspection,
    budget: &mut DecodeBudget,
) {
    let mut archive = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(archive) => archive,
        Err(_) => {
            inspection.coverage_gaps.push(CoverageGap {
                location: format!("attachment:{}", sanitize_component(container_name)),
                reason: "malformed_or_truncated_zip",
            });
            return;
        }
    };
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        inspection.coverage_gaps.push(CoverageGap {
            location: format!("attachment:{}", sanitize_component(container_name)),
            reason: "archive_entry_count_limit",
        });
    }
    let entry_count = archive.len().min(MAX_ARCHIVE_ENTRIES);
    for index in 0..entry_count {
        // Read central-directory metadata without decrypting first. `by_index`
        // returns PASSWORD_REQUIRED before it can yield a ZipFile, which would
        // otherwise hide the fact that the coverage gap is encryption.
        let (entry_name, entry_size, encrypted, is_dir) = match archive.by_index_raw(index) {
            Ok(entry) => (
                sanitize_component(entry.name()),
                entry.size(),
                entry.encrypted(),
                entry.is_dir(),
            ),
            Err(_) => {
                inspection.coverage_gaps.push(CoverageGap {
                    location: format!(
                        "attachment:{}:entry_{}",
                        sanitize_component(container_name),
                        index
                    ),
                    reason: "archive_entry_open_failed",
                });
                continue;
            }
        };
        if is_dir {
            continue;
        }
        let location = format!(
            "attachment:{}:archive:{}",
            sanitize_component(container_name),
            entry_name
        );
        if encrypted {
            inspection.coverage_gaps.push(CoverageGap {
                location,
                reason: "encrypted_archive_entry",
            });
            continue;
        }
        let Ok(entry_size) = usize::try_from(entry_size) else {
            inspection.coverage_gaps.push(CoverageGap {
                location,
                reason: "archive_entry_size_overflow",
            });
            continue;
        };
        if entry_size > MAX_LAYER_BYTES {
            inspection.coverage_gaps.push(CoverageGap {
                location,
                reason: "archive_entry_size_limit",
            });
            continue;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(_) => {
                inspection.coverage_gaps.push(CoverageGap {
                    location,
                    reason: "archive_entry_open_failed",
                });
                continue;
            }
        };
        let bytes = match read_bounded(&mut entry, MAX_LAYER_BYTES) {
            Ok(bytes) => bytes,
            Err(reason) => {
                inspection
                    .coverage_gaps
                    .push(CoverageGap { location, reason });
                continue;
            }
        };
        if !budget.reserve(bytes.len()) {
            inspection.coverage_gaps.push(CoverageGap {
                location,
                reason: "deep_inspection_total_output_limit",
            });
            break;
        }

        let suspicious_name = has_suspicious_executable_name(&entry_name);
        inspection.layers.push(ScanLayer {
            location: location.clone(),
            data: bytes.clone(),
            kind: LayerKind::ArchiveEntry {
                office_container,
                suspicious_name,
                depth,
            },
        });

        if depth + 1 < MAX_NESTED_ARCHIVE_DEPTH && bytes.starts_with(b"PK\x03\x04") {
            collect_zip_layers(
                &format!("{}:{}", container_name, entry_name),
                &bytes,
                office_container,
                depth + 1,
                inspection,
                budget,
            );
        }
    }
}

fn collect_gzip_layer(
    filename: &str,
    data: &[u8],
    inspection: &mut StructuralInspection,
    budget: &mut DecodeBudget,
) {
    let location = format!("attachment:{}:gzip", sanitize_component(filename));
    let bytes = match read_bounded(GzDecoder::new(data), MAX_LAYER_BYTES) {
        Ok(bytes) => bytes,
        Err(reason) => {
            inspection
                .coverage_gaps
                .push(CoverageGap { location, reason });
            return;
        }
    };
    if !budget.reserve(bytes.len()) {
        inspection.coverage_gaps.push(CoverageGap {
            location,
            reason: "deep_inspection_total_output_limit",
        });
        return;
    }
    let inner_name = gzip_inner_name(filename);
    let suspicious_name = has_suspicious_executable_name(&inner_name);
    inspection.layers.push(ScanLayer {
        location: format!("{}:{}", location, sanitize_component(&inner_name)),
        data: bytes,
        kind: LayerKind::ArchiveEntry {
            office_container: false,
            suspicious_name,
            depth: 0,
        },
    });
}

fn gzip_inner_name(filename: &str) -> String {
    let lower = filename.to_ascii_lowercase();
    if let Some(stripped) = lower.strip_suffix(".tgz") {
        return format!("{stripped}.tar");
    }
    if let Some(stripped) = lower.strip_suffix(".gz") {
        return stripped.to_string();
    }
    filename.to_string()
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, &'static str> {    let mut bytes = Vec::new();
    match (&mut reader)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)
    {
        Ok(_) if bytes.len() <= limit => Ok(bytes),
        Ok(_) => Err("decoded_object_size_limit"),
        Err(_) => Err("decoded_object_read_failed"),
    }
}

fn pe_validation_summary(pe: PeInfo) -> String {
    format!(
        "MZ@{} -> PE@{}; machine=0x{:04x}; sections={}; optional=0x{:03x}; dll={}",
        pe.offset, pe.pe_offset, pe.machine, pe.sections, pe.optional_magic, pe.is_dll
    )
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn is_known_pe_machine(machine: u16) -> bool {
    matches!(
        machine,
        0x014c | 0x01c0 | 0x01c2 | 0x01c4 | 0x0200 | 0x8664 | 0xaa64
    )
}

fn has_pdf_header(data: &[u8]) -> bool {
    let end = data.len().min(1024);
    find_subslice(&data[..end], b"%PDF-").is_some()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty() && haystack.len() >= needle.len())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn contains_pdf_name(data: &[u8], name: &[u8]) -> bool {
    data.windows(name.len())
        .enumerate()
        .any(|(offset, window)| {
            if window != name {
                return false;
            }
            let before_ok = offset == 0 || is_pdf_delimiter(data[offset - 1]);
            let after = offset + name.len();
            let after_ok = after == data.len() || is_pdf_delimiter(data[after]);
            before_ok && after_ok
        })
}

fn is_pdf_delimiter(byte: u8) -> bool {
    byte.is_ascii_whitespace()
        || matches!(byte, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'%')
}

fn is_pdf_stream_token(data: &[u8], offset: usize) -> bool {
    let before_ok = offset == 0 || is_pdf_delimiter(data[offset - 1]);
    let after = offset + b"stream".len();
    let after_ok = data
        .get(after)
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n' | b' ' | b'\t'));
    before_ok && after_ok
}

fn pdf_stream_data_start(data: &[u8], mut offset: usize) -> Option<usize> {
    if let Some(b"\r\n") = data.get(offset..offset + 2) {
        return Some(offset + 2);
    }
    if data
        .get(offset)
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Some(offset + 1);
    }
    while data.get(offset).is_some_and(u8::is_ascii_whitespace) {
        offset += 1;
    }
    Some(offset)
}

fn trim_pdf_stream_end(mut data: &[u8]) -> &[u8] {
    while data
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        data = &data[..data.len() - 1];
    }
    data
}

fn pdf_object_id(dictionary: &[u8]) -> Option<usize> {
    let text = String::from_utf8_lossy(dictionary);
    let before_obj = text.rsplit_once(" obj")?.0;
    before_obj.split_whitespace().next_back()?.parse().ok()
}

fn file_extension(filename: &str) -> &str {
    filename
        .rsplit_once('.')
        .map(|(_, extension)| extension)
        .unwrap_or_default()
}

fn is_office_zip_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "pptm" | "odt" | "ods" | "odp"
    )
}

fn is_executable_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "exe" | "dll" | "scr" | "cpl" | "ocx" | "sys" | "com" | "xll" | "efi"
    )
}

fn has_suspicious_executable_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let executable = [".exe", ".dll", ".scr", ".cpl", ".xll", ".com"];
    let lure = [
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt",
    ];
    executable.iter().any(|ext| lower.ends_with(ext))
        && (lure.iter().any(|ext| lower.contains(&format!("{}.", ext)))
            || lower.contains("/embeddings/")
            || lower.contains("\\embeddings\\"))
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(180)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn minimal_pe() -> Vec<u8> {
        let mut data = vec![0u8; 0x400];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        data[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        data[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
        data[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        data[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        data[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        let section = 0x80 + 24 + 0xF0;
        data[section..section + 5].copy_from_slice(b".text");
        data[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        data[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data
    }

    fn flate_pdf(payload: &[u8], embedded: bool, automatic_action: bool) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Filter /FlateDecode ".to_vec();
        if embedded {
            pdf.extend_from_slice(b"/Type /EmbeddedFile ");
        }
        pdf.extend_from_slice(b">>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        if automatic_action {
            pdf.extend_from_slice(b"2 0 obj << /OpenAction 1 0 R >> endobj\n");
        }
        pdf.extend_from_slice(b"%%EOF\n");
        pdf
    }

    #[test]
    fn validates_real_pe_relationship_not_independent_magic() {
        let pe = minimal_pe();
        assert!(validate_pe_at(&pe, 0).is_some());

        let mut coincidence = vec![0u8; 0x400];
        coincidence[16..18].copy_from_slice(b"MZ");
        coincidence[300..304].copy_from_slice(b"PE\0\0");
        assert!(validate_pe_at(&coincidence, 16).is_none());
    }

    #[test]
    fn benign_pdf_compressed_magic_coincidence_is_not_a_pe() {
        let mut pixels = vec![0x41; 4096];
        pixels[100..102].copy_from_slice(b"MZ");
        pixels[3000..3004].copy_from_slice(b"PE\0\0");
        let pdf = flate_pdf(&pixels, false, false);
        let result = inspect_attachment("valuation.pdf", &pdf);
        assert!(
            result.findings.is_empty(),
            "findings: {:?}",
            result.findings
        );
    }

    #[test]
    fn pdf_embedded_pe_with_auto_action_is_a_verified_anchor() {
        let pdf = flate_pdf(&minimal_pe(), true, true);
        let result = inspect_attachment("invoice.pdf", &pdf);
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_name == "PDF_AutoAction_Embedded_PE_Structurally_Valid")
            .expect("verified PDF payload finding");
        assert!(!finding.categories.contains(&"verified_payload_anchor"));
        assert_eq!(finding.severity, "high");
    }

    #[test]
    fn zip_member_pe_is_located_and_generic_archive_is_not_a_hard_anchor() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file(
                    "tools/diagnostic.exe",
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            writer.write_all(&minimal_pe()).unwrap();
            writer.finish().unwrap();
        }
        let result = inspect_attachment("support-tools.zip", cursor.get_ref());
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.rule_name == "Archive_Contains_PE_Structurally_Valid")
            .expect("archive PE finding");
        assert!(finding.location.contains("diagnostic.exe"));
        assert!(!finding.categories.contains(&"verified_payload_anchor"));
        assert_eq!(finding.severity, "medium");
    }

    #[test]
    fn malformed_zip_is_coverage_gap_not_threat() {
        let result = inspect_attachment("broken.zip", b"PK\x03\x04truncated");
        assert!(result.findings.is_empty());
        assert!(
            result
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "malformed_or_truncated_zip")
        );
    }

    #[test]
    fn encrypted_pdf_is_coverage_gap_not_threat() {
        let result = inspect_attachment(
            "protected.pdf",
            b"%PDF-1.7\n1 0 obj << /Encrypt 2 0 R >> endobj\n%%EOF\n",
        );
        assert!(result.findings.is_empty());
        assert!(result.layers.is_empty());
        assert!(
            result
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "encrypted_pdf")
        );
    }

    #[test]
    fn encrypted_zip_member_is_coverage_gap_not_threat() {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default()
                .with_aes_encryption(zip::AesMode::Aes256, "correct horse battery staple");
            writer.start_file("private/report.txt", options).unwrap();
            writer.write_all(b"confidential report").unwrap();
            writer.finish().unwrap();
        }

        let result = inspect_attachment("protected.zip", cursor.get_ref());
        assert!(result.findings.is_empty());
        assert!(result.layers.is_empty());
        assert!(
            result
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "encrypted_archive_entry")
        );
    }

    fn zip_with_pe_member() -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            writer
                .start_file("payload.exe", zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&minimal_pe()).unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn jpeg_zip_polyglot_is_unpacked_and_flagged() {
        // PoC bypass: `cat photo.jpg payload.zip > invoice.jpg` — offset-0
        // magic read Jpeg and the archive was never unpacked, while 7-Zip /
        // Explorer resolve the ZIP from the trailing EOCD.
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        data.extend_from_slice(&vec![0xA5; 256]); // JPEG entropy
        data.extend_from_slice(&zip_with_pe_member());

        let result = inspect_attachment("invoice.jpg", &data);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_name == "Polyglot_Zip_Appended_Archive"
                    && finding.severity == "high"),
            "polyglot container finding missing: {:?}",
            result.findings
        );
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.categories.contains(&"verified_executable_payload")),
            "PE inside the appended archive must be structurally validated: {:?}",
            result.findings
        );
    }

    #[test]
    fn plain_jpeg_without_eocd_tail_stays_quiet() {
        // Normal JPEG: no trailing EOCD → no polyglot finding, no coverage
        // gap, no spurious ZIP unpacking attempt.
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46];
        data.extend_from_slice(&vec![0x7C; 4096]);
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI marker

        let result = inspect_attachment("photo.jpg", &data);
        assert!(
            !result
                .findings
                .iter()
                .any(|finding| finding.rule_name == "Polyglot_Zip_Appended_Archive"),
            "plain JPEG must not raise a polyglot finding: {:?}",
            result.findings
        );
        assert!(
            !result
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "malformed_or_truncated_zip"),
            "plain JPEG must not be probed as a ZIP: {:?}",
            result.coverage_gaps
        );
    }

    #[test]
    fn rar_and_7z_archives_are_coverage_gaps_not_clean_passes() {
        // PoC bypass: an unencrypted invoice.rar carrying a lure docx plus
        // payload.exe produced "no anomalies" because the format was
        // recognized but had neither a decode path nor a gap marker.
        let mut rar = b"Rar!\x1A\x07\x01\x00".to_vec();
        rar.extend_from_slice(&vec![0x33; 256]);
        let result = inspect_attachment("invoice.rar", &rar);
        assert!(
            result
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "unsupported_archive_format"),
            "RAR must surface a coverage gap: {:?}",
            result.coverage_gaps
        );

        let mut sevenz = b"7z\xBC\xAF\x27\x1C".to_vec();
        sevenz.extend_from_slice(&vec![0x44; 256]);
        let result = inspect_attachment("backup.7z", &sevenz);
        assert!(
            result
                .coverage_gaps
                .iter()
                .any(|gap| gap.reason == "unsupported_archive_format"),
            "7z must surface a coverage gap: {:?}",
            result.coverage_gaps
        );
    }

    #[test]
    fn gzip_layer_is_decompressed_and_scanned() {
        // PoC bypass: a .gz attachment wrapping a PE previously had no decode
        // path at all; the member must be inflated and validated.
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&minimal_pe()).unwrap();
        let gz = encoder.finish().unwrap();

        let result = inspect_attachment("invoice.pdf.gz", &gz);
        let finding = result
            .findings
            .iter()
            .find(|finding| finding.categories.contains(&"verified_executable_payload"))
            .expect("PE inside gzip must be structurally validated");
        assert!(
            finding.location.contains("gzip"),
            "finding location must identify the gzip layer: {}",
            finding.location
        );
    }

    fn objstm_pdf(decoded_payload: &[u8], extra_plain_objects: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(decoded_payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut pdf =
            b"%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode >>\nstream\n"
                .to_vec();
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        pdf.extend_from_slice(extra_plain_objects);
        pdf.extend_from_slice(b"%%EOF\n");
        pdf
    }

    fn docx_with_document_relationship(relationship: &[u8]) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            writer.start_file("[Content_Types].xml", options).unwrap();
            writer
                .write_all(br#"<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"#)
                .unwrap();
            writer.start_file("word/document.xml", options).unwrap();
            writer
                .write_all(br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>"#)
                .unwrap();
            writer
                .start_file("word/_rels/document.xml.rels", options)
                .unwrap();
            writer.write_all(relationship).unwrap();
            writer.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn synthetic_docx_external_ole_html_relationship_reaches_yara() {
        use crate::yara::engine::YaraEngine;

        let external_relationship = br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId5"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
    Target="https://fixture.invalid/payload.html!"
    TargetMode="External"/>
</Relationships>"#;
        let docx = docx_with_document_relationship(external_relationship);
        let inspection = inspect_attachment("invoice.docx", &docx);
        let engine = YaraEngine::new().expect("built-in YARA rules compile");
        let names: Vec<_> = inspection
            .layers
            .iter()
            .flat_map(|layer| engine.scan(&layer.data))
            .map(|matched| matched.rule_name)
            .collect();
        assert!(
            names
                .iter()
                .any(|name| name == "Office_External_OLE_HTML_Relationship"),
            "realistic DOCX external OLE member must reach YARA: {names:?}"
        );

        let embedded_relationship = br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId5"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
    Target="../embeddings/oleObject1.bin"/>
</Relationships>"#;
        let docx = docx_with_document_relationship(embedded_relationship);
        let inspection = inspect_attachment("invoice.docx", &docx);
        let names: Vec<_> = inspection
            .layers
            .iter()
            .flat_map(|layer| engine.scan(&layer.data))
            .map(|matched| matched.rule_name)
            .collect();
        assert!(
            !names
                .iter()
                .any(|name| name == "Office_External_OLE_HTML_Relationship"),
            "embedded OLE member must remain a negative control: {names:?}"
        );
    }

    #[test]
    fn objstm_hidden_javascript_is_flagged() {
        // PoC bypass: /JavaScript lives only inside an ObjStm-compressed
        // object, so raw-byte YARA rules (which require a %PDF anchor the
        // decoded layer lacks) never see it.
        let pdf = objstm_pdf(
            b"2 0 << /S /JavaScript /JS (app.alert(1)) >>",
            b"",
        );
        let result = inspect_attachment("report.pdf", &pdf);
        assert!(
            result
                .findings
                .iter()
                .any(|finding| finding.rule_name == "PDF_Hidden_Active_Content"
                    && finding.severity == "high"),
            "hidden ObjStm JavaScript must be flagged: {:?}",
            result.findings
        );
    }

    #[test]
    fn raw_visible_javascript_is_not_double_flagged() {
        // When the JS entry token is already visible in the raw bytes, the
        // YARA PDF rules cover it; the structural layer scan must not emit a
        // duplicate hidden-content finding.
        let pdf = objstm_pdf(
            b"2 0 << /S /JavaScript /JS (app.alert(1)) >>",
            b"9 0 obj\n<< /S /JavaScript >>\nendobj\n",
        );
        let result = inspect_attachment("report.pdf", &pdf);
        assert!(
            !result
                .findings
                .iter()
                .any(|finding| finding.rule_name == "PDF_Hidden_Active_Content"),
            "raw-visible JavaScript must not double-flag: {:?}",
            result.findings
        );
    }
}
