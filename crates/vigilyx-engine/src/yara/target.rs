//! Stable object-target routing for large YARA rule packs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTarget {
    Message,
    Pdf,
    Office,
    Executable,
    Archive,
    Script,
    Html,
    Shortcut,
    DiskImage,
    Generic,
}

impl ScanTarget {
    pub const ALL: [Self; 10] = [
        Self::Message,
        Self::Pdf,
        Self::Office,
        Self::Executable,
        Self::Archive,
        Self::Script,
        Self::Html,
        Self::Shortcut,
        Self::DiskImage,
        Self::Generic,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Pdf => "pdf",
            Self::Office => "office",
            Self::Executable => "executable",
            Self::Archive => "archive",
            Self::Script => "script",
            Self::Html => "html",
            Self::Shortcut => "shortcut",
            Self::DiskImage => "disk_image",
            Self::Generic => "generic",
        }
    }
}

pub fn classify_scan_target(filename: &str, content_type: &str, data: &[u8]) -> ScanTarget {
    let extension = filename
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    let content_type = content_type.to_ascii_lowercase();

    if has_pdf_header(data) || extension == "pdf" || content_type.contains("application/pdf") {
        return ScanTarget::Pdf;
    }
    if is_executable_magic(data) || is_executable_extension(&extension) {
        return ScanTarget::Executable;
    }
    if is_office_extension(&extension)
        || content_type.contains("officedocument")
        || content_type.contains("msword")
        || content_type.contains("ms-excel")
        || content_type.contains("ms-powerpoint")
    {
        return ScanTarget::Office;
    }
    if is_script_extension(&extension)
        || content_type.contains("javascript")
        || content_type.contains("x-sh")
        || content_type.contains("powershell")
    {
        return ScanTarget::Script;
    }
    if matches!(extension.as_str(), "html" | "htm" | "hta" | "svg")
        || content_type.contains("text/html")
        || content_type.contains("image/svg")
    {
        return ScanTarget::Html;
    }
    if matches!(
        extension.as_str(),
        "lnk" | "chm" | "url" | "website" | "rdp" | "iqy"
    ) {
        return ScanTarget::Shortcut;
    }
    if matches!(extension.as_str(), "iso" | "img" | "vhd" | "vhdx") {
        return ScanTarget::DiskImage;
    }
    if data.starts_with(b"PK\x03\x04")
        || matches!(
            extension.as_str(),
            "zip" | "rar" | "7z" | "gz" | "bz2" | "xz" | "tar"
        )
        || content_type.contains("zip")
        || content_type.contains("compressed")
    {
        return ScanTarget::Archive;
    }

    ScanTarget::Generic
}

fn has_pdf_header(data: &[u8]) -> bool {
    let end = data.len().min(1024);
    data[..end].windows(5).any(|window| window == b"%PDF-")
}

fn is_executable_magic(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
        || data.starts_with(b"\x7fELF")
        || data.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || data.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || data.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

fn is_executable_extension(extension: &str) -> bool {
    matches!(
        extension,
        "exe"
            | "dll"
            | "scr"
            | "cpl"
            | "ocx"
            | "sys"
            | "com"
            | "xll"
            | "efi"
            | "msi"
            | "msix"
            | "appx"
    )
}

fn is_office_extension(extension: &str) -> bool {
    matches!(
        extension,
        "doc"
            | "docx"
            | "docm"
            | "dot"
            | "dotm"
            | "xls"
            | "xlsx"
            | "xlsm"
            | "xlsb"
            | "ppt"
            | "pptx"
            | "pptm"
            | "rtf"
            | "odt"
            | "ods"
            | "odp"
            | "one"
    )
}

fn is_script_extension(extension: &str) -> bool {
    matches!(
        extension,
        "ps1"
            | "psm1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "wsh"
            | "sh"
            | "bash"
            | "py"
            | "pl"
            | "rb"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_wins_over_misleading_extension() {
        assert_eq!(
            classify_scan_target("invoice.jpg", "image/jpeg", b"MZ\0\0"),
            ScanTarget::Executable
        );
        assert_eq!(
            classify_scan_target("blob.bin", "application/octet-stream", b"%PDF-1.7"),
            ScanTarget::Pdf
        );
    }

    #[test]
    fn common_mail_delivery_types_route_stably() {
        assert_eq!(
            classify_scan_target("report.docm", "", b"PK\x03\x04"),
            ScanTarget::Office
        );
        assert_eq!(
            classify_scan_target("payload.ps1", "text/plain", b"Write-Host x"),
            ScanTarget::Script
        );
        assert_eq!(
            classify_scan_target("connect.rdp", "text/plain", b"full address:s:x"),
            ScanTarget::Shortcut
        );
    }
}
