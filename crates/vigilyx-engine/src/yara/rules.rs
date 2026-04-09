//! YARA Rule - 4 Class 28 ItemRule.

//! Rule const &str Encode,Compile packet 2Base/Radix.
//! ItemRuleof meta SegmentpacketContains description, category, severity Segment.

/// MaliciousDocumentationRule (8 Item)
/// detect VBA, OLE Object, PDF JavaScript/EmbeddedFile, RTF exploit
pub const MALICIOUS_DOCUMENT_RULES: &str = r#"
rule VBA_Macro_AutoExec {
    meta:
        description = "Office DocumentationContainsAutoExecuteline VBA 宏 + Suspicious调用"
        category = "malicious_document"
        severity = "high"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Auto_Open" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $auto4 = "Workbook_Open" ascii nocase
        $auto5 = "AutoExec" ascii nocase
        $cmd1 = "Shell" ascii nocase
        $cmd2 = "WScript.Shell" ascii nocase
        $cmd3 = "powershell" ascii nocase
        $cmd4 = "cmd.exe" ascii nocase
        $cmd5 = "CreateObject" ascii nocase
    condition:
        any of ($auto*) and any of ($cmd*)
}

rule VBA_Macro_Download {
    meta:
        description = "VBA 宏ContainsNetwork下载line "
        category = "malicious_document"
        severity = "high"
    strings:
        $dl1 = "URLDownloadToFile" ascii nocase
        $dl2 = "XMLHTTP" ascii nocase
        $dl3 = "WinHttp" ascii nocase
        $dl4 = "InternetOpen" ascii nocase
        $dl5 = "Net.WebClient" ascii nocase
        $dl6 = "DownloadString" ascii nocase
        $dl7 = "DownloadFile" ascii nocase
        $dl8 = "Invoke-WebRequest" ascii nocase
    condition:
        2 of them
}

rule OLE_Embedded_Executable {
    meta:
        description = "OLE 复合Documentation嵌入Executable file"
        category = "malicious_document"
        severity = "critical"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $mz  = { 4D 5A 90 00 }
    condition:
        $ole at 0 and $mz
}

rule PDF_JavaScript {
    meta:
        description = "PDF 含可疑 JavaScript — 需同时存在 JS 入口 + 危险行为"
        category = "malicious_document"
        severity = "high"
    strings:
        $pdf = "%PDF" ascii
        $js_entry1 = "/JavaScript" ascii nocase
        $js_entry2 = "/JS" ascii
        $action1 = "eval(" ascii nocase
        $action2 = "app.alert" ascii nocase
        $action3 = "/Launch" ascii
        $action4 = "/OpenAction" ascii
        $action5 = "this.exportDataObject" ascii nocase
        $action6 = "util.printf" ascii nocase
        $action7 = "getAnnots" ascii nocase
        $action8 = "getURL" ascii nocase
    condition:
        $pdf at 0 and any of ($js_entry*) and any of ($action*)
}

rule PDF_EmbeddedFile {
    meta:
        description = "PDF 嵌入FileObject + Suspicious动作（Launch/OpenAction）"
        category = "malicious_document"
        severity = "medium"
    strings:
        $pdf = "%PDF" ascii
        $ef1 = "/EmbeddedFile" ascii
        $ef2 = "/FileAttachment" ascii
        $launch = "/Launch" ascii
        $openaction = "/OpenAction" ascii
        $mz = { 4D 5A }
    condition:
        $pdf at 0 and (
            $launch or
            (any of ($ef*) and ($openaction or $mz))
        )
}

rule RTF_OLE_Object {
    meta:
        description = "RTF Documentation嵌入 OLE Object（CVE-2017-11882 wait利用载体）"
        category = "malicious_document"
        severity = "high"
    strings:
        $rtf = "{\\rtf" ascii
        $ole1 = "\\objdata" ascii nocase
        $ole2 = "\\objemb" ascii nocase
        $ole3 = "d0cf11e0" ascii nocase
    condition:
        $rtf at 0 and any of ($ole*)
}

rule Office_DDE_Field {
    meta:
        description = "Office DocumentationContains DDE AutoExecuteline字Segment"
        category = "malicious_document"
        severity = "high"
    strings:
        $dde1 = "DDEAUTO" ascii nocase
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "cmd /c" ascii nocase
        $cmd3 = "cmd /k" ascii nocase
        $cmd4 = "powershell" ascii nocase
        $cmd5 = "mshta" ascii nocase
        $cmd6 = "wscript" ascii nocase
        $cmd7 = "cscript" ascii nocase
        $cmd8 = "certutil" ascii nocase
    condition:
        $dde1 and any of ($cmd*)
}

rule Office_Macro_Obfuscation {
    meta:
        description = "VBA 宏UseString混淆/Domain squatingConnect技术"
        category = "malicious_document"
        severity = "medium"
    strings:
        $chr1 = "Chr(" ascii nocase
        $chr2 = "ChrW(" ascii nocase
        $concat = "& Chr" ascii nocase
        $env1 = "Environ(" ascii nocase
        $base64 = "Base64" ascii nocase
        $exec = "Shell" ascii nocase
    condition:
        (3 of ($chr*, $concat)) and any of ($env1, $base64, $exec)
}
"#;

/// Executable file Rule (6 Item)
/// detect PE/ELF/MachO Documentation/ImageMedium, extension, SFX Decompress
pub const EXECUTABLE_DISGUISE_RULES: &str = r#"
rule PE_In_Document {
    meta:
        description = "PE Executable file嵌入在非Executable file容Device/HandlerMedium"
        category = "executable_disguise"
        severity = "critical"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $doc = { D0 CF 11 E0 }
        $pdf = "%PDF" ascii
        $jpg = { FF D8 FF }
        $png = { 89 50 4E 47 }
        $zip = { 50 4B 03 04 }
    condition:
        $mz and $pe and any of ($doc, $pdf, $jpg, $png, $zip)
}

rule ELF_In_Attachment {
    meta:
        description = "ELF 2Base/Radix嵌入在emailAttachmentMedium"
        category = "executable_disguise"
        severity = "critical"
    strings:
        $elf = { 7F 45 4C 46 }
    condition:
        $elf at 0
}

rule MachO_In_Attachment {
    meta:
        description = "Mach-O 2Base/Radix嵌入在emailAttachmentMedium"
        category = "executable_disguise"
        severity = "critical"
    strings:
        $macho1 = { FE ED FA CE }
        $macho2 = { FE ED FA CF }
        $macho3 = { CE FA ED FE }
        $macho4 = { CF FA ED FE }
    condition:
        any of them at 0
}

rule SFX_Self_Extracting_Archive {
    meta:
        description = "自DecompressCompresspacket（SFX）packetContains可Executeline入口"
        category = "executable_disguise"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $rar_sfx = "SFX" ascii
        $zip_sfx = { 50 4B 03 04 }
        $winrar = "WinRAR SFX" ascii nocase
        $7z_sfx = "7-Zip SFX" ascii nocase
    condition:
        $mz at 0 and any of ($rar_sfx, $zip_sfx, $winrar, $7z_sfx)
}

rule Packed_UPX_Executable {
    meta:
        description = "UPX Add壳ofExecutable file（常见Malicious软件打packetMethod）"
        category = "executable_disguise"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        $mz at 0 and any of ($upx*)
}

rule Executable_Script_Polyglot {
    meta:
        description = "脚本/可Executeline多态File（Same时可作 多种格式Parse）"
        category = "executable_disguise"
        severity = "high"
    strings:
        $mz = { 4D 5A }
        $js_start = "<script" ascii nocase
        $hta_start = "<HTA:" ascii nocase
        $vbs_start = "CreateObject" ascii nocase
        $ps_start = "powershell" ascii nocase
    condition:
        $mz and any of ($js_start, $hta_start, $vbs_start, $ps_start)
}
"#;

/// already Malicious Rule (8 Item)
/// email ofMalicious Sign
pub const MALWARE_FAMILY_RULES: &str = r#"
rule Emotet_Dropper {
    meta:
        description = "Emotet 下载Device/Handler/投递Device/Handler特征"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "RunDll32" ascii nocase
        $s2 = "regsvr32" ascii nocase
        $s3 = { 89 45 ?? 8B 45 ?? 89 45 ?? 8B 45 }
        $url1 = "http" ascii
        $dll = ".dll" ascii nocase
    condition:
        2 of ($s*) and $url1 and $dll
}

rule CobaltStrike_Beacon {
    meta:
        description = "Cobalt Strike Beacon 载荷特征"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s2 = "beacon.dll" ascii nocase
        $s3 = "%s (admin)" ascii
        $s4 = "ReflectiveLoader" ascii
        $config = { 00 01 00 01 00 02 }
    condition:
        2 of them
}

rule AgentTesla_Keylogger {
    meta:
        description = "AgentTesla 键盘RecordingDevice/Handler/Info窃GetDevice/Handler"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "get_Clipboard" ascii
        $s2 = "get_IsKeyLocked" ascii
        $s3 = "smtp" ascii nocase
        $s4 = "logins.json" ascii
        $s5 = "Web data" ascii
        $s6 = "key3.db" ascii
    condition:
        3 of them
}

rule AsyncRAT_Payload {
    meta:
        description = "AsyncRAT 远控木马载荷"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "AsyncClient" ascii
        $s2 = "Pastebin" ascii nocase
        $s3 = "get_Hwid" ascii
        $s4 = "Anti_Analysis" ascii
        $s5 = "Install" ascii
    condition:
        3 of them
}

rule Formbook_Infostealer {
    meta:
        description = "Formbook Info窃GetDevice/Handler特征"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "formgrabber" ascii nocase
        $s2 = "keylogger" ascii nocase
        $s3 = "screenshot" ascii nocase
        $s4 = { 83 C4 0C 89 45 ?? 8B 45 ?? 3B 45 }
        $decrypt = { 8A 04 ?? 32 04 ?? 88 04 ?? 4? }
    condition:
        2 of them
}

rule Remcos_RAT {
    meta:
        description = "Remcos RAT RemoteManagement木马"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "Remcos" ascii nocase
        $s2 = "licence" ascii
        $s3 = "keylogger" ascii nocase
        $mutex = "Remcos_Mutex" ascii nocase
        $reg = "Software\\Remcos" ascii nocase
    condition:
        2 of them
}

rule QakBot_Loader {
    meta:
        description = "QakBot/Qbot Bank木马LoadDevice/Handler"
        category = "malware_family"
        severity = "critical"
    strings:
        $s1 = "C:\\INTERNAL\\__empty" ascii
        $s2 = { 8B 45 ?? 33 45 ?? 89 45 }
        $dll1 = "DllRegisterServer" ascii
        $dll2 = "DllInstall" ascii
        $cmd = "regsvr32" ascii nocase
    condition:
        2 of ($s*) or (any of ($dll*) and $cmd)
}

rule EICAR_Test_File {
    meta:
        description = "EICAR 反病毒TestFile"
        category = "malware_family"
        severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}
"#;

/// Webshell / Rule (6 Item)
/// detect PowerShell handler, VBS, JS dropper, HTA Executeline
pub const WEBSHELL_SCRIPT_RULES: &str = r#"
rule PowerShell_Download_Exec {
    meta:
        description = "PowerShell 下载并ExecutelineRemote载荷"
        category = "webshell"
        severity = "critical"
    strings:
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $dl1 = "DownloadString" ascii nocase
        $dl2 = "DownloadFile" ascii nocase
        $dl3 = "Invoke-WebRequest" ascii nocase
        $dl4 = "wget" ascii nocase
        $dl5 = "curl" ascii nocase
        $exec1 = "Invoke-Expression" ascii nocase
        $exec2 = "IEX" ascii
        $exec3 = "Start-Process" ascii nocase
        $bypass = "-ExecutionPolicy" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $enc = "-EncodedCommand" ascii nocase
    condition:
        any of ($ps*) and (any of ($dl*) or $enc) and (any of ($exec*) or $bypass or $hidden)
}

rule PowerShell_Base64_Payload {
    meta:
        description = "PowerShell Use Base64 Encode隐藏Command"
        category = "webshell"
        severity = "high"
    strings:
        $ps1 = "powershell" ascii nocase
        $b64_1 = "-enc " ascii nocase
        $b64_2 = "-EncodedCommand" ascii nocase
        $b64_3 = "FromBase64String" ascii nocase
        $b64_4 = "[Convert]::FromBase64" ascii nocase
    condition:
        any of ($ps*) and any of ($b64*)
}

rule VBScript_Obfuscated_Exec {
    meta:
        description = "VBScript 混淆Executeline（charactersDomain squatingConnect + Shell 调用）"
        category = "webshell"
        severity = "high"
    strings:
        $vbs1 = "WScript" ascii nocase
        $vbs2 = "CScript" ascii nocase
        $chr1 = "Chr(" ascii nocase
        $chr2 = "ChrW(" ascii nocase
        $exec1 = "Run" ascii nocase
        $exec2 = "Exec" ascii nocase
        $exec3 = "Shell" ascii nocase
    condition:
        any of ($vbs*) and any of ($chr*) and any of ($exec*)
}

rule JavaScript_Dropper {
    meta:
        description = "JavaScript 投递Device/Handler（ActiveXObject + 下载Executeline）"
        category = "webshell"
        severity = "high"
    strings:
        $js1 = "ActiveXObject" ascii
        $js2 = "WScript.Shell" ascii
        $js3 = "Scripting.FileSystemObject" ascii
        $js4 = "ADODB.Stream" ascii
        $dl1 = "XMLHTTP" ascii nocase
        $dl2 = "ServerXMLHTTP" ascii nocase
        $dl3 = "http" ascii
    condition:
        2 of ($js*) and any of ($dl*)
}

rule HTA_Execution {
    meta:
        description = "HTA FileContainsCommandExecuteline代Code/Digit"
        category = "webshell"
        severity = "high"
    strings:
        $hta1 = "<HTA:" ascii nocase
        $hta2 = "mshta" ascii nocase
        $exec1 = "WScript.Shell" ascii
        $exec2 = "Shell.Application" ascii
        $exec3 = "cmd.exe" ascii nocase
        $exec4 = "powershell" ascii nocase
    condition:
        any of ($hta*) and any of ($exec*)
}

rule Base64_Encoded_PE {
    meta:
        description = "Base64 Encodeof PE Executable file（Memory注入常用手法）"
        category = "webshell"
        severity = "critical"
    strings:
        $b64_mz = "TVqQAAMAAAA" ascii
        $b64_mz2 = "TVpQAAIAAAA" ascii
        $b64_mz3 = "TVoAAAAAAAA" ascii
        $reflect = "ReflectiveLoader" ascii
        $inject = "VirtualAlloc" ascii nocase
    condition:
        any of ($b64_mz*) or ($reflect and $inject)
}
"#;

/// Advanced threat rules (3 rules)
pub const ADVANCED_THREAT_RULES: &str = r#"
rule Doc_SVG_Base64_Smuggle {
    meta:
        description = "SVG 文件 Base64 走私 — 嵌入编码后的恶意载荷"
        category = "advanced_threat"
        severity = "high"
        author = "Vigilyx YARA Foundry"
    strings:
        $svg = "<svg" ascii nocase
        $b64_1 = "base64" ascii nocase
        $b64_2 = "atob(" ascii
        $script = "<script" ascii nocase
        $embed1 = "data:application" ascii nocase
        $embed2 = "data:text/html" ascii nocase
    condition:
        $svg and $script and (any of ($b64_*) or any of ($embed*))
}

rule Doc_Tycoon2FA_AiTM {
    meta:
        description = "Tycoon2FA AiTM 钓鱼套件 — 中间人攻击窃取 MFA 令牌"
        category = "advanced_threat"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
    strings:
        $html = "<html" ascii nocase
        $js = "<script" ascii nocase
        $cf1 = "turnstile" ascii nocase
        $cf2 = "cloudflare" ascii nocase
        $redir1 = "window.location" ascii nocase
        $redir2 = "document.location" ascii nocase
        $redir3 = "location.href" ascii nocase
        $b64 = "atob(" ascii
        $obf1 = "fromCharCode" ascii
        $obf2 = "String.fromCharCode" ascii
        $ms1 = "microsoft" ascii nocase
        $ms2 = "login.microsoftonline" ascii nocase
        $ms3 = "outlook" ascii nocase
    condition:
        $html and $js and
        any of ($cf*) and any of ($redir*) and
        (any of ($b64, $obf1, $obf2) or any of ($ms*))
}

rule Doc_Callback_Phishing {
    meta:
        description = "回拨钓鱼文档 — 冒充订阅/账单，诱导拨打电话安装远控"
        category = "advanced_threat"
        severity = "medium"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1566.001"
    strings:
        $pdf = "%PDF" ascii
        $sub1 = "subscription" ascii nocase
        $sub2 = "renewal" ascii nocase
        $sub3 = "invoice" ascii nocase
        $sub4 = "receipt" ascii nocase
        $sub5 = "order confirmation" ascii nocase
        $amount1 = "$" ascii
        $amount2 = "USD" ascii
        $call1 = "call" ascii nocase
        $call2 = "phone" ascii nocase
        $call3 = "contact" ascii nocase
        $call4 = "cancel" ascii nocase
        $call5 = "refund" ascii nocase
        $urgency1 = "within 24" ascii nocase
        $urgency2 = "immediately" ascii nocase
        $urgency3 = "charged" ascii nocase
        $urgency4 = "auto-renew" ascii nocase
    condition:
        $pdf at 0 and
        2 of ($sub*) and any of ($amount*) and
        2 of ($call*) and any of ($urgency*)
}
"#;

/// Evasion technique rules (7 rules)
pub const EVASION_TECHNIQUE_RULES: &str = r#"
rule Evasion_LNK_Command_Exec {
    meta:
        description = "恶意 LNK 快捷方式 — 调用 cmd/powershell/mshta 执行命令"
        category = "evasion_technique"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1204.002"
    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $cmd1 = "cmd" ascii nocase
        $cmd2 = "cmd.exe" ascii nocase
        $ps1 = "powershell" ascii nocase
        $ps2 = "pwsh" ascii nocase
        $mshta = "mshta" ascii nocase
        $wscript = "wscript" ascii nocase
        $cscript = "cscript" ascii nocase
        $rundll = "rundll32" ascii nocase
        $hidden1 = "/c " ascii nocase
        $hidden2 = "-w hidden" ascii nocase
        $hidden3 = "-WindowStyle" ascii nocase
    condition:
        $lnk_magic at 0 and
        any of ($cmd*, $ps*, $mshta, $wscript, $cscript, $rundll) and
        any of ($hidden*)
}

rule Evasion_ISO_IMG_Delivery {
    meta:
        description = "ISO/IMG 磁盘镜像投递 — 绕过 MOTW 标记，内含可执行文件"
        category = "evasion_technique"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1553.005"
    strings:
        $iso_magic = "CD001" ascii
        $udf_magic = "NSR0" ascii
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $exe = ".exe" ascii nocase
        $dll = ".dll" ascii nocase
        $lnk = ".lnk" ascii nocase
        $bat = ".bat" ascii nocase
        $cmd = ".cmd" ascii nocase
        $vbs = ".vbs" ascii nocase
        $js_ext = ".js" ascii nocase
    condition:
        ($iso_magic or $udf_magic) and
        ($mz or $pe or 2 of ($exe, $dll, $lnk, $bat, $cmd, $vbs, $js_ext))
}

rule Evasion_HTML_Smuggling {
    meta:
        description = "HTML 走私 — 邮件附件 HTML 内嵌 Base64/Blob 解码释放恶意文件"
        category = "evasion_technique"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1027.006"
    strings:
        $html1 = "<html" ascii nocase
        $html2 = "<script" ascii nocase
        $b64_1 = "atob(" ascii
        $b64_2 = "fromCharCode" ascii
        $blob1 = "new Blob" ascii
        $blob2 = "URL.createObjectURL" ascii
        $blob3 = "msSaveOrOpenBlob" ascii
        $dl1 = "download" ascii
        $dl2 = "saveAs" ascii
        $dl3 = ".click()" ascii
        $mime1 = "application/octet-stream" ascii
        $mime2 = "application/zip" ascii
        $mime3 = "application/x-msdownload" ascii
    condition:
        any of ($html*) and
        any of ($b64_*) and
        any of ($blob*) and
        (any of ($dl*) or any of ($mime*))
}

rule Evasion_RTLO_Filename_Spoof {
    meta:
        description = "RTLO (U+202E) 文件名欺骗 — 利用右到左覆盖字符伪装扩展名"
        category = "evasion_technique"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1036.002"
    strings:
        $rtlo_utf8 = { E2 80 AE }
        $exe = ".exe" ascii nocase
        $scr = ".scr" ascii nocase
        $bat = ".bat" ascii nocase
        $cmd = ".cmd" ascii nocase
        $pif = ".pif" ascii nocase
        $com = ".com" ascii nocase
    condition:
        $rtlo_utf8 and any of ($exe, $scr, $bat, $cmd, $pif, $com)
}

rule Evasion_SVG_Script_Exec {
    meta:
        description = "SVG 恶意脚本 — SVG 文件内嵌 JavaScript/事件处理器执行恶意代码"
        category = "evasion_technique"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1027.006"
    strings:
        $svg = "<svg" ascii nocase
        $script1 = "<script" ascii nocase
        $event1 = "onload=" ascii nocase
        $event2 = "onerror=" ascii nocase
        $event3 = "onclick=" ascii nocase
        $event4 = "onmouseover=" ascii nocase
        $js1 = "document.location" ascii nocase
        $js2 = "window.location" ascii nocase
        $js3 = "eval(" ascii nocase
        $js4 = "atob(" ascii
        $js5 = "fromCharCode" ascii
        $js6 = "fetch(" ascii
        $js7 = "XMLHttpRequest" ascii
        $redir1 = "http://" ascii nocase
        $redir2 = "https://" ascii nocase
    condition:
        $svg and
        (($script1 and any of ($js*)) or
         (any of ($event*) and any of ($js*)) or
         ($script1 and any of ($redir*) and any of ($js1, $js2)))
}

rule Evasion_Double_Extension {
    meta:
        description = "双扩展名伪装 — 文件名含 .pdf.exe 等欺骗性扩展名组合"
        category = "evasion_technique"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1036.007"
    strings:
        $mz = { 4D 5A }
        $dbl1 = ".pdf.exe" ascii nocase
        $dbl2 = ".doc.exe" ascii nocase
        $dbl3 = ".docx.exe" ascii nocase
        $dbl4 = ".xls.exe" ascii nocase
        $dbl5 = ".xlsx.exe" ascii nocase
        $dbl6 = ".jpg.exe" ascii nocase
        $dbl7 = ".png.exe" ascii nocase
        $dbl8 = ".pdf.scr" ascii nocase
        $dbl9 = ".doc.scr" ascii nocase
        $dbl10 = ".pdf.bat" ascii nocase
        $dbl11 = ".doc.bat" ascii nocase
        $dbl12 = ".pdf.cmd" ascii nocase
        $dbl13 = ".pdf.pif" ascii nocase
        $dbl14 = ".txt.exe" ascii nocase
        $dbl15 = ".csv.exe" ascii nocase
    condition:
        $mz and any of ($dbl*)
}

rule Doc_OneNote_Embedded_Payload {
    meta:
        description = "OneNote 文档嵌入恶意载荷 — .one 文件内含脚本/可执行文件"
        category = "evasion_technique"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1566.001"
    strings:
        $onenote_magic = { E4 52 5C 7B 8C D8 A7 4D }
        $mz = { 4D 5A }
        $hta = "<HTA:" ascii nocase
        $vbs1 = "WScript" ascii nocase
        $vbs2 = "CreateObject" ascii nocase
        $ps1 = "powershell" ascii nocase
        $cmd1 = "cmd.exe" ascii nocase
        $bat1 = ".bat" ascii nocase
        $wsf = ".wsf" ascii nocase
    condition:
        $onenote_magic at 0 and
        ($mz or 2 of ($hta, $vbs1, $vbs2, $ps1, $cmd1, $bat1, $wsf))
}
"#;

/// Extended malware-family rules — active 2025-2026 threats (15 rules)
pub const EXTENDED_MALWARE_RULES: &str = r##"
rule Mal_Lumma_Stealer {
    meta:
        description = "Lumma Stealer 信息窃取器 — 窃取浏览器凭证、加密货币钱包、2FA 令牌"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1555.003"
    strings:
        $s1 = "LummaC2" ascii nocase
        $s2 = "lumma" ascii nocase
        $browser1 = "Login Data" ascii
        $browser2 = "Cookies" ascii
        $browser3 = "Web Data" ascii
        $wallet1 = "wallet.dat" ascii nocase
        $wallet2 = "exodus" ascii nocase
        $wallet3 = "metamask" ascii nocase
        $crypto1 = "Electrum" ascii
        $crypto2 = "Coinomi" ascii
        $api1 = "InternetOpenA" ascii
        $api2 = "HttpSendRequestA" ascii
        $api3 = "CryptUnprotectData" ascii
    condition:
        (any of ($s*)) or
        (2 of ($browser*) and any of ($wallet*, $crypto*) and any of ($api*))
}

rule Mal_XWorm_RAT {
    meta:
        description = "XWorm 远控木马 — 键盘记录、屏幕截图、凭证窃取、勒索加密"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1059.001"
    strings:
        $xworm1 = "XWorm" ascii nocase
        $xworm2 = "xClient" ascii
        $xworm3 = "XLogger" ascii
        $mutex1 = "XWormMutex" ascii nocase
        $func1 = "StartKeylogger" ascii
        $func2 = "StartDDOS" ascii
        $func3 = "GetScreenshot" ascii
        $func4 = "RunPE" ascii
        $func5 = "DownloadAndExecute" ascii
        $cfg1 = "Groub" ascii
        $cfg2 = "splitter" ascii
    condition:
        2 of ($xworm*, $mutex1) or
        (3 of ($func*)) or
        (any of ($xworm*, $mutex1) and 2 of ($func*)) or
        ($cfg1 and $cfg2 and any of ($func*))
}

rule Mal_SnakeKeylogger {
    meta:
        description = "Snake Keylogger (.NET) — 键盘记录 + 浏览器凭证窃取 + 邮件外发"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1056.001"
    strings:
        $snake1 = "SnakeKeylogger" ascii nocase
        $snake2 = "snake_log" ascii nocase
        $net1 = "System.Net.Mail" ascii
        $net2 = "SmtpClient" ascii
        $net3 = "NetworkCredential" ascii
        $steal1 = "\\Google\\Chrome\\User Data" ascii
        $steal2 = "\\Mozilla\\Firefox\\Profiles" ascii
        $steal3 = "logins.json" ascii
        $steal4 = "signons.sqlite" ascii
        $clip1 = "GetClipboardData" ascii
        $clip2 = "SetClipboardViewer" ascii
        $ftp1 = "FtpWebRequest" ascii
        $tele1 = "api.telegram.org" ascii
    condition:
        any of ($snake*) or
        (any of ($net*) and 2 of ($steal*) and any of ($clip*, $ftp1, $tele1))
}

rule Mal_DarkGate_Loader {
    meta:
        description = "DarkGate 加载器 — 远控/挖矿/信息窃取多功能后门"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1059.001"
    strings:
        $dg1 = "DarkGate" ascii nocase
        $dg2 = "darkgate" ascii
        $autoit1 = "#AutoIt3Wrapper" ascii
        $autoit2 = "AutoItObject" ascii
        $autoit3 = "Au3Stripper" ascii
        $autoit_func1 = "ShellExecute" ascii
        $autoit_func2 = "DllCall" ascii
        $autoit_func3 = "BinaryToString" ascii
        $vbs_chain = "cscript" ascii nocase
        $hta_chain = "mshta" ascii nocase
        $ps_chain = "powershell" ascii nocase
        $running1 = "0=still_running" ascii
        $running2 = "1=still_running" ascii
    condition:
        any of ($dg*) or
        ($running1 or $running2) or
        (2 of ($autoit*) and any of ($autoit_func*) and any of ($vbs_chain, $hta_chain, $ps_chain))
}

rule Mal_Latrodectus_Loader {
    meta:
        description = "Latrodectus 加载器 — IcedID/BokBot 继任者，投递后续恶意载荷"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1566.001"
    strings:
        $latro1 = "Latrodectus" ascii nocase
        $latro2 = "DVZLQVOY" ascii
        $js_over1 = "WScript.Shell" ascii
        $js_over2 = "Scripting.FileSystemObject" ascii
        $js_over3 = "MSXML2.XMLHTTP" ascii
        $js_over4 = "ADODB.Stream" ascii
        $js_dl = ".dll" ascii nocase
        $msi_chain = "msiexec" ascii nocase
        $rundll = "rundll32" ascii nocase
    condition:
        any of ($latro*) or
        (3 of ($js_over*) and ($js_dl or $msi_chain or $rundll))
}

rule Mal_Vidar_Stealer {
    meta:
        description = "Vidar Stealer 信息窃取器 — 窃取浏览器/FTP/加密货币/2FA"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1555.003"
    strings:
        $vidar1 = "Vidar" ascii nocase
        $steam = "SteamPath" ascii
        $tele = "Telegram" ascii
        $discord = "discord" ascii nocase
        $wallet1 = "wallet.dat" ascii
        $wallet2 = "Ethereum" ascii
        $browser1 = "Login Data" ascii
        $browser2 = "Web Data" ascii
        $browser3 = "Cookies" ascii
        $authy = "Authy" ascii
        $ftp1 = "FileZilla" ascii
        $ftp2 = "recentservers.xml" ascii
        $hwid = "HWID" ascii
    condition:
        $vidar1 or
        ($hwid and 3 of ($steam, $tele, $discord, $wallet1, $wallet2, $browser1, $browser2, $browser3, $authy, $ftp1, $ftp2))
}

rule Mal_GuLoader_Shellcode {
    meta:
        description = "GuLoader 下载器 — VBS/VBE 包装 shellcode 下载远程 PE 载荷"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1059.005"
    strings:
        $vbs1 = "WScript.Shell" ascii
        $vbs2 = "CreateObject" ascii
        $vbs3 = "RegRead" ascii
        $vbs4 = "RegWrite" ascii
        $shell1 = "VirtualAlloc" ascii
        $shell2 = "NtProtectVirtualMemory" ascii
        $shell3 = "EnumWindows" ascii
        $api1 = "CallWindowProc" ascii
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "CheckRemoteDebuggerPresent" ascii
        $anti3 = "GetTickCount" ascii
        $cloud1 = "drive.google.com" ascii nocase
        $cloud2 = "onedrive.live.com" ascii nocase
        $cloud3 = "discord" ascii nocase
    condition:
        (2 of ($vbs*) and any of ($shell*)) or
        (2 of ($shell*, $api1) and any of ($anti*)) or
        (any of ($vbs*) and any of ($cloud*) and any of ($shell*))
}

rule Mal_Pikabot_Loader {
    meta:
        description = "Pikabot 加载器 — QakBot 继任者，DLL 注入 + 反沙箱"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1566.001"
    strings:
        $pika1 = "pikabot" ascii nocase
        $pika2 = "PikaBot" ascii
        $api1 = "NtQueryInformationProcess" ascii
        $api2 = "NtCreateSection" ascii
        $api3 = "NtMapViewOfSection" ascii
        $api4 = "NtQueueApcThread" ascii
        $anti1 = "GetTickCount64" ascii
        $anti2 = "IsDebuggerPresent" ascii
        $anti3 = "CheckRemoteDebuggerPresent" ascii
        $inject1 = "VirtualAllocEx" ascii
        $inject2 = "WriteProcessMemory" ascii
        $inject3 = "CreateRemoteThread" ascii
        $dll1 = "DllRegisterServer" ascii
        $dll2 = "rundll32" ascii nocase
    condition:
        any of ($pika*) or
        (3 of ($api*) and any of ($anti*)) or
        (2 of ($inject*) and any of ($anti*) and any of ($dll*))
}

rule Mal_Redline_Stealer {
    meta:
        description = "Redline Stealer 信息窃取器 — 浏览器/FTP/VPN/加密货币钱包凭证窃取"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1555.003"
    strings:
        $redline1 = "RedLine" ascii
        $redline2 = "Redline" ascii
        $net1 = "System.Net.Sockets" ascii
        $steal1 = "\\Google\\Chrome\\User Data" ascii
        $steal2 = "\\Mozilla\\Firefox\\Profiles" ascii
        $steal3 = "Login Data" ascii
        $steal4 = "Web Data" ascii
        $vpn1 = "NordVPN" ascii
        $vpn2 = "OpenVPN" ascii
        $vpn3 = "ProtonVPN" ascii
        $crypto1 = "Armory" ascii
        $crypto2 = "Electrum" ascii
        $crypto3 = "Ethereum" ascii
        $ftp1 = "FileZilla" ascii
        $ftp2 = "WinSCP" ascii
        $sys1 = "OperatingSystem" ascii
        $sys2 = "GraphicsCard" ascii
    condition:
        any of ($redline*) or
        ($net1 and 2 of ($steal*) and (any of ($vpn*) or any of ($crypto*) or any of ($ftp*))) or
        (any of ($sys*) and 2 of ($steal*) and any of ($net1))
}

rule Mal_Bumblebee_Loader {
    meta:
        description = "Bumblebee 加载器 — 通过 ISO/VHD/ZIP 投递，加载 Cobalt Strike/Meterpreter"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1566.001"
    strings:
        $bb1 = "bumblebee" ascii nocase
        $bb2 = "BumbleBee" ascii
        $com1 = "COM Object" ascii nocase
        $wmi1 = "Win32_ComputerSystem" ascii
        $wmi2 = "Win32_Process" ascii
        $wmi3 = "Win32_NetworkAdapter" ascii
        $inject1 = "VirtualAlloc" ascii
        $inject2 = "VirtualProtect" ascii
        $inject3 = "NtWriteVirtualMemory" ascii
        $anti1 = "IsDebuggerPresent" ascii
        $anti2 = "OutputDebugString" ascii
        $anti3 = "GetTickCount" ascii
        $ldr1 = "LoadLibraryA" ascii
        $ldr2 = "GetProcAddress" ascii
    condition:
        any of ($bb*) or
        ($com1 and any of ($wmi*) and any of ($inject*)) or
        (2 of ($wmi*) and any of ($inject*) and any of ($anti*)) or
        (2 of ($inject*) and 2 of ($anti*) and all of ($ldr*))
}

rule Mal_IcedID_BokBot {
    meta:
        description = "IcedID/BokBot 银行木马 — Web 注入 + 后续载荷投递"
        category = "malware_family"
        severity = "critical"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1566.001"
    strings:
        $icedid1 = "IcedID" ascii nocase
        $icedid2 = "BokBot" ascii nocase
        $gzip_dll = { 1F 8B 08 }
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
        $photo1 = "image/jpeg" ascii
        $photo2 = "JFIF" ascii
        $api1 = "InternetOpenA" ascii
        $api2 = "InternetConnectA" ascii
        $api3 = "HttpOpenRequestA" ascii
        $inject1 = "NtCreateSection" ascii
        $inject2 = "NtMapViewOfSection" ascii
        $hook1 = "HttpSendRequestW" ascii
        $hook2 = "InternetReadFile" ascii
    condition:
        any of ($icedid*) or
        ($gzip_dll and ($mz or $pe) and any of ($photo*)) or
        (2 of ($api*) and any of ($inject*) and any of ($hook*))
}
"##;

/// Extended script/webshell rules — WSF delivery + MintsLoader (2 rules)
pub const EXTENDED_WEBSHELL_RULES: &str = r#"
rule Script_WSF_Malicious {
    meta:
        description = "恶意 WSF 脚本 — Windows Script File 混合 JScript/VBScript 执行恶意代码"
        category = "webshell"
        severity = "high"
        author = "Vigilyx YARA Foundry"
        mitre_attack = "T1059.007"
    strings:
        $wsf1 = "<job" ascii nocase
        $wsf2 = "<script" ascii nocase
        $wsf3 = "</job>" ascii nocase
        $wsf4 = "<package>" ascii nocase
        $lang1 = "JScript" ascii nocase
        $lang2 = "VBScript" ascii nocase
        $exec1 = "WScript.Shell" ascii
        $exec2 = "Shell.Application" ascii
        $exec3 = "Scripting.FileSystemObject" ascii
        $dl1 = "MSXML2.XMLHTTP" ascii
        $dl2 = "WinHttp" ascii nocase
        $dl3 = "ADODB.Stream" ascii
        $obf1 = "fromCharCode" ascii
        $obf2 = "Chr(" ascii nocase
        $obf3 = "eval(" ascii nocase
    condition:
        2 of ($wsf*) and any of ($lang*) and
        (any of ($exec*) and (any of ($dl*) or any of ($obf*)))
}
"#;

/// Rule source list (used for compilation)
pub const ALL_RULE_SOURCES: &[(&str, &str)] = &[
    ("malicious_document", MALICIOUS_DOCUMENT_RULES),
    ("executable_disguise", EXECUTABLE_DISGUISE_RULES),
    ("malware_family", MALWARE_FAMILY_RULES),
    ("malware_family_ext", EXTENDED_MALWARE_RULES),
    ("webshell", WEBSHELL_SCRIPT_RULES),
    ("webshell_ext", EXTENDED_WEBSHELL_RULES),
    ("advanced_threat", ADVANCED_THREAT_RULES),
    ("evasion_technique", EVASION_TECHNIQUE_RULES),
];

/// RuleClass Yuandata(Used forfirst)
pub struct RuleCategoryMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
}

pub const RULE_CATEGORIES: &[RuleCategoryMeta] = &[
    RuleCategoryMeta {
        id: "malicious_document",
        name: "恶意文档",
        description: "VBA 宏、OLE 嵌入、PDF JavaScript、RTF 漏洞利用、OneNote 载荷",
    },
    RuleCategoryMeta {
        id: "executable_disguise",
        name: "可执行文件伪装",
        description: "PE/ELF/MachO 嵌入、SFX 自解压、UPX 加壳",
    },
    RuleCategoryMeta {
        id: "malware_family",
        name: "已知恶意软件家族",
        description: "Emotet、Cobalt Strike、AgentTesla、Lumma、XWorm、DarkGate 等 23 个家族",
    },
    RuleCategoryMeta {
        id: "webshell",
        name: "脚本木马",
        description: "PowerShell 下载器、VBS 混淆、JS dropper、HTA 执行、WSF 恶意脚本",
    },
    RuleCategoryMeta {
        id: "advanced_threat",
        name: "高级威胁",
        description: "SVG 走私、Tycoon2FA AiTM、回拨钓鱼",
    },
    RuleCategoryMeta {
        id: "evasion_technique",
        name: "逃逸技术",
        description: "LNK 命令执行、ISO/IMG 投递、HTML 走私、RTLO 欺骗、双扩展名、SVG 脚本",
    },
];
