-- Vigilyx YARA custom rules — production-quality set
-- Use $$dollar quoting$$ to avoid escaping issues

-- === HTML Smuggling ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Doc_HTML_Smuggling_Blob', 'advanced_threat', 'critical', 'custom',
$$rule Doc_HTML_Smuggling_Blob {
    meta:
        description = "HTML Smuggling via JavaScript Blob + createObjectURL"
        category = "advanced_threat"
        severity = "critical"
        mitre_attack = "T1027.006"
    strings:
        $html = "<html" ascii nocase
        $blob1 = "new Blob" ascii nocase
        $blob2 = "createObjectURL" ascii nocase
        $blob3 = "msSaveOrOpenBlob" ascii nocase
        $decode1 = "atob(" ascii nocase
        $decode2 = "Uint8Array" ascii
        $dl1 = ".download" ascii
        $dl2 = ".click()" ascii
    condition:
        $html and any of ($blob*) and any of ($decode*) and any of ($dl*)
}$$, 'HTML Smuggling: Blob + createObjectURL 自动下载', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Doc_HTML_Smuggling_Base64PE', 'advanced_threat', 'critical', 'custom',
$$rule Doc_HTML_Smuggling_Base64PE {
    meta:
        description = "HTML with Base64-encoded PE payload and JS decoder"
        category = "advanced_threat"
        severity = "critical"
        mitre_attack = "T1027.006"
    strings:
        $html = "<html" ascii nocase
        $script = "<script" ascii nocase
        $b64_mz1 = "TVqQAAMAAAA" ascii
        $b64_mz2 = "TVpQAAIAAAA" ascii
        $decode = "atob" ascii
    condition:
        $html and $script and any of ($b64_mz*) and $decode
}$$, 'HTML 附件含 Base64 编码 PE + JS 解码器', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === ISO/IMG Delivery ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Doc_ISO_With_LNK', 'advanced_threat', 'critical', 'custom',
$$rule Doc_ISO_With_LNK {
    meta:
        description = "ISO disk image containing LNK shortcut and command interpreter"
        category = "advanced_threat"
        severity = "critical"
        mitre_attack = "T1566.001"
    strings:
        $iso = "CD001" ascii
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $cmd1 = "cmd" ascii nocase
        $cmd2 = "powershell" ascii nocase
        $cmd3 = "mshta" ascii nocase
        $cmd4 = "rundll32" ascii nocase
    condition:
        $iso and $lnk and any of ($cmd*)
}$$, 'ISO 磁盘映像含 LNK + 命令执行', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === Malicious OneNote Embedding ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Doc_OneNote_EmbeddedScript', 'advanced_threat', 'critical', 'custom',
$$rule Doc_OneNote_EmbeddedScript {
    meta:
        description = "OneNote with embedded VBS/BAT/HTA script"
        category = "advanced_threat"
        severity = "critical"
        mitre_attack = "T1566.001"
    strings:
        $one = { E4 52 5C 7B 8C D8 A7 4D }
        $ext1 = ".vbs" ascii nocase
        $ext2 = ".bat" ascii nocase
        $ext3 = ".hta" ascii nocase
        $ext4 = ".cmd" ascii nocase
        $ext5 = ".exe" ascii nocase
        $ext6 = ".ps1" ascii nocase
    condition:
        $one at 0 and 2 of ($ext*)
}$$, 'OneNote 嵌入脚本/可执行文件', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === LNK Weaponization ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_LNK_CmdExecution', 'advanced_threat', 'critical', 'custom',
$$rule Mal_LNK_CmdExecution {
    meta:
        description = "LNK shortcut with cmd/powershell execution"
        category = "advanced_threat"
        severity = "critical"
        mitre_attack = "T1204.002"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $cmd1 = "cmd.exe" ascii nocase
        $cmd2 = "cmd /c" ascii nocase
        $ps1 = "powershell" ascii nocase
        $mshta = "mshta" ascii nocase
        $rundll = "rundll32" ascii nocase
        $regsvr = "regsvr32" ascii nocase
    condition:
        $lnk at 0 and (any of ($cmd*) or $ps1 or $mshta or $rundll or $regsvr)
}$$, 'LNK 快捷方式执行恶意命令', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_LNK_DownloadExec', 'advanced_threat', 'critical', 'custom',
$$rule Mal_LNK_DownloadExec {
    meta:
        description = "LNK with download-and-execute command"
        category = "advanced_threat"
        severity = "critical"
        mitre_attack = "T1204.002"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $dl1 = "DownloadFile" ascii nocase
        $dl2 = "DownloadString" ascii nocase
        $dl3 = "Invoke-WebRequest" ascii nocase
        $dl4 = "certutil" ascii nocase
        $dl5 = "bitsadmin" ascii nocase
        $url = "http" ascii nocase
    condition:
        $lnk at 0 and any of ($dl*) and $url
}$$, 'LNK 下载并执行远程载荷', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === .NET Malware ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_DotNet_Obfuscated', 'malware_family', 'high', 'custom',
$$rule Mal_DotNet_Obfuscated {
    meta:
        description = ".NET malware with obfuscator signatures"
        category = "malware_family"
        severity = "high"
        mitre_attack = "T1027.002"
    strings:
        $dotnet1 = "mscoree.dll" ascii
        $dotnet2 = { 42 53 4A 42 }
        $confuser1 = "ConfuserEx" ascii
        $confuser2 = "Confuser.Core" ascii
        $reactor = ".NET Reactor" ascii
        $smart = "SmartAssembly" ascii
        $anti1 = "Debugger" ascii
        $anti2 = "IsAttached" ascii
    condition:
        any of ($dotnet*) and (any of ($confuser*, $reactor, $smart) or all of ($anti*))
}$$, '.NET 恶意程序含混淆器特征', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_DotNet_ReflectiveLoad', 'malware_family', 'critical', 'custom',
$$rule Mal_DotNet_ReflectiveLoad {
    meta:
        description = ".NET Assembly.Load with Base64 decode and reflection"
        category = "malware_family"
        severity = "critical"
        mitre_attack = "T1620"
    strings:
        $dotnet = "mscoree.dll" ascii
        $load1 = "Assembly.Load" ascii
        $load2 = "AppDomain" ascii
        $reflect1 = "Invoke" ascii
        $reflect2 = "GetMethod" ascii
        $b64 = "FromBase64String" ascii
        $gzip = "GZipStream" ascii
    condition:
        $dotnet and any of ($load*) and any of ($reflect*) and ($b64 or $gzip)
}$$, '.NET 反射加载 + Base64 解码', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === Shellcode ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_Shellcode_PEB_Walk', 'executable_disguise', 'critical', 'custom',
$$rule Mal_Shellcode_PEB_Walk {
    meta:
        description = "Shellcode PEB walking to resolve kernel32"
        category = "executable_disguise"
        severity = "critical"
        mitre_attack = "T1059.004"
    strings:
        $peb32 = { 64 A1 30 00 00 00 }
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        $kernel = "kernel32" ascii nocase
        $getproc = "GetProcAddress" ascii
    condition:
        any of ($peb*) and ($kernel or $getproc)
}$$, 'Shellcode PEB 遍历定位 kernel32', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_Shellcode_SyscallStub', 'executable_disguise', 'critical', 'custom',
$$rule Mal_Shellcode_SyscallStub {
    meta:
        description = "Direct syscall stub bypassing EDR hooks"
        category = "executable_disguise"
        severity = "critical"
        mitre_attack = "T1106"
    strings:
        $syscall64 = { 4C 8B D1 B8 ?? 00 00 00 0F 05 C3 }
        $ntapi1 = "NtAllocateVirtualMemory" ascii
        $ntapi2 = "NtWriteVirtualMemory" ascii
        $ntapi3 = "NtCreateThreadEx" ascii
    condition:
        $syscall64 and any of ($ntapi*)
}$$, '直接 syscall 绕过 EDR hook', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === Macro Evasion ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Doc_XLM_Macro4', 'malicious_document', 'high', 'custom',
$$rule Doc_XLM_Macro4 {
    meta:
        description = "Excel 4.0 XLM macro bypassing VBA detection"
        category = "malicious_document"
        severity = "high"
        mitre_attack = "T1059.010"
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $xlm1 = "EXEC(" ascii nocase
        $xlm2 = "CALL(" ascii nocase
        $xlm3 = "HALT()" ascii nocase
        $xlm4 = "RUN(" ascii nocase
        $xlm5 = "FORMULA(" ascii nocase
        $sheet = "Macro1" ascii
    condition:
        $ole at 0 and 2 of ($xlm*) and $sheet
}$$, 'Excel 4.0 XLM 宏绕过 VBA 检测', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === SVG Script Payloads ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Doc_SVG_EmbeddedScript', 'advanced_threat', 'high', 'custom',
$$rule Doc_SVG_EmbeddedScript {
    meta:
        description = "SVG with embedded JavaScript or event handlers"
        category = "advanced_threat"
        severity = "high"
        mitre_attack = "T1059.007"
    strings:
        $svg = "<svg" ascii nocase
        $script = "<script" ascii nocase
        $on1 = "onload=" ascii nocase
        $on2 = "onerror=" ascii nocase
        $js1 = "eval(" ascii nocase
        $js2 = "fetch(" ascii
    condition:
        $svg and ($script or any of ($on*)) and any of ($js*)
}$$, 'SVG 嵌入 JavaScript/事件处理器', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === Ransomware ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_Ransomware_Note', 'malware_family', 'critical', 'custom',
$$rule Mal_Ransomware_Note {
    meta:
        description = "Ransomware note with BTC wallet and decryption demands"
        category = "malware_family"
        severity = "critical"
        mitre_attack = "T1486"
    strings:
        $r1 = "your files" ascii nocase
        $r2 = "encrypted" ascii nocase
        $r3 = "decrypt" ascii nocase
        $r4 = "bitcoin" ascii nocase
        $r5 = "wallet" ascii nocase
        $r6 = "ransom" ascii nocase
        $tor = ".onion" ascii nocase
        $email = "protonmail" ascii nocase
        $timer = "hours" ascii nocase
    condition:
        3 of ($r*) and ($tor or $email) and $timer
}$$, '勒索信: BTC 钱包 + 解密要求', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_Ransomware_CryptoAPI', 'malware_family', 'critical', 'custom',
$$rule Mal_Ransomware_CryptoAPI {
    meta:
        description = "Ransomware crypto API + file enumeration + shadow delete"
        category = "malware_family"
        severity = "critical"
        mitre_attack = "T1486"
    strings:
        $mz = { 4D 5A }
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "BCryptEncrypt" ascii
        $crypt3 = "CryptGenKey" ascii
        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii
        $shadow1 = "vssadmin" ascii nocase
        $shadow2 = "shadowcopy" ascii nocase
    condition:
        $mz at 0 and any of ($crypt*) and any of ($file*) and any of ($shadow*)
}$$, '勒索软件加密 API + 文件遍历 + 卷影删除', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === Evasion Techniques ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Evasion_AMSI_Bypass', 'evasion_technique', 'critical', 'custom',
$$rule Evasion_AMSI_Bypass {
    meta:
        description = "AMSI bypass: patching AmsiScanBuffer"
        category = "evasion_technique"
        severity = "critical"
        mitre_attack = "T1562.001"
    strings:
        $amsi1 = "AmsiScanBuffer" ascii
        $amsi2 = "amsi.dll" ascii nocase
        $patch1 = "VirtualProtect" ascii
        $patch2 = "WriteProcessMemory" ascii
    condition:
        any of ($amsi*) and any of ($patch*)
}$$, 'AMSI 绕过: 补丁 AmsiScanBuffer', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Evasion_NTDLL_Unhook', 'evasion_technique', 'critical', 'custom',
$$rule Evasion_NTDLL_Unhook {
    meta:
        description = "NTDLL unhooking: reload from disk to bypass EDR"
        category = "evasion_technique"
        severity = "critical"
        mitre_attack = "T1562.001"
    strings:
        $ntdll = "ntdll.dll" ascii nocase
        $path = "System32" ascii nocase
        $map1 = "NtMapViewOfSection" ascii
        $map2 = "MapViewOfFile" ascii
    condition:
        $ntdll and $path and any of ($map*)
}$$, 'NTDLL unhooking 绕过 EDR', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

-- === C2 Frameworks ===
INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_Mimikatz_Strings', 'malware_family', 'critical', 'custom',
$$rule Mal_Mimikatz_Strings {
    meta:
        description = "Mimikatz credential theft tool indicators"
        category = "malware_family"
        severity = "critical"
        mitre_attack = "T1003.001"
    strings:
        $s1 = "mimikatz" ascii nocase
        $s2 = "gentilkiwi" ascii
        $s3 = "sekurlsa" ascii nocase
        $s4 = "logonpasswords" ascii nocase
        $s5 = "wdigest" ascii nocase
        $s6 = "lsadump" ascii nocase
        $s7 = "privilege::debug" ascii nocase
    condition:
        3 of them
}$$, 'Mimikatz 凭证窃取工具', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_Sliver_Implant', 'malware_family', 'critical', 'custom',
$$rule Mal_Sliver_Implant {
    meta:
        description = "Sliver C2 framework implant indicators"
        category = "malware_family"
        severity = "critical"
        mitre_attack = "T1071.001"
    strings:
        $s1 = "sliverpb" ascii
        $s2 = "bishopfox" ascii nocase
        $go = "go.buildid" ascii
        $impl1 = "ActiveC2" ascii
        $impl2 = "StartBeacon" ascii
    condition:
        any of ($s*) and $go and any of ($impl*)
}$$, 'Sliver C2 implant 载荷', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;

INSERT INTO security_yara_rules (id, rule_name, category, severity, source, rule_source, description, enabled, hit_count, created_at, updated_at)
VALUES (gen_random_uuid()::text, 'Mal_BruteRatel_Badger', 'malware_family', 'critical', 'custom',
$$rule Mal_BruteRatel_Badger {
    meta:
        description = "Brute Ratel C4 badger payload"
        category = "malware_family"
        severity = "critical"
        mitre_attack = "T1071.001"
    strings:
        $s1 = "badger" ascii nocase
        $s2 = "bruteratel" ascii nocase
        $api1 = "NtQueueApcThread" ascii
        $api2 = "NtAlertResumeThread" ascii
        $api3 = "RtlCreateUserThread" ascii
    condition:
        any of ($s*) and 2 of ($api*)
}$$, 'Brute Ratel C4 badger', TRUE, 0, now()::text, now()::text)
ON CONFLICT (rule_name) DO UPDATE SET rule_source=EXCLUDED.rule_source, updated_at=EXCLUDED.updated_at;
