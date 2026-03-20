// ============================================================
// ASTRA AV Engine — Episode 2: Sample YARA Rules

rule wannacry_ransomware
{
    meta:
        author = "Astra"
        description = "This is a rule that tests against strings in WannaCry"
        threat_level = 3
        in_the_wild = false

    strings:
        $b = "C:\\%s\\qeriuwjhrf"
        $c = "WNcry@2017"
        $d = "msg/m_bulgarian.wnry"
        $e = "WanaCryptor"

    condition:
        3 of them
}

rule mimikatz_strings
{
    meta:
        author = "Astra"
        description = "Detects Mimikatz usage"
        threat_level = 5

    strings:
        $m1 = "sekurlsa::logonpasswords"
        $m2 = "mimikatz"
        $m3 = "lsadump::sam"
        $m4 = "kerberos::tickets"
        $m5 = "privilege::debug"

    condition:
        2 of them
}

rule generic_ransomware_extensions
{
    meta:
        author = "Astra"
        description = "Detects ransomware file extensions"
        threat_level = 3

    strings:
        $r1 = ".locked"
        $r2 = ".encrypted"
        $r3 = ".crypt"
        $r4 = "restore_files"
        $r5 = "readme.txt"

    condition:
        3 of them
}

rule highly_sus_shellcode
{
    meta:
        author = "Astra"
        description = "This is a rule that alerts against suspicious shellcode"
        threat_level = 3
        in_the_wild = true

    strings:
        $b = "0x89,0x00,0x00,0x00,0x60,0x89"
        $c = "0x01,0xd0,0x50,0x8b"
        $d = "0x93,0x31,0xc0,0x66"
        $e = "0x83,0xec,0x04,0xeb,0xce"

    condition:
        3 of them
}

rule lokibot_stealer
{
    meta:
        author = "Astra"
        description = "Detects LokiBot stealer behavior"
        threat_level = 4

    strings:
        $l1 = "pass.txt"
        $l2 = "wallet.dat"
        $l3 = "cookies.sqlite"
        $l4 = "logins.json"
        $l5 = "FileZilla"

    condition:
        3 of them
}

rule obfuscated_powershell
{
    meta:
        author = "Astra"
        description = "This is a rule that alerts against an obfuscated powershell payload"
        threat_level = 3
        in_the_wild = true

    strings:
        $b = "mGcVRgVTSg0q91EScQsi7mS"
        $c = "iSaH2oYMVNrRIwCV"
        $d = "L6jTXt+0GocRGF"
        $e = "wwZw0TenIvTDvtnrZM"

    condition:
        3 of them
}