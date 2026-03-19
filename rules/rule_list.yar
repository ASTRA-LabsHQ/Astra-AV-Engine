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
        $a = "C:\\%s\\qeriuwjhrf"
        $b = "WNcry@2ol7"
        $c = "msg/m_bulgarian.wnry"
        $d = "WanaCrypt0r"
    condition:
        3 of them
}
