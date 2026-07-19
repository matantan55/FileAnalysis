// ──────────────────────────────────────────────────────────────
// Hacking Toolkit Detection
// Detects known offensive security tools and webshells
// ──────────────────────────────────────────────────────────────

rule Mimikatz_Indicators {
    meta:
        description = "Detects Mimikatz credential dumping tool strings"
        severity = "critical"
        reference = "T1003.001"
    strings:
        // Module commands
        $cmd1 = "sekurlsa::" ascii wide nocase
        $cmd2 = "lsadump::" ascii wide nocase
        $cmd3 = "kerberos::" ascii wide nocase
        $cmd4 = "privilege::debug" ascii wide nocase
        $cmd5 = "token::elevate" ascii wide nocase
        $cmd6 = "crypto::" ascii wide nocase
        $cmd7 = "dpapi::" ascii wide nocase
        // Mimikatz identity strings
        $id1 = "mimikatz" ascii wide nocase
        $id2 = "gentilkiwi" ascii wide nocase
        $id3 = "benjamin" ascii wide nocase
        $id4 = "delpy" ascii wide nocase
        // LSASS targeting
        $lsass1 = "lsass.exe" ascii wide nocase
        $lsass2 = "lsass" ascii wide nocase
    condition:
        3 of ($cmd*) or
        (any of ($id*) and 2 of ($cmd*)) or
        (2 of ($id*) and any of ($lsass*))
}

rule LaZagne_Indicators {
    meta:
        description = "Detects LaZagne password recovery tool"
        severity = "critical"
        reference = "T1555"
    strings:
        $lz1 = "lazagne" ascii wide nocase
        $lz2 = "laZagne" ascii wide
        // Module names
        $mod1 = "softwares.browsers" ascii wide
        $mod2 = "softwares.sysadmin" ascii wide
        $mod3 = "softwares.wifi" ascii wide
        $mod4 = "softwares.mails" ascii wide
        $mod5 = "softwares.databases" ascii wide
        $mod6 = "softwares.memory" ascii wide
        // Password extraction strings
        $pw1 = "masterpassword" ascii wide nocase
        $pw2 = "passwordFound" ascii wide
    condition:
        any of ($lz*) and 2 of ($mod*) or
        3 of ($mod*) or
        (any of ($lz*) and any of ($pw*))
}

rule PsExec_Indicators {
    meta:
        description = "Detects PsExec and similar remote execution tools"
        severity = "high"
        reference = "T1569.002"
    strings:
        $ps1 = "PsExec" ascii wide nocase
        $ps2 = "psexesvc" ascii wide nocase
        $ps3 = "\\PSEXESVC" ascii wide nocase
        // PAExec (open-source PsExec alternative)
        $pa1 = "PAExec" ascii wide nocase
        $pa2 = "\\PAEXESVC" ascii wide nocase
        // Remote service creation
        $svc1 = "\\pipe\\svcctl" ascii wide
        $svc2 = "sc \\\\*" ascii wide nocase
        $svc3 = "OpenSCManager" ascii wide
        $svc4 = "CreateService" ascii wide
    condition:
        2 of ($ps*) or 2 of ($pa*) or
        (any of ($ps*, $pa*) and 2 of ($svc*))
}

rule Webshell_Generic {
    meta:
        description = "Detects common PHP/ASP/JSP webshell patterns"
        severity = "critical"
        reference = "T1505.003"
    strings:
        // PHP webshell patterns
        $php1 = "<?php" ascii nocase
        $php_cmd1 = "system(" ascii nocase
        $php_cmd2 = "exec(" ascii nocase
        $php_cmd3 = "passthru(" ascii nocase
        $php_cmd4 = "shell_exec(" ascii nocase
        $php_cmd5 = "popen(" ascii nocase
        $php_cmd6 = "proc_open(" ascii nocase
        $php_eval = "eval(" ascii nocase
        $php_b64 = "base64_decode(" ascii nocase
        // ASP/ASPX webshell patterns
        $asp1 = "<%@ " ascii nocase
        $asp_cmd1 = "Request(" ascii nocase
        $asp_cmd2 = "Execute(" ascii nocase
        $asp_cmd3 = "WScript.Shell" ascii nocase
        $asp_cmd4 = "cmd.exe" ascii nocase
        // JSP webshell patterns
        $jsp1 = "<%@page" ascii nocase
        $jsp_cmd1 = "Runtime.getRuntime().exec(" ascii nocase
        $jsp_cmd2 = "ProcessBuilder" ascii nocase
    condition:
        // PHP webshell
        ($php1 and $php_eval and $php_b64) or
        ($php1 and 3 of ($php_cmd*)) or
        // ASP webshell
        ($asp1 and $asp_cmd3 and $asp_cmd4) or
        ($asp1 and $asp_cmd2 and any of ($asp_cmd*)) or
        // JSP webshell
        ($jsp1 and any of ($jsp_cmd*))
}
