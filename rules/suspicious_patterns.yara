// ──────────────────────────────────────────────────────────────
// Suspicious Patterns & Process Injection Detection
// ──────────────────────────────────────────────────────────────

rule EICAR_Test_File {
    meta:
        description = "Standard Antivirus Test File"
        severity = "critical"
        reference = "https://www.eicar.org/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

rule Suspicious_Shellcode {
    meta:
        description = "Detects potential Windows x86/x64 shellcode triggers or API hashes"
        severity = "high"
        reference = "T1059"
    strings:
        // Common Win32 API hashing signatures or shellcode headers
        $sc_win = { 55 8B EC 83 EC } // push ebp; mov ebp, esp; sub esp, ...
        $sc_call = { E8 00 00 00 00 58 } // call $+5; pop eax (get PC)
    condition:
        any of them
}

rule Process_Injection_APIs {
    meta:
        description = "Detects classic process injection API call chain (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)"
        severity = "high"
        reference = "T1055"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtWriteVirtualMemory" ascii wide
        $api5 = "RtlCreateUserThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        $api1 and $api2 and ($api3 or $api4 or $api5)
}

rule Process_Hollowing {
    meta:
        description = "Detects process hollowing technique (unmap + write + resume)"
        severity = "critical"
        reference = "T1055.012"
    strings:
        $api1 = "NtUnmapViewOfSection" ascii wide
        $api1b = "ZwUnmapViewOfSection" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "ResumeThread" ascii wide
        $api4 = "NtResumeThread" ascii wide
        $api5 = "SetThreadContext" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        ($api1 or $api1b) and $api2 and ($api3 or $api4 or $api5)
}

rule Reflective_DLL_Injection {
    meta:
        description = "Detects reflective DLL injection via ReflectiveLoader export or known stub"
        severity = "critical"
        reference = "T1620"
    strings:
        $export1 = "ReflectiveLoader" ascii wide
        $export2 = "_ReflectiveLoader@4" ascii
        $export3 = "reflective_dll" ascii nocase
        // Stephen Fewer's reflective loader stub signature
        $stub = { 4D 5A 41 52 55 48 89 E5 }
    condition:
        any of them
}
