rule EICAR_Test_File {
    meta:
        description = "Standard Antivirus Test File"
        severity = "critical"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

rule Suspicious_Shellcode {
    meta:
        description = "Detects potential Windows x86/x64 shellcode triggers or API hashes"
        severity = "high"
    strings:
        // Common Win32 API hashing signatures or shellcode headers
        $sc_win = { 55 8B EC 83 EC } // push ebp; mov ebp, esp; sub esp, ...
        $sc_call = { E8 00 00 00 00 58 } // call $+5; pop eax (get PC)
    condition:
        all of them
}
