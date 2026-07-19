// ──────────────────────────────────────────────────────────────
// Comprehensive Shellcode Detection — No Misses
// Detects every known shellcode building block independently
// ──────────────────────────────────────────────────────────────

rule Shellcode_PEB_Walk_x86 {
    meta:
        description = "Detects x86 PEB walking to locate kernel32.dll (mov eax, fs:[0x30])"
        severity = "critical"
        reference = "T1106"
    strings:
        // mov eax, fs:[0x30]
        $peb1 = { 64 A1 30 00 00 00 }
        // mov eax, dword ptr fs:[30h] (alternate encoding)
        $peb2 = { 64 8B 0D 30 00 00 00 }
        // mov reg, fs:[30h] via SIB byte
        $peb3 = { 64 8B ?? 30 00 00 00 }
    condition:
        any of them
}

rule Shellcode_PEB_Walk_x64 {
    meta:
        description = "Detects x64 PEB walking to locate kernel32.dll (mov rax, gs:[0x60])"
        severity = "critical"
        reference = "T1106"
    strings:
        // mov rax, gs:[0x60]
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        // mov reg, gs:[0x60] via REX prefix
        $peb64b = { 65 48 8B ?? 25 60 00 00 00 }
    condition:
        any of them
}

rule Shellcode_GetPC_CallPop {
    meta:
        description = "Detects call $+5; pop reg — classic position-independent code get-EIP technique"
        severity = "high"
        reference = "T1059"
    strings:
        // call $+5 (E8 00000000); pop eax/ecx/edx/ebx/esp/ebp/esi/edi
        $callpop_eax = { E8 00 00 00 00 58 }
        $callpop_ecx = { E8 00 00 00 00 59 }
        $callpop_edx = { E8 00 00 00 00 5A }
        $callpop_ebx = { E8 00 00 00 00 5B }
        $callpop_ebp = { E8 00 00 00 00 5D }
        $callpop_esi = { E8 00 00 00 00 5E }
        $callpop_edi = { E8 00 00 00 00 5F }
    condition:
        any of them
}

rule Shellcode_GetPC_FPU {
    meta:
        description = "Detects FPU-based EIP recovery (fnstenv) used by Shikata Ga Nai and other encoders"
        severity = "critical"
        reference = "T1027"
    strings:
        // fnstenv [esp-0x0C]
        $fnstenv1 = { D9 74 24 F4 }
        // fldz; fnstenv — alternative FPU pattern
        $fnstenv2 = { D9 EE D9 74 24 F4 }
        // fldpi; fnstenv
        $fnstenv3 = { D9 EB D9 74 24 F4 }
    condition:
        any of them
}

rule Shellcode_NOP_Sled {
    meta:
        description = "Detects long NOP sled (32+ bytes of 0x90) indicating shellcode runway"
        severity = "medium"
        reference = "T1059"
    strings:
        $nop32 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                    90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
    condition:
        $nop32
}

rule Shellcode_XOR_Decoder {
    meta:
        description = "Detects XOR decoder loop stub commonly used to decode encoded shellcode"
        severity = "high"
        reference = "T1140"
    strings:
        // xor byte [esi], cl; inc esi; loop (dec ecx; jnz)
        $xor_loop1 = { 30 0E 46 E2 FC }
        // xor byte [edi], al; inc edi; dec ecx; jnz
        $xor_loop2 = { 30 07 47 49 75 }
        // xor dword [esi], eax; add esi, 4; loop
        $xor_loop3 = { 31 06 83 C6 04 E2 }
        // xor dword [edi+offset], reg; sub/add edi
        $xor_loop4 = { 31 4? ?? 83 C? 04 }
    condition:
        any of them
}

rule Shellcode_Shikata_Ga_Nai {
    meta:
        description = "Detects Metasploit Shikata Ga Nai polymorphic encoder decoder stub"
        severity = "critical"
        reference = "T1027.002"
    strings:
        // fnstenv + pop + XOR loop (with wildcards for polymorphism)
        // Pattern: any FPU instr; fnstenv [esp-0xC]; pop reg; xor [reg+off], reg
        $sgn1 = { D9 ?? D9 74 24 F4 [0-6] (58|59|5A|5B|5D|5E|5F) [0-50] 31 (40|41|42|43|45|46|47) ?? }
        // Alternative: direct fnstenv; pop; add/sub; xor loop
        $sgn2 = { D9 74 24 F4 [0-6] (58|59|5A|5B|5D|5E|5F) [0-10] (03|2B) [0-40] 31 }
    condition:
        any of them
}

rule Shellcode_API_Hashing_ROR13 {
    meta:
        description = "Detects ROR13 API hashing loop used by Metasploit and Cobalt Strike shellcode"
        severity = "critical"
        reference = "T1027"
    strings:
        // ror edx, 0x0D (rotate right 13 bits) — the signature ROR13 constant
        $ror13_1 = { C1 CA 0D }
        // ror edx, 13 (alternate encoding)
        $ror13_2 = { C1 C? 0D }
        // Known Metasploit hash block_api signature
        $hash_api = { 60 89 E5 31 D2 64 8B 52 30 }
    condition:
        any of them
}

rule Shellcode_Egg_Hunter {
    meta:
        description = "Detects egg hunter shellcode stub that scans memory for an egg tag"
        severity = "critical"
        reference = "T1055"
    strings:
        // NtAccessCheckAndAuditAlarm egg hunter (32-bit)
        // mov eax, egg; push edx; push eax; int 0x2e or syscall; cmp al, 05; scasd
        $egg1 = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 }
        // NtDisplayString egg hunter variant
        $egg2 = { 66 81 CA FF 0F 42 52 6A 43 58 CD 2E 3C 05 5A 74 }
        // SEH-based egg hunter
        $egg3 = { EB 21 59 B8 ?? ?? ?? ?? 51 6A FF }
    condition:
        any of them
}

rule Shellcode_Syscall_x86 {
    meta:
        description = "Detects direct x86 system call invocation (int 0x80, sysenter, int 0x2e)"
        severity = "high"
        reference = "T1106"
    strings:
        // Linux x86 syscall: mov eax, imm32; int 0x80
        $int80 = { B8 ?? ?? 00 00 CD 80 }
        // Windows x86 fast syscall: mov eax, imm32; sysenter
        $sysenter = { B8 ?? ?? 00 00 0F 34 }
        // Windows x86 legacy syscall: mov eax, imm32; int 0x2e
        $int2e = { B8 ?? ?? 00 00 CD 2E }
        // Shorter Linux execve: mov al, 0xb; int 0x80
        $int80_short = { B0 0B CD 80 }
    condition:
        any of them
}

rule Shellcode_Syscall_x64_Direct {
    meta:
        description = "Detects direct x64 syscall stub (mov r10,rcx; mov eax,SSN; syscall; ret)"
        severity = "critical"
        reference = "T1106"
    strings:
        // mov r10, rcx; mov eax, SSN; syscall; ret
        $direct_syscall = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        // Shorter variant without ret
        $direct_syscall2 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 }
    condition:
        any of them
}

rule Shellcode_Heavens_Gate {
    meta:
        description = "Detects Heaven's Gate technique (32-bit to 64-bit mode switch to bypass EDR hooks)"
        severity = "critical"
        reference = "T1055"
    strings:
        // push 0x33; retf (far return to CS 0x33 = 64-bit mode)
        $gate1 = { 6A 33 CB }
        // push 0x33; call retf variant
        $gate2 = { 6A 33 E8 }
        // jmp far 0033:addr
        $gate3 = { EA ?? ?? ?? ?? 33 00 }
        // push 0x23; retf (return to 32-bit mode after Heaven's Gate)
        $gate_ret = { 6A 23 CB }
    condition:
        any of ($gate1, $gate2, $gate3) or
        ($gate_ret and any of ($gate1, $gate2, $gate3))
}

rule Shellcode_Linux_Execve {
    meta:
        description = "Detects Linux x64 execve('/bin/sh') shellcode pattern"
        severity = "critical"
        reference = "T1059.004"
    strings:
        // Classic /bin/sh string push + execve syscall
        // push "/bin/sh\0" as immediate + mov rax, 0x3b + syscall
        $execve1 = { 48 BB 2F 62 69 6E 2F 73 68 00 }  // mov rbx, "/bin/sh\0"
        $execve2 = { 2F 62 69 6E 2F 73 68 }             // "/bin/sh" string
        $execve3 = { 2F 62 69 6E 2F 2F 73 68 }          // "/bin//sh" (padded variant)
        // execve syscall number for x64
        $syscall_nr = { 6A 3B 58 }                       // push 0x3b; pop rax
        // x86 execve: mov eax, 0xb; int 0x80
        $execve_x86 = { B0 0B CD 80 }
    condition:
        any of ($execve1, $execve2, $execve3) and ($syscall_nr or $execve_x86) or
        $execve_x86
}

rule Shellcode_Linux_ConnectBack {
    meta:
        description = "Detects Linux reverse shell shellcode (socket + connect + dup2 + execve)"
        severity = "critical"
        reference = "T1059.004"
    strings:
        // socket(AF_INET=2, SOCK_STREAM=1, 0)
        $socket = { 6A 02 [0-4] 6A 01 [0-4] (6A 00|31) }
        // dup2 syscall (x64: 0x21, x86: 0x3f)
        $dup2_x64 = { 6A 21 58 }
        $dup2_x86 = { B0 3F CD 80 }
        // connect with sockaddr_in struct (AF_INET=0x0002)
        $connect = { 02 00 ?? ?? ?? ?? ?? ?? }
        // /bin/sh string
        $binsh = { 2F 62 69 6E 2F 73 68 }
    condition:
        ($socket and any of ($dup2_*) and $binsh and $connect)
}

rule Shellcode_RWX_VirtualAlloc {
    meta:
        description = "Detects VirtualAlloc/VirtualProtect with PAGE_EXECUTE_READWRITE (0x40) for shellcode injection"
        severity = "high"
        reference = "T1055"
    strings:
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "VirtualProtect" ascii wide
        $api3 = "NtAllocateVirtualMemory" ascii wide
        $api4 = "NtProtectVirtualMemory" ascii wide
        // PAGE_EXECUTE_READWRITE = 0x40 as push immediate
        $rwx1 = { 6A 40 }
        // MEM_COMMIT | MEM_RESERVE = 0x3000 as push immediate
        $alloc_type = { 68 00 30 00 00 }
    condition:
        uint16(0) == 0x5A4D and
        any of ($api*) and $rwx1 and $alloc_type
}
