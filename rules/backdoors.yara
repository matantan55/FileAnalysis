// ──────────────────────────────────────────────────────────────
// Backdoor, Reverse Shell & C2 Beacon Detection
// ──────────────────────────────────────────────────────────────

rule Reverse_Shell_Generic {
    meta:
        description = "Detects generic reverse shell patterns (cmd.exe + socket pipe redirection)"
        severity = "critical"
        reference = "T1059"
    strings:
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "cmd /c" ascii wide nocase
        $cmd3 = "/bin/sh" ascii
        $cmd4 = "/bin/bash" ascii
        // Socket/pipe indicators
        $sock1 = "WSAStartup" ascii wide
        $sock2 = "WSASocket" ascii wide
        $sock3 = "connect" ascii wide
        // Pipe redirection to cmd
        $pipe1 = "CreatePipe" ascii wide
        $pipe2 = "PeekNamedPipe" ascii wide
        // Process creation with redirected I/O
        $proc1 = "CreateProcess" ascii wide
        $proc2 = "STARTUPINFO" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        any of ($cmd*) and
        (2 of ($sock*) or 2 of ($pipe*)) and
        any of ($proc*)
}

rule Meterpreter_Payload {
    meta:
        description = "Detects Metasploit Meterpreter payload indicators"
        severity = "critical"
        reference = "T1059"
    strings:
        $met1 = "metsrv" ascii wide
        $met2 = "stdapi" ascii wide
        $met3 = "ReflectiveLoader" ascii wide
        $met4 = "met_priv" ascii wide
        $met5 = "core_channel" ascii wide
        $met6 = "ext_server" ascii wide
        $met7 = "packet_dispatch" ascii wide
        // Metasploit stager patterns
        $stager1 = "msfpayload" ascii wide nocase
        $stager2 = "msfvenom" ascii wide nocase
    condition:
        3 of them
}

rule Cobalt_Strike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon configuration artifacts and named pipes"
        severity = "critical"
        reference = "T1071.001"
    strings:
        // Default named pipes
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\postex_" ascii wide
        $pipe3 = "\\\\.\\pipe\\status_" ascii wide
        $pipe4 = "\\\\.\\pipe\\MSSE-" ascii wide
        // Beacon configuration strings
        $cfg1 = "%windir%\\sysnative" ascii wide
        $cfg2 = "sleeptime" ascii wide
        $cfg3 = "%COMSPEC%" ascii wide
        $cfg4 = "spawnto_x86" ascii wide
        $cfg5 = "spawnto_x64" ascii wide
        // Beacon commands
        $cmd1 = "bypassuac" ascii wide
        $cmd2 = "hashdump" ascii wide
        $cmd3 = "mimikatz" ascii wide
        $cmd4 = "inject" ascii wide
    condition:
        3 of ($pipe*) or
        3 of ($cfg*) or
        (any of ($pipe*) and 2 of ($cfg*)) or
        (2 of ($cmd*) and any of ($pipe*, $cfg*))
}

rule Netcat_Usage {
    meta:
        description = "Detects Netcat reverse/bind shell usage patterns"
        severity = "high"
        reference = "T1059"
    strings:
        $nc1 = "nc -e" ascii wide nocase
        $nc2 = "nc.exe -e" ascii wide nocase
        $nc3 = "ncat --exec" ascii wide nocase
        $nc4 = "ncat -e" ascii wide nocase
        $nc5 = "nc -lvp" ascii wide nocase
        $nc6 = "nc.exe -l" ascii wide nocase
        $nc7 = "ncat -l" ascii wide nocase
        // socat reverse shell
        $socat1 = "socat exec:" ascii wide nocase
        $socat2 = "socat tcp:" ascii wide nocase
    condition:
        any of them
}

rule PowerShell_Reverse_Shell {
    meta:
        description = "Detects encoded/hidden PowerShell with network socket patterns for reverse shells"
        severity = "critical"
        reference = "T1059.001"
    strings:
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        // Obfuscation flags
        $flag1 = "-encodedcommand" ascii wide nocase
        $flag2 = "-enc " ascii wide nocase
        $flag3 = "-w hidden" ascii wide nocase
        $flag4 = "-windowstyle hidden" ascii wide nocase
        $flag5 = "-nop" ascii wide nocase
        $flag6 = "-noprofile" ascii wide nocase
        // Network indicators in PS
        $net1 = "Net.Sockets.TCPClient" ascii wide nocase
        $net2 = "System.Net.Sockets" ascii wide nocase
        $net3 = "Invoke-Expression" ascii wide nocase
        $net4 = "IEX" ascii wide
        $net5 = "downloadstring" ascii wide nocase
        $net6 = "downloadfile" ascii wide nocase
        $net7 = "Net.WebClient" ascii wide nocase
        $net8 = "Invoke-WebRequest" ascii wide nocase
    condition:
        any of ($ps*) and
        (any of ($flag*) and any of ($net*))
}
