// ──────────────────────────────────────────────────────────────
// Worm & Self-Propagation Detection
// Detects USB spreading, network propagation, and self-replication
// ──────────────────────────────────────────────────────────────

rule Worm_USB_Propagation {
    meta:
        description = "Detects USB worm propagation via autorun.inf and removable drive scanning"
        severity = "high"
        reference = "T1091"
    strings:
        $autorun1 = "autorun.inf" ascii wide nocase
        $autorun2 = "[autorun]" ascii wide nocase
        $autorun3 = "open=" ascii wide nocase
        $autorun4 = "shellexecute=" ascii wide nocase
        // Drive type checking
        $drive1 = "GetDriveType" ascii wide
        $drive2 = "DRIVE_REMOVABLE" ascii wide
        $drive3 = "GetLogicalDrives" ascii wide
        $drive4 = "GetLogicalDriveStrings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($autorun*)) or
        (any of ($autorun*) and 2 of ($drive*))
}

rule Worm_Network_Spread {
    meta:
        description = "Detects network worm propagation via SMB/share enumeration and file copy"
        severity = "high"
        reference = "T1021.002"
    strings:
        // Network share enumeration
        $share1 = "NetShareEnum" ascii wide
        $share2 = "WNetOpenEnum" ascii wide
        $share3 = "WNetEnumResource" ascii wide
        $share4 = "WNetAddConnection" ascii wide
        // Admin shares
        $admin1 = "\\\\*\\ADMIN$" ascii wide
        $admin2 = "\\\\*\\C$" ascii wide
        $admin3 = "\\\\*\\IPC$" ascii wide
        // File copy to network
        $copy1 = "CopyFile" ascii wide
        $copy2 = "MoveFile" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        2 of ($share*) and any of ($copy*) or
        (any of ($admin*) and any of ($copy*))
}

rule Worm_Email_Spread {
    meta:
        description = "Detects email worm propagation via SMTP/MAPI with contact harvesting"
        severity = "high"
        reference = "T1566.001"
    strings:
        // SMTP indicators
        $smtp1 = "MAIL FROM:" ascii wide nocase
        $smtp2 = "RCPT TO:" ascii wide nocase
        $smtp3 = "EHLO " ascii wide nocase
        $smtp4 = "HELO " ascii wide nocase
        $smtp5 = "smtp" ascii wide nocase
        // MAPI
        $mapi1 = "MAPISendMail" ascii wide
        $mapi2 = "MAPILogon" ascii wide
        // Address book harvesting
        $harvest1 = "WAB" ascii wide
        $harvest2 = "@" ascii wide
        $harvest3 = "address book" ascii wide nocase
        $harvest4 = "Outlook" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($smtp*) or 2 of ($mapi*)) and
        2 of ($harvest*)
}

rule Worm_Self_Copy {
    meta:
        description = "Detects self-replication pattern (GetModuleFileName + CopyFile)"
        severity = "medium"
        reference = "T1570"
    strings:
        // Get own path
        $self1 = "GetModuleFileName" ascii wide
        $self2 = "GetModuleHandle" ascii wide
        // Copy self
        $copy1 = "CopyFile" ascii wide
        $copy2 = "MoveFile" ascii wide
        // Startup persistence
        $persist1 = "\\Start Menu\\Programs\\Startup" ascii wide nocase
        $persist2 = "\\CurrentVersion\\Run" ascii wide nocase
        $persist3 = "HKCU" ascii wide
        $persist4 = "HKLM" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        any of ($self*) and any of ($copy*) and
        2 of ($persist*)
}
