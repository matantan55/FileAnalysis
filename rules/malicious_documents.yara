// ──────────────────────────────────────────────────────────────
// Malicious Document Detection
// Detects weaponized Office documents, PDFs, and document-based droppers
// ──────────────────────────────────────────────────────────────

rule Malicious_OLE_Macro {
    meta:
        description = "Detects OLE documents with VBA macro indicators and suspicious patterns"
        severity = "high"
        reference = "T1204.002"
    strings:
        // OLE file header (Classic Office .doc, .xls, .ppt)
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }
        // VBA project indicators
        $vba1 = "vbaProject.bin" ascii wide
        $vba2 = { 41 74 74 72 69 62 75 74 } // "Attribut" (VBA compressed stream marker)
        $vba3 = "_VBA_PROJECT" ascii wide
        $vba4 = "VBA" ascii wide
        // Suspicious macro actions
        $action1 = "Auto_Open" ascii wide nocase
        $action2 = "AutoOpen" ascii wide nocase
        $action3 = "Document_Open" ascii wide nocase
        $action4 = "Workbook_Open" ascii wide nocase
        $action5 = "AutoExec" ascii wide nocase
        // Dangerous function calls inside macros
        $func1 = "Shell(" ascii wide nocase
        $func2 = "WScript.Shell" ascii wide nocase
        $func3 = "CreateObject" ascii wide nocase
        $func4 = "CallByName" ascii wide nocase
        $func5 = "powershell" ascii wide nocase
        $func6 = "cmd.exe" ascii wide nocase
    condition:
        $ole_header at 0 and
        any of ($vba*) and
        (any of ($action*) and any of ($func*))
}

rule Malicious_PDF_JavaScript {
    meta:
        description = "Detects PDFs with embedded JavaScript or suspicious actions"
        severity = "high"
        reference = "T1204.002"
    strings:
        $pdf_header = "%PDF-" ascii
        // JavaScript in PDF
        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS " ascii
        $js3 = "/JS(" ascii
        // Automatic actions
        $action1 = "/OpenAction" ascii
        $action2 = "/AA" ascii
        $action3 = "/Launch" ascii
        $action4 = "/SubmitForm" ascii
        $action5 = "/ImportData" ascii
        // Embedded file indicators
        $embed1 = "/EmbeddedFile" ascii
        $embed2 = "/Filespec" ascii
        // Suspicious JavaScript content
        $exploit1 = "eval(" ascii nocase
        $exploit2 = "unescape(" ascii nocase
        $exploit3 = "String.fromCharCode" ascii nocase
        $exploit4 = "getAnnots" ascii nocase
        $exploit5 = "getPageNthWord" ascii nocase
        $exploit6 = "this.exportDataObject" ascii nocase
    condition:
        $pdf_header at 0 and
        (any of ($js*) and any of ($action*)) or
        (any of ($js*) and 2 of ($exploit*)) or
        ($action3 and any of ($embed*))
}

rule Malicious_Office_PowerShell {
    meta:
        description = "Detects Office documents containing PowerShell execution commands"
        severity = "critical"
        reference = "T1059.001"
    strings:
        // OLE header
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        // OOXML (ZIP) header
        $zip = { 50 4B 03 04 }
        // PowerShell indicators
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "pwsh" ascii wide nocase
        $ps3 = "-encodedcommand" ascii wide nocase
        $ps4 = "-enc " ascii wide nocase
        $ps5 = "Invoke-Expression" ascii wide nocase
        $ps6 = "IEX" ascii wide
        $ps7 = "-w hidden" ascii wide nocase
        $ps8 = "downloadstring" ascii wide nocase
        $ps9 = "Net.WebClient" ascii wide nocase
        $ps10 = "Start-Process" ascii wide nocase
    condition:
        ($ole at 0 or $zip at 0) and
        3 of ($ps*)
}

rule Malicious_Document_Dropper {
    meta:
        description = "Detects documents with embedded PE executables (MZ header inside document)"
        severity = "critical"
        reference = "T1027.006"
    strings:
        // Document headers
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip = { 50 4B 03 04 }
        $pdf = "%PDF-" ascii
        $rtf = "{\\rtf" ascii
        // Embedded PE file (MZ header NOT at position 0)
        $mz = "MZ" ascii
        // PE signature
        $pe = "PE\x00\x00" ascii
        // Common dropper strings
        $drop1 = "This program cannot be run in DOS mode" ascii
        $drop2 = ".text" ascii
        $drop3 = ".rdata" ascii
    condition:
        ($ole at 0 or $zip at 0 or $pdf at 0 or $rtf at 0) and
        $mz and $pe and
        any of ($drop*)
}
