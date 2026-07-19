// ──────────────────────────────────────────────────────────────
// Packers & Obfuscation Detection
// Detects files packed or protected with known packers/protectors
// ──────────────────────────────────────────────────────────────

rule UPX_Packed {
    meta:
        description = "Detects files packed with UPX"
        severity = "medium"
        reference = "T1027.002"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX2" ascii
        $upx_sig = "UPX!" ascii
    condition:
        2 of them
}

rule ASPack_Packed {
    meta:
        description = "Detects files packed with ASPack"
        severity = "medium"
        reference = "T1027.002"
    strings:
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
    condition:
        all of them
}

rule Themida_Packed {
    meta:
        description = "Detects files protected with Themida/WinLicense"
        severity = "high"
        reference = "T1027.002"
    strings:
        $s1 = ".themida" ascii
        $s2 = ".winlice" ascii
        $s3 = "THEMIDA" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule MPRESS_Packed {
    meta:
        description = "Detects files packed with MPRESS"
        severity = "medium"
        reference = "T1027.002"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule VMProtect_Packed {
    meta:
        description = "Detects files protected with VMProtect virtualizer"
        severity = "high"
        reference = "T1027.002"
    strings:
        $s1 = ".vmp0" ascii
        $s2 = ".vmp1" ascii
        $s3 = ".vmp2" ascii
        $s4 = "VMProtect" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Enigma_Packed {
    meta:
        description = "Detects files protected with Enigma Protector"
        severity = "medium"
        reference = "T1027.002"
    strings:
        $s1 = ".enigma1" ascii
        $s2 = ".enigma2" ascii
        $s3 = "Enigma protector" ascii nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule NSPack_Packed {
    meta:
        description = "Detects files packed with NSPack/North Star Packer"
        severity = "medium"
        reference = "T1027.002"
    strings:
        $s1 = ".nsp0" ascii
        $s2 = ".nsp1" ascii
        $s3 = ".nsp2" ascii
        $s4 = "nsPack" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
