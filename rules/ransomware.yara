// ──────────────────────────────────────────────────────────────
// Ransomware Detection
// Detects ransomware encryption, shadow copy deletion, and ransom notes
// ──────────────────────────────────────────────────────────────

rule Ransomware_CryptoAPI {
    meta:
        description = "Detects combination of Windows CryptoAPI/BCrypt encryption functions with ransom indicators"
        severity = "critical"
        reference = "T1486"
    strings:
        // Legacy CryptoAPI
        $crypto1 = "CryptAcquireContext" ascii wide
        $crypto2 = "CryptEncrypt" ascii wide
        $crypto3 = "CryptGenKey" ascii wide
        $crypto4 = "CryptDeriveKey" ascii wide
        $crypto5 = "CryptImportKey" ascii wide
        // Modern BCrypt API
        $bcrypt1 = "BCryptEncrypt" ascii wide
        $bcrypt2 = "BCryptGenerateSymmetricKey" ascii wide
        $bcrypt3 = "BCryptImportKeyPair" ascii wide
        // Ransomware behavioral indicators (must be paired with crypto)
        $ransom1 = "YOUR FILES" ascii wide nocase
        $ransom2 = "DECRYPT" ascii wide nocase
        $ransom3 = "bitcoin" ascii wide nocase
        $ransom4 = "ransom" ascii wide nocase
        $ransom5 = "payment" ascii wide nocase
        $ransom6 = "wallet" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($crypto*) or 2 of ($bcrypt*)) and
        2 of ($ransom*)
}

rule Ransomware_Shadow_Delete {
    meta:
        description = "Detects Volume Shadow Copy deletion commands used by ransomware"
        severity = "critical"
        reference = "T1490"
    strings:
        $vss1 = "vssadmin delete shadows" ascii wide nocase
        $vss2 = "vssadmin.exe delete shadows" ascii wide nocase
        $vss3 = "wmic shadowcopy delete" ascii wide nocase
        $vss4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $vss5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $vss6 = "wbadmin delete catalog" ascii wide nocase
        // PowerShell variants
        $ps1 = "Get-WmiObject Win32_ShadowCopy" ascii wide nocase
        $ps2 = "Win32_ShadowCopy" ascii wide nocase
    condition:
        any of them
}

rule Ransomware_Note_Indicators {
    meta:
        description = "Detects common ransomware ransom note filenames and patterns"
        severity = "high"
        reference = "T1486"
    strings:
        $note1 = "HOW_TO_RECOVER" ascii wide nocase
        $note2 = "HOW_TO_DECRYPT" ascii wide nocase
        $note3 = "README_TO_DECRYPT" ascii wide nocase
        $note4 = "RECOVERY_INSTRUCTIONS" ascii wide nocase
        $note5 = "DECRYPT_INSTRUCTIONS" ascii wide nocase
        $note6 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $note7 = "RESTORE_FILES" ascii wide nocase
        $note8 = "FILES_ENCRYPTED" ascii wide nocase
        $note9 = "HELP_DECRYPT" ascii wide nocase
        $note10 = "!README!" ascii wide
    condition:
        2 of them
}

rule Ransomware_File_Extensions {
    meta:
        description = "Detects references to known ransomware encrypted file extensions"
        severity = "high"
        reference = "T1486"
    strings:
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypt" ascii wide
        $ext4 = ".wncry" ascii wide
        $ext5 = ".wcry" ascii wide
        $ext6 = ".locky" ascii wide
        $ext7 = ".cerber" ascii wide
        $ext8 = ".zepto" ascii wide
        $ext9 = ".dharma" ascii wide
        $ext10 = ".ryuk" ascii wide
        $ext11 = ".conti" ascii wide
        $ext12 = ".lockbit" ascii wide
        $ext13 = ".blackcat" ascii wide
        $ext14 = ".hive" ascii wide
    condition:
        3 of them
}
