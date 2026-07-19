// ──────────────────────────────────────────────────────────────
// Infostealer & Keylogger Detection
// Detects credential theft, browser data exfiltration, and input capture
// ──────────────────────────────────────────────────────────────

rule Infostealer_Browser_Paths {
    meta:
        description = "Detects references to browser credential and cookie storage paths"
        severity = "high"
        reference = "T1555.003"
    strings:
        // Chrome
        $chrome1 = "\\Google\\Chrome\\User Data" ascii wide nocase
        $chrome2 = "Login Data" ascii wide
        $chrome3 = "Web Data" ascii wide
        $chrome4 = "Cookies" ascii wide
        // Firefox
        $ff1 = "\\Mozilla\\Firefox\\Profiles" ascii wide nocase
        $ff2 = "logins.json" ascii wide
        $ff3 = "key4.db" ascii wide
        $ff4 = "cookies.sqlite" ascii wide
        // Edge
        $edge1 = "\\Microsoft\\Edge\\User Data" ascii wide nocase
        // Opera
        $opera1 = "\\Opera Software\\Opera Stable" ascii wide nocase
        // Brave
        $brave1 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        4 of them
}

rule Infostealer_Crypto_Wallets {
    meta:
        description = "Detects references to cryptocurrency wallet files and browser extensions"
        severity = "high"
        reference = "T1005"
    strings:
        $wallet1 = "wallet.dat" ascii wide nocase
        $wallet2 = "\\Electrum\\wallets" ascii wide nocase
        $wallet3 = "\\Ethereum\\keystore" ascii wide nocase
        $wallet4 = "\\Exodus\\exodus.wallet" ascii wide nocase
        $wallet5 = "\\Atomic\\Local Storage" ascii wide nocase
        $wallet6 = "\\com.liberty.jaxx" ascii wide nocase
        $wallet7 = "\\Coinomi\\wallets" ascii wide nocase
        // MetaMask browser extension IDs
        $mm1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        // Phantom wallet
        $mm2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
    condition:
        3 of them
}

rule Keylogger_APIs {
    meta:
        description = "Detects Windows API combination commonly used by keyloggers"
        severity = "high"
        reference = "T1056.001"
    strings:
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetAsyncKeyState" ascii wide
        $api3 = "GetKeyState" ascii wide
        $api4 = "GetForegroundWindow" ascii wide
        $api5 = "GetWindowText" ascii wide
        $api6 = "MapVirtualKey" ascii wide
        $api7 = "GetKeyboardState" ascii wide
        $api8 = "GetClipboardData" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        3 of ($api*)
}

rule Infostealer_DPAPI {
    meta:
        description = "Detects Windows DPAPI abuse for credential decryption"
        severity = "high"
        reference = "T1555"
    strings:
        $dpapi1 = "CryptUnprotectData" ascii wide
        $dpapi2 = "CryptProtectData" ascii wide
        // Combined with browser paths = infostealer
        $browser1 = "Login Data" ascii wide
        $browser2 = "Cookies" ascii wide
        $browser3 = "Web Data" ascii wide
        $browser4 = "\\Chrome\\" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        any of ($dpapi*) and 2 of ($browser*)
}
