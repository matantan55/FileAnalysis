// ──────────────────────────────────────────────────────────────
// Cryptominer Detection
// Detects cryptocurrency mining software and stratum protocol usage
// ──────────────────────────────────────────────────────────────

rule Cryptominer_XMRig {
    meta:
        description = "Detects XMRig Monero miner configuration strings"
        severity = "high"
        reference = "T1496"
    strings:
        $xmrig1 = "xmrig" ascii wide nocase
        $xmrig2 = "XMRig" ascii wide
        // Mining algorithm names
        $algo1 = "cryptonight" ascii wide nocase
        $algo2 = "randomx" ascii wide nocase
        $algo3 = "cn/r" ascii wide nocase
        $algo4 = "rx/0" ascii wide nocase
        $algo5 = "argon2" ascii wide nocase
        // Configuration strings
        $cfg1 = "donate-level" ascii wide
        $cfg2 = "mining server" ascii wide nocase
        $cfg3 = "threads count" ascii wide nocase
        $cfg4 = "enable CUDA" ascii wide nocase
        $cfg5 = "enable OpenCL" ascii wide nocase
        // Hashrate indicators
        $hash1 = "hashrate" ascii wide nocase
        $hash2 = "H/s" ascii wide
        $hash3 = "KH/s" ascii wide
    condition:
        any of ($xmrig*) and any of ($algo*) or
        3 of ($algo*) or
        (2 of ($cfg*) and any of ($algo*)) or
        (any of ($hash*) and any of ($algo*))
}

rule Cryptominer_Stratum {
    meta:
        description = "Detects Stratum mining protocol indicators"
        severity = "high"
        reference = "T1496"
    strings:
        $stratum1 = "stratum+tcp://" ascii wide nocase
        $stratum2 = "stratum+ssl://" ascii wide nocase
        $stratum3 = "stratum+tls://" ascii wide nocase
        // JSON-RPC mining methods
        $rpc1 = "mining.subscribe" ascii wide
        $rpc2 = "mining.authorize" ascii wide
        $rpc3 = "mining.submit" ascii wide
        $rpc4 = "mining.notify" ascii wide
    condition:
        any of ($stratum*) or
        2 of ($rpc*)
}

rule Cryptominer_Generic {
    meta:
        description = "Detects generic cryptocurrency mining indicators (pool domains, wallet patterns)"
        severity = "medium"
        reference = "T1496"
    strings:
        // Common mining pool domains
        $pool1 = "pool.minexmr.com" ascii wide nocase
        $pool2 = "xmrpool.eu" ascii wide nocase
        $pool3 = "pool.supportxmr.com" ascii wide nocase
        $pool4 = "mine.moneropool.com" ascii wide nocase
        $pool5 = "monerohash.com" ascii wide nocase
        $pool6 = "nanopool.org" ascii wide nocase
        $pool7 = "2miners.com" ascii wide nocase
        $pool8 = "hashvault.pro" ascii wide nocase
        $pool9 = "herominers.com" ascii wide nocase
        $pool10 = "unmineable.com" ascii wide nocase
        // Mining-related strings
        $mine1 = "coin-hive" ascii wide nocase
        $mine2 = "coinhive" ascii wide nocase
        $mine3 = "minergate" ascii wide nocase
        // Wallet address patterns (Monero 95-char addresses starting with 4)
        $wallet_xmr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
    condition:
        any of ($pool*) or
        2 of ($mine*) or
        ($wallet_xmr and any of ($mine*, $pool*))
}
