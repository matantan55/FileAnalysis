rule UPX_Packed {
    meta:
        description = "Detects files packed with UPX"
        severity = "medium"
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
    strings:
        $aspack = ".aspack" ascii
        $adata = ".adata" ascii
    condition:
        all of them
}
