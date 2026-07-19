// ──────────────────────────────────────────────────────────────
// Rootkit Detection
// Detects kernel manipulation, driver loading, and process hiding techniques
// ──────────────────────────────────────────────────────────────

rule Rootkit_Kernel_APIs {
    meta:
        description = "Detects rootkit-associated kernel manipulation APIs (DKOM, process/file hiding)"
        severity = "critical"
        reference = "T1014"
    strings:
        // Direct kernel object manipulation
        $api1 = "NtQuerySystemInformation" ascii wide
        $api2 = "ZwQuerySystemInformation" ascii wide
        $api3 = "NtQueryDirectoryFile" ascii wide
        $api4 = "ZwQueryDirectoryFile" ascii wide
        $api5 = "NtQueryInformationProcess" ascii wide
        // Process/thread hiding
        $hide1 = "PsGetCurrentProcess" ascii wide
        $hide2 = "PsLookupProcessByProcessId" ascii wide
        $hide3 = "ObDereferenceObject" ascii wide
        // EPROCESS manipulation keywords
        $eproc1 = "ActiveProcessLinks" ascii wide
        $eproc2 = "EPROCESS" ascii wide
        $eproc3 = "KPROCESS" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($api*) and any of ($hide*)) or
        (any of ($eproc*) and 2 of ($api*))
}

rule Rootkit_Driver_Loading {
    meta:
        description = "Detects suspicious kernel driver loading patterns"
        severity = "critical"
        reference = "T1014"
    strings:
        $drv1 = "NtLoadDriver" ascii wide
        $drv2 = "ZwLoadDriver" ascii wide
        $drv3 = "IoCreateDevice" ascii wide
        $drv4 = "IoCreateSymbolicLink" ascii wide
        $drv5 = "DriverEntry" ascii wide
        $drv6 = "IRP_MJ_CREATE" ascii wide
        $drv7 = "IRP_MJ_DEVICE_CONTROL" ascii wide
        // System service registration
        $svc1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" ascii wide nocase
        $svc2 = "\\Driver\\" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (($drv1 or $drv2) and any of ($drv3, $drv4)) or
        ($drv5 and 2 of ($drv6, $drv7, $drv3, $drv4) and any of ($svc*))
}

rule Rootkit_SSDT_Hook {
    meta:
        description = "Detects SSDT (System Service Descriptor Table) hooking references"
        severity = "critical"
        reference = "T1014"
    strings:
        $ssdt1 = "KeServiceDescriptorTable" ascii wide
        $ssdt2 = "KiServiceTable" ascii wide
        $ssdt3 = "ServiceTableBase" ascii wide
        $ssdt4 = "NumberOfServices" ascii wide
        // Inline hooking patterns
        $hook1 = "MmGetSystemRoutineAddress" ascii wide
        $hook2 = "ExAllocatePool" ascii wide
        $hook3 = "MmMapIoSpace" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (2 of ($ssdt*)) or
        (any of ($ssdt*) and 2 of ($hook*))
}

rule Rootkit_Process_Hide {
    meta:
        description = "Detects process hiding via EPROCESS linked list unlinking (DKOM)"
        severity = "critical"
        reference = "T1014"
    strings:
        // EPROCESS linked list manipulation
        $dkom1 = "ActiveProcessLinks" ascii wide
        $dkom2 = "Flink" ascii wide
        $dkom3 = "Blink" ascii wide
        // Process lookup
        $proc1 = "PsLookupProcessByProcessId" ascii wide
        $proc2 = "PsGetCurrentProcess" ascii wide
        $proc3 = "KeAttachProcess" ascii wide
        // Thread hiding
        $thread1 = "PsLookupThreadByThreadId" ascii wide
        $thread2 = "KeInsertQueueApc" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        $dkom1 and ($dkom2 or $dkom3) and
        (any of ($proc*) or any of ($thread*))
}
