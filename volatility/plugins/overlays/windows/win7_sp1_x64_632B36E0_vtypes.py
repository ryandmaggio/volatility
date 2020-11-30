ntkrnlmp_types = {
    '_FILE_BASIC_INFORMATION': [
        0x28,
        {
            'CreationTime': [0x0, ['_LARGE_INTEGER']],
            'LastAccessTime': [0x8, ['_LARGE_INTEGER']],
            'LastWriteTime': [0x10, ['_LARGE_INTEGER']],
            'ChangeTime': [0x18, ['_LARGE_INTEGER']],
            'FileAttributes': [0x20, ['unsigned long']],
        },
    ],
    '_SECURITY_SUBJECT_CONTEXT': [
        0x20,
        {
            'ClientToken': [0x0, ['pointer64', ['void']]],
            'ImpersonationLevel': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'SecurityAnonymous',
                            1: 'SecurityIdentification',
                            2: 'SecurityImpersonation',
                            3: 'SecurityDelegation',
                        },
                    ),
                ],
            ],
            'PrimaryToken': [0x10, ['pointer64', ['void']]],
            'ProcessAuditId': [0x18, ['pointer64', ['void']]],
        },
    ],
    '_KBUGCHECK_ACTIVE_STATE': [
        0x4,
        {
            'BugCheckState': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'RecursionCount': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'BugCheckOwner': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'Value': [0x0, ['long']],
        },
    ],
    '_PF_KERNEL_GLOBALS': [
        0x60,
        {
            'AccessBufferAgeThreshold': [0x0, ['unsigned long long']],
            'AccessBufferRef': [0x8, ['_EX_RUNDOWN_REF']],
            'AccessBufferExistsEvent': [0x10, ['_KEVENT']],
            'AccessBufferMax': [0x28, ['unsigned long']],
            'AccessBufferList': [0x40, ['_SLIST_HEADER']],
            'StreamSequenceNumber': [0x50, ['long']],
            'Flags': [0x54, ['unsigned long']],
            'ScenarioPrefetchCount': [0x58, ['long']],
        },
    ],
    '_ARBITER_QUERY_ARBITRATE_PARAMETERS': [
        0x8,
        {
            'ArbitrationList': [0x0, ['pointer64', ['_LIST_ENTRY']]],
        },
    ],
    '_ARBITER_BOOT_ALLOCATION_PARAMETERS': [
        0x8,
        {
            'ArbitrationList': [0x0, ['pointer64', ['_LIST_ENTRY']]],
        },
    ],
    '_EXCEPTION_REGISTRATION_RECORD': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_EXCEPTION_REGISTRATION_RECORD']]],
            'Handler': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_POP_SYSTEM_IDLE': [
        0x38,
        {
            'AverageIdleness': [0x0, ['long']],
            'LowestIdleness': [0x4, ['long']],
            'Time': [0x8, ['unsigned long']],
            'Timeout': [0xC, ['unsigned long']],
            'LastUserInput': [0x10, ['unsigned long']],
            'Action': [0x14, ['POWER_ACTION_POLICY']],
            'MinState': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'SystemRequired': [0x24, ['unsigned char']],
            'IdleWorker': [0x25, ['unsigned char']],
            'Sampling': [0x26, ['unsigned char']],
            'LastTick': [0x28, ['unsigned long long']],
            'LastSystemRequiredTime': [0x30, ['unsigned long']],
        },
    ],
    '_VF_TARGET_ALL_SHARED_EXPORT_THUNKS': [
        0x18,
        {
            'SharedExportThunks': [
                0x0,
                ['pointer64', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
            'PoolSharedExportThunks': [
                0x8,
                ['pointer64', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
            'OrderDependentSharedExportThunks': [
                0x10,
                ['pointer64', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
        },
    ],
    '_ETW_REF_CLOCK': [
        0x10,
        {
            'StartTime': [0x0, ['_LARGE_INTEGER']],
            'StartPerfClock': [0x8, ['_LARGE_INTEGER']],
        },
    ],
    '_OB_DUPLICATE_OBJECT_STATE': [
        0x28,
        {
            'SourceProcess': [0x0, ['pointer64', ['_EPROCESS']]],
            'SourceHandle': [0x8, ['pointer64', ['void']]],
            'Object': [0x10, ['pointer64', ['void']]],
            'TargetAccess': [0x18, ['unsigned long']],
            'ObjectInfo': [0x1C, ['_HANDLE_TABLE_ENTRY_INFO']],
            'HandleAttributes': [0x20, ['unsigned long']],
        },
    ],
    '_MMPTE_SUBSECTION': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SubsectionAddress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=16, end_bit=64, native_type='long long'),
                ],
            ],
        },
    ],
    '_POWER_STATE': [
        0x4,
        {
            'SystemState': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'DeviceState': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerDeviceUnspecified',
                            1: 'PowerDeviceD0',
                            2: 'PowerDeviceD1',
                            3: 'PowerDeviceD2',
                            4: 'PowerDeviceD3',
                            5: 'PowerDeviceMaximum',
                        },
                    ),
                ],
            ],
        },
    ],
    '_EFI_FIRMWARE_INFORMATION': [
        0x18,
        {
            'FirmwareVersion': [0x0, ['unsigned long']],
            'VirtualEfiRuntimeServices': [
                0x8,
                ['pointer64', ['_VIRTUAL_EFI_RUNTIME_SERVICES']],
            ],
            'SetVirtualAddressMapStatus': [0x10, ['long']],
            'MissedMappingsCount': [0x14, ['unsigned long']],
        },
    ],
    '__unnamed_202c': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_202e': [
        0x10,
        {
            'Level': [0x0, ['unsigned short']],
            'Group': [0x2, ['unsigned short']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_2030': [
        0x10,
        {
            'Group': [0x0, ['unsigned short']],
            'MessageCount': [0x2, ['unsigned short']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_2032': [
        0x10,
        {
            'Raw': [0x0, ['__unnamed_2030']],
            'Translated': [0x0, ['__unnamed_202e']],
        },
    ],
    '__unnamed_2034': [
        0xC,
        {
            'Channel': [0x0, ['unsigned long']],
            'Port': [0x4, ['unsigned long']],
            'Reserved1': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2036': [
        0xC,
        {
            'Start': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2038': [
        0xC,
        {
            'DataSize': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_203a': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length40': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_203c': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length48': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_203e': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length64': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2040': [
        0x10,
        {
            'Generic': [0x0, ['__unnamed_202c']],
            'Port': [0x0, ['__unnamed_202c']],
            'Interrupt': [0x0, ['__unnamed_202e']],
            'MessageInterrupt': [0x0, ['__unnamed_2032']],
            'Memory': [0x0, ['__unnamed_202c']],
            'Dma': [0x0, ['__unnamed_2034']],
            'DevicePrivate': [0x0, ['__unnamed_1eff']],
            'BusNumber': [0x0, ['__unnamed_2036']],
            'DeviceSpecificData': [0x0, ['__unnamed_2038']],
            'Memory40': [0x0, ['__unnamed_203a']],
            'Memory48': [0x0, ['__unnamed_203c']],
            'Memory64': [0x0, ['__unnamed_203e']],
        },
    ],
    '_CM_PARTIAL_RESOURCE_DESCRIPTOR': [
        0x14,
        {
            'Type': [0x0, ['unsigned char']],
            'ShareDisposition': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned short']],
            'u': [0x4, ['__unnamed_2040']],
        },
    ],
    '__unnamed_2045': [
        0x4,
        {
            'PhysicalAddress': [0x0, ['unsigned long']],
            'VirtualSize': [0x0, ['unsigned long']],
        },
    ],
    '_IMAGE_SECTION_HEADER': [
        0x28,
        {
            'Name': [0x0, ['array', 8, ['unsigned char']]],
            'Misc': [0x8, ['__unnamed_2045']],
            'VirtualAddress': [0xC, ['unsigned long']],
            'SizeOfRawData': [0x10, ['unsigned long']],
            'PointerToRawData': [0x14, ['unsigned long']],
            'PointerToRelocations': [0x18, ['unsigned long']],
            'PointerToLinenumbers': [0x1C, ['unsigned long']],
            'NumberOfRelocations': [0x20, ['unsigned short']],
            'NumberOfLinenumbers': [0x22, ['unsigned short']],
            'Characteristics': [0x24, ['unsigned long']],
        },
    ],
    '_ARBITER_ADD_RESERVED_PARAMETERS': [
        0x8,
        {
            'ReserveDevice': [0x0, ['pointer64', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_204f': [
        0x50,
        {
            'CellData': [0x0, ['_CELL_DATA']],
            'List': [0x0, ['array', 1, ['unsigned long long']]],
        },
    ],
    '_CM_CACHED_VALUE_INDEX': [
        0x58,
        {
            'CellIndex': [0x0, ['unsigned long']],
            'Data': [0x8, ['__unnamed_204f']],
        },
    ],
    '_CONFIGURATION_COMPONENT_DATA': [
        0x48,
        {
            'Parent': [0x0, ['pointer64', ['_CONFIGURATION_COMPONENT_DATA']]],
            'Child': [0x8, ['pointer64', ['_CONFIGURATION_COMPONENT_DATA']]],
            'Sibling': [
                0x10,
                ['pointer64', ['_CONFIGURATION_COMPONENT_DATA']],
            ],
            'ComponentEntry': [0x18, ['_CONFIGURATION_COMPONENT']],
            'ConfigurationData': [0x40, ['pointer64', ['void']]],
        },
    ],
    '_DBGKD_QUERY_SPECIAL_CALLS': [
        0x4,
        {
            'NumberOfSpecialCalls': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_2059': [
        0x8,
        {
            'Balance': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='long long'),
                ],
            ],
            'Parent': [0x0, ['pointer64', ['_MMSUBSECTION_NODE']]],
        },
    ],
    '_MMSUBSECTION_NODE': [
        0x28,
        {
            'u': [0x0, ['__unnamed_1fb7']],
            'StartingSector': [0x4, ['unsigned long']],
            'NumberOfFullSectors': [0x8, ['unsigned long']],
            'u1': [0x10, ['__unnamed_2059']],
            'LeftChild': [0x18, ['pointer64', ['_MMSUBSECTION_NODE']]],
            'RightChild': [0x20, ['pointer64', ['_MMSUBSECTION_NODE']]],
        },
    ],
    '_VF_AVL_TREE_NODE': [
        0x10,
        {
            'p': [0x0, ['pointer64', ['void']]],
            'RangeSize': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_2061': [
        0x8,
        {
            'IdleTime': [0x0, ['unsigned long']],
            'NonIdleTime': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2063': [
        0x8,
        {
            'Disk': [0x0, ['__unnamed_2061']],
        },
    ],
    '_DEVICE_OBJECT_POWER_EXTENSION': [
        0x58,
        {
            'IdleCount': [0x0, ['unsigned long']],
            'BusyCount': [0x4, ['unsigned long']],
            'BusyReference': [0x8, ['unsigned long']],
            'TotalBusyCount': [0xC, ['unsigned long']],
            'ConservationIdleTime': [0x10, ['unsigned long']],
            'PerformanceIdleTime': [0x14, ['unsigned long']],
            'DeviceObject': [0x18, ['pointer64', ['_DEVICE_OBJECT']]],
            'IdleList': [0x20, ['_LIST_ENTRY']],
            'IdleType': [
                0x30,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'DeviceIdleNormal', 1: 'DeviceIdleDisk'},
                    ),
                ],
            ],
            'IdleState': [
                0x34,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerDeviceUnspecified',
                            1: 'PowerDeviceD0',
                            2: 'PowerDeviceD1',
                            3: 'PowerDeviceD2',
                            4: 'PowerDeviceD3',
                            5: 'PowerDeviceMaximum',
                        },
                    ),
                ],
            ],
            'CurrentState': [
                0x38,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerDeviceUnspecified',
                            1: 'PowerDeviceD0',
                            2: 'PowerDeviceD1',
                            3: 'PowerDeviceD2',
                            4: 'PowerDeviceD3',
                            5: 'PowerDeviceMaximum',
                        },
                    ),
                ],
            ],
            'Volume': [0x40, ['_LIST_ENTRY']],
            'Specific': [0x50, ['__unnamed_2063']],
        },
    ],
    '_ARBITER_RETEST_ALLOCATION_PARAMETERS': [
        0x18,
        {
            'ArbitrationList': [0x0, ['pointer64', ['_LIST_ENTRY']]],
            'AllocateFromCount': [0x8, ['unsigned long']],
            'AllocateFrom': [
                0x10,
                ['pointer64', ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
        },
    ],
    '_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS': [
        0x1,
        {
            'FRUId': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'FRUText': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'AsUCHAR': [0x0, ['unsigned char']],
        },
    ],
    '_FS_FILTER_CALLBACKS': [
        0x68,
        {
            'SizeOfFsFilterCallbacks': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'PreAcquireForSectionSynchronization': [
                0x8,
                ['pointer64', ['void']],
            ],
            'PostAcquireForSectionSynchronization': [
                0x10,
                ['pointer64', ['void']],
            ],
            'PreReleaseForSectionSynchronization': [
                0x18,
                ['pointer64', ['void']],
            ],
            'PostReleaseForSectionSynchronization': [
                0x20,
                ['pointer64', ['void']],
            ],
            'PreAcquireForCcFlush': [0x28, ['pointer64', ['void']]],
            'PostAcquireForCcFlush': [0x30, ['pointer64', ['void']]],
            'PreReleaseForCcFlush': [0x38, ['pointer64', ['void']]],
            'PostReleaseForCcFlush': [0x40, ['pointer64', ['void']]],
            'PreAcquireForModifiedPageWriter': [0x48, ['pointer64', ['void']]],
            'PostAcquireForModifiedPageWriter': [
                0x50,
                ['pointer64', ['void']],
            ],
            'PreReleaseForModifiedPageWriter': [0x58, ['pointer64', ['void']]],
            'PostReleaseForModifiedPageWriter': [
                0x60,
                ['pointer64', ['void']],
            ],
        },
    ],
    '_KENLISTMENT': [
        0x1E0,
        {
            'cookie': [0x0, ['unsigned long']],
            'NamespaceLink': [0x8, ['_KTMOBJECT_NAMESPACE_LINK']],
            'EnlistmentId': [0x30, ['_GUID']],
            'Mutex': [0x40, ['_KMUTANT']],
            'NextSameTx': [0x78, ['_LIST_ENTRY']],
            'NextSameRm': [0x88, ['_LIST_ENTRY']],
            'ResourceManager': [0x98, ['pointer64', ['_KRESOURCEMANAGER']]],
            'Transaction': [0xA0, ['pointer64', ['_KTRANSACTION']]],
            'State': [
                0xA8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KEnlistmentUninitialized',
                            256: 'KEnlistmentActive',
                            258: 'KEnlistmentPrepared',
                            259: 'KEnlistmentInDoubt',
                            260: 'KEnlistmentCommitted',
                            261: 'KEnlistmentCommittedNotify',
                            262: 'KEnlistmentCommitRequested',
                            257: 'KEnlistmentPreparing',
                            264: 'KEnlistmentDelegated',
                            265: 'KEnlistmentDelegatedDisconnected',
                            266: 'KEnlistmentPrePreparing',
                            263: 'KEnlistmentAborted',
                            268: 'KEnlistmentRecovering',
                            269: 'KEnlistmentAborting',
                            270: 'KEnlistmentReadOnly',
                            271: 'KEnlistmentOutcomeUnavailable',
                            272: 'KEnlistmentOffline',
                            273: 'KEnlistmentPrePrepared',
                            274: 'KEnlistmentInitialized',
                            267: 'KEnlistmentForgotten',
                        },
                    ),
                ],
            ],
            'Flags': [0xAC, ['unsigned long']],
            'NotificationMask': [0xB0, ['unsigned long']],
            'Key': [0xB8, ['pointer64', ['void']]],
            'KeyRefCount': [0xC0, ['unsigned long']],
            'RecoveryInformation': [0xC8, ['pointer64', ['void']]],
            'RecoveryInformationLength': [0xD0, ['unsigned long']],
            'DynamicNameInformation': [0xD8, ['pointer64', ['void']]],
            'DynamicNameInformationLength': [0xE0, ['unsigned long']],
            'FinalNotification': [
                0xE8,
                ['pointer64', ['_KTMNOTIFICATION_PACKET']],
            ],
            'SupSubEnlistment': [0xF0, ['pointer64', ['_KENLISTMENT']]],
            'SupSubEnlHandle': [0xF8, ['pointer64', ['void']]],
            'SubordinateTxHandle': [0x100, ['pointer64', ['void']]],
            'CrmEnlistmentEnId': [0x108, ['_GUID']],
            'CrmEnlistmentTmId': [0x118, ['_GUID']],
            'CrmEnlistmentRmId': [0x128, ['_GUID']],
            'NextHistory': [0x138, ['unsigned long']],
            'History': [0x13C, ['array', 20, ['_KENLISTMENT_HISTORY']]],
        },
    ],
    '_ARBITER_INTERFACE': [
        0x30,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x8, ['pointer64', ['void']]],
            'InterfaceReference': [0x10, ['pointer64', ['void']]],
            'InterfaceDereference': [0x18, ['pointer64', ['void']]],
            'ArbiterHandler': [0x20, ['pointer64', ['void']]],
            'Flags': [0x28, ['unsigned long']],
        },
    ],
    '_KAPC_STATE': [
        0x30,
        {
            'ApcListHead': [0x0, ['array', 2, ['_LIST_ENTRY']]],
            'Process': [0x20, ['pointer64', ['_KPROCESS']]],
            'KernelApcInProgress': [0x28, ['unsigned char']],
            'KernelApcPending': [0x29, ['unsigned char']],
            'UserApcPending': [0x2A, ['unsigned char']],
        },
    ],
    '_IA64_LOADER_BLOCK': [
        0x4,
        {
            'PlaceHolder': [0x0, ['unsigned long']],
        },
    ],
    '_IA64_DBGKD_CONTROL_SET': [
        0x14,
        {
            'Continue': [0x0, ['unsigned long']],
            'CurrentSymbolStart': [0x4, ['unsigned long long']],
            'CurrentSymbolEnd': [0xC, ['unsigned long long']],
        },
    ],
    '_DEVICE_RELATIONS': [
        0x10,
        {
            'Count': [0x0, ['unsigned long']],
            'Objects': [0x8, ['array', 1, ['pointer64', ['_DEVICE_OBJECT']]]],
        },
    ],
    '_IMAGE_ROM_OPTIONAL_HEADER': [
        0x38,
        {
            'Magic': [0x0, ['unsigned short']],
            'MajorLinkerVersion': [0x2, ['unsigned char']],
            'MinorLinkerVersion': [0x3, ['unsigned char']],
            'SizeOfCode': [0x4, ['unsigned long']],
            'SizeOfInitializedData': [0x8, ['unsigned long']],
            'SizeOfUninitializedData': [0xC, ['unsigned long']],
            'AddressOfEntryPoint': [0x10, ['unsigned long']],
            'BaseOfCode': [0x14, ['unsigned long']],
            'BaseOfData': [0x18, ['unsigned long']],
            'BaseOfBss': [0x1C, ['unsigned long']],
            'GprMask': [0x20, ['unsigned long']],
            'CprMask': [0x24, ['array', 4, ['unsigned long']]],
            'GpValue': [0x34, ['unsigned long']],
        },
    ],
    '_ALPC_COMPLETION_LIST_HEADER': [
        0x300,
        {
            'StartMagic': [0x0, ['unsigned long long']],
            'TotalSize': [0x8, ['unsigned long']],
            'ListOffset': [0xC, ['unsigned long']],
            'ListSize': [0x10, ['unsigned long']],
            'BitmapOffset': [0x14, ['unsigned long']],
            'BitmapSize': [0x18, ['unsigned long']],
            'DataOffset': [0x1C, ['unsigned long']],
            'DataSize': [0x20, ['unsigned long']],
            'AttributeFlags': [0x24, ['unsigned long']],
            'AttributeSize': [0x28, ['unsigned long']],
            'State': [0x80, ['_ALPC_COMPLETION_LIST_STATE']],
            'LastMessageId': [0x88, ['unsigned long']],
            'LastCallbackId': [0x8C, ['unsigned long']],
            'PostCount': [0x100, ['unsigned long']],
            'ReturnCount': [0x180, ['unsigned long']],
            'LogSequenceNumber': [0x200, ['unsigned long']],
            'UserLock': [0x280, ['_RTL_SRWLOCK']],
            'EndMagic': [0x288, ['unsigned long long']],
        },
    ],
    '_IMAGE_DEBUG_DIRECTORY': [
        0x1C,
        {
            'Characteristics': [0x0, ['unsigned long']],
            'TimeDateStamp': [0x4, ['unsigned long']],
            'MajorVersion': [0x8, ['unsigned short']],
            'MinorVersion': [0xA, ['unsigned short']],
            'Type': [0xC, ['unsigned long']],
            'SizeOfData': [0x10, ['unsigned long']],
            'AddressOfRawData': [0x14, ['unsigned long']],
            'PointerToRawData': [0x18, ['unsigned long']],
        },
    ],
    '_ETW_WMITRACE_WORK': [
        0xF0,
        {
            'LoggerId': [0x0, ['unsigned long']],
            'LoggerName': [0x8, ['array', 65, ['unsigned char']]],
            'FileName': [0x49, ['array', 129, ['unsigned char']]],
            'MaximumFileSize': [0xCC, ['unsigned long']],
            'MinBuffers': [0xD0, ['unsigned long']],
            'MaxBuffers': [0xD4, ['unsigned long']],
            'BufferSize': [0xD8, ['unsigned long']],
            'Mode': [0xDC, ['unsigned long']],
            'FlushTimer': [0xE0, ['unsigned long']],
            'MatchAny': [0x8, ['unsigned long long']],
            'MatchAll': [0x10, ['unsigned long long']],
            'EnableProperty': [0x18, ['unsigned long']],
            'Guid': [0x1C, ['_GUID']],
            'Level': [0x2C, ['unsigned char']],
            'Status': [0xE8, ['long']],
        },
    ],
    '_DEVICE_MAP': [
        0x40,
        {
            'DosDevicesDirectory': [0x0, ['pointer64', ['_OBJECT_DIRECTORY']]],
            'GlobalDosDevicesDirectory': [
                0x8,
                ['pointer64', ['_OBJECT_DIRECTORY']],
            ],
            'DosDevicesDirectoryHandle': [0x10, ['pointer64', ['void']]],
            'ReferenceCount': [0x18, ['unsigned long']],
            'DriveMap': [0x1C, ['unsigned long']],
            'DriveType': [0x20, ['array', 32, ['unsigned char']]],
        },
    ],
    '_HEAP_DEBUGGING_INFORMATION': [
        0x30,
        {
            'InterceptorFunction': [0x0, ['pointer64', ['void']]],
            'InterceptorValue': [0x8, ['unsigned short']],
            'ExtendedOptions': [0xC, ['unsigned long']],
            'StackTraceDepth': [0x10, ['unsigned long']],
            'MinTotalBlockSize': [0x18, ['unsigned long long']],
            'MaxTotalBlockSize': [0x20, ['unsigned long long']],
            'HeapLeakEnumerationRoutine': [0x28, ['pointer64', ['void']]],
        },
    ],
    '_IO_RESOURCE_LIST': [
        0x28,
        {
            'Version': [0x0, ['unsigned short']],
            'Revision': [0x2, ['unsigned short']],
            'Count': [0x4, ['unsigned long']],
            'Descriptors': [0x8, ['array', 1, ['_IO_RESOURCE_DESCRIPTOR']]],
        },
    ],
    '_MMBANKED_SECTION': [
        0x38,
        {
            'BasePhysicalPage': [0x0, ['unsigned long long']],
            'BasedPte': [0x8, ['pointer64', ['_MMPTE']]],
            'BankSize': [0x10, ['unsigned long']],
            'BankShift': [0x14, ['unsigned long']],
            'BankedRoutine': [0x18, ['pointer64', ['void']]],
            'Context': [0x20, ['pointer64', ['void']]],
            'CurrentMappedPte': [0x28, ['pointer64', ['_MMPTE']]],
            'BankTemplate': [0x30, ['array', 1, ['_MMPTE']]],
        },
    ],
    '_WHEA_ERROR_RECORD_HEADER_FLAGS': [
        0x4,
        {
            'Recovered': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'PreviousError': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Simulated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_XSAVE_AREA_HEADER': [
        0x40,
        {
            'Mask': [0x0, ['unsigned long long']],
            'Reserved': [0x8, ['array', 7, ['unsigned long long']]],
        },
    ],
    '_HEAP_VIRTUAL_ALLOC_ENTRY': [
        0x40,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'ExtraStuff': [0x10, ['_HEAP_ENTRY_EXTRA']],
            'CommitSize': [0x20, ['unsigned long long']],
            'ReserveSize': [0x28, ['unsigned long long']],
            'BusyBlock': [0x30, ['_HEAP_ENTRY']],
        },
    ],
    '_PNP_DEVICE_COMPLETION_REQUEST': [
        0x68,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'DeviceNode': [0x10, ['pointer64', ['_DEVICE_NODE']]],
            'Context': [0x18, ['pointer64', ['void']]],
            'CompletionState': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            768: 'DeviceNodeUnspecified',
                            769: 'DeviceNodeUninitialized',
                            770: 'DeviceNodeInitialized',
                            771: 'DeviceNodeDriversAdded',
                            772: 'DeviceNodeResourcesAssigned',
                            773: 'DeviceNodeStartPending',
                            774: 'DeviceNodeStartCompletion',
                            775: 'DeviceNodeStartPostWork',
                            776: 'DeviceNodeStarted',
                            777: 'DeviceNodeQueryStopped',
                            778: 'DeviceNodeStopped',
                            779: 'DeviceNodeRestartCompletion',
                            780: 'DeviceNodeEnumeratePending',
                            781: 'DeviceNodeEnumerateCompletion',
                            782: 'DeviceNodeAwaitingQueuedDeletion',
                            783: 'DeviceNodeAwaitingQueuedRemoval',
                            784: 'DeviceNodeQueryRemoved',
                            785: 'DeviceNodeRemovePendingCloses',
                            786: 'DeviceNodeRemoved',
                            787: 'DeviceNodeDeletePendingCloses',
                            788: 'DeviceNodeDeleted',
                            789: 'MaxDeviceNodeState',
                        },
                    ),
                ],
            ],
            'IrpPended': [0x24, ['unsigned long']],
            'Status': [0x28, ['long']],
            'Information': [0x30, ['pointer64', ['void']]],
            'WorkItem': [0x38, ['_WORK_QUEUE_ITEM']],
            'FailingDriver': [0x58, ['pointer64', ['_DRIVER_OBJECT']]],
            'ReferenceCount': [0x60, ['long']],
        },
    ],
    '_KTSS64': [
        0x68,
        {
            'Reserved0': [0x0, ['unsigned long']],
            'Rsp0': [0x4, ['unsigned long long']],
            'Rsp1': [0xC, ['unsigned long long']],
            'Rsp2': [0x14, ['unsigned long long']],
            'Ist': [0x1C, ['array', 8, ['unsigned long long']]],
            'Reserved1': [0x5C, ['unsigned long long']],
            'Reserved2': [0x64, ['unsigned short']],
            'IoMapBase': [0x66, ['unsigned short']],
        },
    ],
    '_EVENT_FILTER_HEADER': [
        0x18,
        {
            'Id': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['array', 5, ['unsigned char']]],
            'InstanceId': [0x8, ['unsigned long long']],
            'Size': [0x10, ['unsigned long']],
            'NextOffset': [0x14, ['unsigned long']],
        },
    ],
    '_WAIT_CONTEXT_BLOCK': [
        0x48,
        {
            'WaitQueueEntry': [0x0, ['_KDEVICE_QUEUE_ENTRY']],
            'DeviceRoutine': [0x18, ['pointer64', ['void']]],
            'DeviceContext': [0x20, ['pointer64', ['void']]],
            'NumberOfMapRegisters': [0x28, ['unsigned long']],
            'DeviceObject': [0x30, ['pointer64', ['void']]],
            'CurrentIrp': [0x38, ['pointer64', ['void']]],
            'BufferChainingDpc': [0x40, ['pointer64', ['_KDPC']]],
        },
    ],
    '_SECTION_OBJECT': [
        0x30,
        {
            'StartingVa': [0x0, ['pointer64', ['void']]],
            'EndingVa': [0x8, ['pointer64', ['void']]],
            'Parent': [0x10, ['pointer64', ['void']]],
            'LeftChild': [0x18, ['pointer64', ['void']]],
            'RightChild': [0x20, ['pointer64', ['void']]],
            'Segment': [0x28, ['pointer64', ['_SEGMENT_OBJECT']]],
        },
    ],
    '_CM_NAME_CONTROL_BLOCK': [
        0x20,
        {
            'Compressed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'RefCount': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'NameHash': [0x8, ['_CM_NAME_HASH']],
            'ConvKey': [0x8, ['unsigned long']],
            'NextHash': [0x10, ['pointer64', ['_CM_KEY_HASH']]],
            'NameLength': [0x18, ['unsigned short']],
            'Name': [0x1A, ['array', 1, ['wchar']]],
        },
    ],
    '_u': [
        0x50,
        {
            'KeyNode': [0x0, ['_CM_KEY_NODE']],
            'KeyValue': [0x0, ['_CM_KEY_VALUE']],
            'KeySecurity': [0x0, ['_CM_KEY_SECURITY']],
            'KeyIndex': [0x0, ['_CM_KEY_INDEX']],
            'ValueData': [0x0, ['_CM_BIG_DATA']],
            'KeyList': [0x0, ['array', 1, ['unsigned long']]],
            'KeyString': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '_GENERAL_LOOKASIDE_POOL': [
        0x60,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
            'SingleListHead': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Depth': [0x10, ['unsigned short']],
            'MaximumDepth': [0x12, ['unsigned short']],
            'TotalAllocates': [0x14, ['unsigned long']],
            'AllocateMisses': [0x18, ['unsigned long']],
            'AllocateHits': [0x18, ['unsigned long']],
            'TotalFrees': [0x1C, ['unsigned long']],
            'FreeMisses': [0x20, ['unsigned long']],
            'FreeHits': [0x20, ['unsigned long']],
            'Type': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPool',
                            1: 'PagedPool',
                            2: 'NonPagedPoolMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'Tag': [0x28, ['unsigned long']],
            'Size': [0x2C, ['unsigned long']],
            'AllocateEx': [0x30, ['pointer64', ['void']]],
            'Allocate': [0x30, ['pointer64', ['void']]],
            'FreeEx': [0x38, ['pointer64', ['void']]],
            'Free': [0x38, ['pointer64', ['void']]],
            'ListEntry': [0x40, ['_LIST_ENTRY']],
            'LastTotalAllocates': [0x50, ['unsigned long']],
            'LastAllocateMisses': [0x54, ['unsigned long']],
            'LastAllocateHits': [0x54, ['unsigned long']],
            'Future': [0x58, ['array', 2, ['unsigned long']]],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE_ENTRY': [
        0x18,
        {
            'Linkage': [0x0, ['_LIST_ENTRY']],
            'Signature': [0x10, ['unsigned long long']],
        },
    ],
    '__unnamed_20e2': [
        0x4,
        {
            'AsULONG': [0x0, ['unsigned long']],
            'IncreasePolicy': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'DecreasePolicy': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_PPM_PERF_STATES': [
        0xB0,
        {
            'Count': [0x0, ['unsigned long']],
            'MaxFrequency': [0x4, ['unsigned long']],
            'PStateCap': [0x8, ['unsigned long']],
            'TStateCap': [0xC, ['unsigned long']],
            'MaxPerfState': [0x10, ['unsigned long']],
            'MinPerfState': [0x14, ['unsigned long']],
            'LowestPState': [0x18, ['unsigned long']],
            'IncreaseTime': [0x1C, ['unsigned long']],
            'DecreaseTime': [0x20, ['unsigned long']],
            'BusyAdjThreshold': [0x24, ['unsigned char']],
            'Reserved': [0x25, ['unsigned char']],
            'ThrottleStatesOnly': [0x26, ['unsigned char']],
            'PolicyType': [0x27, ['unsigned char']],
            'TimerInterval': [0x28, ['unsigned long']],
            'Flags': [0x2C, ['__unnamed_20e2']],
            'TargetProcessors': [0x30, ['_KAFFINITY_EX']],
            'PStateHandler': [0x58, ['pointer64', ['void']]],
            'PStateContext': [0x60, ['unsigned long long']],
            'TStateHandler': [0x68, ['pointer64', ['void']]],
            'TStateContext': [0x70, ['unsigned long long']],
            'FeedbackHandler': [0x78, ['pointer64', ['void']]],
            'GetFFHThrottleState': [0x80, ['pointer64', ['void']]],
            'State': [0x88, ['array', 1, ['_PPM_PERF_STATE']]],
        },
    ],
    '_M128A': [
        0x10,
        {
            'Low': [0x0, ['unsigned long long']],
            'High': [0x8, ['long long']],
        },
    ],
    '_HEAP_LOOKASIDE': [
        0x40,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
            'Depth': [0x10, ['unsigned short']],
            'MaximumDepth': [0x12, ['unsigned short']],
            'TotalAllocates': [0x14, ['unsigned long']],
            'AllocateMisses': [0x18, ['unsigned long']],
            'TotalFrees': [0x1C, ['unsigned long']],
            'FreeMisses': [0x20, ['unsigned long']],
            'LastTotalAllocates': [0x24, ['unsigned long']],
            'LastAllocateMisses': [0x28, ['unsigned long']],
            'Counters': [0x2C, ['array', 2, ['unsigned long']]],
        },
    ],
    '_WMI_TRACE_PACKET': [
        0x4,
        {
            'Size': [0x0, ['unsigned short']],
            'HookId': [0x2, ['unsigned short']],
            'Type': [0x2, ['unsigned char']],
            'Group': [0x3, ['unsigned char']],
        },
    ],
    '_KTIMER': [
        0x40,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'DueTime': [0x18, ['_ULARGE_INTEGER']],
            'TimerListEntry': [0x20, ['_LIST_ENTRY']],
            'Dpc': [0x30, ['pointer64', ['_KDPC']]],
            'Processor': [0x38, ['unsigned long']],
            'Period': [0x3C, ['unsigned long']],
        },
    ],
    '_RTL_ATOM_TABLE': [
        0x70,
        {
            'Signature': [0x0, ['unsigned long']],
            'CriticalSection': [0x8, ['_RTL_CRITICAL_SECTION']],
            'RtlHandleTable': [0x30, ['_RTL_HANDLE_TABLE']],
            'NumberOfBuckets': [0x60, ['unsigned long']],
            'Buckets': [
                0x68,
                ['array', 1, ['pointer64', ['_RTL_ATOM_TABLE_ENTRY']]],
            ],
        },
    ],
    '_POP_POWER_ACTION': [
        0xC0,
        {
            'Updates': [0x0, ['unsigned char']],
            'State': [0x1, ['unsigned char']],
            'Shutdown': [0x2, ['unsigned char']],
            'Action': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerActionNone',
                            1: 'PowerActionReserved',
                            2: 'PowerActionSleep',
                            3: 'PowerActionHibernate',
                            4: 'PowerActionShutdown',
                            5: 'PowerActionShutdownReset',
                            6: 'PowerActionShutdownOff',
                            7: 'PowerActionWarmEject',
                        },
                    ),
                ],
            ],
            'LightestState': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'Flags': [0xC, ['unsigned long']],
            'Status': [0x10, ['long']],
            'DeviceType': [
                0x14,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PolicyDeviceSystemButton',
                            1: 'PolicyDeviceThermalZone',
                            2: 'PolicyDeviceBattery',
                            3: 'PolicyDeviceMemory',
                            4: 'PolicyInitiatePowerActionAPI',
                            5: 'PolicySetPowerStateAPI',
                            6: 'PolicyImmediateDozeS4',
                            7: 'PolicySystemIdle',
                            8: 'PolicyDeviceMax',
                        },
                    ),
                ],
            ],
            'DeviceTypeFlags': [0x18, ['unsigned long']],
            'IrpMinor': [0x1C, ['unsigned char']],
            'Waking': [0x1D, ['unsigned char']],
            'SystemState': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'NextSystemState': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'EffectiveSystemState': [
                0x28,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'CurrentSystemState': [
                0x2C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'ShutdownBugCode': [
                0x30,
                ['pointer64', ['_POP_SHUTDOWN_BUG_CHECK']],
            ],
            'DevState': [0x38, ['pointer64', ['_POP_DEVICE_SYS_STATE']]],
            'HiberContext': [0x40, ['pointer64', ['_POP_HIBER_CONTEXT']]],
            'WakeTime': [0x48, ['unsigned long long']],
            'SleepTime': [0x50, ['unsigned long long']],
            'ProgrammedRTCTime': [0x58, ['unsigned long long']],
            'WakeOnRTC': [0x60, ['unsigned char']],
            'WakeTimerInfo': [0x68, ['pointer64', ['_DIAGNOSTIC_BUFFER']]],
            'FilteredCapabilities': [0x70, ['SYSTEM_POWER_CAPABILITIES']],
        },
    ],
    '_CM_KEY_VALUE': [
        0x18,
        {
            'Signature': [0x0, ['unsigned short']],
            'NameLength': [0x2, ['unsigned short']],
            'DataLength': [0x4, ['unsigned long']],
            'Data': [0x8, ['unsigned long']],
            'Type': [0xC, ['unsigned long']],
            'Flags': [0x10, ['unsigned short']],
            'Spare': [0x12, ['unsigned short']],
            'Name': [0x14, ['array', 1, ['wchar']]],
        },
    ],
    '_AMD64_DBGKD_CONTROL_SET': [
        0x1C,
        {
            'TraceFlag': [0x0, ['unsigned long']],
            'Dr7': [0x4, ['unsigned long long']],
            'CurrentSymbolStart': [0xC, ['unsigned long long']],
            'CurrentSymbolEnd': [0x14, ['unsigned long long']],
        },
    ],
    '_PO_DEVICE_NOTIFY': [
        0x68,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'PowerChildren': [0x10, ['_LIST_ENTRY']],
            'PowerParents': [0x20, ['_LIST_ENTRY']],
            'TargetDevice': [0x30, ['pointer64', ['_DEVICE_OBJECT']]],
            'OrderLevel': [0x38, ['unsigned char']],
            'DeviceObject': [0x40, ['pointer64', ['_DEVICE_OBJECT']]],
            'DeviceName': [0x48, ['pointer64', ['unsigned short']]],
            'DriverName': [0x50, ['pointer64', ['unsigned short']]],
            'ChildCount': [0x58, ['unsigned long']],
            'ActiveChild': [0x5C, ['unsigned long']],
            'ParentCount': [0x60, ['unsigned long']],
            'ActiveParent': [0x64, ['unsigned long']],
        },
    ],
    '_CM_KEY_SECURITY_CACHE_ENTRY': [
        0x10,
        {
            'Cell': [0x0, ['unsigned long']],
            'CachedSecurity': [0x8, ['pointer64', ['_CM_KEY_SECURITY_CACHE']]],
        },
    ],
    '_FS_FILTER_CALLBACK_DATA': [
        0x40,
        {
            'SizeOfFsFilterCallbackData': [0x0, ['unsigned long']],
            'Operation': [0x4, ['unsigned char']],
            'Reserved': [0x5, ['unsigned char']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'FileObject': [0x10, ['pointer64', ['_FILE_OBJECT']]],
            'Parameters': [0x18, ['_FS_FILTER_PARAMETERS']],
        },
    ],
    '_PROC_IDLE_STATE_ACCOUNTING': [
        0x228,
        {
            'TotalTime': [0x0, ['unsigned long long']],
            'IdleTransitions': [0x8, ['unsigned long']],
            'FailedTransitions': [0xC, ['unsigned long']],
            'InvalidBucketIndex': [0x10, ['unsigned long']],
            'MinTime': [0x18, ['unsigned long long']],
            'MaxTime': [0x20, ['unsigned long long']],
            'IdleTimeBuckets': [
                0x28,
                ['array', 16, ['_PROC_IDLE_STATE_BUCKET']],
            ],
        },
    ],
    '_IMAGE_SECURITY_CONTEXT': [
        0x8,
        {
            'PageHashes': [0x0, ['pointer64', ['void']]],
            'Value': [0x0, ['unsigned long long']],
            'SecurityBeingCreated': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SecurityMandatory': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageHashPointer': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '__unnamed_2124': [
        0x4,
        {
            'Level': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_2126': [
        0x4,
        {
            'Type': [0x0, ['unsigned long']],
        },
    ],
    '_POP_ACTION_TRIGGER': [
        0x18,
        {
            'Type': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PolicyDeviceSystemButton',
                            1: 'PolicyDeviceThermalZone',
                            2: 'PolicyDeviceBattery',
                            3: 'PolicyDeviceMemory',
                            4: 'PolicyInitiatePowerActionAPI',
                            5: 'PolicySetPowerStateAPI',
                            6: 'PolicyImmediateDozeS4',
                            7: 'PolicySystemIdle',
                            8: 'PolicyDeviceMax',
                        },
                    ),
                ],
            ],
            'Flags': [0x4, ['unsigned long']],
            'Wait': [0x8, ['pointer64', ['_POP_TRIGGER_WAIT']]],
            'Battery': [0x10, ['__unnamed_2124']],
            'Button': [0x10, ['__unnamed_2126']],
        },
    ],
    '_KENLISTMENT_HISTORY': [
        0x8,
        {
            'Notification': [0x0, ['unsigned long']],
            'NewState': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KEnlistmentUninitialized',
                            256: 'KEnlistmentActive',
                            258: 'KEnlistmentPrepared',
                            259: 'KEnlistmentInDoubt',
                            260: 'KEnlistmentCommitted',
                            261: 'KEnlistmentCommittedNotify',
                            262: 'KEnlistmentCommitRequested',
                            257: 'KEnlistmentPreparing',
                            264: 'KEnlistmentDelegated',
                            265: 'KEnlistmentDelegatedDisconnected',
                            266: 'KEnlistmentPrePreparing',
                            263: 'KEnlistmentAborted',
                            268: 'KEnlistmentRecovering',
                            269: 'KEnlistmentAborting',
                            270: 'KEnlistmentReadOnly',
                            271: 'KEnlistmentOutcomeUnavailable',
                            272: 'KEnlistmentOffline',
                            273: 'KEnlistmentPrePrepared',
                            274: 'KEnlistmentInitialized',
                            267: 'KEnlistmentForgotten',
                        },
                    ),
                ],
            ],
        },
    ],
    '_FAST_IO_DISPATCH': [
        0xE0,
        {
            'SizeOfFastIoDispatch': [0x0, ['unsigned long']],
            'FastIoCheckIfPossible': [0x8, ['pointer64', ['void']]],
            'FastIoRead': [0x10, ['pointer64', ['void']]],
            'FastIoWrite': [0x18, ['pointer64', ['void']]],
            'FastIoQueryBasicInfo': [0x20, ['pointer64', ['void']]],
            'FastIoQueryStandardInfo': [0x28, ['pointer64', ['void']]],
            'FastIoLock': [0x30, ['pointer64', ['void']]],
            'FastIoUnlockSingle': [0x38, ['pointer64', ['void']]],
            'FastIoUnlockAll': [0x40, ['pointer64', ['void']]],
            'FastIoUnlockAllByKey': [0x48, ['pointer64', ['void']]],
            'FastIoDeviceControl': [0x50, ['pointer64', ['void']]],
            'AcquireFileForNtCreateSection': [0x58, ['pointer64', ['void']]],
            'ReleaseFileForNtCreateSection': [0x60, ['pointer64', ['void']]],
            'FastIoDetachDevice': [0x68, ['pointer64', ['void']]],
            'FastIoQueryNetworkOpenInfo': [0x70, ['pointer64', ['void']]],
            'AcquireForModWrite': [0x78, ['pointer64', ['void']]],
            'MdlRead': [0x80, ['pointer64', ['void']]],
            'MdlReadComplete': [0x88, ['pointer64', ['void']]],
            'PrepareMdlWrite': [0x90, ['pointer64', ['void']]],
            'MdlWriteComplete': [0x98, ['pointer64', ['void']]],
            'FastIoReadCompressed': [0xA0, ['pointer64', ['void']]],
            'FastIoWriteCompressed': [0xA8, ['pointer64', ['void']]],
            'MdlReadCompleteCompressed': [0xB0, ['pointer64', ['void']]],
            'MdlWriteCompleteCompressed': [0xB8, ['pointer64', ['void']]],
            'FastIoQueryOpen': [0xC0, ['pointer64', ['void']]],
            'ReleaseForModWrite': [0xC8, ['pointer64', ['void']]],
            'AcquireForCcFlush': [0xD0, ['pointer64', ['void']]],
            'ReleaseForCcFlush': [0xD8, ['pointer64', ['void']]],
        },
    ],
    '_KIDTENTRY64': [
        0x10,
        {
            'OffsetLow': [0x0, ['unsigned short']],
            'Selector': [0x2, ['unsigned short']],
            'IstIndex': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'Reserved0': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'Type': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=8, end_bit=13, native_type='unsigned short'
                    ),
                ],
            ],
            'Dpl': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=15, native_type='unsigned short'
                    ),
                ],
            ],
            'Present': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'OffsetMiddle': [0x6, ['unsigned short']],
            'OffsetHigh': [0x8, ['unsigned long']],
            'Reserved1': [0xC, ['unsigned long']],
            'Alignment': [0x0, ['unsigned long long']],
        },
    ],
    '_CM_CELL_REMAP_BLOCK': [
        0x8,
        {
            'OldCell': [0x0, ['unsigned long']],
            'NewCell': [0x4, ['unsigned long']],
        },
    ],
    '_OBJECT_DIRECTORY_ENTRY': [
        0x18,
        {
            'ChainLink': [0x0, ['pointer64', ['_OBJECT_DIRECTORY_ENTRY']]],
            'Object': [0x8, ['pointer64', ['void']]],
            'HashValue': [0x10, ['unsigned long']],
        },
    ],
    '_LOADER_PARAMETER_EXTENSION': [
        0x148,
        {
            'Size': [0x0, ['unsigned long']],
            'Profile': [0x4, ['_PROFILE_PARAMETER_BLOCK']],
            'EmInfFileImage': [0x18, ['pointer64', ['void']]],
            'EmInfFileSize': [0x20, ['unsigned long']],
            'TriageDumpBlock': [0x28, ['pointer64', ['void']]],
            'LoaderPagesSpanned': [0x30, ['unsigned long long']],
            'HeadlessLoaderBlock': [
                0x38,
                ['pointer64', ['_HEADLESS_LOADER_BLOCK']],
            ],
            'SMBiosEPSHeader': [0x40, ['pointer64', ['_SMBIOS_TABLE_HEADER']]],
            'DrvDBImage': [0x48, ['pointer64', ['void']]],
            'DrvDBSize': [0x50, ['unsigned long']],
            'NetworkLoaderBlock': [
                0x58,
                ['pointer64', ['_NETWORK_LOADER_BLOCK']],
            ],
            'FirmwareDescriptorListHead': [0x60, ['_LIST_ENTRY']],
            'AcpiTable': [0x70, ['pointer64', ['void']]],
            'AcpiTableSize': [0x78, ['unsigned long']],
            'LastBootSucceeded': [
                0x7C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'LastBootShutdown': [
                0x7C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'IoPortAccessSupported': [
                0x7C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x7C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'LoaderPerformanceData': [
                0x80,
                ['pointer64', ['_LOADER_PERFORMANCE_DATA']],
            ],
            'BootApplicationPersistentData': [0x88, ['_LIST_ENTRY']],
            'WmdTestResult': [0x98, ['pointer64', ['void']]],
            'BootIdentifier': [0xA0, ['_GUID']],
            'ResumePages': [0xB0, ['unsigned long']],
            'DumpHeader': [0xB8, ['pointer64', ['void']]],
            'BgContext': [0xC0, ['pointer64', ['void']]],
            'NumaLocalityInfo': [0xC8, ['pointer64', ['void']]],
            'NumaGroupAssignment': [0xD0, ['pointer64', ['void']]],
            'AttachedHives': [0xD8, ['_LIST_ENTRY']],
            'MemoryCachingRequirementsCount': [0xE8, ['unsigned long']],
            'MemoryCachingRequirements': [0xF0, ['pointer64', ['void']]],
            'TpmBootEntropyResult': [0xF8, ['_TPM_BOOT_ENTROPY_LDR_RESULT']],
            'ProcessorCounterFrequency': [0x140, ['unsigned long long']],
        },
    ],
    '_PI_RESOURCE_ARBITER_ENTRY': [
        0x70,
        {
            'DeviceArbiterList': [0x0, ['_LIST_ENTRY']],
            'ResourceType': [0x10, ['unsigned char']],
            'ArbiterInterface': [0x18, ['pointer64', ['_ARBITER_INTERFACE']]],
            'DeviceNode': [0x20, ['pointer64', ['_DEVICE_NODE']]],
            'ResourceList': [0x28, ['_LIST_ENTRY']],
            'BestResourceList': [0x38, ['_LIST_ENTRY']],
            'BestConfig': [0x48, ['_LIST_ENTRY']],
            'ActiveArbiterList': [0x58, ['_LIST_ENTRY']],
            'State': [0x68, ['unsigned char']],
            'ResourcesChanged': [0x69, ['unsigned char']],
        },
    ],
    '_SECURITY_DESCRIPTOR': [
        0x28,
        {
            'Revision': [0x0, ['unsigned char']],
            'Sbz1': [0x1, ['unsigned char']],
            'Control': [0x2, ['unsigned short']],
            'Owner': [0x8, ['pointer64', ['void']]],
            'Group': [0x10, ['pointer64', ['void']]],
            'Sacl': [0x18, ['pointer64', ['_ACL']]],
            'Dacl': [0x20, ['pointer64', ['_ACL']]],
        },
    ],
    '_KUMS_CONTEXT_HEADER': [
        0x70,
        {
            'P1Home': [0x0, ['unsigned long long']],
            'P2Home': [0x8, ['unsigned long long']],
            'P3Home': [0x10, ['unsigned long long']],
            'P4Home': [0x18, ['unsigned long long']],
            'StackTop': [0x20, ['pointer64', ['void']]],
            'StackSize': [0x28, ['unsigned long long']],
            'RspOffset': [0x30, ['unsigned long long']],
            'Rip': [0x38, ['unsigned long long']],
            'FltSave': [0x40, ['pointer64', ['_XSAVE_FORMAT']]],
            'Volatile': [
                0x48,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x48,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Flags': [0x48, ['unsigned long long']],
            'TrapFrame': [0x50, ['pointer64', ['_KTRAP_FRAME']]],
            'ExceptionFrame': [0x58, ['pointer64', ['_KEXCEPTION_FRAME']]],
            'SourceThread': [0x60, ['pointer64', ['_KTHREAD']]],
            'Return': [0x68, ['unsigned long long']],
        },
    ],
    '_RTL_USER_PROCESS_PARAMETERS': [
        0x400,
        {
            'MaximumLength': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Flags': [0x8, ['unsigned long']],
            'DebugFlags': [0xC, ['unsigned long']],
            'ConsoleHandle': [0x10, ['pointer64', ['void']]],
            'ConsoleFlags': [0x18, ['unsigned long']],
            'StandardInput': [0x20, ['pointer64', ['void']]],
            'StandardOutput': [0x28, ['pointer64', ['void']]],
            'StandardError': [0x30, ['pointer64', ['void']]],
            'CurrentDirectory': [0x38, ['_CURDIR']],
            'DllPath': [0x50, ['_UNICODE_STRING']],
            'ImagePathName': [0x60, ['_UNICODE_STRING']],
            'CommandLine': [0x70, ['_UNICODE_STRING']],
            'Environment': [0x80, ['pointer64', ['void']]],
            'StartingX': [0x88, ['unsigned long']],
            'StartingY': [0x8C, ['unsigned long']],
            'CountX': [0x90, ['unsigned long']],
            'CountY': [0x94, ['unsigned long']],
            'CountCharsX': [0x98, ['unsigned long']],
            'CountCharsY': [0x9C, ['unsigned long']],
            'FillAttribute': [0xA0, ['unsigned long']],
            'WindowFlags': [0xA4, ['unsigned long']],
            'ShowWindowFlags': [0xA8, ['unsigned long']],
            'WindowTitle': [0xB0, ['_UNICODE_STRING']],
            'DesktopInfo': [0xC0, ['_UNICODE_STRING']],
            'ShellInfo': [0xD0, ['_UNICODE_STRING']],
            'RuntimeData': [0xE0, ['_UNICODE_STRING']],
            'CurrentDirectores': [
                0xF0,
                ['array', 32, ['_RTL_DRIVE_LETTER_CURDIR']],
            ],
            'EnvironmentSize': [0x3F0, ['unsigned long long']],
            'EnvironmentVersion': [0x3F8, ['unsigned long long']],
        },
    ],
    '_PHYSICAL_MEMORY_RUN': [
        0x10,
        {
            'BasePage': [0x0, ['unsigned long long']],
            'PageCount': [0x8, ['unsigned long long']],
        },
    ],
    '_RTL_SRWLOCK': [
        0x8,
        {
            'Locked': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Waiting': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Waking': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'MultipleShared': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Shared': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Value': [0x0, ['unsigned long long']],
            'Ptr': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_ALPC_MESSAGE_ZONE': [
        0x30,
        {
            'Mdl': [0x0, ['pointer64', ['_MDL']]],
            'UserVa': [0x8, ['pointer64', ['void']]],
            'UserLimit': [0x10, ['pointer64', ['void']]],
            'SystemVa': [0x18, ['pointer64', ['void']]],
            'SystemLimit': [0x20, ['pointer64', ['void']]],
            'Size': [0x28, ['unsigned long long']],
        },
    ],
    '_KTMOBJECT_NAMESPACE_LINK': [
        0x28,
        {
            'Links': [0x0, ['_RTL_BALANCED_LINKS']],
            'Expired': [0x20, ['unsigned char']],
        },
    ],
    '_CACHE_MANAGER_CALLBACKS': [
        0x20,
        {
            'AcquireForLazyWrite': [0x0, ['pointer64', ['void']]],
            'ReleaseFromLazyWrite': [0x8, ['pointer64', ['void']]],
            'AcquireForReadAhead': [0x10, ['pointer64', ['void']]],
            'ReleaseFromReadAhead': [0x18, ['pointer64', ['void']]],
        },
    ],
    '_PROC_PERF_LOAD': [
        0x2,
        {
            'BusyPercentage': [0x0, ['unsigned char']],
            'FrequencyPercentage': [0x1, ['unsigned char']],
        },
    ],
    '_PROC_HISTORY_ENTRY': [
        0x4,
        {
            'Utility': [0x0, ['unsigned short']],
            'Frequency': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
        },
    ],
    '_RTL_RANGE': [
        0x28,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
            'UserData': [0x10, ['pointer64', ['void']]],
            'Owner': [0x18, ['pointer64', ['void']]],
            'Attributes': [0x20, ['unsigned char']],
            'Flags': [0x21, ['unsigned char']],
        },
    ],
    '_KSPECIAL_REGISTERS': [
        0xD8,
        {
            'Cr0': [0x0, ['unsigned long long']],
            'Cr2': [0x8, ['unsigned long long']],
            'Cr3': [0x10, ['unsigned long long']],
            'Cr4': [0x18, ['unsigned long long']],
            'KernelDr0': [0x20, ['unsigned long long']],
            'KernelDr1': [0x28, ['unsigned long long']],
            'KernelDr2': [0x30, ['unsigned long long']],
            'KernelDr3': [0x38, ['unsigned long long']],
            'KernelDr6': [0x40, ['unsigned long long']],
            'KernelDr7': [0x48, ['unsigned long long']],
            'Gdtr': [0x50, ['_KDESCRIPTOR']],
            'Idtr': [0x60, ['_KDESCRIPTOR']],
            'Tr': [0x70, ['unsigned short']],
            'Ldtr': [0x72, ['unsigned short']],
            'MxCsr': [0x74, ['unsigned long']],
            'DebugControl': [0x78, ['unsigned long long']],
            'LastBranchToRip': [0x80, ['unsigned long long']],
            'LastBranchFromRip': [0x88, ['unsigned long long']],
            'LastExceptionToRip': [0x90, ['unsigned long long']],
            'LastExceptionFromRip': [0x98, ['unsigned long long']],
            'Cr8': [0xA0, ['unsigned long long']],
            'MsrGsBase': [0xA8, ['unsigned long long']],
            'MsrGsSwap': [0xB0, ['unsigned long long']],
            'MsrStar': [0xB8, ['unsigned long long']],
            'MsrLStar': [0xC0, ['unsigned long long']],
            'MsrCStar': [0xC8, ['unsigned long long']],
            'MsrSyscallMask': [0xD0, ['unsigned long long']],
        },
    ],
    '_SYSTEM_POWER_POLICY': [
        0xE8,
        {
            'Revision': [0x0, ['unsigned long']],
            'PowerButton': [0x4, ['POWER_ACTION_POLICY']],
            'SleepButton': [0x10, ['POWER_ACTION_POLICY']],
            'LidClose': [0x1C, ['POWER_ACTION_POLICY']],
            'LidOpenWake': [
                0x28,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'Reserved': [0x2C, ['unsigned long']],
            'Idle': [0x30, ['POWER_ACTION_POLICY']],
            'IdleTimeout': [0x3C, ['unsigned long']],
            'IdleSensitivity': [0x40, ['unsigned char']],
            'DynamicThrottle': [0x41, ['unsigned char']],
            'Spare2': [0x42, ['array', 2, ['unsigned char']]],
            'MinSleep': [
                0x44,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'MaxSleep': [
                0x48,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'ReducedLatencySleep': [
                0x4C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'WinLogonFlags': [0x50, ['unsigned long']],
            'Spare3': [0x54, ['unsigned long']],
            'DozeS4Timeout': [0x58, ['unsigned long']],
            'BroadcastCapacityResolution': [0x5C, ['unsigned long']],
            'DischargePolicy': [0x60, ['array', 4, ['SYSTEM_POWER_LEVEL']]],
            'VideoTimeout': [0xC0, ['unsigned long']],
            'VideoDimDisplay': [0xC4, ['unsigned char']],
            'VideoReserved': [0xC8, ['array', 3, ['unsigned long']]],
            'SpindownTimeout': [0xD4, ['unsigned long']],
            'OptimizeForPower': [0xD8, ['unsigned char']],
            'FanThrottleTolerance': [0xD9, ['unsigned char']],
            'ForcedThrottle': [0xDA, ['unsigned char']],
            'MinThrottle': [0xDB, ['unsigned char']],
            'OverThrottled': [0xDC, ['POWER_ACTION_POLICY']],
        },
    ],
    '_POOL_HEADER': [
        0x10,
        {
            'PreviousSize': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'PoolIndex': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'BlockSize': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'PoolType': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'Ulong1': [0x0, ['unsigned long']],
            'PoolTag': [0x4, ['unsigned long']],
            'ProcessBilled': [0x8, ['pointer64', ['_EPROCESS']]],
            'AllocatorBackTraceIndex': [0x8, ['unsigned short']],
            'PoolTagHash': [0xA, ['unsigned short']],
        },
    ],
    '_ETW_PROVIDER_TABLE_ENTRY': [
        0x18,
        {
            'RefCount': [0x0, ['long']],
            'State': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'EtwProviderStateFree',
                            1: 'EtwProviderStateTransition',
                            2: 'EtwProviderStateActive',
                            3: 'EtwProviderStateMax',
                        },
                    ),
                ],
            ],
            'RegEntry': [0x8, ['pointer64', ['_ETW_REG_ENTRY']]],
            'Caller': [0x10, ['pointer64', ['void']]],
        },
    ],
    '_PEB64': [
        0x380,
        {
            'InheritedAddressSpace': [0x0, ['unsigned char']],
            'ReadImageFileExecOptions': [0x1, ['unsigned char']],
            'BeingDebugged': [0x2, ['unsigned char']],
            'BitField': [0x3, ['unsigned char']],
            'ImageUsesLargePages': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'IsProtectedProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'IsLegacyProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'IsImageDynamicallyRelocated': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'SkipPatchingUser32Forwarders': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Mutant': [0x8, ['unsigned long long']],
            'ImageBaseAddress': [0x10, ['unsigned long long']],
            'Ldr': [0x18, ['unsigned long long']],
            'ProcessParameters': [0x20, ['unsigned long long']],
            'SubSystemData': [0x28, ['unsigned long long']],
            'ProcessHeap': [0x30, ['unsigned long long']],
            'FastPebLock': [0x38, ['unsigned long long']],
            'AtlThunkSListPtr': [0x40, ['unsigned long long']],
            'IFEOKey': [0x48, ['unsigned long long']],
            'CrossProcessFlags': [0x50, ['unsigned long']],
            'ProcessInJob': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ProcessInitializing': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingVEH': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingVCH': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingFTH': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ReservedBits0': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'KernelCallbackTable': [0x58, ['unsigned long long']],
            'UserSharedInfoPtr': [0x58, ['unsigned long long']],
            'SystemReserved': [0x60, ['array', 1, ['unsigned long']]],
            'AtlThunkSListPtr32': [0x64, ['unsigned long']],
            'ApiSetMap': [0x68, ['unsigned long long']],
            'TlsExpansionCounter': [0x70, ['unsigned long']],
            'TlsBitmap': [0x78, ['unsigned long long']],
            'TlsBitmapBits': [0x80, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x88, ['unsigned long long']],
            'HotpatchInformation': [0x90, ['unsigned long long']],
            'ReadOnlyStaticServerData': [0x98, ['unsigned long long']],
            'AnsiCodePageData': [0xA0, ['unsigned long long']],
            'OemCodePageData': [0xA8, ['unsigned long long']],
            'UnicodeCaseTableData': [0xB0, ['unsigned long long']],
            'NumberOfProcessors': [0xB8, ['unsigned long']],
            'NtGlobalFlag': [0xBC, ['unsigned long']],
            'CriticalSectionTimeout': [0xC0, ['_LARGE_INTEGER']],
            'HeapSegmentReserve': [0xC8, ['unsigned long long']],
            'HeapSegmentCommit': [0xD0, ['unsigned long long']],
            'HeapDeCommitTotalFreeThreshold': [0xD8, ['unsigned long long']],
            'HeapDeCommitFreeBlockThreshold': [0xE0, ['unsigned long long']],
            'NumberOfHeaps': [0xE8, ['unsigned long']],
            'MaximumNumberOfHeaps': [0xEC, ['unsigned long']],
            'ProcessHeaps': [0xF0, ['unsigned long long']],
            'GdiSharedHandleTable': [0xF8, ['unsigned long long']],
            'ProcessStarterHelper': [0x100, ['unsigned long long']],
            'GdiDCAttributeList': [0x108, ['unsigned long']],
            'LoaderLock': [0x110, ['unsigned long long']],
            'OSMajorVersion': [0x118, ['unsigned long']],
            'OSMinorVersion': [0x11C, ['unsigned long']],
            'OSBuildNumber': [0x120, ['unsigned short']],
            'OSCSDVersion': [0x122, ['unsigned short']],
            'OSPlatformId': [0x124, ['unsigned long']],
            'ImageSubsystem': [0x128, ['unsigned long']],
            'ImageSubsystemMajorVersion': [0x12C, ['unsigned long']],
            'ImageSubsystemMinorVersion': [0x130, ['unsigned long']],
            'ActiveProcessAffinityMask': [0x138, ['unsigned long long']],
            'GdiHandleBuffer': [0x140, ['array', 60, ['unsigned long']]],
            'PostProcessInitRoutine': [0x230, ['unsigned long long']],
            'TlsExpansionBitmap': [0x238, ['unsigned long long']],
            'TlsExpansionBitmapBits': [
                0x240,
                ['array', 32, ['unsigned long']],
            ],
            'SessionId': [0x2C0, ['unsigned long']],
            'AppCompatFlags': [0x2C8, ['_ULARGE_INTEGER']],
            'AppCompatFlagsUser': [0x2D0, ['_ULARGE_INTEGER']],
            'pShimData': [0x2D8, ['unsigned long long']],
            'AppCompatInfo': [0x2E0, ['unsigned long long']],
            'CSDVersion': [0x2E8, ['_STRING64']],
            'ActivationContextData': [0x2F8, ['unsigned long long']],
            'ProcessAssemblyStorageMap': [0x300, ['unsigned long long']],
            'SystemDefaultActivationContextData': [
                0x308,
                ['unsigned long long'],
            ],
            'SystemAssemblyStorageMap': [0x310, ['unsigned long long']],
            'MinimumStackCommit': [0x318, ['unsigned long long']],
            'FlsCallback': [0x320, ['unsigned long long']],
            'FlsListHead': [0x328, ['LIST_ENTRY64']],
            'FlsBitmap': [0x338, ['unsigned long long']],
            'FlsBitmapBits': [0x340, ['array', 4, ['unsigned long']]],
            'FlsHighIndex': [0x350, ['unsigned long']],
            'WerRegistrationData': [0x358, ['unsigned long long']],
            'WerShipAssertPtr': [0x360, ['unsigned long long']],
            'pContextData': [0x368, ['unsigned long long']],
            'pImageHeaderHash': [0x370, ['unsigned long long']],
            'TracingFlags': [0x378, ['unsigned long']],
            'HeapTracingEnabled': [
                0x378,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'CritSecTracingEnabled': [
                0x378,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SpareTracingBits': [
                0x378,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_SE_AUDIT_PROCESS_CREATION_INFO': [
        0x8,
        {
            'ImageFileName': [
                0x0,
                ['pointer64', ['_OBJECT_NAME_INFORMATION']],
            ],
        },
    ],
    '_HEAP_ENTRY_EXTRA': [
        0x10,
        {
            'AllocatorBackTraceIndex': [0x0, ['unsigned short']],
            'TagIndex': [0x2, ['unsigned short']],
            'Settable': [0x8, ['unsigned long long']],
            'ZeroInit': [0x0, ['unsigned long long']],
            'ZeroInit1': [0x8, ['unsigned long long']],
        },
    ],
    '_VF_POOL_TRACE': [
        0x80,
        {
            'Address': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned long long']],
            'Thread': [0x10, ['pointer64', ['_ETHREAD']]],
            'StackTrace': [0x18, ['array', 13, ['pointer64', ['void']]]],
        },
    ],
    '__unnamed_21ca': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MM_SESSION_SPACE_FLAGS']],
        },
    ],
    '_MM_SESSION_SPACE': [
        0x1F80,
        {
            'ReferenceCount': [0x0, ['long']],
            'u': [0x4, ['__unnamed_21ca']],
            'SessionId': [0x8, ['unsigned long']],
            'ProcessReferenceToSession': [0xC, ['long']],
            'ProcessList': [0x10, ['_LIST_ENTRY']],
            'LastProcessSwappedOutTime': [0x20, ['_LARGE_INTEGER']],
            'SessionPageDirectoryIndex': [0x28, ['unsigned long long']],
            'NonPagablePages': [0x30, ['unsigned long long']],
            'CommittedPages': [0x38, ['unsigned long long']],
            'PagedPoolStart': [0x40, ['pointer64', ['void']]],
            'PagedPoolEnd': [0x48, ['pointer64', ['void']]],
            'SessionObject': [0x50, ['pointer64', ['void']]],
            'SessionObjectHandle': [0x58, ['pointer64', ['void']]],
            'ResidentProcessCount': [0x60, ['long']],
            'SessionPoolAllocationFailures': [
                0x64,
                ['array', 4, ['unsigned long']],
            ],
            'ImageList': [0x78, ['_LIST_ENTRY']],
            'LocaleId': [0x88, ['unsigned long']],
            'AttachCount': [0x8C, ['unsigned long']],
            'AttachGate': [0x90, ['_KGATE']],
            'WsListEntry': [0xA8, ['_LIST_ENTRY']],
            'Lookaside': [0xC0, ['array', 21, ['_GENERAL_LOOKASIDE']]],
            'Session': [0xB40, ['_MMSESSION']],
            'PagedPoolInfo': [0xB98, ['_MM_PAGED_POOL_INFO']],
            'Vm': [0xC00, ['_MMSUPPORT']],
            'Wsle': [0xC88, ['pointer64', ['_MMWSLE']]],
            'DriverUnload': [0xC90, ['pointer64', ['void']]],
            'PagedPool': [0xCC0, ['_POOL_DESCRIPTOR']],
            'PageDirectory': [0x1E00, ['_MMPTE']],
            'SessionVaLock': [0x1E08, ['_KGUARDED_MUTEX']],
            'DynamicVaBitMap': [0x1E40, ['_RTL_BITMAP']],
            'DynamicVaHint': [0x1E50, ['unsigned long']],
            'SpecialPool': [0x1E58, ['_MI_SPECIAL_POOL']],
            'SessionPteLock': [0x1EA0, ['_KGUARDED_MUTEX']],
            'PoolBigEntriesInUse': [0x1ED8, ['long']],
            'PagedPoolPdeCount': [0x1EDC, ['unsigned long']],
            'SpecialPoolPdeCount': [0x1EE0, ['unsigned long']],
            'DynamicSessionPdeCount': [0x1EE4, ['unsigned long']],
            'SystemPteInfo': [0x1EE8, ['_MI_SYSTEM_PTE_TYPE']],
            'PoolTrackTableExpansion': [0x1F30, ['pointer64', ['void']]],
            'PoolTrackTableExpansionSize': [0x1F38, ['unsigned long long']],
            'PoolTrackBigPages': [0x1F40, ['pointer64', ['void']]],
            'PoolTrackBigPagesSize': [0x1F48, ['unsigned long long']],
            'IoState': [
                0x1F50,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'IoSessionStateCreated',
                            2: 'IoSessionStateInitialized',
                            3: 'IoSessionStateConnected',
                            4: 'IoSessionStateDisconnected',
                            5: 'IoSessionStateDisconnectedLoggedOn',
                            6: 'IoSessionStateLoggedOn',
                            7: 'IoSessionStateLoggedOff',
                            8: 'IoSessionStateTerminated',
                            9: 'IoSessionStateMax',
                        },
                    ),
                ],
            ],
            'IoStateSequence': [0x1F54, ['unsigned long']],
            'IoNotificationEvent': [0x1F58, ['_KEVENT']],
            'CreateTime': [0x1F70, ['unsigned long long']],
            'CpuQuotaBlock': [0x1F78, ['pointer64', ['_PS_CPU_QUOTA_BLOCK']]],
        },
    ],
    '_OBJECT_HANDLE_COUNT_ENTRY': [
        0x10,
        {
            'Process': [0x0, ['pointer64', ['_EPROCESS']]],
            'HandleCount': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'LockCount': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_CLIENT_ID': [
        0x10,
        {
            'UniqueProcess': [0x0, ['pointer64', ['void']]],
            'UniqueThread': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_WHEA_MEMORY_ERROR_SECTION': [
        0x49,
        {
            'ValidBits': [0x0, ['_WHEA_MEMORY_ERROR_SECTION_VALIDBITS']],
            'ErrorStatus': [0x8, ['_WHEA_ERROR_STATUS']],
            'PhysicalAddress': [0x10, ['unsigned long long']],
            'PhysicalAddressMask': [0x18, ['unsigned long long']],
            'Node': [0x20, ['unsigned short']],
            'Card': [0x22, ['unsigned short']],
            'Module': [0x24, ['unsigned short']],
            'Bank': [0x26, ['unsigned short']],
            'Device': [0x28, ['unsigned short']],
            'Row': [0x2A, ['unsigned short']],
            'Column': [0x2C, ['unsigned short']],
            'BitPosition': [0x2E, ['unsigned short']],
            'RequesterId': [0x30, ['unsigned long long']],
            'ResponderId': [0x38, ['unsigned long long']],
            'TargetId': [0x40, ['unsigned long long']],
            'ErrorType': [0x48, ['unsigned char']],
        },
    ],
    '_KWAIT_STATUS_REGISTER': [
        0x1,
        {
            'Flags': [0x0, ['unsigned char']],
            'State': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Affinity': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Priority': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Apc': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'UserApc': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Alert': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_VI_DEADLOCK_RESOURCE': [
        0xF8,
        {
            'Type': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'VfDeadlockUnknown',
                            1: 'VfDeadlockMutex',
                            2: 'VfDeadlockMutexAbandoned',
                            3: 'VfDeadlockFastMutex',
                            4: 'VfDeadlockFastMutexUnsafe',
                            5: 'VfDeadlockSpinLock',
                            6: 'VfDeadlockInStackQueuedSpinLock',
                            7: 'VfDeadlockUnusedSpinLock',
                            8: 'VfDeadlockEresource',
                            9: 'VfDeadlockTypeMaximum',
                        },
                    ),
                ],
            ],
            'NodeCount': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'RecursionCount': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ResourceAddress': [0x8, ['pointer64', ['void']]],
            'ThreadOwner': [0x10, ['pointer64', ['_VI_DEADLOCK_THREAD']]],
            'ResourceList': [0x18, ['_LIST_ENTRY']],
            'HashChainList': [0x28, ['_LIST_ENTRY']],
            'FreeListEntry': [0x28, ['_LIST_ENTRY']],
            'StackTrace': [0x38, ['array', 8, ['pointer64', ['void']]]],
            'LastAcquireTrace': [0x78, ['array', 8, ['pointer64', ['void']]]],
            'LastReleaseTrace': [0xB8, ['array', 8, ['pointer64', ['void']]]],
        },
    ],
    '_DBGKD_GET_SET_BUS_DATA': [
        0x14,
        {
            'BusDataType': [0x0, ['unsigned long']],
            'BusNumber': [0x4, ['unsigned long']],
            'SlotNumber': [0x8, ['unsigned long']],
            'Offset': [0xC, ['unsigned long']],
            'Length': [0x10, ['unsigned long']],
        },
    ],
    '_MMSECTION_FLAGS': [
        0x4,
        {
            'BeingDeleted': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'BeingCreated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'BeingPurged': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'NoModifiedWriting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'FailAllIo': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Image': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Based': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'File': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Networked': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Rom': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'PhysicalMemory': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserve': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'Commit': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'WasPurged': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'UserReference': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'GlobalMemory': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'DeleteOnClose': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'FilePointerNull': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'GlobalOnlyPerSession': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'SetMappedFileIoComplete': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'CollidedFlush': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'NoChange': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'AttemptingDelete': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'UserWritable': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'PreferredNode': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_SECURITY_CLIENT_CONTEXT': [
        0x48,
        {
            'SecurityQos': [0x0, ['_SECURITY_QUALITY_OF_SERVICE']],
            'ClientToken': [0x10, ['pointer64', ['void']]],
            'DirectlyAccessClientToken': [0x18, ['unsigned char']],
            'DirectAccessEffectiveOnly': [0x19, ['unsigned char']],
            'ServerIsRemote': [0x1A, ['unsigned char']],
            'ClientTokenControl': [0x1C, ['_TOKEN_CONTROL']],
        },
    ],
    '_MM_PAGED_POOL_INFO': [
        0x68,
        {
            'Mutex': [0x0, ['_KGUARDED_MUTEX']],
            'PagedPoolAllocationMap': [0x38, ['_RTL_BITMAP']],
            'FirstPteForPagedPool': [0x48, ['pointer64', ['_MMPTE']]],
            'PagedPoolHint': [0x50, ['unsigned long']],
            'PagedPoolCommit': [0x58, ['unsigned long long']],
            'AllocatedPagedPool': [0x60, ['unsigned long long']],
        },
    ],
    '_BITMAP_RANGE': [
        0x30,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'BasePage': [0x10, ['long long']],
            'FirstDirtyPage': [0x18, ['unsigned long']],
            'LastDirtyPage': [0x1C, ['unsigned long']],
            'DirtyPages': [0x20, ['unsigned long']],
            'Bitmap': [0x28, ['pointer64', ['unsigned long']]],
        },
    ],
    '_NT_TIB64': [
        0x38,
        {
            'ExceptionList': [0x0, ['unsigned long long']],
            'StackBase': [0x8, ['unsigned long long']],
            'StackLimit': [0x10, ['unsigned long long']],
            'SubSystemTib': [0x18, ['unsigned long long']],
            'FiberData': [0x20, ['unsigned long long']],
            'Version': [0x20, ['unsigned long']],
            'ArbitraryUserPointer': [0x28, ['unsigned long long']],
            'Self': [0x30, ['unsigned long long']],
        },
    ],
    '_IO_SECURITY_CONTEXT': [
        0x18,
        {
            'SecurityQos': [
                0x0,
                ['pointer64', ['_SECURITY_QUALITY_OF_SERVICE']],
            ],
            'AccessState': [0x8, ['pointer64', ['_ACCESS_STATE']]],
            'DesiredAccess': [0x10, ['unsigned long']],
            'FullCreateOptions': [0x14, ['unsigned long']],
        },
    ],
    '_PROC_PERF_DOMAIN': [
        0xB8,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'Master': [0x10, ['pointer64', ['_KPRCB']]],
            'Members': [0x18, ['_KAFFINITY_EX']],
            'FeedbackHandler': [0x40, ['pointer64', ['void']]],
            'GetFFHThrottleState': [0x48, ['pointer64', ['void']]],
            'BoostPolicyHandler': [0x50, ['pointer64', ['void']]],
            'PerfSelectionHandler': [0x58, ['pointer64', ['void']]],
            'PerfHandler': [0x60, ['pointer64', ['void']]],
            'Processors': [0x68, ['pointer64', ['_PROC_PERF_CONSTRAINT']]],
            'PerfChangeTime': [0x70, ['unsigned long long']],
            'ProcessorCount': [0x78, ['unsigned long']],
            'PreviousFrequencyMhz': [0x7C, ['unsigned long']],
            'CurrentFrequencyMhz': [0x80, ['unsigned long']],
            'PreviousFrequency': [0x84, ['unsigned long']],
            'CurrentFrequency': [0x88, ['unsigned long']],
            'CurrentPerfContext': [0x8C, ['unsigned long']],
            'DesiredFrequency': [0x90, ['unsigned long']],
            'MaxFrequency': [0x94, ['unsigned long']],
            'MinPerfPercent': [0x98, ['unsigned long']],
            'MinThrottlePercent': [0x9C, ['unsigned long']],
            'MaxPercent': [0xA0, ['unsigned long']],
            'MinPercent': [0xA4, ['unsigned long']],
            'ConstrainedMaxPercent': [0xA8, ['unsigned long']],
            'ConstrainedMinPercent': [0xAC, ['unsigned long']],
            'Coordination': [0xB0, ['unsigned char']],
            'PerfChangeIntervalCount': [0xB4, ['long']],
        },
    ],
    '_X86_DBGKD_CONTROL_SET': [
        0x10,
        {
            'TraceFlag': [0x0, ['unsigned long']],
            'Dr7': [0x4, ['unsigned long']],
            'CurrentSymbolStart': [0x8, ['unsigned long']],
            'CurrentSymbolEnd': [0xC, ['unsigned long']],
        },
    ],
    '_HANDLE_TRACE_DB_ENTRY': [
        0xA0,
        {
            'ClientId': [0x0, ['_CLIENT_ID']],
            'Handle': [0x10, ['pointer64', ['void']]],
            'Type': [0x18, ['unsigned long']],
            'StackTrace': [0x20, ['array', 16, ['pointer64', ['void']]]],
        },
    ],
    '_DUMMY_FILE_OBJECT': [
        0x110,
        {
            'ObjectHeader': [0x0, ['_OBJECT_HEADER']],
            'FileObjectBody': [0x38, ['array', 216, ['unsigned char']]],
        },
    ],
    '_POP_TRIGGER_WAIT': [
        0x38,
        {
            'Event': [0x0, ['_KEVENT']],
            'Status': [0x18, ['long']],
            'Link': [0x20, ['_LIST_ENTRY']],
            'Trigger': [0x30, ['pointer64', ['_POP_ACTION_TRIGGER']]],
        },
    ],
    '_RELATION_LIST': [
        0x18,
        {
            'Count': [0x0, ['unsigned long']],
            'TagCount': [0x4, ['unsigned long']],
            'FirstLevel': [0x8, ['unsigned long']],
            'MaxLevel': [0xC, ['unsigned long']],
            'Entries': [
                0x10,
                ['array', 1, ['pointer64', ['_RELATION_LIST_ENTRY']]],
            ],
        },
    ],
    '_IO_TIMER': [
        0x30,
        {
            'Type': [0x0, ['short']],
            'TimerFlag': [0x2, ['short']],
            'TimerList': [0x8, ['_LIST_ENTRY']],
            'TimerRoutine': [0x18, ['pointer64', ['void']]],
            'Context': [0x20, ['pointer64', ['void']]],
            'DeviceObject': [0x28, ['pointer64', ['_DEVICE_OBJECT']]],
        },
    ],
    '_ARBITER_TEST_ALLOCATION_PARAMETERS': [
        0x18,
        {
            'ArbitrationList': [0x0, ['pointer64', ['_LIST_ENTRY']]],
            'AllocateFromCount': [0x8, ['unsigned long']],
            'AllocateFrom': [
                0x10,
                ['pointer64', ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
        },
    ],
    '_MI_SPECIAL_POOL': [
        0x48,
        {
            'PteBase': [0x0, ['pointer64', ['_MMPTE']]],
            'Lock': [0x8, ['unsigned long long']],
            'Paged': [0x10, ['_MI_SPECIAL_POOL_PTE_LIST']],
            'NonPaged': [0x20, ['_MI_SPECIAL_POOL_PTE_LIST']],
            'PagesInUse': [0x30, ['long long']],
            'SpecialPoolPdes': [0x38, ['_RTL_BITMAP']],
        },
    ],
    '_ARBITER_QUERY_CONFLICT_PARAMETERS': [
        0x20,
        {
            'PhysicalDeviceObject': [0x0, ['pointer64', ['_DEVICE_OBJECT']]],
            'ConflictingResource': [
                0x8,
                ['pointer64', ['_IO_RESOURCE_DESCRIPTOR']],
            ],
            'ConflictCount': [0x10, ['pointer64', ['unsigned long']]],
            'Conflicts': [
                0x18,
                ['pointer64', ['pointer64', ['_ARBITER_CONFLICT_INFO']]],
            ],
        },
    ],
    '_PHYSICAL_MEMORY_DESCRIPTOR': [
        0x20,
        {
            'NumberOfRuns': [0x0, ['unsigned long']],
            'NumberOfPages': [0x8, ['unsigned long long']],
            'Run': [0x10, ['array', 1, ['_PHYSICAL_MEMORY_RUN']]],
        },
    ],
    '__unnamed_2240': [
        0x4,
        {
            'BaseMiddle': [0x0, ['unsigned char']],
            'Flags1': [0x1, ['unsigned char']],
            'Flags2': [0x2, ['unsigned char']],
            'BaseHigh': [0x3, ['unsigned char']],
        },
    ],
    '__unnamed_2244': [
        0x4,
        {
            'BaseMiddle': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Type': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=13, native_type='unsigned long'),
                ],
            ],
            'Dpl': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'Present': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'LimitHigh': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'System': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'LongMode': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultBig': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'Granularity': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'BaseHigh': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_KGDTENTRY64': [
        0x10,
        {
            'LimitLow': [0x0, ['unsigned short']],
            'BaseLow': [0x2, ['unsigned short']],
            'Bytes': [0x4, ['__unnamed_2240']],
            'Bits': [0x4, ['__unnamed_2244']],
            'BaseUpper': [0x8, ['unsigned long']],
            'MustBeZero': [0xC, ['unsigned long']],
            'Alignment': [0x0, ['unsigned long long']],
        },
    ],
    '_PNP_DEVICE_EVENT_LIST': [
        0x88,
        {
            'Status': [0x0, ['long']],
            'EventQueueMutex': [0x8, ['_KMUTANT']],
            'Lock': [0x40, ['_KGUARDED_MUTEX']],
            'List': [0x78, ['_LIST_ENTRY']],
        },
    ],
    '_MAILSLOT_CREATE_PARAMETERS': [
        0x18,
        {
            'MailslotQuota': [0x0, ['unsigned long']],
            'MaximumMessageSize': [0x4, ['unsigned long']],
            'ReadTimeout': [0x8, ['_LARGE_INTEGER']],
            'TimeoutSpecified': [0x10, ['unsigned char']],
        },
    ],
    '_PO_IRP_MANAGER': [
        0x20,
        {
            'DeviceIrpQueue': [0x0, ['_PO_IRP_QUEUE']],
            'SystemIrpQueue': [0x10, ['_PO_IRP_QUEUE']],
        },
    ],
    '_PPM_PERF_STATE': [
        0x28,
        {
            'Frequency': [0x0, ['unsigned long']],
            'Power': [0x4, ['unsigned long']],
            'PercentFrequency': [0x8, ['unsigned char']],
            'IncreaseLevel': [0x9, ['unsigned char']],
            'DecreaseLevel': [0xA, ['unsigned char']],
            'Type': [0xB, ['unsigned char']],
            'Control': [0x10, ['unsigned long long']],
            'Status': [0x18, ['unsigned long long']],
            'TotalHitCount': [0x20, ['unsigned long']],
            'DesiredCount': [0x24, ['unsigned long']],
        },
    ],
    '_PPM_FFH_THROTTLE_STATE_INFO': [
        0x20,
        {
            'EnableLogging': [0x0, ['unsigned char']],
            'MismatchCount': [0x4, ['unsigned long']],
            'Initialized': [0x8, ['unsigned char']],
            'LastValue': [0x10, ['unsigned long long']],
            'LastLogTickCount': [0x18, ['_LARGE_INTEGER']],
        },
    ],
    '_SECURITY_DESCRIPTOR_RELATIVE': [
        0x14,
        {
            'Revision': [0x0, ['unsigned char']],
            'Sbz1': [0x1, ['unsigned char']],
            'Control': [0x2, ['unsigned short']],
            'Owner': [0x4, ['unsigned long']],
            'Group': [0x8, ['unsigned long']],
            'Sacl': [0xC, ['unsigned long']],
            'Dacl': [0x10, ['unsigned long']],
        },
    ],
    '_CLIENT_ID64': [
        0x10,
        {
            'UniqueProcess': [0x0, ['unsigned long long']],
            'UniqueThread': [0x8, ['unsigned long long']],
        },
    ],
    '_KDPC_DATA': [
        0x20,
        {
            'DpcListHead': [0x0, ['_LIST_ENTRY']],
            'DpcLock': [0x10, ['unsigned long long']],
            'DpcQueueDepth': [0x18, ['long']],
            'DpcCount': [0x1C, ['unsigned long']],
        },
    ],
    '_NAMED_PIPE_CREATE_PARAMETERS': [
        0x28,
        {
            'NamedPipeType': [0x0, ['unsigned long']],
            'ReadMode': [0x4, ['unsigned long']],
            'CompletionMode': [0x8, ['unsigned long']],
            'MaximumInstances': [0xC, ['unsigned long']],
            'InboundQuota': [0x10, ['unsigned long']],
            'OutboundQuota': [0x14, ['unsigned long']],
            'DefaultTimeout': [0x18, ['_LARGE_INTEGER']],
            'TimeoutSpecified': [0x20, ['unsigned char']],
        },
    ],
    '_CM_BIG_DATA': [
        0x8,
        {
            'Signature': [0x0, ['unsigned short']],
            'Count': [0x2, ['unsigned short']],
            'List': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2260': [
        0x10,
        {
            'UserData': [0x0, ['pointer64', ['void']]],
            'Owner': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_2262': [
        0x10,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
        },
    ],
    '_RTLP_RANGE_LIST_ENTRY': [
        0x38,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
            'Allocated': [0x10, ['__unnamed_2260']],
            'Merged': [0x10, ['__unnamed_2262']],
            'Attributes': [0x20, ['unsigned char']],
            'PublicFlags': [0x21, ['unsigned char']],
            'PrivateFlags': [0x22, ['unsigned short']],
            'ListEntry': [0x28, ['_LIST_ENTRY']],
        },
    ],
    '_ALPC_COMPLETION_PACKET_LOOKASIDE_ENTRY': [
        0x18,
        {
            'ListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Packet': [
                0x8,
                ['pointer64', ['_IO_MINI_COMPLETION_PACKET_USER']],
            ],
            'Lookaside': [
                0x10,
                ['pointer64', ['_ALPC_COMPLETION_PACKET_LOOKASIDE']],
            ],
        },
    ],
    '__unnamed_226a': [
        0x2,
        {
            'AsUSHORT': [0x0, ['unsigned short']],
            'AllowScaling': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'Disabled': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
        },
    ],
    'PROCESSOR_IDLESTATE_POLICY': [
        0x20,
        {
            'Revision': [0x0, ['unsigned short']],
            'Flags': [0x2, ['__unnamed_226a']],
            'PolicyCount': [0x4, ['unsigned long']],
            'Policy': [0x8, ['array', 3, ['PROCESSOR_IDLESTATE_INFO']]],
        },
    ],
    '_ACTIVATION_CONTEXT_STACK': [
        0x28,
        {
            'ActiveFrame': [
                0x0,
                ['pointer64', ['_RTL_ACTIVATION_CONTEXT_STACK_FRAME']],
            ],
            'FrameListCache': [0x8, ['_LIST_ENTRY']],
            'Flags': [0x18, ['unsigned long']],
            'NextCookieSequenceNumber': [0x1C, ['unsigned long']],
            'StackId': [0x20, ['unsigned long']],
        },
    ],
    '_MSUBSECTION': [
        0x70,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'SubsectionBase': [0x8, ['pointer64', ['_MMPTE']]],
            'NextSubsection': [0x10, ['pointer64', ['_SUBSECTION']]],
            'NextMappedSubsection': [0x10, ['pointer64', ['_MSUBSECTION']]],
            'PtesInSubsection': [0x18, ['unsigned long']],
            'UnusedPtes': [0x20, ['unsigned long']],
            'GlobalPerSessionHead': [0x20, ['pointer64', ['_MM_AVL_TABLE']]],
            'u': [0x28, ['__unnamed_1fb7']],
            'StartingSector': [0x2C, ['unsigned long']],
            'NumberOfFullSectors': [0x30, ['unsigned long']],
            'u1': [0x38, ['__unnamed_2059']],
            'LeftChild': [0x40, ['pointer64', ['_MMSUBSECTION_NODE']]],
            'RightChild': [0x48, ['pointer64', ['_MMSUBSECTION_NODE']]],
            'DereferenceList': [0x50, ['_LIST_ENTRY']],
            'NumberOfMappedViews': [0x60, ['unsigned long long']],
            'NumberOfPfnReferences': [0x68, ['unsigned long long']],
        },
    ],
    '_RTL_DRIVE_LETTER_CURDIR': [
        0x18,
        {
            'Flags': [0x0, ['unsigned short']],
            'Length': [0x2, ['unsigned short']],
            'TimeStamp': [0x4, ['unsigned long']],
            'DosPath': [0x8, ['_STRING']],
        },
    ],
    '_VIRTUAL_EFI_RUNTIME_SERVICES': [
        0x70,
        {
            'GetTime': [0x0, ['unsigned long long']],
            'SetTime': [0x8, ['unsigned long long']],
            'GetWakeupTime': [0x10, ['unsigned long long']],
            'SetWakeupTime': [0x18, ['unsigned long long']],
            'SetVirtualAddressMap': [0x20, ['unsigned long long']],
            'ConvertPointer': [0x28, ['unsigned long long']],
            'GetVariable': [0x30, ['unsigned long long']],
            'GetNextVariableName': [0x38, ['unsigned long long']],
            'SetVariable': [0x40, ['unsigned long long']],
            'GetNextHighMonotonicCount': [0x48, ['unsigned long long']],
            'ResetSystem': [0x50, ['unsigned long long']],
            'UpdateCapsule': [0x58, ['unsigned long long']],
            'QueryCapsuleCapabilities': [0x60, ['unsigned long long']],
            'QueryVariableInfo': [0x68, ['unsigned long long']],
        },
    ],
    '_MI_SPECIAL_POOL_PTE_LIST': [
        0x10,
        {
            'FreePteHead': [0x0, ['_MMPTE']],
            'FreePteTail': [0x8, ['_MMPTE']],
        },
    ],
    'SYSTEM_POWER_CAPABILITIES': [
        0x4C,
        {
            'PowerButtonPresent': [0x0, ['unsigned char']],
            'SleepButtonPresent': [0x1, ['unsigned char']],
            'LidPresent': [0x2, ['unsigned char']],
            'SystemS1': [0x3, ['unsigned char']],
            'SystemS2': [0x4, ['unsigned char']],
            'SystemS3': [0x5, ['unsigned char']],
            'SystemS4': [0x6, ['unsigned char']],
            'SystemS5': [0x7, ['unsigned char']],
            'HiberFilePresent': [0x8, ['unsigned char']],
            'FullWake': [0x9, ['unsigned char']],
            'VideoDimPresent': [0xA, ['unsigned char']],
            'ApmPresent': [0xB, ['unsigned char']],
            'UpsPresent': [0xC, ['unsigned char']],
            'ThermalControl': [0xD, ['unsigned char']],
            'ProcessorThrottle': [0xE, ['unsigned char']],
            'ProcessorMinThrottle': [0xF, ['unsigned char']],
            'ProcessorMaxThrottle': [0x10, ['unsigned char']],
            'FastSystemS4': [0x11, ['unsigned char']],
            'spare2': [0x12, ['array', 3, ['unsigned char']]],
            'DiskSpinDown': [0x15, ['unsigned char']],
            'spare3': [0x16, ['array', 8, ['unsigned char']]],
            'SystemBatteriesPresent': [0x1E, ['unsigned char']],
            'BatteriesAreShortTerm': [0x1F, ['unsigned char']],
            'BatteryScale': [0x20, ['array', 3, ['BATTERY_REPORTING_SCALE']]],
            'AcOnLineWake': [
                0x38,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'SoftLidWake': [
                0x3C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'RtcWake': [
                0x40,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'MinDeviceWakeState': [
                0x44,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'DefaultLowLatencyWake': [
                0x48,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_2280': [
        0x8,
        {
            'ImageCommitment': [0x0, ['unsigned long long']],
            'CreatingProcess': [0x0, ['pointer64', ['_EPROCESS']]],
        },
    ],
    '__unnamed_2284': [
        0x8,
        {
            'ImageInformation': [
                0x0,
                ['pointer64', ['_MI_SECTION_IMAGE_INFORMATION']],
            ],
            'FirstMappedVa': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_SEGMENT': [
        0x50,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'SegmentFlags': [0xC, ['_SEGMENT_FLAGS']],
            'NumberOfCommittedPages': [0x10, ['unsigned long long']],
            'SizeOfSegment': [0x18, ['unsigned long long']],
            'ExtendInfo': [0x20, ['pointer64', ['_MMEXTEND_INFO']]],
            'BasedAddress': [0x20, ['pointer64', ['void']]],
            'SegmentLock': [0x28, ['_EX_PUSH_LOCK']],
            'u1': [0x30, ['__unnamed_2280']],
            'u2': [0x38, ['__unnamed_2284']],
            'PrototypePte': [0x40, ['pointer64', ['_MMPTE']]],
            'ThePtes': [0x48, ['array', 1, ['_MMPTE']]],
        },
    ],
    '_DIAGNOSTIC_CONTEXT': [
        0x20,
        {
            'CallerType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KernelRequester',
                            1: 'UserProcessRequester',
                            2: 'UserSharedServiceRequester',
                        },
                    ),
                ],
            ],
            'Process': [0x8, ['pointer64', ['_EPROCESS']]],
            'ServiceTag': [0x10, ['unsigned long']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'ReasonSize': [0x18, ['unsigned long long']],
        },
    ],
    '__unnamed_228d': [
        0x4,
        {
            'MissedEtwRegistration': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_228f': [
        0x4,
        {
            'Flags': [0x0, ['__unnamed_228d']],
            'Whole': [0x0, ['unsigned long']],
        },
    ],
    '_VF_TARGET_VERIFIED_DRIVER_DATA': [
        0x100,
        {
            'SuspectDriverEntry': [
                0x0,
                ['pointer64', ['_VF_SUSPECT_DRIVER_ENTRY']],
            ],
            'WMICallback': [0x8, ['pointer64', ['void']]],
            'EtwHandlesListHead': [0x10, ['_LIST_ENTRY']],
            'u1': [0x20, ['__unnamed_228f']],
            'Signature': [0x28, ['unsigned long long']],
            'PoolPageHeaders': [0x30, ['_SLIST_HEADER']],
            'PoolTrackers': [0x40, ['_SLIST_HEADER']],
            'CurrentPagedPoolAllocations': [0x50, ['unsigned long']],
            'CurrentNonPagedPoolAllocations': [0x54, ['unsigned long']],
            'PeakPagedPoolAllocations': [0x58, ['unsigned long']],
            'PeakNonPagedPoolAllocations': [0x5C, ['unsigned long']],
            'PagedBytes': [0x60, ['unsigned long long']],
            'NonPagedBytes': [0x68, ['unsigned long long']],
            'PeakPagedBytes': [0x70, ['unsigned long long']],
            'PeakNonPagedBytes': [0x78, ['unsigned long long']],
            'RaiseIrqls': [0x80, ['unsigned long']],
            'AcquireSpinLocks': [0x84, ['unsigned long']],
            'SynchronizeExecutions': [0x88, ['unsigned long']],
            'AllocationsWithNoTag': [0x8C, ['unsigned long']],
            'AllocationsFailed': [0x90, ['unsigned long']],
            'AllocationsFailedDeliberately': [0x94, ['unsigned long']],
            'LockedBytes': [0x98, ['unsigned long long']],
            'PeakLockedBytes': [0xA0, ['unsigned long long']],
            'MappedLockedBytes': [0xA8, ['unsigned long long']],
            'PeakMappedLockedBytes': [0xB0, ['unsigned long long']],
            'MappedIoSpaceBytes': [0xB8, ['unsigned long long']],
            'PeakMappedIoSpaceBytes': [0xC0, ['unsigned long long']],
            'PagesForMdlBytes': [0xC8, ['unsigned long long']],
            'PeakPagesForMdlBytes': [0xD0, ['unsigned long long']],
            'ContiguousMemoryBytes': [0xD8, ['unsigned long long']],
            'PeakContiguousMemoryBytes': [0xE0, ['unsigned long long']],
            'ContiguousMemoryListHead': [0xE8, ['_LIST_ENTRY']],
        },
    ],
    '_PCAT_FIRMWARE_INFORMATION': [
        0x4,
        {
            'PlaceHolder': [0x0, ['unsigned long']],
        },
    ],
    '_PRIVATE_CACHE_MAP': [
        0x68,
        {
            'NodeTypeCode': [0x0, ['short']],
            'Flags': [0x0, ['_PRIVATE_CACHE_MAP_FLAGS']],
            'UlongFlags': [0x0, ['unsigned long']],
            'ReadAheadMask': [0x4, ['unsigned long']],
            'FileObject': [0x8, ['pointer64', ['_FILE_OBJECT']]],
            'FileOffset1': [0x10, ['_LARGE_INTEGER']],
            'BeyondLastByte1': [0x18, ['_LARGE_INTEGER']],
            'FileOffset2': [0x20, ['_LARGE_INTEGER']],
            'BeyondLastByte2': [0x28, ['_LARGE_INTEGER']],
            'SequentialReadCount': [0x30, ['unsigned long']],
            'ReadAheadLength': [0x34, ['unsigned long']],
            'ReadAheadOffset': [0x38, ['_LARGE_INTEGER']],
            'ReadAheadBeyondLastByte': [0x40, ['_LARGE_INTEGER']],
            'ReadAheadSpinLock': [0x48, ['unsigned long long']],
            'PrivateLinks': [0x50, ['_LIST_ENTRY']],
            'ReadAheadWorkItem': [0x60, ['pointer64', ['void']]],
        },
    ],
    '_CM_KEY_NODE': [
        0x50,
        {
            'Signature': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned short']],
            'LastWriteTime': [0x4, ['_LARGE_INTEGER']],
            'Spare': [0xC, ['unsigned long']],
            'Parent': [0x10, ['unsigned long']],
            'SubKeyCounts': [0x14, ['array', 2, ['unsigned long']]],
            'SubKeyLists': [0x1C, ['array', 2, ['unsigned long']]],
            'ValueList': [0x24, ['_CHILD_LIST']],
            'ChildHiveReference': [0x1C, ['_CM_KEY_REFERENCE']],
            'Security': [0x2C, ['unsigned long']],
            'Class': [0x30, ['unsigned long']],
            'MaxNameLen': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'UserFlags': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'VirtControlFlags': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'Debug': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'MaxClassLen': [0x38, ['unsigned long']],
            'MaxValueNameLen': [0x3C, ['unsigned long']],
            'MaxValueDataLen': [0x40, ['unsigned long']],
            'WorkVar': [0x44, ['unsigned long']],
            'NameLength': [0x48, ['unsigned short']],
            'ClassLength': [0x4A, ['unsigned short']],
            'Name': [0x4C, ['array', 1, ['wchar']]],
        },
    ],
    '_TPM_BOOT_ENTROPY_LDR_RESULT': [
        0x48,
        {
            'Policy': [0x0, ['unsigned long long']],
            'ResultCode': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'TpmBootEntropyStructureUninitialized',
                            1: 'TpmBootEntropyDisabledByPolicy',
                            2: 'TpmBootEntropyNoTpmFound',
                            3: 'TpmBootEntropyTpmError',
                            4: 'TpmBootEntropySuccess',
                        },
                    ),
                ],
            ],
            'ResultStatus': [0xC, ['long']],
            'Time': [0x10, ['unsigned long long']],
            'EntropyLength': [0x18, ['unsigned long']],
            'EntropyData': [0x1C, ['array', 40, ['unsigned char']]],
        },
    ],
    '_RTL_HANDLE_TABLE': [
        0x30,
        {
            'MaximumNumberOfHandles': [0x0, ['unsigned long']],
            'SizeOfHandleTableEntry': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['array', 2, ['unsigned long']]],
            'FreeHandles': [0x10, ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']]],
            'CommittedHandles': [
                0x18,
                ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']],
            ],
            'UnCommittedHandles': [
                0x20,
                ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']],
            ],
            'MaxReservedHandles': [
                0x28,
                ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']],
            ],
        },
    ],
    '_PTE_TRACKER': [
        0x58,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Mdl': [0x10, ['pointer64', ['_MDL']]],
            'Count': [0x18, ['unsigned long long']],
            'SystemVa': [0x20, ['pointer64', ['void']]],
            'StartVa': [0x28, ['pointer64', ['void']]],
            'Offset': [0x30, ['unsigned long']],
            'Length': [0x34, ['unsigned long']],
            'Page': [0x38, ['unsigned long long']],
            'IoMapping': [
                0x40,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Matched': [
                0x40,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'CacheAttribute': [
                0x40,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Spare': [
                0x40,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'CallingAddress': [0x48, ['pointer64', ['void']]],
            'CallersCaller': [0x50, ['pointer64', ['void']]],
        },
    ],
    '_KTHREAD_COUNTERS': [
        0x1A8,
        {
            'WaitReasonBitMap': [0x0, ['unsigned long long']],
            'UserData': [0x8, ['pointer64', ['_THREAD_PERFORMANCE_DATA']]],
            'Flags': [0x10, ['unsigned long']],
            'ContextSwitches': [0x14, ['unsigned long']],
            'CycleTimeBias': [0x18, ['unsigned long long']],
            'HardwareCounters': [0x20, ['unsigned long long']],
            'HwCounter': [0x28, ['array', 16, ['_COUNTER_READING']]],
        },
    ],
    '_SHARED_CACHE_MAP_LIST_CURSOR': [
        0x18,
        {
            'SharedCacheMapLinks': [0x0, ['_LIST_ENTRY']],
            'Flags': [0x10, ['unsigned long']],
        },
    ],
    '_DBGKD_GET_VERSION64': [
        0x28,
        {
            'MajorVersion': [0x0, ['unsigned short']],
            'MinorVersion': [0x2, ['unsigned short']],
            'ProtocolVersion': [0x4, ['unsigned char']],
            'KdSecondaryVersion': [0x5, ['unsigned char']],
            'Flags': [0x6, ['unsigned short']],
            'MachineType': [0x8, ['unsigned short']],
            'MaxPacketType': [0xA, ['unsigned char']],
            'MaxStateChange': [0xB, ['unsigned char']],
            'MaxManipulate': [0xC, ['unsigned char']],
            'Simulation': [0xD, ['unsigned char']],
            'Unused': [0xE, ['array', 1, ['unsigned short']]],
            'KernBase': [0x10, ['unsigned long long']],
            'PsLoadedModuleList': [0x18, ['unsigned long long']],
            'DebuggerDataList': [0x20, ['unsigned long long']],
        },
    ],
    '_STRING32': [
        0x8,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x4, ['unsigned long']],
        },
    ],
    '_HMAP_ENTRY': [
        0x20,
        {
            'BlockAddress': [0x0, ['unsigned long long']],
            'BinAddress': [0x8, ['unsigned long long']],
            'CmView': [0x10, ['pointer64', ['_CM_VIEW_OF_FILE']]],
            'MemAlloc': [0x18, ['unsigned long']],
        },
    ],
    '_RTL_ATOM_TABLE_ENTRY': [
        0x18,
        {
            'HashLink': [0x0, ['pointer64', ['_RTL_ATOM_TABLE_ENTRY']]],
            'HandleIndex': [0x8, ['unsigned short']],
            'Atom': [0xA, ['unsigned short']],
            'ReferenceCount': [0xC, ['unsigned short']],
            'Flags': [0xE, ['unsigned char']],
            'NameLength': [0xF, ['unsigned char']],
            'Name': [0x10, ['array', 1, ['wchar']]],
        },
    ],
    '_TXN_PARAMETER_BLOCK': [
        0x10,
        {
            'Length': [0x0, ['unsigned short']],
            'TxFsContext': [0x2, ['unsigned short']],
            'TransactionObject': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_LOADER_PERFORMANCE_DATA': [
        0x10,
        {
            'StartTime': [0x0, ['unsigned long long']],
            'EndTime': [0x8, ['unsigned long long']],
        },
    ],
    '_PNP_DEVICE_ACTION_ENTRY': [
        0x38,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'DeviceObject': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'RequestType': [
                0x18,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'AssignResources',
                            1: 'ClearDeviceProblem',
                            2: 'ClearProblem',
                            3: 'ClearEjectProblem',
                            4: 'HaltDevice',
                            5: 'QueryPowerRelations',
                            6: 'Rebalance',
                            7: 'ReenumerateBootDevices',
                            8: 'ReenumerateDeviceOnly',
                            9: 'ReenumerateDeviceTree',
                            10: 'ReenumerateRootDevices',
                            11: 'RequeryDeviceState',
                            12: 'ResetDevice',
                            13: 'ResourceRequirementsChanged',
                            14: 'RestartEnumeration',
                            15: 'SetDeviceProblem',
                            16: 'StartDevice',
                            17: 'StartSystemDevicesPass0',
                            18: 'StartSystemDevicesPass1',
                        },
                    ),
                ],
            ],
            'ReorderingBarrier': [0x1C, ['unsigned char']],
            'RequestArgument': [0x20, ['unsigned long long']],
            'CompletionEvent': [0x28, ['pointer64', ['_KEVENT']]],
            'CompletionStatus': [0x30, ['pointer64', ['long']]],
        },
    ],
    '_COUNTER_READING': [
        0x18,
        {
            'Type': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'PMCCounter', 1: 'MaxHardwareCounterType'},
                    ),
                ],
            ],
            'Index': [0x4, ['unsigned long']],
            'Start': [0x8, ['unsigned long long']],
            'Total': [0x10, ['unsigned long long']],
        },
    ],
    '_MMSESSION': [
        0x58,
        {
            'SystemSpaceViewLock': [0x0, ['_KGUARDED_MUTEX']],
            'SystemSpaceViewLockPointer': [
                0x38,
                ['pointer64', ['_KGUARDED_MUTEX']],
            ],
            'SystemSpaceViewTable': [0x40, ['pointer64', ['_MMVIEW']]],
            'SystemSpaceHashSize': [0x48, ['unsigned long']],
            'SystemSpaceHashEntries': [0x4C, ['unsigned long']],
            'SystemSpaceHashKey': [0x50, ['unsigned long']],
            'BitmapFailures': [0x54, ['unsigned long']],
        },
    ],
    '_ETW_REG_ENTRY': [
        0x70,
        {
            'RegList': [0x0, ['_LIST_ENTRY']],
            'GroupRegList': [0x10, ['_LIST_ENTRY']],
            'GuidEntry': [0x20, ['pointer64', ['_ETW_GUID_ENTRY']]],
            'GroupEntry': [0x28, ['pointer64', ['_ETW_GUID_ENTRY']]],
            'Index': [0x30, ['unsigned short']],
            'Flags': [0x32, ['unsigned short']],
            'EnableMask': [0x34, ['unsigned char']],
            'GroupEnableMask': [0x35, ['unsigned char']],
            'UseDescriptorType': [0x36, ['unsigned char']],
            'SessionId': [0x38, ['unsigned long']],
            'ReplyQueue': [0x38, ['pointer64', ['_ETW_REPLY_QUEUE']]],
            'ReplySlot': [
                0x38,
                ['array', 4, ['pointer64', ['_ETW_REG_ENTRY']]],
            ],
            'Process': [0x58, ['pointer64', ['_EPROCESS']]],
            'Callback': [0x58, ['pointer64', ['void']]],
            'CallbackContext': [0x60, ['pointer64', ['void']]],
            'Traits': [0x68, ['pointer64', ['_ETW_PROVIDER_TRAITS']]],
        },
    ],
    '_LPCP_PORT_OBJECT': [
        0x100,
        {
            'ConnectionPort': [0x0, ['pointer64', ['_LPCP_PORT_OBJECT']]],
            'ConnectedPort': [0x8, ['pointer64', ['_LPCP_PORT_OBJECT']]],
            'MsgQueue': [0x10, ['_LPCP_PORT_QUEUE']],
            'Creator': [0x30, ['_CLIENT_ID']],
            'ClientSectionBase': [0x40, ['pointer64', ['void']]],
            'ServerSectionBase': [0x48, ['pointer64', ['void']]],
            'PortContext': [0x50, ['pointer64', ['void']]],
            'ClientThread': [0x58, ['pointer64', ['_ETHREAD']]],
            'SecurityQos': [0x60, ['_SECURITY_QUALITY_OF_SERVICE']],
            'StaticSecurity': [0x70, ['_SECURITY_CLIENT_CONTEXT']],
            'LpcReplyChainHead': [0xB8, ['_LIST_ENTRY']],
            'LpcDataInfoChainHead': [0xC8, ['_LIST_ENTRY']],
            'ServerProcess': [0xD8, ['pointer64', ['_EPROCESS']]],
            'MappingProcess': [0xD8, ['pointer64', ['_EPROCESS']]],
            'MaxMessageLength': [0xE0, ['unsigned short']],
            'MaxConnectionInfoLength': [0xE2, ['unsigned short']],
            'Flags': [0xE4, ['unsigned long']],
            'WaitEvent': [0xE8, ['_KEVENT']],
        },
    ],
    '_ARBITER_LIST_ENTRY': [
        0x60,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'AlternativeCount': [0x10, ['unsigned long']],
            'Alternatives': [0x18, ['pointer64', ['_IO_RESOURCE_DESCRIPTOR']]],
            'PhysicalDeviceObject': [0x20, ['pointer64', ['_DEVICE_OBJECT']]],
            'RequestSource': [
                0x28,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ArbiterRequestLegacyReported',
                            1: 'ArbiterRequestHalReported',
                            2: 'ArbiterRequestLegacyAssigned',
                            3: 'ArbiterRequestPnpDetected',
                            4: 'ArbiterRequestPnpEnumerated',
                            -1: 'ArbiterRequestUndefined',
                        },
                    ),
                ],
            ],
            'Flags': [0x2C, ['unsigned long']],
            'WorkSpace': [0x30, ['long long']],
            'InterfaceType': [
                0x38,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Internal',
                            1: 'Isa',
                            2: 'Eisa',
                            3: 'MicroChannel',
                            4: 'TurboChannel',
                            5: 'PCIBus',
                            6: 'VMEBus',
                            7: 'NuBus',
                            8: 'PCMCIABus',
                            9: 'CBus',
                            10: 'MPIBus',
                            11: 'MPSABus',
                            12: 'ProcessorInternal',
                            13: 'InternalPowerBus',
                            14: 'PNPISABus',
                            15: 'PNPBus',
                            16: 'Vmcs',
                            17: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'SlotNumber': [0x3C, ['unsigned long']],
            'BusNumber': [0x40, ['unsigned long']],
            'Assignment': [
                0x48,
                ['pointer64', ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
            'SelectedAlternative': [
                0x50,
                ['pointer64', ['_IO_RESOURCE_DESCRIPTOR']],
            ],
            'Result': [
                0x58,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ArbiterResultSuccess',
                            1: 'ArbiterResultExternalConflict',
                            2: 'ArbiterResultNullRequest',
                            -1: 'ArbiterResultUndefined',
                        },
                    ),
                ],
            ],
        },
    ],
    '_ETW_PROVIDER_TRAITS': [
        0x20,
        {
            'Node': [0x0, ['_RTL_BALANCED_NODE']],
            'ReferenceCount': [0x18, ['unsigned long']],
            'Traits': [0x1C, ['array', 1, ['unsigned char']]],
        },
    ],
    '_POP_DEVICE_SYS_STATE': [
        0x2F8,
        {
            'IrpMinor': [0x0, ['unsigned char']],
            'SystemState': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'SpinLock': [0x8, ['unsigned long long']],
            'Thread': [0x10, ['pointer64', ['_KTHREAD']]],
            'AbortEvent': [0x18, ['pointer64', ['_KEVENT']]],
            'ReadySemaphore': [0x20, ['pointer64', ['_KSEMAPHORE']]],
            'FinishedSemaphore': [0x28, ['pointer64', ['_KSEMAPHORE']]],
            'GetNewDeviceList': [0x30, ['unsigned char']],
            'Order': [0x38, ['_PO_DEVICE_NOTIFY_ORDER']],
            'Pending': [0x2D0, ['_LIST_ENTRY']],
            'Status': [0x2E0, ['long']],
            'FailedDevice': [0x2E8, ['pointer64', ['_DEVICE_OBJECT']]],
            'Waking': [0x2F0, ['unsigned char']],
            'Cancelled': [0x2F1, ['unsigned char']],
            'IgnoreErrors': [0x2F2, ['unsigned char']],
            'IgnoreNotImplemented': [0x2F3, ['unsigned char']],
            'TimeRefreshLockAcquired': [0x2F4, ['unsigned char']],
        },
    ],
    '_SEGMENT_FLAGS': [
        0x4,
        {
            'TotalNumberOfPtes4132': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'ExtraSharedWowSubsections': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'LargePages': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'WatchProto': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'DebugSymbolsLoaded': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteCombined': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'NoCache': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'FloppyMedia': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultProtectionMask': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'Binary32': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'ContainsDebug': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_VF_KE_CRITICAL_REGION_TRACE': [
        0x40,
        {
            'Thread': [0x0, ['pointer64', ['_ETHREAD']]],
            'StackTrace': [0x8, ['array', 7, ['pointer64', ['void']]]],
        },
    ],
    '_DIAGNOSTIC_BUFFER': [
        0x28,
        {
            'Size': [0x0, ['unsigned long long']],
            'CallerType': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KernelRequester',
                            1: 'UserProcessRequester',
                            2: 'UserSharedServiceRequester',
                        },
                    ),
                ],
            ],
            'ProcessImageNameOffset': [0x10, ['unsigned long long']],
            'ProcessId': [0x18, ['unsigned long']],
            'ServiceTag': [0x1C, ['unsigned long']],
            'DeviceDescriptionOffset': [0x10, ['unsigned long long']],
            'DevicePathOffset': [0x18, ['unsigned long long']],
            'ReasonOffset': [0x20, ['unsigned long long']],
        },
    ],
    '_EX_WORK_QUEUE': [
        0x58,
        {
            'WorkerQueue': [0x0, ['_KQUEUE']],
            'DynamicThreadCount': [0x40, ['unsigned long']],
            'WorkItemsProcessed': [0x44, ['unsigned long']],
            'WorkItemsProcessedLastPass': [0x48, ['unsigned long']],
            'QueueDepthLastPass': [0x4C, ['unsigned long']],
            'Info': [0x50, ['EX_QUEUE_WORKER_INFO']],
        },
    ],
    '_CLIENT_ID32': [
        0x8,
        {
            'UniqueProcess': [0x0, ['unsigned long']],
            'UniqueThread': [0x4, ['unsigned long']],
        },
    ],
    '_TEB32': [
        0xFE4,
        {
            'NtTib': [0x0, ['_NT_TIB32']],
            'EnvironmentPointer': [0x1C, ['unsigned long']],
            'ClientId': [0x20, ['_CLIENT_ID32']],
            'ActiveRpcHandle': [0x28, ['unsigned long']],
            'ThreadLocalStoragePointer': [0x2C, ['unsigned long']],
            'ProcessEnvironmentBlock': [0x30, ['unsigned long']],
            'LastErrorValue': [0x34, ['unsigned long']],
            'CountOfOwnedCriticalSections': [0x38, ['unsigned long']],
            'CsrClientThread': [0x3C, ['unsigned long']],
            'Win32ThreadInfo': [0x40, ['unsigned long']],
            'User32Reserved': [0x44, ['array', 26, ['unsigned long']]],
            'UserReserved': [0xAC, ['array', 5, ['unsigned long']]],
            'WOW32Reserved': [0xC0, ['unsigned long']],
            'CurrentLocale': [0xC4, ['unsigned long']],
            'FpSoftwareStatusRegister': [0xC8, ['unsigned long']],
            'SystemReserved1': [0xCC, ['array', 54, ['unsigned long']]],
            'ExceptionCode': [0x1A4, ['long']],
            'ActivationContextStackPointer': [0x1A8, ['unsigned long']],
            'SpareBytes': [0x1AC, ['array', 36, ['unsigned char']]],
            'TxFsContext': [0x1D0, ['unsigned long']],
            'GdiTebBatch': [0x1D4, ['_GDI_TEB_BATCH32']],
            'RealClientId': [0x6B4, ['_CLIENT_ID32']],
            'GdiCachedProcessHandle': [0x6BC, ['unsigned long']],
            'GdiClientPID': [0x6C0, ['unsigned long']],
            'GdiClientTID': [0x6C4, ['unsigned long']],
            'GdiThreadLocalInfo': [0x6C8, ['unsigned long']],
            'Win32ClientInfo': [0x6CC, ['array', 62, ['unsigned long']]],
            'glDispatchTable': [0x7C4, ['array', 233, ['unsigned long']]],
            'glReserved1': [0xB68, ['array', 29, ['unsigned long']]],
            'glReserved2': [0xBDC, ['unsigned long']],
            'glSectionInfo': [0xBE0, ['unsigned long']],
            'glSection': [0xBE4, ['unsigned long']],
            'glTable': [0xBE8, ['unsigned long']],
            'glCurrentRC': [0xBEC, ['unsigned long']],
            'glContext': [0xBF0, ['unsigned long']],
            'LastStatusValue': [0xBF4, ['unsigned long']],
            'StaticUnicodeString': [0xBF8, ['_STRING32']],
            'StaticUnicodeBuffer': [0xC00, ['array', 261, ['wchar']]],
            'DeallocationStack': [0xE0C, ['unsigned long']],
            'TlsSlots': [0xE10, ['array', 64, ['unsigned long']]],
            'TlsLinks': [0xF10, ['LIST_ENTRY32']],
            'Vdm': [0xF18, ['unsigned long']],
            'ReservedForNtRpc': [0xF1C, ['unsigned long']],
            'DbgSsReserved': [0xF20, ['array', 2, ['unsigned long']]],
            'HardErrorMode': [0xF28, ['unsigned long']],
            'Instrumentation': [0xF2C, ['array', 9, ['unsigned long']]],
            'ActivityId': [0xF50, ['_GUID']],
            'SubProcessTag': [0xF60, ['unsigned long']],
            'EtwLocalData': [0xF64, ['unsigned long']],
            'EtwTraceData': [0xF68, ['unsigned long']],
            'WinSockData': [0xF6C, ['unsigned long']],
            'GdiBatchCount': [0xF70, ['unsigned long']],
            'CurrentIdealProcessor': [0xF74, ['_PROCESSOR_NUMBER']],
            'IdealProcessorValue': [0xF74, ['unsigned long']],
            'ReservedPad0': [0xF74, ['unsigned char']],
            'ReservedPad1': [0xF75, ['unsigned char']],
            'ReservedPad2': [0xF76, ['unsigned char']],
            'IdealProcessor': [0xF77, ['unsigned char']],
            'GuaranteedStackBytes': [0xF78, ['unsigned long']],
            'ReservedForPerf': [0xF7C, ['unsigned long']],
            'ReservedForOle': [0xF80, ['unsigned long']],
            'WaitingOnLoaderLock': [0xF84, ['unsigned long']],
            'SavedPriorityState': [0xF88, ['unsigned long']],
            'SoftPatchPtr1': [0xF8C, ['unsigned long']],
            'ThreadPoolData': [0xF90, ['unsigned long']],
            'TlsExpansionSlots': [0xF94, ['unsigned long']],
            'MuiGeneration': [0xF98, ['unsigned long']],
            'IsImpersonating': [0xF9C, ['unsigned long']],
            'NlsCache': [0xFA0, ['unsigned long']],
            'pShimData': [0xFA4, ['unsigned long']],
            'HeapVirtualAffinity': [0xFA8, ['unsigned long']],
            'CurrentTransactionHandle': [0xFAC, ['unsigned long']],
            'ActiveFrame': [0xFB0, ['unsigned long']],
            'FlsData': [0xFB4, ['unsigned long']],
            'PreferredLanguages': [0xFB8, ['unsigned long']],
            'UserPrefLanguages': [0xFBC, ['unsigned long']],
            'MergedPrefLanguages': [0xFC0, ['unsigned long']],
            'MuiImpersonation': [0xFC4, ['unsigned long']],
            'CrossTebFlags': [0xFC8, ['unsigned short']],
            'SpareCrossTebBits': [
                0xFC8,
                [
                    'BitField',
                    dict(
                        start_bit=0, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'SameTebFlags': [0xFCA, ['unsigned short']],
            'SafeThunkCall': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'InDebugPrint': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'HasFiberData': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'SkipThreadAttach': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'WerInShipAssertCode': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'RanProcessInit': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'ClonedThread': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'SuppressDebugMsg': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'DisableUserStackWalk': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned short'),
                ],
            ],
            'RtlExceptionAttached': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=9, end_bit=10, native_type='unsigned short'
                    ),
                ],
            ],
            'InitialThread': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned short'
                    ),
                ],
            ],
            'SpareSameTebBits': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0xFCC, ['unsigned long']],
            'TxnScopeExitCallback': [0xFD0, ['unsigned long']],
            'TxnScopeContext': [0xFD4, ['unsigned long']],
            'LockCount': [0xFD8, ['unsigned long']],
            'SpareUlong0': [0xFDC, ['unsigned long']],
            'ResourceRetValue': [0xFE0, ['unsigned long']],
        },
    ],
    '_CM_KEY_INDEX': [
        0x8,
        {
            'Signature': [0x0, ['unsigned short']],
            'Count': [0x2, ['unsigned short']],
            'List': [0x4, ['array', 1, ['unsigned long']]],
        },
    ],
    '_VI_DEADLOCK_THREAD': [
        0x38,
        {
            'Thread': [0x0, ['pointer64', ['_KTHREAD']]],
            'CurrentSpinNode': [0x8, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            'CurrentOtherNode': [0x10, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            'ListEntry': [0x18, ['_LIST_ENTRY']],
            'FreeListEntry': [0x18, ['_LIST_ENTRY']],
            'NodeCount': [0x28, ['unsigned long']],
            'PagingCount': [0x2C, ['unsigned long']],
            'ThreadUsesEresources': [0x30, ['unsigned char']],
        },
    ],
    '_PPM_IDLE_STATE': [
        0x60,
        {
            'DomainMembers': [0x0, ['_KAFFINITY_EX']],
            'IdleCheck': [0x28, ['pointer64', ['void']]],
            'IdleHandler': [0x30, ['pointer64', ['void']]],
            'HvConfig': [0x38, ['unsigned long long']],
            'Context': [0x40, ['pointer64', ['void']]],
            'Latency': [0x48, ['unsigned long']],
            'Power': [0x4C, ['unsigned long']],
            'TimeCheck': [0x50, ['unsigned long']],
            'StateFlags': [0x54, ['unsigned long']],
            'PromotePercent': [0x58, ['unsigned char']],
            'DemotePercent': [0x59, ['unsigned char']],
            'PromotePercentBase': [0x5A, ['unsigned char']],
            'DemotePercentBase': [0x5B, ['unsigned char']],
            'StateType': [0x5C, ['unsigned char']],
        },
    ],
    '_KRESOURCEMANAGER': [
        0x250,
        {
            'NotificationAvailable': [0x0, ['_KEVENT']],
            'cookie': [0x18, ['unsigned long']],
            'State': [
                0x1C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KResourceManagerUninitialized',
                            1: 'KResourceManagerOffline',
                            2: 'KResourceManagerOnline',
                        },
                    ),
                ],
            ],
            'Flags': [0x20, ['unsigned long']],
            'Mutex': [0x28, ['_KMUTANT']],
            'NamespaceLink': [0x60, ['_KTMOBJECT_NAMESPACE_LINK']],
            'RmId': [0x88, ['_GUID']],
            'NotificationQueue': [0x98, ['_KQUEUE']],
            'NotificationMutex': [0xD8, ['_KMUTANT']],
            'EnlistmentHead': [0x110, ['_LIST_ENTRY']],
            'EnlistmentCount': [0x120, ['unsigned long']],
            'NotificationRoutine': [0x128, ['pointer64', ['void']]],
            'Key': [0x130, ['pointer64', ['void']]],
            'ProtocolListHead': [0x138, ['_LIST_ENTRY']],
            'PendingPropReqListHead': [0x148, ['_LIST_ENTRY']],
            'CRMListEntry': [0x158, ['_LIST_ENTRY']],
            'Tm': [0x168, ['pointer64', ['_KTM']]],
            'Description': [0x170, ['_UNICODE_STRING']],
            'Enlistments': [0x180, ['_KTMOBJECT_NAMESPACE']],
            'CompletionBinding': [
                0x228,
                ['_KRESOURCEMANAGER_COMPLETION_BINDING'],
            ],
        },
    ],
    '_GDI_TEB_BATCH64': [
        0x4E8,
        {
            'Offset': [0x0, ['unsigned long']],
            'HDC': [0x8, ['unsigned long long']],
            'Buffer': [0x10, ['array', 310, ['unsigned long']]],
        },
    ],
    '__unnamed_2318': [
        0x4,
        {
            'NodeSize': [0x0, ['unsigned long']],
            'UseLookaside': [0x0, ['unsigned long']],
        },
    ],
    '_VF_AVL_TREE': [
        0x40,
        {
            'Lock': [0x0, ['long']],
            'NodeToFree': [0x8, ['pointer64', ['void']]],
            'NodeRangeSize': [0x10, ['unsigned long long']],
            'NodeCount': [0x18, ['unsigned long long']],
            'Tables': [0x20, ['pointer64', ['_VF_AVL_TABLE']]],
            'TablesNo': [0x28, ['unsigned long']],
            'u1': [0x2C, ['__unnamed_2318']],
        },
    ],
    '_FILE_NETWORK_OPEN_INFORMATION': [
        0x38,
        {
            'CreationTime': [0x0, ['_LARGE_INTEGER']],
            'LastAccessTime': [0x8, ['_LARGE_INTEGER']],
            'LastWriteTime': [0x10, ['_LARGE_INTEGER']],
            'ChangeTime': [0x18, ['_LARGE_INTEGER']],
            'AllocationSize': [0x20, ['_LARGE_INTEGER']],
            'EndOfFile': [0x28, ['_LARGE_INTEGER']],
            'FileAttributes': [0x30, ['unsigned long']],
        },
    ],
    '_WHEA_MEMORY_ERROR_SECTION_VALIDBITS': [
        0x8,
        {
            'ErrorStatus': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PhysicalAddress': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PhysicalAddressMask': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Node': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Card': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Module': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=6,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Bank': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=6,
                        end_bit=7,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Device': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=7,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Row': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=9,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Column': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'BitPosition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'RequesterId': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ResponderId': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=13,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'TargetId': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13,
                        end_bit=14,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ErrorType': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14,
                        end_bit=15,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ValidBits': [0x0, ['unsigned long long']],
        },
    ],
    '_RELATION_LIST_ENTRY': [
        0x10,
        {
            'Count': [0x0, ['unsigned long']],
            'MaxCount': [0x4, ['unsigned long']],
            'Devices': [0x8, ['array', 1, ['pointer64', ['_DEVICE_OBJECT']]]],
        },
    ],
    '_HEAP_FREE_ENTRY_EXTRA': [
        0x4,
        {
            'TagIndex': [0x0, ['unsigned short']],
            'FreeBackTraceIndex': [0x2, ['unsigned short']],
        },
    ],
    '_VI_DEADLOCK_GLOBALS': [
        0x8168,
        {
            'TimeAcquire': [0x0, ['long long']],
            'TimeRelease': [0x8, ['long long']],
            'ResourceDatabase': [0x10, ['pointer64', ['_LIST_ENTRY']]],
            'ResourceDatabaseCount': [0x18, ['unsigned long long']],
            'ResourceAddressRange': [
                0x20,
                ['array', 1023, ['_VF_ADDRESS_RANGE']],
            ],
            'ThreadDatabase': [0x4010, ['pointer64', ['_LIST_ENTRY']]],
            'ThreadDatabaseCount': [0x4018, ['unsigned long long']],
            'ThreadAddressRange': [
                0x4020,
                ['array', 1023, ['_VF_ADDRESS_RANGE']],
            ],
            'AllocationFailures': [0x8010, ['unsigned long']],
            'NodesTrimmedBasedOnAge': [0x8014, ['unsigned long']],
            'NodesTrimmedBasedOnCount': [0x8018, ['unsigned long']],
            'NodesSearched': [0x801C, ['unsigned long']],
            'MaxNodesSearched': [0x8020, ['unsigned long']],
            'SequenceNumber': [0x8024, ['unsigned long']],
            'RecursionDepthLimit': [0x8028, ['unsigned long']],
            'SearchedNodesLimit': [0x802C, ['unsigned long']],
            'DepthLimitHits': [0x8030, ['unsigned long']],
            'SearchLimitHits': [0x8034, ['unsigned long']],
            'ABC_ACB_Skipped': [0x8038, ['unsigned long']],
            'OutOfOrderReleases': [0x803C, ['unsigned long']],
            'NodesReleasedOutOfOrder': [0x8040, ['unsigned long']],
            'TotalReleases': [0x8044, ['unsigned long']],
            'RootNodesDeleted': [0x8048, ['unsigned long']],
            'ForgetHistoryCounter': [0x804C, ['unsigned long']],
            'Instigator': [0x8050, ['pointer64', ['void']]],
            'NumberOfParticipants': [0x8058, ['unsigned long']],
            'Participant': [
                0x8060,
                ['array', 32, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            ],
            'ChildrenCountWatermark': [0x8160, ['long']],
        },
    ],
    '_KTM': [
        0x3C0,
        {
            'cookie': [0x0, ['unsigned long']],
            'Mutex': [0x8, ['_KMUTANT']],
            'State': [
                0x40,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KKtmUninitialized',
                            1: 'KKtmInitialized',
                            2: 'KKtmRecovering',
                            3: 'KKtmOnline',
                            4: 'KKtmRecoveryFailed',
                            5: 'KKtmOffline',
                        },
                    ),
                ],
            ],
            'NamespaceLink': [0x48, ['_KTMOBJECT_NAMESPACE_LINK']],
            'TmIdentity': [0x70, ['_GUID']],
            'Flags': [0x80, ['unsigned long']],
            'VolatileFlags': [0x84, ['unsigned long']],
            'LogFileName': [0x88, ['_UNICODE_STRING']],
            'LogFileObject': [0x98, ['pointer64', ['_FILE_OBJECT']]],
            'MarshallingContext': [0xA0, ['pointer64', ['void']]],
            'LogManagementContext': [0xA8, ['pointer64', ['void']]],
            'Transactions': [0xB0, ['_KTMOBJECT_NAMESPACE']],
            'ResourceManagers': [0x158, ['_KTMOBJECT_NAMESPACE']],
            'LsnOrderedMutex': [0x200, ['_KMUTANT']],
            'LsnOrderedList': [0x238, ['_LIST_ENTRY']],
            'CommitVirtualClock': [0x248, ['_LARGE_INTEGER']],
            'CommitVirtualClockMutex': [0x250, ['_FAST_MUTEX']],
            'BaseLsn': [0x288, ['_CLS_LSN']],
            'CurrentReadLsn': [0x290, ['_CLS_LSN']],
            'LastRecoveredLsn': [0x298, ['_CLS_LSN']],
            'TmRmHandle': [0x2A0, ['pointer64', ['void']]],
            'TmRm': [0x2A8, ['pointer64', ['_KRESOURCEMANAGER']]],
            'LogFullNotifyEvent': [0x2B0, ['_KEVENT']],
            'CheckpointWorkItem': [0x2C8, ['_WORK_QUEUE_ITEM']],
            'CheckpointTargetLsn': [0x2E8, ['_CLS_LSN']],
            'LogFullCompletedWorkItem': [0x2F0, ['_WORK_QUEUE_ITEM']],
            'LogWriteResource': [0x310, ['_ERESOURCE']],
            'LogFlags': [0x378, ['unsigned long']],
            'LogFullStatus': [0x37C, ['long']],
            'RecoveryStatus': [0x380, ['long']],
            'LastCheckBaseLsn': [0x388, ['_CLS_LSN']],
            'RestartOrderedList': [0x390, ['_LIST_ENTRY']],
            'OfflineWorkItem': [0x3A0, ['_WORK_QUEUE_ITEM']],
        },
    ],
    '_CONFIGURATION_COMPONENT': [
        0x28,
        {
            'Class': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'SystemClass',
                            1: 'ProcessorClass',
                            2: 'CacheClass',
                            3: 'AdapterClass',
                            4: 'ControllerClass',
                            5: 'PeripheralClass',
                            6: 'MemoryClass',
                            7: 'MaximumClass',
                        },
                    ),
                ],
            ],
            'Type': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ArcSystem',
                            1: 'CentralProcessor',
                            2: 'FloatingPointProcessor',
                            3: 'PrimaryIcache',
                            4: 'PrimaryDcache',
                            5: 'SecondaryIcache',
                            6: 'SecondaryDcache',
                            7: 'SecondaryCache',
                            8: 'EisaAdapter',
                            9: 'TcAdapter',
                            10: 'ScsiAdapter',
                            11: 'DtiAdapter',
                            12: 'MultiFunctionAdapter',
                            13: 'DiskController',
                            14: 'TapeController',
                            15: 'CdromController',
                            16: 'WormController',
                            17: 'SerialController',
                            18: 'NetworkController',
                            19: 'DisplayController',
                            20: 'ParallelController',
                            21: 'PointerController',
                            22: 'KeyboardController',
                            23: 'AudioController',
                            24: 'OtherController',
                            25: 'DiskPeripheral',
                            26: 'FloppyDiskPeripheral',
                            27: 'TapePeripheral',
                            28: 'ModemPeripheral',
                            29: 'MonitorPeripheral',
                            30: 'PrinterPeripheral',
                            31: 'PointerPeripheral',
                            32: 'KeyboardPeripheral',
                            33: 'TerminalPeripheral',
                            34: 'OtherPeripheral',
                            35: 'LinePeripheral',
                            36: 'NetworkPeripheral',
                            37: 'SystemMemory',
                            38: 'DockingInformation',
                            39: 'RealModeIrqRoutingTable',
                            40: 'RealModePCIEnumeration',
                            41: 'MaximumType',
                        },
                    ),
                ],
            ],
            'Flags': [0x8, ['_DEVICE_FLAGS']],
            'Version': [0xC, ['unsigned short']],
            'Revision': [0xE, ['unsigned short']],
            'Key': [0x10, ['unsigned long']],
            'AffinityMask': [0x14, ['unsigned long']],
            'Group': [0x14, ['unsigned short']],
            'GroupIndex': [0x16, ['unsigned short']],
            'ConfigurationDataLength': [0x18, ['unsigned long']],
            'IdentifierLength': [0x1C, ['unsigned long']],
            'Identifier': [0x20, ['pointer64', ['unsigned char']]],
        },
    ],
    '_KTRANSACTION': [
        0x2D8,
        {
            'OutcomeEvent': [0x0, ['_KEVENT']],
            'cookie': [0x18, ['unsigned long']],
            'Mutex': [0x20, ['_KMUTANT']],
            'TreeTx': [0x58, ['pointer64', ['_KTRANSACTION']]],
            'GlobalNamespaceLink': [0x60, ['_KTMOBJECT_NAMESPACE_LINK']],
            'TmNamespaceLink': [0x88, ['_KTMOBJECT_NAMESPACE_LINK']],
            'UOW': [0xB0, ['_GUID']],
            'State': [
                0xC0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KTransactionUninitialized',
                            1: 'KTransactionActive',
                            2: 'KTransactionPreparing',
                            3: 'KTransactionPrepared',
                            4: 'KTransactionInDoubt',
                            5: 'KTransactionCommitted',
                            6: 'KTransactionAborted',
                            7: 'KTransactionDelegated',
                            8: 'KTransactionPrePreparing',
                            9: 'KTransactionForgotten',
                            10: 'KTransactionRecovering',
                            11: 'KTransactionPrePrepared',
                        },
                    ),
                ],
            ],
            'Flags': [0xC4, ['unsigned long']],
            'EnlistmentHead': [0xC8, ['_LIST_ENTRY']],
            'EnlistmentCount': [0xD8, ['unsigned long']],
            'RecoverableEnlistmentCount': [0xDC, ['unsigned long']],
            'PrePrepareRequiredEnlistmentCount': [0xE0, ['unsigned long']],
            'PrepareRequiredEnlistmentCount': [0xE4, ['unsigned long']],
            'OutcomeRequiredEnlistmentCount': [0xE8, ['unsigned long']],
            'PendingResponses': [0xEC, ['unsigned long']],
            'SuperiorEnlistment': [0xF0, ['pointer64', ['_KENLISTMENT']]],
            'LastLsn': [0xF8, ['_CLS_LSN']],
            'PromotedEntry': [0x100, ['_LIST_ENTRY']],
            'PromoterTransaction': [0x110, ['pointer64', ['_KTRANSACTION']]],
            'PromotePropagation': [0x118, ['pointer64', ['void']]],
            'IsolationLevel': [0x120, ['unsigned long']],
            'IsolationFlags': [0x124, ['unsigned long']],
            'Timeout': [0x128, ['_LARGE_INTEGER']],
            'Description': [0x130, ['_UNICODE_STRING']],
            'RollbackThread': [0x140, ['pointer64', ['_KTHREAD']]],
            'RollbackWorkItem': [0x148, ['_WORK_QUEUE_ITEM']],
            'RollbackDpc': [0x168, ['_KDPC']],
            'RollbackTimer': [0x1A8, ['_KTIMER']],
            'LsnOrderedEntry': [0x1E8, ['_LIST_ENTRY']],
            'Outcome': [
                0x1F8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'KTxOutcomeUninitialized',
                            1: 'KTxOutcomeUndetermined',
                            2: 'KTxOutcomeCommitted',
                            3: 'KTxOutcomeAborted',
                            4: 'KTxOutcomeUnavailable',
                        },
                    ),
                ],
            ],
            'Tm': [0x200, ['pointer64', ['_KTM']]],
            'CommitReservation': [0x208, ['long long']],
            'TransactionHistory': [
                0x210,
                ['array', 10, ['_KTRANSACTION_HISTORY']],
            ],
            'TransactionHistoryCount': [0x260, ['unsigned long']],
            'DTCPrivateInformation': [0x268, ['pointer64', ['void']]],
            'DTCPrivateInformationLength': [0x270, ['unsigned long']],
            'DTCPrivateInformationMutex': [0x278, ['_KMUTANT']],
            'PromotedTxSelfHandle': [0x2B0, ['pointer64', ['void']]],
            'PendingPromotionCount': [0x2B8, ['unsigned long']],
            'PromotionCompletedEvent': [0x2C0, ['_KEVENT']],
        },
    ],
    '_PRIVATE_CACHE_MAP_FLAGS': [
        0x4,
        {
            'DontUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'ReadAheadActive': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'ReadAheadEnabled': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'PagePriority': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'Available': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_CM_KCB_UOW': [
        0x60,
        {
            'TransactionListEntry': [0x0, ['_LIST_ENTRY']],
            'KCBLock': [0x10, ['pointer64', ['_CM_INTENT_LOCK']]],
            'KeyLock': [0x18, ['pointer64', ['_CM_INTENT_LOCK']]],
            'KCBListEntry': [0x20, ['_LIST_ENTRY']],
            'KeyControlBlock': [
                0x30,
                ['pointer64', ['_CM_KEY_CONTROL_BLOCK']],
            ],
            'Transaction': [0x38, ['pointer64', ['_CM_TRANS']]],
            'UoWState': [0x40, ['unsigned long']],
            'ActionType': [
                0x44,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'UoWAddThisKey',
                            1: 'UoWAddChildKey',
                            2: 'UoWDeleteThisKey',
                            3: 'UoWDeleteChildKey',
                            4: 'UoWSetValueNew',
                            5: 'UoWSetValueExisting',
                            6: 'UoWDeleteValue',
                            7: 'UoWSetKeyUserFlags',
                            8: 'UoWSetLastWriteTime',
                            9: 'UoWSetSecurityDescriptor',
                            10: 'UoWRenameSubKey',
                            11: 'UoWRenameOldSubKey',
                            12: 'UoWRenameNewSubKey',
                            13: 'UoWIsolation',
                            14: 'UoWInvalid',
                        },
                    ),
                ],
            ],
            'StorageType': [
                0x48,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Stable',
                            1: 'Volatile',
                            2: 'InvalidStorage',
                        },
                    ),
                ],
            ],
            'ChildKCB': [0x50, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'VolatileKeyCell': [0x50, ['unsigned long']],
            'OldValueCell': [0x50, ['unsigned long']],
            'NewValueCell': [0x54, ['unsigned long']],
            'UserFlags': [0x50, ['unsigned long']],
            'LastWriteTime': [0x50, ['_LARGE_INTEGER']],
            'TxSecurityCell': [0x50, ['unsigned long']],
            'OldChildKCB': [0x50, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'NewChildKCB': [0x58, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'OtherChildKCB': [0x50, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'ThisVolatileKeyCell': [0x58, ['unsigned long']],
        },
    ],
    '_MMPTE_TRANSITION': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Write': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Owner': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'WriteThrough': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CacheDisable': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Transition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFrameNumber': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=48,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=48,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_KREQUEST_PACKET': [
        0x20,
        {
            'CurrentPacket': [0x0, ['array', 3, ['pointer64', ['void']]]],
            'WorkerRoutine': [0x18, ['pointer64', ['void']]],
        },
    ],
    '_VF_WATCHDOG_IRP': [
        0x20,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Irp': [0x10, ['pointer64', ['_IRP']]],
            'DueTickCount': [0x18, ['unsigned long']],
            'Inserted': [0x1C, ['unsigned char']],
            'TrackedStackLocation': [0x1D, ['unsigned char']],
            'CancelTimeoutTicks': [0x1E, ['unsigned short']],
        },
    ],
    '_flags': [
        0x1,
        {
            'Removable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'GroupAssigned': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'GroupCommitted': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'GroupAssignmentFixed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Fill': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '__unnamed_2367': [
        0x8,
        {
            'Head': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=24,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Tail': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24,
                        end_bit=48,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ActiveThreadCount': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=48,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '__unnamed_2369': [
        0x8,
        {
            's1': [0x0, ['__unnamed_2367']],
            'Value': [0x0, ['unsigned long long']],
        },
    ],
    '_ALPC_COMPLETION_LIST_STATE': [
        0x8,
        {
            'u1': [0x0, ['__unnamed_2369']],
        },
    ],
    '_PSP_CPU_SHARE_CAPTURED_WEIGHT_DATA': [
        0x8,
        {
            'CapturedCpuShareWeight': [0x0, ['unsigned long']],
            'CapturedTotalWeight': [0x4, ['unsigned long']],
            'CombinedData': [0x0, ['long long']],
        },
    ],
    '_CM_NAME_HASH': [
        0x18,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x8, ['pointer64', ['_CM_NAME_HASH']]],
            'NameLength': [0x10, ['unsigned short']],
            'Name': [0x12, ['array', 1, ['wchar']]],
        },
    ],
    '_PROC_IDLE_STATE_BUCKET': [
        0x20,
        {
            'TotalTime': [0x0, ['unsigned long long']],
            'MinTime': [0x8, ['unsigned long long']],
            'MaxTime': [0x10, ['unsigned long long']],
            'Count': [0x18, ['unsigned long']],
        },
    ],
    '_MMSECURE_FLAGS': [
        0x4,
        {
            'ReadOnly': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoWrite': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=12, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_PO_IRP_QUEUE': [
        0x10,
        {
            'CurrentIrp': [0x0, ['pointer64', ['_IRP']]],
            'PendingIrpList': [0x8, ['pointer64', ['_IRP']]],
        },
    ],
    '__unnamed_237c': [
        0x4,
        {
            'Active': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'OnlyTryAcquireUsed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ReleasedOutOfOrder': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'SequenceNumber': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'Whole': [0x0, ['unsigned long']],
        },
    ],
    '_VI_DEADLOCK_NODE': [
        0xD0,
        {
            'Parent': [0x0, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            'ChildrenList': [0x8, ['_LIST_ENTRY']],
            'SiblingsList': [0x18, ['_LIST_ENTRY']],
            'ResourceList': [0x28, ['_LIST_ENTRY']],
            'FreeListEntry': [0x28, ['_LIST_ENTRY']],
            'Root': [0x38, ['pointer64', ['_VI_DEADLOCK_RESOURCE']]],
            'ThreadEntry': [0x40, ['pointer64', ['_VI_DEADLOCK_THREAD']]],
            'u1': [0x48, ['__unnamed_237c']],
            'ChildrenCount': [0x4C, ['long']],
            'StackTrace': [0x50, ['array', 8, ['pointer64', ['void']]]],
            'ParentStackTrace': [0x90, ['array', 8, ['pointer64', ['void']]]],
        },
    ],
    'PROCESSOR_IDLESTATE_INFO': [
        0x8,
        {
            'TimeCheck': [0x0, ['unsigned long']],
            'DemotePercent': [0x4, ['unsigned char']],
            'PromotePercent': [0x5, ['unsigned char']],
            'Spare': [0x6, ['array', 2, ['unsigned char']]],
        },
    ],
    '_KTMOBJECT_NAMESPACE': [
        0xA8,
        {
            'Table': [0x0, ['_RTL_AVL_TABLE']],
            'Mutex': [0x68, ['_KMUTANT']],
            'LinksOffset': [0xA0, ['unsigned short']],
            'GuidOffset': [0xA2, ['unsigned short']],
            'Expired': [0xA4, ['unsigned char']],
        },
    ],
    '_LPCP_PORT_QUEUE': [
        0x20,
        {
            'NonPagedPortQueue': [
                0x0,
                ['pointer64', ['_LPCP_NONPAGED_PORT_QUEUE']],
            ],
            'Semaphore': [0x8, ['pointer64', ['_KSEMAPHORE']]],
            'ReceiveHead': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_CM_KEY_REFERENCE': [
        0x10,
        {
            'KeyCell': [0x0, ['unsigned long']],
            'KeyHive': [0x8, ['pointer64', ['_HHIVE']]],
        },
    ],
    'SYSTEM_POWER_LEVEL': [
        0x18,
        {
            'Enable': [0x0, ['unsigned char']],
            'Spare': [0x1, ['array', 3, ['unsigned char']]],
            'BatteryLevel': [0x4, ['unsigned long']],
            'PowerPolicy': [0x8, ['POWER_ACTION_POLICY']],
            'MinSystemState': [
                0x14,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
        },
    ],
    '_OBJECT_DUMP_CONTROL': [
        0x10,
        {
            'Stream': [0x0, ['pointer64', ['void']]],
            'Detail': [0x8, ['unsigned long']],
        },
    ],
    '_VF_ADDRESS_RANGE': [
        0x10,
        {
            'Start': [0x0, ['pointer64', ['unsigned char']]],
            'End': [0x8, ['pointer64', ['unsigned char']]],
        },
    ],
    '_OBJECT_SYMBOLIC_LINK': [
        0x20,
        {
            'CreationTime': [0x0, ['_LARGE_INTEGER']],
            'LinkTarget': [0x8, ['_UNICODE_STRING']],
            'DosDeviceDriveIndex': [0x18, ['unsigned long']],
            'Flags': [0x1C, ['unsigned long']],
        },
    ],
    '_LPCP_NONPAGED_PORT_QUEUE': [
        0x28,
        {
            'Semaphore': [0x0, ['_KSEMAPHORE']],
            'BackPointer': [0x20, ['pointer64', ['_LPCP_PORT_OBJECT']]],
        },
    ],
    '_KRESOURCEMANAGER_COMPLETION_BINDING': [
        0x28,
        {
            'NotificationListHead': [0x0, ['_LIST_ENTRY']],
            'Port': [0x10, ['pointer64', ['void']]],
            'Key': [0x18, ['unsigned long long']],
            'BindingProcess': [0x20, ['pointer64', ['_EPROCESS']]],
        },
    ],
    '_VF_TRACKER': [
        0x10,
        {
            'TrackerFlags': [0x0, ['unsigned long']],
            'TrackerSize': [0x4, ['unsigned long']],
            'TrackerIndex': [0x8, ['unsigned long']],
            'TraceDepth': [0xC, ['unsigned long']],
        },
    ],
    '_CALL_PERFORMANCE_DATA': [
        0x408,
        {
            'SpinLock': [0x0, ['unsigned long long']],
            'HashTable': [0x8, ['array', 64, ['_LIST_ENTRY']]],
        },
    ],
    '_ARBITER_ALTERNATIVE': [
        0x40,
        {
            'Minimum': [0x0, ['unsigned long long']],
            'Maximum': [0x8, ['unsigned long long']],
            'Length': [0x10, ['unsigned long long']],
            'Alignment': [0x18, ['unsigned long long']],
            'Priority': [0x20, ['long']],
            'Flags': [0x24, ['unsigned long']],
            'Descriptor': [0x28, ['pointer64', ['_IO_RESOURCE_DESCRIPTOR']]],
            'Reserved': [0x30, ['array', 3, ['unsigned long']]],
        },
    ],
    '_WHEA_ERROR_STATUS': [
        0x8,
        {
            'ErrorStatus': [0x0, ['unsigned long long']],
            'Reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ErrorType': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Address': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=17,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Control': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=17,
                        end_bit=18,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Data': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=18,
                        end_bit=19,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Responder': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=19,
                        end_bit=20,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Requester': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20,
                        end_bit=21,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'FirstError': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21,
                        end_bit=22,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Overflow': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22,
                        end_bit=23,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved2': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_WHEA_PERSISTENCE_INFO': [
        0x8,
        {
            'Signature': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Length': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Identifier': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
                        end_bit=56,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Attributes': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=56,
                        end_bit=58,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'DoNotLog': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=58,
                        end_bit=59,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=59,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'AsULONGLONG': [0x0, ['unsigned long long']],
        },
    ],
    '_MI_SECTION_IMAGE_INFORMATION': [
        0x48,
        {
            'ExportedImageInformation': [0x0, ['_SECTION_IMAGE_INFORMATION']],
            'InternalImageInformation': [
                0x40,
                ['_MI_EXTRA_IMAGE_INFORMATION'],
            ],
        },
    ],
    '_HEAP_USERDATA_HEADER': [
        0x20,
        {
            'SFreeListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'SubSegment': [0x0, ['pointer64', ['_HEAP_SUBSEGMENT']]],
            'Reserved': [0x8, ['pointer64', ['void']]],
            'SizeIndex': [0x10, ['unsigned long long']],
            'Signature': [0x18, ['unsigned long long']],
        },
    ],
    '_STRING64': [
        0x10,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x8, ['unsigned long long']],
        },
    ],
    '_STACK_TABLE': [
        0x8088,
        {
            'NumStackTraces': [0x0, ['unsigned short']],
            'TraceCapacity': [0x2, ['unsigned short']],
            'StackTrace': [
                0x8,
                ['array', 16, ['pointer64', ['_OBJECT_REF_TRACE']]],
            ],
            'StackTableHash': [0x88, ['array', 16381, ['unsigned short']]],
        },
    ],
    '_TOKEN_CONTROL': [
        0x28,
        {
            'TokenId': [0x0, ['_LUID']],
            'AuthenticationId': [0x8, ['_LUID']],
            'ModifiedId': [0x10, ['_LUID']],
            'TokenSource': [0x18, ['_TOKEN_SOURCE']],
        },
    ],
    '_DEFERRED_WRITE': [
        0x48,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteSize': [0x2, ['short']],
            'FileObject': [0x8, ['pointer64', ['_FILE_OBJECT']]],
            'BytesToWrite': [0x10, ['unsigned long']],
            'DeferredWriteLinks': [0x18, ['_LIST_ENTRY']],
            'Event': [0x28, ['pointer64', ['_KEVENT']]],
            'PostRoutine': [0x30, ['pointer64', ['void']]],
            'Context1': [0x38, ['pointer64', ['void']]],
            'Context2': [0x40, ['pointer64', ['void']]],
        },
    ],
    '_ARBITER_ORDERING_LIST': [
        0x10,
        {
            'Count': [0x0, ['unsigned short']],
            'Maximum': [0x2, ['unsigned short']],
            'Orderings': [0x8, ['pointer64', ['_ARBITER_ORDERING']]],
        },
    ],
    '_SECTION_IMAGE_INFORMATION': [
        0x40,
        {
            'TransferAddress': [0x0, ['pointer64', ['void']]],
            'ZeroBits': [0x8, ['unsigned long']],
            'MaximumStackSize': [0x10, ['unsigned long long']],
            'CommittedStackSize': [0x18, ['unsigned long long']],
            'SubSystemType': [0x20, ['unsigned long']],
            'SubSystemMinorVersion': [0x24, ['unsigned short']],
            'SubSystemMajorVersion': [0x26, ['unsigned short']],
            'SubSystemVersion': [0x24, ['unsigned long']],
            'GpValue': [0x28, ['unsigned long']],
            'ImageCharacteristics': [0x2C, ['unsigned short']],
            'DllCharacteristics': [0x2E, ['unsigned short']],
            'Machine': [0x30, ['unsigned short']],
            'ImageContainsCode': [0x32, ['unsigned char']],
            'ImageFlags': [0x33, ['unsigned char']],
            'ComPlusNativeReady': [
                0x33,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ComPlusILOnly': [
                0x33,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'ImageDynamicallyRelocated': [
                0x33,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'ImageMappedFlat': [
                0x33,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x33,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'LoaderFlags': [0x34, ['unsigned long']],
            'ImageFileSize': [0x38, ['unsigned long']],
            'CheckSum': [0x3C, ['unsigned long']],
        },
    ],
    '_VF_AVL_TABLE': [
        0x70,
        {
            'RtlTable': [0x0, ['_RTL_AVL_TABLE']],
            'ReservedNode': [0x68, ['pointer64', ['_VF_AVL_TREE_NODE']]],
        },
    ],
    '_TOKEN_AUDIT_POLICY': [
        0x1B,
        {
            'PerUserPolicy': [0x0, ['array', 27, ['unsigned char']]],
        },
    ],
    '__unnamed_23d4': [
        0x10,
        {
            'EndingOffset': [0x0, ['pointer64', ['_LARGE_INTEGER']]],
            'ResourceToRelease': [
                0x8,
                ['pointer64', ['pointer64', ['_ERESOURCE']]],
            ],
        },
    ],
    '__unnamed_23d6': [
        0x8,
        {
            'ResourceToRelease': [0x0, ['pointer64', ['_ERESOURCE']]],
        },
    ],
    '__unnamed_23da': [
        0x8,
        {
            'SyncType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'SyncTypeOther',
                            1: 'SyncTypeCreateSection',
                        },
                    ),
                ],
            ],
            'PageProtection': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_23de': [
        0x10,
        {
            'NotificationType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NotifyTypeCreate',
                            1: 'NotifyTypeRetired',
                        },
                    ),
                ],
            ],
            'SafeToRecurse': [0x8, ['unsigned char']],
        },
    ],
    '__unnamed_23e0': [
        0x28,
        {
            'Argument1': [0x0, ['pointer64', ['void']]],
            'Argument2': [0x8, ['pointer64', ['void']]],
            'Argument3': [0x10, ['pointer64', ['void']]],
            'Argument4': [0x18, ['pointer64', ['void']]],
            'Argument5': [0x20, ['pointer64', ['void']]],
        },
    ],
    '_FS_FILTER_PARAMETERS': [
        0x28,
        {
            'AcquireForModifiedPageWriter': [0x0, ['__unnamed_23d4']],
            'ReleaseForModifiedPageWriter': [0x0, ['__unnamed_23d6']],
            'AcquireForSectionSynchronization': [0x0, ['__unnamed_23da']],
            'NotifyStreamFileObject': [0x0, ['__unnamed_23de']],
            'Others': [0x0, ['__unnamed_23e0']],
        },
    ],
    '_PROFILE_PARAMETER_BLOCK': [
        0x10,
        {
            'Status': [0x0, ['unsigned short']],
            'Reserved': [0x2, ['unsigned short']],
            'DockingState': [0x4, ['unsigned short']],
            'Capabilities': [0x6, ['unsigned short']],
            'DockID': [0x8, ['unsigned long']],
            'SerialNumber': [0xC, ['unsigned long']],
        },
    ],
    '_COMPRESSED_DATA_INFO': [
        0xC,
        {
            'CompressionFormatAndEngine': [0x0, ['unsigned short']],
            'CompressionUnitShift': [0x2, ['unsigned char']],
            'ChunkShift': [0x3, ['unsigned char']],
            'ClusterShift': [0x4, ['unsigned char']],
            'Reserved': [0x5, ['unsigned char']],
            'NumberOfChunks': [0x6, ['unsigned short']],
            'CompressedChunkSizes': [0x8, ['array', 1, ['unsigned long']]],
        },
    ],
    '_POP_HIBER_CONTEXT': [
        0x110,
        {
            'WriteToFile': [0x0, ['unsigned char']],
            'ReserveLoaderMemory': [0x1, ['unsigned char']],
            'ReserveFreeMemory': [0x2, ['unsigned char']],
            'Reset': [0x3, ['unsigned char']],
            'HiberFlags': [0x4, ['unsigned char']],
            'WroteHiberFile': [0x5, ['unsigned char']],
            'MapFrozen': [0x6, ['unsigned char']],
            'MemoryMap': [0x8, ['_RTL_BITMAP']],
            'DiscardedMemoryPages': [0x18, ['_RTL_BITMAP']],
            'ClonedRanges': [0x28, ['_LIST_ENTRY']],
            'ClonedRangeCount': [0x38, ['unsigned long']],
            'NextCloneRange': [0x40, ['pointer64', ['_LIST_ENTRY']]],
            'NextPreserve': [0x48, ['unsigned long long']],
            'LoaderMdl': [0x50, ['pointer64', ['_MDL']]],
            'AllocatedMdl': [0x58, ['pointer64', ['_MDL']]],
            'PagesOut': [0x60, ['unsigned long long']],
            'IoPages': [0x68, ['pointer64', ['void']]],
            'IoPagesCount': [0x70, ['unsigned long']],
            'CurrentMcb': [0x78, ['pointer64', ['void']]],
            'DumpStack': [0x80, ['pointer64', ['_DUMP_STACK_CONTEXT']]],
            'WakeState': [0x88, ['pointer64', ['_KPROCESSOR_STATE']]],
            'PreferredIoWriteSize': [0x90, ['unsigned long']],
            'IoProgress': [0x94, ['unsigned long']],
            'HiberVa': [0x98, ['unsigned long long']],
            'HiberPte': [0xA0, ['_LARGE_INTEGER']],
            'Status': [0xA8, ['long']],
            'MemoryImage': [0xB0, ['pointer64', ['PO_MEMORY_IMAGE']]],
            'CompressionWorkspace': [0xB8, ['pointer64', ['void']]],
            'CompressedWriteBuffer': [0xC0, ['pointer64', ['unsigned char']]],
            'CompressedWriteBufferSize': [0xC8, ['unsigned long']],
            'MaxCompressedOutputSize': [0xCC, ['unsigned long']],
            'PerformanceStats': [0xD0, ['pointer64', ['unsigned long']]],
            'CompressionBlock': [0xD8, ['pointer64', ['void']]],
            'DmaIO': [0xE0, ['pointer64', ['void']]],
            'TemporaryHeap': [0xE8, ['pointer64', ['void']]],
            'BootLoaderLogMdl': [0xF0, ['pointer64', ['_MDL']]],
            'FirmwareRuntimeInformationMdl': [0xF8, ['pointer64', ['_MDL']]],
            'ResumeContext': [0x100, ['pointer64', ['void']]],
            'ResumeContextPages': [0x108, ['unsigned long']],
        },
    ],
    '_OBJECT_REF_TRACE': [
        0x80,
        {
            'StackTrace': [0x0, ['array', 16, ['pointer64', ['void']]]],
        },
    ],
    '_OBJECT_NAME_INFORMATION': [
        0x10,
        {
            'Name': [0x0, ['_UNICODE_STRING']],
        },
    ],
    '_KDESCRIPTOR': [
        0x10,
        {
            'Pad': [0x0, ['array', 3, ['unsigned short']]],
            'Limit': [0x6, ['unsigned short']],
            'Base': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_PCW_COUNTER_INFORMATION': [
        0x10,
        {
            'CounterMask': [0x0, ['unsigned long long']],
            'InstanceMask': [0x8, ['pointer64', ['_UNICODE_STRING']]],
        },
    ],
    '_DUMP_STACK_CONTEXT': [
        0x110,
        {
            'Init': [0x0, ['_DUMP_INITIALIZATION_CONTEXT']],
            'PartitionOffset': [0xA0, ['_LARGE_INTEGER']],
            'DumpPointers': [0xA8, ['pointer64', ['void']]],
            'PointersLength': [0xB0, ['unsigned long']],
            'ModulePrefix': [0xB8, ['pointer64', ['unsigned short']]],
            'DriverList': [0xC0, ['_LIST_ENTRY']],
            'InitMsg': [0xD0, ['_STRING']],
            'ProgMsg': [0xE0, ['_STRING']],
            'DoneMsg': [0xF0, ['_STRING']],
            'FileObject': [0x100, ['pointer64', ['void']]],
            'UsageType': [
                0x108,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DeviceUsageTypeUndefined',
                            1: 'DeviceUsageTypePaging',
                            2: 'DeviceUsageTypeHibernation',
                            3: 'DeviceUsageTypeDumpFile',
                        },
                    ),
                ],
            ],
        },
    ],
    '_FILE_STANDARD_INFORMATION': [
        0x18,
        {
            'AllocationSize': [0x0, ['_LARGE_INTEGER']],
            'EndOfFile': [0x8, ['_LARGE_INTEGER']],
            'NumberOfLinks': [0x10, ['unsigned long']],
            'DeletePending': [0x14, ['unsigned char']],
            'Directory': [0x15, ['unsigned char']],
        },
    ],
    '_POP_SHUTDOWN_BUG_CHECK': [
        0x40,
        {
            'ThreadHandle': [0x0, ['pointer64', ['void']]],
            'ThreadId': [0x8, ['pointer64', ['void']]],
            'ProcessId': [0x10, ['pointer64', ['void']]],
            'Code': [0x18, ['unsigned long']],
            'Parameter1': [0x20, ['unsigned long long']],
            'Parameter2': [0x28, ['unsigned long long']],
            'Parameter3': [0x30, ['unsigned long long']],
            'Parameter4': [0x38, ['unsigned long long']],
        },
    ],
    '_MI_EXTRA_IMAGE_INFORMATION': [
        0x8,
        {
            'SizeOfHeaders': [0x0, ['unsigned long']],
            'SizeOfImage': [0x4, ['unsigned long']],
        },
    ],
    '_PCW_MASK_INFORMATION': [
        0x28,
        {
            'CounterMask': [0x0, ['unsigned long long']],
            'InstanceMask': [0x8, ['pointer64', ['_UNICODE_STRING']]],
            'InstanceId': [0x10, ['unsigned long']],
            'CollectMultiple': [0x14, ['unsigned char']],
            'Buffer': [0x18, ['pointer64', ['_PCW_BUFFER']]],
            'CancelEvent': [0x20, ['pointer64', ['_KEVENT']]],
        },
    ],
    '_RTL_HANDLE_TABLE_ENTRY': [
        0x8,
        {
            'Flags': [0x0, ['unsigned long']],
            'NextFree': [0x0, ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']]],
        },
    ],
    '__unnamed_2406': [
        0x20,
        {
            'TestAllocation': [0x0, ['_ARBITER_TEST_ALLOCATION_PARAMETERS']],
            'RetestAllocation': [
                0x0,
                ['_ARBITER_RETEST_ALLOCATION_PARAMETERS'],
            ],
            'BootAllocation': [0x0, ['_ARBITER_BOOT_ALLOCATION_PARAMETERS']],
            'QueryAllocatedResources': [
                0x0,
                ['_ARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS'],
            ],
            'QueryConflict': [0x0, ['_ARBITER_QUERY_CONFLICT_PARAMETERS']],
            'QueryArbitrate': [0x0, ['_ARBITER_QUERY_ARBITRATE_PARAMETERS']],
            'AddReserved': [0x0, ['_ARBITER_ADD_RESERVED_PARAMETERS']],
        },
    ],
    '_ARBITER_PARAMETERS': [
        0x20,
        {
            'Parameters': [0x0, ['__unnamed_2406']],
        },
    ],
    '__unnamed_240a': [
        0x8,
        {
            'idxRecord': [0x0, ['unsigned long']],
            'cidContainer': [0x4, ['unsigned long']],
        },
    ],
    '_CLS_LSN': [
        0x8,
        {
            'offset': [0x0, ['__unnamed_240a']],
            'ullOffset': [0x0, ['unsigned long long']],
        },
    ],
    '_NT_TIB32': [
        0x1C,
        {
            'ExceptionList': [0x0, ['unsigned long']],
            'StackBase': [0x4, ['unsigned long']],
            'StackLimit': [0x8, ['unsigned long']],
            'SubSystemTib': [0xC, ['unsigned long']],
            'FiberData': [0x10, ['unsigned long']],
            'Version': [0x10, ['unsigned long']],
            'ArbitraryUserPointer': [0x14, ['unsigned long']],
            'Self': [0x18, ['unsigned long']],
        },
    ],
    'POWER_ACTION_POLICY': [
        0xC,
        {
            'Action': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerActionNone',
                            1: 'PowerActionReserved',
                            2: 'PowerActionSleep',
                            3: 'PowerActionHibernate',
                            4: 'PowerActionShutdown',
                            5: 'PowerActionShutdownReset',
                            6: 'PowerActionShutdownOff',
                            7: 'PowerActionWarmEject',
                        },
                    ),
                ],
            ],
            'Flags': [0x4, ['unsigned long']],
            'EventCode': [0x8, ['unsigned long']],
        },
    ],
    'PO_MEMORY_IMAGE': [
        0x128,
        {
            'Signature': [0x0, ['unsigned long']],
            'ImageType': [0x4, ['unsigned long']],
            'CheckSum': [0x8, ['unsigned long']],
            'LengthSelf': [0xC, ['unsigned long']],
            'PageSelf': [0x10, ['unsigned long long']],
            'PageSize': [0x18, ['unsigned long']],
            'SystemTime': [0x20, ['_LARGE_INTEGER']],
            'InterruptTime': [0x28, ['unsigned long long']],
            'FeatureFlags': [0x30, ['unsigned long']],
            'HiberFlags': [0x34, ['unsigned char']],
            'spare': [0x35, ['array', 3, ['unsigned char']]],
            'NoHiberPtes': [0x38, ['unsigned long']],
            'HiberVa': [0x40, ['unsigned long long']],
            'HiberPte': [0x48, ['_LARGE_INTEGER']],
            'NoFreePages': [0x50, ['unsigned long']],
            'FreeMapCheck': [0x54, ['unsigned long']],
            'WakeCheck': [0x58, ['unsigned long']],
            'FirstTablePage': [0x60, ['unsigned long long']],
            'PerfInfo': [0x68, ['_PO_HIBER_PERF']],
            'FirmwareRuntimeInformationPages': [0xC0, ['unsigned long']],
            'FirmwareRuntimeInformation': [
                0xC8,
                ['array', 1, ['unsigned long long']],
            ],
            'NoBootLoaderLogPages': [0xD0, ['unsigned long']],
            'BootLoaderLogPages': [0xD8, ['array', 8, ['unsigned long long']]],
            'NotUsed': [0x118, ['unsigned long']],
            'ResumeContextCheck': [0x11C, ['unsigned long']],
            'ResumeContextPages': [0x120, ['unsigned long']],
        },
    ],
    'EX_QUEUE_WORKER_INFO': [
        0x4,
        {
            'QueueDisabled': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'MakeThreadsAsNecessary': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'WaitMode': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WorkerCount': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'QueueWorkerInfo': [0x0, ['long']],
        },
    ],
    'BATTERY_REPORTING_SCALE': [
        0x8,
        {
            'Granularity': [0x0, ['unsigned long']],
            'Capacity': [0x4, ['unsigned long']],
        },
    ],
    '_CURDIR': [
        0x18,
        {
            'DosPath': [0x0, ['_UNICODE_STRING']],
            'Handle': [0x10, ['pointer64', ['void']]],
        },
    ],
    '_PO_HIBER_PERF': [
        0x58,
        {
            'IoTicks': [0x0, ['unsigned long long']],
            'InitTicks': [0x8, ['unsigned long long']],
            'CopyTicks': [0x10, ['unsigned long long']],
            'ElapsedTicks': [0x18, ['unsigned long long']],
            'CompressTicks': [0x20, ['unsigned long long']],
            'ResumeAppTime': [0x28, ['unsigned long long']],
            'HiberFileResumeTime': [0x30, ['unsigned long long']],
            'BytesCopied': [0x38, ['unsigned long long']],
            'PagesProcessed': [0x40, ['unsigned long long']],
            'PagesWritten': [0x48, ['unsigned long']],
            'DumpCount': [0x4C, ['unsigned long']],
            'FileRuns': [0x50, ['unsigned long']],
        },
    ],
    '_DEVICE_FLAGS': [
        0x4,
        {
            'Failed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReadOnly': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Removable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ConsoleIn': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ConsoleOut': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Input': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Output': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_RTL_BALANCED_LINKS': [
        0x20,
        {
            'Parent': [0x0, ['pointer64', ['_RTL_BALANCED_LINKS']]],
            'LeftChild': [0x8, ['pointer64', ['_RTL_BALANCED_LINKS']]],
            'RightChild': [0x10, ['pointer64', ['_RTL_BALANCED_LINKS']]],
            'Balance': [0x18, ['unsigned char']],
            'Reserved': [0x19, ['array', 3, ['unsigned char']]],
        },
    ],
    '_MMVIEW': [
        0x30,
        {
            'Entry': [0x0, ['unsigned long long']],
            'Writable': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ControlArea': [0x8, ['pointer64', ['_CONTROL_AREA']]],
            'ViewLinks': [0x10, ['_LIST_ENTRY']],
            'SessionViewVa': [0x20, ['pointer64', ['void']]],
            'SessionId': [0x28, ['unsigned long']],
        },
    ],
    '_MM_SESSION_SPACE_FLAGS': [
        0x4,
        {
            'Initialized': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DeletePending': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'PoolInitialized': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'DynamicVaInitialized': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'WsInitialized': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'PoolDestroyed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'ObjectInitialized': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Filler': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_HEADLESS_LOADER_BLOCK': [
        0x40,
        {
            'UsedBiosSettings': [0x0, ['unsigned char']],
            'DataBits': [0x1, ['unsigned char']],
            'StopBits': [0x2, ['unsigned char']],
            'Parity': [0x3, ['unsigned char']],
            'BaudRate': [0x4, ['unsigned long']],
            'PortNumber': [0x8, ['unsigned long']],
            'PortAddress': [0x10, ['pointer64', ['unsigned char']]],
            'PciDeviceId': [0x18, ['unsigned short']],
            'PciVendorId': [0x1A, ['unsigned short']],
            'PciBusNumber': [0x1C, ['unsigned char']],
            'PciBusSegment': [0x1E, ['unsigned short']],
            'PciSlotNumber': [0x20, ['unsigned char']],
            'PciFunctionNumber': [0x21, ['unsigned char']],
            'PciFlags': [0x24, ['unsigned long']],
            'SystemGUID': [0x28, ['_GUID']],
            'IsMMIODevice': [0x38, ['unsigned char']],
            'TerminalType': [0x39, ['unsigned char']],
        },
    ],
    '__unnamed_2434': [
        0x8,
        {
            'Signature': [0x0, ['unsigned long']],
            'CheckSum': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2436': [
        0x10,
        {
            'DiskId': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_2438': [
        0x10,
        {
            'Mbr': [0x0, ['__unnamed_2434']],
            'Gpt': [0x0, ['__unnamed_2436']],
        },
    ],
    '_DUMP_INITIALIZATION_CONTEXT': [
        0xA0,
        {
            'Length': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'MemoryBlock': [0x8, ['pointer64', ['void']]],
            'CommonBuffer': [0x10, ['array', 2, ['pointer64', ['void']]]],
            'PhysicalAddress': [0x20, ['array', 2, ['_LARGE_INTEGER']]],
            'StallRoutine': [0x30, ['pointer64', ['void']]],
            'OpenRoutine': [0x38, ['pointer64', ['void']]],
            'WriteRoutine': [0x40, ['pointer64', ['void']]],
            'FinishRoutine': [0x48, ['pointer64', ['void']]],
            'AdapterObject': [0x50, ['pointer64', ['_ADAPTER_OBJECT']]],
            'MappedRegisterBase': [0x58, ['pointer64', ['void']]],
            'PortConfiguration': [0x60, ['pointer64', ['void']]],
            'CrashDump': [0x68, ['unsigned char']],
            'MaximumTransferSize': [0x6C, ['unsigned long']],
            'CommonBufferSize': [0x70, ['unsigned long']],
            'TargetAddress': [0x78, ['pointer64', ['void']]],
            'WritePendingRoutine': [0x80, ['pointer64', ['void']]],
            'PartitionStyle': [0x88, ['unsigned long']],
            'DiskInfo': [0x8C, ['__unnamed_2438']],
        },
    ],
    '_MI_SYSTEM_PTE_TYPE': [
        0x48,
        {
            'Bitmap': [0x0, ['_RTL_BITMAP']],
            'Flags': [0x10, ['unsigned long']],
            'Hint': [0x14, ['unsigned long']],
            'BasePte': [0x18, ['pointer64', ['_MMPTE']]],
            'FailureCount': [0x20, ['pointer64', ['unsigned long']]],
            'Vm': [0x28, ['pointer64', ['_MMSUPPORT']]],
            'TotalSystemPtes': [0x30, ['long']],
            'TotalFreeSystemPtes': [0x34, ['long']],
            'CachedPteCount': [0x38, ['long']],
            'PteFailures': [0x3C, ['unsigned long']],
            'SpinLock': [0x40, ['unsigned long long']],
            'GlobalMutex': [0x40, ['pointer64', ['_KGUARDED_MUTEX']]],
        },
    ],
    '_NETWORK_LOADER_BLOCK': [
        0x20,
        {
            'DHCPServerACK': [0x0, ['pointer64', ['unsigned char']]],
            'DHCPServerACKLength': [0x8, ['unsigned long']],
            'BootServerReplyPacket': [0x10, ['pointer64', ['unsigned char']]],
            'BootServerReplyPacketLength': [0x18, ['unsigned long']],
        },
    ],
    '_CM_KEY_SECURITY': [
        0x28,
        {
            'Signature': [0x0, ['unsigned short']],
            'Reserved': [0x2, ['unsigned short']],
            'Flink': [0x4, ['unsigned long']],
            'Blink': [0x8, ['unsigned long']],
            'ReferenceCount': [0xC, ['unsigned long']],
            'DescriptorLength': [0x10, ['unsigned long']],
            'Descriptor': [0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
        },
    ],
    '_PO_DEVICE_NOTIFY_ORDER': [
        0x298,
        {
            'Locked': [0x0, ['unsigned char']],
            'WarmEjectPdoPointer': [
                0x8,
                ['pointer64', ['pointer64', ['_DEVICE_OBJECT']]],
            ],
            'OrderLevel': [0x10, ['array', 9, ['_PO_NOTIFY_ORDER_LEVEL']]],
        },
    ],
    '_ARBITER_CONFLICT_INFO': [
        0x18,
        {
            'OwningObject': [0x0, ['pointer64', ['_DEVICE_OBJECT']]],
            'Start': [0x8, ['unsigned long long']],
            'End': [0x10, ['unsigned long long']],
        },
    ],
    '_PO_NOTIFY_ORDER_LEVEL': [
        0x48,
        {
            'DeviceCount': [0x0, ['unsigned long']],
            'ActiveCount': [0x4, ['unsigned long']],
            'WaitSleep': [0x8, ['_LIST_ENTRY']],
            'ReadySleep': [0x18, ['_LIST_ENTRY']],
            'ReadyS0': [0x28, ['_LIST_ENTRY']],
            'WaitS0': [0x38, ['_LIST_ENTRY']],
        },
    ],
    '_THREAD_PERFORMANCE_DATA': [
        0x1C0,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'ProcessorNumber': [0x4, ['_PROCESSOR_NUMBER']],
            'ContextSwitches': [0x8, ['unsigned long']],
            'HwCountersCount': [0xC, ['unsigned long']],
            'UpdateCount': [0x10, ['unsigned long long']],
            'WaitReasonBitMap': [0x18, ['unsigned long long']],
            'HardwareCounters': [0x20, ['unsigned long long']],
            'CycleTime': [0x28, ['_COUNTER_READING']],
            'HwCounters': [0x40, ['array', 16, ['_COUNTER_READING']]],
        },
    ],
    '_GDI_TEB_BATCH32': [
        0x4E0,
        {
            'Offset': [0x0, ['unsigned long']],
            'HDC': [0x4, ['unsigned long']],
            'Buffer': [0x8, ['array', 310, ['unsigned long']]],
        },
    ],
    '_ETW_REPLY_QUEUE': [
        0x48,
        {
            'Queue': [0x0, ['_KQUEUE']],
            'EventsLost': [0x40, ['long']],
        },
    ],
    '_ARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS': [
        0x8,
        {
            'AllocatedResources': [
                0x0,
                ['pointer64', ['pointer64', ['_CM_PARTIAL_RESOURCE_LIST']]],
            ],
        },
    ],
    '_RTL_ACTIVATION_CONTEXT_STACK_FRAME': [
        0x18,
        {
            'Previous': [
                0x0,
                ['pointer64', ['_RTL_ACTIVATION_CONTEXT_STACK_FRAME']],
            ],
            'ActivationContext': [0x8, ['pointer64', ['_ACTIVATION_CONTEXT']]],
            'Flags': [0x10, ['unsigned long']],
        },
    ],
    '_ARBITER_ORDERING': [
        0x10,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
        },
    ],
    '_RTL_AVL_TABLE': [
        0x68,
        {
            'BalancedRoot': [0x0, ['_RTL_BALANCED_LINKS']],
            'OrderedPointer': [0x20, ['pointer64', ['void']]],
            'WhichOrderedElement': [0x28, ['unsigned long']],
            'NumberGenericTableElements': [0x2C, ['unsigned long']],
            'DepthOfTree': [0x30, ['unsigned long']],
            'RestartKey': [0x38, ['pointer64', ['_RTL_BALANCED_LINKS']]],
            'DeleteCount': [0x40, ['unsigned long']],
            'CompareRoutine': [0x48, ['pointer64', ['void']]],
            'AllocateRoutine': [0x50, ['pointer64', ['void']]],
            'FreeRoutine': [0x58, ['pointer64', ['void']]],
            'TableContext': [0x60, ['pointer64', ['void']]],
        },
    ],
    '_KTRANSACTION_HISTORY': [
        0x8,
        {
            'RecordType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'KTMOH_CommitTransaction_Result',
                            2: 'KTMOH_RollbackTransaction_Result',
                        },
                    ),
                ],
            ],
            'Payload': [0x4, ['unsigned long']],
        },
    ],
    'LIST_ENTRY64': [
        0x10,
        {
            'Flink': [0x0, ['unsigned long long']],
            'Blink': [0x8, ['unsigned long long']],
        },
    ],
    'LIST_ENTRY32': [
        0x8,
        {
            'Flink': [0x0, ['unsigned long']],
            'Blink': [0x4, ['unsigned long']],
        },
    ],
    '_KUSER_SHARED_DATA': [
        0x5F0,
        {
            'TickCountLowDeprecated': [0x0, ['unsigned long']],
            'TickCountMultiplier': [0x4, ['unsigned long']],
            'InterruptTime': [0x8, ['_KSYSTEM_TIME']],
            'SystemTime': [0x14, ['_KSYSTEM_TIME']],
            'TimeZoneBias': [0x20, ['_KSYSTEM_TIME']],
            'ImageNumberLow': [0x2C, ['unsigned short']],
            'ImageNumberHigh': [0x2E, ['unsigned short']],
            'NtSystemRoot': [0x30, ['array', 260, ['wchar']]],
            'MaxStackTraceDepth': [0x238, ['unsigned long']],
            'CryptoExponent': [0x23C, ['unsigned long']],
            'TimeZoneId': [0x240, ['unsigned long']],
            'LargePageMinimum': [0x244, ['unsigned long']],
            'Reserved2': [0x248, ['array', 7, ['unsigned long']]],
            'NtProductType': [
                0x264,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'NtProductWinNt',
                            2: 'NtProductLanManNt',
                            3: 'NtProductServer',
                        },
                    ),
                ],
            ],
            'ProductTypeIsValid': [0x268, ['unsigned char']],
            'NtMajorVersion': [0x26C, ['unsigned long']],
            'NtMinorVersion': [0x270, ['unsigned long']],
            'ProcessorFeatures': [0x274, ['array', 64, ['unsigned char']]],
            'Reserved1': [0x2B4, ['unsigned long']],
            'Reserved3': [0x2B8, ['unsigned long']],
            'TimeSlip': [0x2BC, ['unsigned long']],
            'AlternativeArchitecture': [
                0x2C0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'StandardDesign',
                            1: 'NEC98x86',
                            2: 'EndAlternatives',
                        },
                    ),
                ],
            ],
            'AltArchitecturePad': [0x2C4, ['array', 1, ['unsigned long']]],
            'SystemExpirationDate': [0x2C8, ['_LARGE_INTEGER']],
            'SuiteMask': [0x2D0, ['unsigned long']],
            'KdDebuggerEnabled': [0x2D4, ['unsigned char']],
            'NXSupportPolicy': [0x2D5, ['unsigned char']],
            'ActiveConsoleId': [0x2D8, ['unsigned long']],
            'DismountCount': [0x2DC, ['unsigned long']],
            'ComPlusPackage': [0x2E0, ['unsigned long']],
            'LastSystemRITEventTickCount': [0x2E4, ['unsigned long']],
            'NumberOfPhysicalPages': [0x2E8, ['unsigned long']],
            'SafeBootMode': [0x2EC, ['unsigned char']],
            'TscQpcData': [0x2ED, ['unsigned char']],
            'TscQpcEnabled': [
                0x2ED,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'TscQpcSpareFlag': [
                0x2ED,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'TscQpcShift': [
                0x2ED,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'TscQpcPad': [0x2EE, ['array', 2, ['unsigned char']]],
            'SharedDataFlags': [0x2F0, ['unsigned long']],
            'DbgErrorPortPresent': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DbgElevationEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'DbgVirtEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'DbgInstallerDetectEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'DbgSystemDllRelocated': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'DbgDynProcessorEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'DbgSEHValidationEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SpareBits': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'DataFlagsPad': [0x2F4, ['array', 1, ['unsigned long']]],
            'TestRetInstruction': [0x2F8, ['unsigned long long']],
            'SystemCall': [0x300, ['unsigned long']],
            'SystemCallReturn': [0x304, ['unsigned long']],
            'SystemCallPad': [0x308, ['array', 3, ['unsigned long long']]],
            'TickCount': [0x320, ['_KSYSTEM_TIME']],
            'TickCountQuad': [0x320, ['unsigned long long']],
            'ReservedTickCountOverlay': [
                0x320,
                ['array', 3, ['unsigned long']],
            ],
            'TickCountPad': [0x32C, ['array', 1, ['unsigned long']]],
            'Cookie': [0x330, ['unsigned long']],
            'CookiePad': [0x334, ['array', 1, ['unsigned long']]],
            'ConsoleSessionForegroundProcessId': [0x338, ['long long']],
            'DEPRECATED_Wow64SharedInformation': [
                0x340,
                ['array', 16, ['unsigned long']],
            ],
            'UserModeGlobalLogger': [0x380, ['array', 16, ['unsigned short']]],
            'ImageFileExecutionOptions': [0x3A0, ['unsigned long']],
            'LangGenerationCount': [0x3A4, ['unsigned long']],
            'Reserved5': [0x3A8, ['unsigned long long']],
            'InterruptTimeBias': [0x3B0, ['unsigned long long']],
            'TscQpcBias': [0x3B8, ['unsigned long long']],
            'ActiveProcessorCount': [0x3C0, ['unsigned long']],
            'ActiveGroupCount': [0x3C4, ['unsigned short']],
            'Reserved4': [0x3C6, ['unsigned short']],
            'AitSamplingValue': [0x3C8, ['unsigned long']],
            'AppCompatFlag': [0x3CC, ['unsigned long']],
            'DEPRECATED_SystemDllNativeRelocation': [
                0x3D0,
                ['unsigned long long'],
            ],
            'DEPRECATED_SystemDllWowRelocation': [0x3D8, ['unsigned long']],
            'XStatePad': [0x3DC, ['array', 1, ['unsigned long']]],
            'XState': [0x3E0, ['_XSTATE_CONFIGURATION']],
        },
    ],
    '__unnamed_1043': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['unsigned long']],
        },
    ],
    '_ULARGE_INTEGER': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['unsigned long']],
            'u': [0x0, ['__unnamed_1043']],
            'QuadPart': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_1047': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['long']],
        },
    ],
    '_LARGE_INTEGER': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['long']],
            'u': [0x0, ['__unnamed_1047']],
            'QuadPart': [0x0, ['long long']],
        },
    ],
    '__unnamed_105f': [
        0x4,
        {
            'LongFunction': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Persistent': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Private': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_1061': [
        0x4,
        {
            'Flags': [0x0, ['unsigned long']],
            's': [0x0, ['__unnamed_105f']],
        },
    ],
    '_TP_CALLBACK_ENVIRON_V3': [
        0x48,
        {
            'Version': [0x0, ['unsigned long']],
            'Pool': [0x8, ['pointer64', ['_TP_POOL']]],
            'CleanupGroup': [0x10, ['pointer64', ['_TP_CLEANUP_GROUP']]],
            'CleanupGroupCancelCallback': [0x18, ['pointer64', ['void']]],
            'RaceDll': [0x20, ['pointer64', ['void']]],
            'ActivationContext': [
                0x28,
                ['pointer64', ['_ACTIVATION_CONTEXT']],
            ],
            'FinalizationCallback': [0x30, ['pointer64', ['void']]],
            'u': [0x38, ['__unnamed_1061']],
            'CallbackPriority': [
                0x3C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'TP_CALLBACK_PRIORITY_HIGH',
                            1: 'TP_CALLBACK_PRIORITY_NORMAL',
                            2: 'TP_CALLBACK_PRIORITY_LOW',
                            3: 'TP_CALLBACK_PRIORITY_INVALID',
                        },
                    ),
                ],
            ],
            'Size': [0x40, ['unsigned long']],
        },
    ],
    '_TP_TASK': [
        0x20,
        {
            'Callbacks': [0x0, ['pointer64', ['_TP_TASK_CALLBACKS']]],
            'NumaNode': [0x8, ['unsigned long']],
            'IdealProcessor': [0xC, ['unsigned char']],
            'ListEntry': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_TP_TASK_CALLBACKS': [
        0x10,
        {
            'ExecuteCallback': [0x0, ['pointer64', ['void']]],
            'Unposted': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_TP_DIRECT': [
        0x10,
        {
            'Callback': [0x0, ['pointer64', ['void']]],
            'NumaNode': [0x8, ['unsigned long']],
            'IdealProcessor': [0xC, ['unsigned char']],
        },
    ],
    '_TEB': [
        0x1818,
        {
            'NtTib': [0x0, ['_NT_TIB']],
            'EnvironmentPointer': [0x38, ['pointer64', ['void']]],
            'ClientId': [0x40, ['_CLIENT_ID']],
            'ActiveRpcHandle': [0x50, ['pointer64', ['void']]],
            'ThreadLocalStoragePointer': [0x58, ['pointer64', ['void']]],
            'ProcessEnvironmentBlock': [0x60, ['pointer64', ['_PEB']]],
            'LastErrorValue': [0x68, ['unsigned long']],
            'CountOfOwnedCriticalSections': [0x6C, ['unsigned long']],
            'CsrClientThread': [0x70, ['pointer64', ['void']]],
            'Win32ThreadInfo': [0x78, ['pointer64', ['void']]],
            'User32Reserved': [0x80, ['array', 26, ['unsigned long']]],
            'UserReserved': [0xE8, ['array', 5, ['unsigned long']]],
            'WOW32Reserved': [0x100, ['pointer64', ['void']]],
            'CurrentLocale': [0x108, ['unsigned long']],
            'FpSoftwareStatusRegister': [0x10C, ['unsigned long']],
            'SystemReserved1': [0x110, ['array', 54, ['pointer64', ['void']]]],
            'ExceptionCode': [0x2C0, ['long']],
            'ActivationContextStackPointer': [
                0x2C8,
                ['pointer64', ['_ACTIVATION_CONTEXT_STACK']],
            ],
            'SpareBytes': [0x2D0, ['array', 24, ['unsigned char']]],
            'TxFsContext': [0x2E8, ['unsigned long']],
            'GdiTebBatch': [0x2F0, ['_GDI_TEB_BATCH']],
            'RealClientId': [0x7D8, ['_CLIENT_ID']],
            'GdiCachedProcessHandle': [0x7E8, ['pointer64', ['void']]],
            'GdiClientPID': [0x7F0, ['unsigned long']],
            'GdiClientTID': [0x7F4, ['unsigned long']],
            'GdiThreadLocalInfo': [0x7F8, ['pointer64', ['void']]],
            'Win32ClientInfo': [0x800, ['array', 62, ['unsigned long long']]],
            'glDispatchTable': [
                0x9F0,
                ['array', 233, ['pointer64', ['void']]],
            ],
            'glReserved1': [0x1138, ['array', 29, ['unsigned long long']]],
            'glReserved2': [0x1220, ['pointer64', ['void']]],
            'glSectionInfo': [0x1228, ['pointer64', ['void']]],
            'glSection': [0x1230, ['pointer64', ['void']]],
            'glTable': [0x1238, ['pointer64', ['void']]],
            'glCurrentRC': [0x1240, ['pointer64', ['void']]],
            'glContext': [0x1248, ['pointer64', ['void']]],
            'LastStatusValue': [0x1250, ['unsigned long']],
            'StaticUnicodeString': [0x1258, ['_UNICODE_STRING']],
            'StaticUnicodeBuffer': [0x1268, ['array', 261, ['wchar']]],
            'DeallocationStack': [0x1478, ['pointer64', ['void']]],
            'TlsSlots': [0x1480, ['array', 64, ['pointer64', ['void']]]],
            'TlsLinks': [0x1680, ['_LIST_ENTRY']],
            'Vdm': [0x1690, ['pointer64', ['void']]],
            'ReservedForNtRpc': [0x1698, ['pointer64', ['void']]],
            'DbgSsReserved': [0x16A0, ['array', 2, ['pointer64', ['void']]]],
            'HardErrorMode': [0x16B0, ['unsigned long']],
            'Instrumentation': [
                0x16B8,
                ['array', 11, ['pointer64', ['void']]],
            ],
            'ActivityId': [0x1710, ['_GUID']],
            'SubProcessTag': [0x1720, ['pointer64', ['void']]],
            'EtwLocalData': [0x1728, ['pointer64', ['void']]],
            'EtwTraceData': [0x1730, ['pointer64', ['void']]],
            'WinSockData': [0x1738, ['pointer64', ['void']]],
            'GdiBatchCount': [0x1740, ['unsigned long']],
            'CurrentIdealProcessor': [0x1744, ['_PROCESSOR_NUMBER']],
            'IdealProcessorValue': [0x1744, ['unsigned long']],
            'ReservedPad0': [0x1744, ['unsigned char']],
            'ReservedPad1': [0x1745, ['unsigned char']],
            'ReservedPad2': [0x1746, ['unsigned char']],
            'IdealProcessor': [0x1747, ['unsigned char']],
            'GuaranteedStackBytes': [0x1748, ['unsigned long']],
            'ReservedForPerf': [0x1750, ['pointer64', ['void']]],
            'ReservedForOle': [0x1758, ['pointer64', ['void']]],
            'WaitingOnLoaderLock': [0x1760, ['unsigned long']],
            'SavedPriorityState': [0x1768, ['pointer64', ['void']]],
            'SoftPatchPtr1': [0x1770, ['unsigned long long']],
            'ThreadPoolData': [0x1778, ['pointer64', ['void']]],
            'TlsExpansionSlots': [
                0x1780,
                ['pointer64', ['pointer64', ['void']]],
            ],
            'DeallocationBStore': [0x1788, ['pointer64', ['void']]],
            'BStoreLimit': [0x1790, ['pointer64', ['void']]],
            'MuiGeneration': [0x1798, ['unsigned long']],
            'IsImpersonating': [0x179C, ['unsigned long']],
            'NlsCache': [0x17A0, ['pointer64', ['void']]],
            'pShimData': [0x17A8, ['pointer64', ['void']]],
            'HeapVirtualAffinity': [0x17B0, ['unsigned long']],
            'CurrentTransactionHandle': [0x17B8, ['pointer64', ['void']]],
            'ActiveFrame': [0x17C0, ['pointer64', ['_TEB_ACTIVE_FRAME']]],
            'FlsData': [0x17C8, ['pointer64', ['void']]],
            'PreferredLanguages': [0x17D0, ['pointer64', ['void']]],
            'UserPrefLanguages': [0x17D8, ['pointer64', ['void']]],
            'MergedPrefLanguages': [0x17E0, ['pointer64', ['void']]],
            'MuiImpersonation': [0x17E8, ['unsigned long']],
            'CrossTebFlags': [0x17EC, ['unsigned short']],
            'SpareCrossTebBits': [
                0x17EC,
                [
                    'BitField',
                    dict(
                        start_bit=0, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'SameTebFlags': [0x17EE, ['unsigned short']],
            'SafeThunkCall': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'InDebugPrint': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'HasFiberData': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'SkipThreadAttach': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'WerInShipAssertCode': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'RanProcessInit': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'ClonedThread': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'SuppressDebugMsg': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'DisableUserStackWalk': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned short'),
                ],
            ],
            'RtlExceptionAttached': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=9, end_bit=10, native_type='unsigned short'
                    ),
                ],
            ],
            'InitialThread': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned short'
                    ),
                ],
            ],
            'SpareSameTebBits': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0x17F0, ['pointer64', ['void']]],
            'TxnScopeExitCallback': [0x17F8, ['pointer64', ['void']]],
            'TxnScopeContext': [0x1800, ['pointer64', ['void']]],
            'LockCount': [0x1808, ['unsigned long']],
            'SpareUlong0': [0x180C, ['unsigned long']],
            'ResourceRetValue': [0x1810, ['pointer64', ['void']]],
        },
    ],
    '_LIST_ENTRY': [
        0x10,
        {
            'Flink': [0x0, ['pointer64', ['_LIST_ENTRY']]],
            'Blink': [0x8, ['pointer64', ['_LIST_ENTRY']]],
        },
    ],
    '_SINGLE_LIST_ENTRY': [
        0x8,
        {
            'Next': [0x0, ['pointer64', ['_SINGLE_LIST_ENTRY']]],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE_CONTEXT': [
        0x18,
        {
            'ChainHead': [0x0, ['pointer64', ['_LIST_ENTRY']]],
            'PrevLinkage': [0x8, ['pointer64', ['_LIST_ENTRY']]],
            'Signature': [0x10, ['unsigned long long']],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE_ENUMERATOR': [
        0x28,
        {
            'HashEntry': [0x0, ['_RTL_DYNAMIC_HASH_TABLE_ENTRY']],
            'ChainHead': [0x18, ['pointer64', ['_LIST_ENTRY']]],
            'BucketIndex': [0x20, ['unsigned long']],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE': [
        0x28,
        {
            'Flags': [0x0, ['unsigned long']],
            'Shift': [0x4, ['unsigned long']],
            'TableSize': [0x8, ['unsigned long']],
            'Pivot': [0xC, ['unsigned long']],
            'DivisorMask': [0x10, ['unsigned long']],
            'NumEntries': [0x14, ['unsigned long']],
            'NonEmptyBuckets': [0x18, ['unsigned long']],
            'NumEnumerators': [0x1C, ['unsigned long']],
            'Directory': [0x20, ['pointer64', ['void']]],
        },
    ],
    '_UNICODE_STRING': [
        0x10,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x8, ['pointer64', ['unsigned short']]],
        },
    ],
    '_STRING': [
        0x10,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x8, ['pointer64', ['unsigned char']]],
        },
    ],
    '_RTL_BITMAP': [
        0x10,
        {
            'SizeOfBitMap': [0x0, ['unsigned long']],
            'Buffer': [0x8, ['pointer64', ['unsigned long']]],
        },
    ],
    '_LUID': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['long']],
        },
    ],
    '_IMAGE_NT_HEADERS64': [
        0x108,
        {
            'Signature': [0x0, ['unsigned long']],
            'FileHeader': [0x4, ['_IMAGE_FILE_HEADER']],
            'OptionalHeader': [0x18, ['_IMAGE_OPTIONAL_HEADER64']],
        },
    ],
    '_IMAGE_DOS_HEADER': [
        0x40,
        {
            'e_magic': [0x0, ['unsigned short']],
            'e_cblp': [0x2, ['unsigned short']],
            'e_cp': [0x4, ['unsigned short']],
            'e_crlc': [0x6, ['unsigned short']],
            'e_cparhdr': [0x8, ['unsigned short']],
            'e_minalloc': [0xA, ['unsigned short']],
            'e_maxalloc': [0xC, ['unsigned short']],
            'e_ss': [0xE, ['unsigned short']],
            'e_sp': [0x10, ['unsigned short']],
            'e_csum': [0x12, ['unsigned short']],
            'e_ip': [0x14, ['unsigned short']],
            'e_cs': [0x16, ['unsigned short']],
            'e_lfarlc': [0x18, ['unsigned short']],
            'e_ovno': [0x1A, ['unsigned short']],
            'e_res': [0x1C, ['array', 4, ['unsigned short']]],
            'e_oemid': [0x24, ['unsigned short']],
            'e_oeminfo': [0x26, ['unsigned short']],
            'e_res2': [0x28, ['array', 10, ['unsigned short']]],
            'e_lfanew': [0x3C, ['long']],
        },
    ],
    '_KPCR': [
        0x4E80,
        {
            'NtTib': [0x0, ['_NT_TIB']],
            'GdtBase': [0x0, ['pointer64', ['_KGDTENTRY64']]],
            'TssBase': [0x8, ['pointer64', ['_KTSS64']]],
            'UserRsp': [0x10, ['unsigned long long']],
            'Self': [0x18, ['pointer64', ['_KPCR']]],
            'CurrentPrcb': [0x20, ['pointer64', ['_KPRCB']]],
            'LockArray': [0x28, ['pointer64', ['_KSPIN_LOCK_QUEUE']]],
            'Used_Self': [0x30, ['pointer64', ['void']]],
            'IdtBase': [0x38, ['pointer64', ['_KIDTENTRY64']]],
            'Unused': [0x40, ['array', 2, ['unsigned long long']]],
            'Irql': [0x50, ['unsigned char']],
            'SecondLevelCacheAssociativity': [0x51, ['unsigned char']],
            'ObsoleteNumber': [0x52, ['unsigned char']],
            'Fill0': [0x53, ['unsigned char']],
            'Unused0': [0x54, ['array', 3, ['unsigned long']]],
            'MajorVersion': [0x60, ['unsigned short']],
            'MinorVersion': [0x62, ['unsigned short']],
            'StallScaleFactor': [0x64, ['unsigned long']],
            'Unused1': [0x68, ['array', 3, ['pointer64', ['void']]]],
            'KernelReserved': [0x80, ['array', 15, ['unsigned long']]],
            'SecondLevelCacheSize': [0xBC, ['unsigned long']],
            'HalReserved': [0xC0, ['array', 16, ['unsigned long']]],
            'Unused2': [0x100, ['unsigned long']],
            'KdVersionBlock': [0x108, ['pointer64', ['void']]],
            'Unused3': [0x110, ['pointer64', ['void']]],
            'PcrAlign1': [0x118, ['array', 24, ['unsigned long']]],
            'Prcb': [0x180, ['_KPRCB']],
        },
    ],
    '_KPRCB': [
        0x4D00,
        {
            'MxCsr': [0x0, ['unsigned long']],
            'LegacyNumber': [0x4, ['unsigned char']],
            'ReservedMustBeZero': [0x5, ['unsigned char']],
            'InterruptRequest': [0x6, ['unsigned char']],
            'IdleHalt': [0x7, ['unsigned char']],
            'CurrentThread': [0x8, ['pointer64', ['_KTHREAD']]],
            'NextThread': [0x10, ['pointer64', ['_KTHREAD']]],
            'IdleThread': [0x18, ['pointer64', ['_KTHREAD']]],
            'NestingLevel': [0x20, ['unsigned char']],
            'PrcbPad00': [0x21, ['array', 3, ['unsigned char']]],
            'Number': [0x24, ['unsigned long']],
            'RspBase': [0x28, ['unsigned long long']],
            'PrcbLock': [0x30, ['unsigned long long']],
            'PrcbPad01': [0x38, ['unsigned long long']],
            'ProcessorState': [0x40, ['_KPROCESSOR_STATE']],
            'CpuType': [0x5F0, ['unsigned char']],
            'CpuID': [0x5F1, ['unsigned char']],
            'CpuStep': [0x5F2, ['unsigned short']],
            'CpuStepping': [0x5F2, ['unsigned char']],
            'CpuModel': [0x5F3, ['unsigned char']],
            'MHz': [0x5F4, ['unsigned long']],
            'HalReserved': [0x5F8, ['array', 8, ['unsigned long long']]],
            'MinorVersion': [0x638, ['unsigned short']],
            'MajorVersion': [0x63A, ['unsigned short']],
            'BuildType': [0x63C, ['unsigned char']],
            'CpuVendor': [0x63D, ['unsigned char']],
            'CoresPerPhysicalProcessor': [0x63E, ['unsigned char']],
            'LogicalProcessorsPerCore': [0x63F, ['unsigned char']],
            'ApicMask': [0x640, ['unsigned long']],
            'CFlushSize': [0x644, ['unsigned long']],
            'AcpiReserved': [0x648, ['pointer64', ['void']]],
            'InitialApicId': [0x650, ['unsigned long']],
            'Stride': [0x654, ['unsigned long']],
            'Group': [0x658, ['unsigned short']],
            'GroupSetMember': [0x660, ['unsigned long long']],
            'GroupIndex': [0x668, ['unsigned char']],
            'LockQueue': [0x670, ['array', 17, ['_KSPIN_LOCK_QUEUE']]],
            'PPLookasideList': [0x780, ['array', 16, ['_PP_LOOKASIDE_LIST']]],
            'PPNPagedLookasideList': [
                0x880,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PPPagedLookasideList': [
                0x1480,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PacketBarrier': [0x2080, ['long']],
            'DeferredReadyListHead': [0x2088, ['_SINGLE_LIST_ENTRY']],
            'MmPageFaultCount': [0x2090, ['long']],
            'MmCopyOnWriteCount': [0x2094, ['long']],
            'MmTransitionCount': [0x2098, ['long']],
            'MmDemandZeroCount': [0x209C, ['long']],
            'MmPageReadCount': [0x20A0, ['long']],
            'MmPageReadIoCount': [0x20A4, ['long']],
            'MmDirtyPagesWriteCount': [0x20A8, ['long']],
            'MmDirtyWriteIoCount': [0x20AC, ['long']],
            'MmMappedPagesWriteCount': [0x20B0, ['long']],
            'MmMappedWriteIoCount': [0x20B4, ['long']],
            'KeSystemCalls': [0x20B8, ['unsigned long']],
            'KeContextSwitches': [0x20BC, ['unsigned long']],
            'CcFastReadNoWait': [0x20C0, ['unsigned long']],
            'CcFastReadWait': [0x20C4, ['unsigned long']],
            'CcFastReadNotPossible': [0x20C8, ['unsigned long']],
            'CcCopyReadNoWait': [0x20CC, ['unsigned long']],
            'CcCopyReadWait': [0x20D0, ['unsigned long']],
            'CcCopyReadNoWaitMiss': [0x20D4, ['unsigned long']],
            'LookasideIrpFloat': [0x20D8, ['long']],
            'IoReadOperationCount': [0x20DC, ['long']],
            'IoWriteOperationCount': [0x20E0, ['long']],
            'IoOtherOperationCount': [0x20E4, ['long']],
            'IoReadTransferCount': [0x20E8, ['_LARGE_INTEGER']],
            'IoWriteTransferCount': [0x20F0, ['_LARGE_INTEGER']],
            'IoOtherTransferCount': [0x20F8, ['_LARGE_INTEGER']],
            'TargetCount': [0x2100, ['long']],
            'IpiFrozen': [0x2104, ['unsigned long']],
            'DpcData': [0x2180, ['array', 2, ['_KDPC_DATA']]],
            'DpcStack': [0x21C0, ['pointer64', ['void']]],
            'MaximumDpcQueueDepth': [0x21C8, ['long']],
            'DpcRequestRate': [0x21CC, ['unsigned long']],
            'MinimumDpcRate': [0x21D0, ['unsigned long']],
            'DpcLastCount': [0x21D4, ['unsigned long']],
            'ThreadDpcEnable': [0x21D8, ['unsigned char']],
            'QuantumEnd': [0x21D9, ['unsigned char']],
            'DpcRoutineActive': [0x21DA, ['unsigned char']],
            'IdleSchedule': [0x21DB, ['unsigned char']],
            'DpcRequestSummary': [0x21DC, ['long']],
            'DpcRequestSlot': [0x21DC, ['array', 2, ['short']]],
            'NormalDpcState': [0x21DC, ['short']],
            'DpcThreadActive': [
                0x21DE,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'ThreadDpcState': [0x21DE, ['short']],
            'TimerHand': [0x21E0, ['unsigned long']],
            'MasterOffset': [0x21E4, ['long']],
            'LastTick': [0x21E8, ['unsigned long']],
            'UnusedPad': [0x21EC, ['unsigned long']],
            'PrcbPad50': [0x21F0, ['array', 2, ['unsigned long long']]],
            'TimerTable': [0x2200, ['_KTIMER_TABLE']],
            'DpcGate': [0x4400, ['_KGATE']],
            'PrcbPad52': [0x4418, ['pointer64', ['void']]],
            'CallDpc': [0x4420, ['_KDPC']],
            'ClockKeepAlive': [0x4460, ['long']],
            'ClockCheckSlot': [0x4464, ['unsigned char']],
            'ClockPollCycle': [0x4465, ['unsigned char']],
            'NmiActive': [0x4466, ['unsigned short']],
            'DpcWatchdogPeriod': [0x4468, ['long']],
            'DpcWatchdogCount': [0x446C, ['long']],
            'TickOffset': [0x4470, ['unsigned long long']],
            'KeSpinLockOrdering': [0x4478, ['long']],
            'PrcbPad70': [0x447C, ['unsigned long']],
            'WaitListHead': [0x4480, ['_LIST_ENTRY']],
            'WaitLock': [0x4490, ['unsigned long long']],
            'ReadySummary': [0x4498, ['unsigned long']],
            'QueueIndex': [0x449C, ['unsigned long']],
            'TimerExpirationDpc': [0x44A0, ['_KDPC']],
            'PrcbPad72': [0x44E0, ['array', 4, ['unsigned long long']]],
            'DispatcherReadyListHead': [
                0x4500,
                ['array', 32, ['_LIST_ENTRY']],
            ],
            'InterruptCount': [0x4700, ['unsigned long']],
            'KernelTime': [0x4704, ['unsigned long']],
            'UserTime': [0x4708, ['unsigned long']],
            'DpcTime': [0x470C, ['unsigned long']],
            'InterruptTime': [0x4710, ['unsigned long']],
            'AdjustDpcThreshold': [0x4714, ['unsigned long']],
            'DebuggerSavedIRQL': [0x4718, ['unsigned char']],
            'PrcbPad80': [0x4719, ['array', 7, ['unsigned char']]],
            'DpcTimeCount': [0x4720, ['unsigned long']],
            'DpcTimeLimit': [0x4724, ['unsigned long']],
            'PeriodicCount': [0x4728, ['unsigned long']],
            'PeriodicBias': [0x472C, ['unsigned long']],
            'AvailableTime': [0x4730, ['unsigned long']],
            'KeExceptionDispatchCount': [0x4734, ['unsigned long']],
            'ParentNode': [0x4738, ['pointer64', ['_KNODE']]],
            'StartCycles': [0x4740, ['unsigned long long']],
            'PrcbPad82': [0x4748, ['array', 3, ['unsigned long long']]],
            'MmSpinLockOrdering': [0x4760, ['long']],
            'PageColor': [0x4764, ['unsigned long']],
            'NodeColor': [0x4768, ['unsigned long']],
            'NodeShiftedColor': [0x476C, ['unsigned long']],
            'SecondaryColorMask': [0x4770, ['unsigned long']],
            'PrcbPad83': [0x4774, ['unsigned long']],
            'CycleTime': [0x4778, ['unsigned long long']],
            'CcFastMdlReadNoWait': [0x4780, ['unsigned long']],
            'CcFastMdlReadWait': [0x4784, ['unsigned long']],
            'CcFastMdlReadNotPossible': [0x4788, ['unsigned long']],
            'CcMapDataNoWait': [0x478C, ['unsigned long']],
            'CcMapDataWait': [0x4790, ['unsigned long']],
            'CcPinMappedDataCount': [0x4794, ['unsigned long']],
            'CcPinReadNoWait': [0x4798, ['unsigned long']],
            'CcPinReadWait': [0x479C, ['unsigned long']],
            'CcMdlReadNoWait': [0x47A0, ['unsigned long']],
            'CcMdlReadWait': [0x47A4, ['unsigned long']],
            'CcLazyWriteHotSpots': [0x47A8, ['unsigned long']],
            'CcLazyWriteIos': [0x47AC, ['unsigned long']],
            'CcLazyWritePages': [0x47B0, ['unsigned long']],
            'CcDataFlushes': [0x47B4, ['unsigned long']],
            'CcDataPages': [0x47B8, ['unsigned long']],
            'CcLostDelayedWrites': [0x47BC, ['unsigned long']],
            'CcFastReadResourceMiss': [0x47C0, ['unsigned long']],
            'CcCopyReadWaitMiss': [0x47C4, ['unsigned long']],
            'CcFastMdlReadResourceMiss': [0x47C8, ['unsigned long']],
            'CcMapDataNoWaitMiss': [0x47CC, ['unsigned long']],
            'CcMapDataWaitMiss': [0x47D0, ['unsigned long']],
            'CcPinReadNoWaitMiss': [0x47D4, ['unsigned long']],
            'CcPinReadWaitMiss': [0x47D8, ['unsigned long']],
            'CcMdlReadNoWaitMiss': [0x47DC, ['unsigned long']],
            'CcMdlReadWaitMiss': [0x47E0, ['unsigned long']],
            'CcReadAheadIos': [0x47E4, ['unsigned long']],
            'MmCacheTransitionCount': [0x47E8, ['long']],
            'MmCacheReadCount': [0x47EC, ['long']],
            'MmCacheIoCount': [0x47F0, ['long']],
            'PrcbPad91': [0x47F4, ['array', 1, ['unsigned long']]],
            'RuntimeAccumulation': [0x47F8, ['unsigned long long']],
            'PowerState': [0x4800, ['_PROCESSOR_POWER_STATE']],
            'PrcbPad92': [0x4900, ['array', 16, ['unsigned char']]],
            'KeAlignmentFixupCount': [0x4910, ['unsigned long']],
            'DpcWatchdogDpc': [0x4918, ['_KDPC']],
            'DpcWatchdogTimer': [0x4958, ['_KTIMER']],
            'Cache': [0x4998, ['array', 5, ['_CACHE_DESCRIPTOR']]],
            'CacheCount': [0x49D4, ['unsigned long']],
            'CachedCommit': [0x49D8, ['unsigned long']],
            'CachedResidentAvailable': [0x49DC, ['unsigned long']],
            'HyperPte': [0x49E0, ['pointer64', ['void']]],
            'WheaInfo': [0x49E8, ['pointer64', ['void']]],
            'EtwSupport': [0x49F0, ['pointer64', ['void']]],
            'InterruptObjectPool': [0x4A00, ['_SLIST_HEADER']],
            'HypercallPageList': [0x4A10, ['_SLIST_HEADER']],
            'HypercallPageVirtual': [0x4A20, ['pointer64', ['void']]],
            'VirtualApicAssist': [0x4A28, ['pointer64', ['void']]],
            'StatisticsPage': [0x4A30, ['pointer64', ['unsigned long long']]],
            'RateControl': [0x4A38, ['pointer64', ['void']]],
            'CacheProcessorMask': [
                0x4A40,
                ['array', 5, ['unsigned long long']],
            ],
            'PackageProcessorSet': [0x4A68, ['_KAFFINITY_EX']],
            'CoreProcessorSet': [0x4A90, ['unsigned long long']],
            'PebsIndexAddress': [0x4A98, ['pointer64', ['void']]],
            'PrcbPad93': [0x4AA0, ['array', 12, ['unsigned long long']]],
            'SpinLockAcquireCount': [0x4B00, ['unsigned long']],
            'SpinLockContentionCount': [0x4B04, ['unsigned long']],
            'SpinLockSpinCount': [0x4B08, ['unsigned long']],
            'IpiSendRequestBroadcastCount': [0x4B0C, ['unsigned long']],
            'IpiSendRequestRoutineCount': [0x4B10, ['unsigned long']],
            'IpiSendSoftwareInterruptCount': [0x4B14, ['unsigned long']],
            'ExInitializeResourceCount': [0x4B18, ['unsigned long']],
            'ExReInitializeResourceCount': [0x4B1C, ['unsigned long']],
            'ExDeleteResourceCount': [0x4B20, ['unsigned long']],
            'ExecutiveResourceAcquiresCount': [0x4B24, ['unsigned long']],
            'ExecutiveResourceContentionsCount': [0x4B28, ['unsigned long']],
            'ExecutiveResourceReleaseExclusiveCount': [
                0x4B2C,
                ['unsigned long'],
            ],
            'ExecutiveResourceReleaseSharedCount': [0x4B30, ['unsigned long']],
            'ExecutiveResourceConvertsCount': [0x4B34, ['unsigned long']],
            'ExAcqResExclusiveAttempts': [0x4B38, ['unsigned long']],
            'ExAcqResExclusiveAcquiresExclusive': [0x4B3C, ['unsigned long']],
            'ExAcqResExclusiveAcquiresExclusiveRecursive': [
                0x4B40,
                ['unsigned long'],
            ],
            'ExAcqResExclusiveWaits': [0x4B44, ['unsigned long']],
            'ExAcqResExclusiveNotAcquires': [0x4B48, ['unsigned long']],
            'ExAcqResSharedAttempts': [0x4B4C, ['unsigned long']],
            'ExAcqResSharedAcquiresExclusive': [0x4B50, ['unsigned long']],
            'ExAcqResSharedAcquiresShared': [0x4B54, ['unsigned long']],
            'ExAcqResSharedAcquiresSharedRecursive': [
                0x4B58,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaits': [0x4B5C, ['unsigned long']],
            'ExAcqResSharedNotAcquires': [0x4B60, ['unsigned long']],
            'ExAcqResSharedStarveExclusiveAttempts': [
                0x4B64,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveAcquiresExclusive': [
                0x4B68,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveAcquiresShared': [
                0x4B6C,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveAcquiresSharedRecursive': [
                0x4B70,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveWaits': [0x4B74, ['unsigned long']],
            'ExAcqResSharedStarveExclusiveNotAcquires': [
                0x4B78,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAttempts': [
                0x4B7C,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAcquiresExclusive': [
                0x4B80,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAcquiresShared': [
                0x4B84,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive': [
                0x4B88,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveWaits': [0x4B8C, ['unsigned long']],
            'ExAcqResSharedWaitForExclusiveNotAcquires': [
                0x4B90,
                ['unsigned long'],
            ],
            'ExSetResOwnerPointerExclusive': [0x4B94, ['unsigned long']],
            'ExSetResOwnerPointerSharedNew': [0x4B98, ['unsigned long']],
            'ExSetResOwnerPointerSharedOld': [0x4B9C, ['unsigned long']],
            'ExTryToAcqExclusiveAttempts': [0x4BA0, ['unsigned long']],
            'ExTryToAcqExclusiveAcquires': [0x4BA4, ['unsigned long']],
            'ExBoostExclusiveOwner': [0x4BA8, ['unsigned long']],
            'ExBoostSharedOwners': [0x4BAC, ['unsigned long']],
            'ExEtwSynchTrackingNotificationsCount': [
                0x4BB0,
                ['unsigned long'],
            ],
            'ExEtwSynchTrackingNotificationsAccountedCount': [
                0x4BB4,
                ['unsigned long'],
            ],
            'VendorString': [0x4BB8, ['array', 13, ['unsigned char']]],
            'PrcbPad10': [0x4BC5, ['array', 3, ['unsigned char']]],
            'FeatureBits': [0x4BC8, ['unsigned long']],
            'UpdateSignature': [0x4BD0, ['_LARGE_INTEGER']],
            'Context': [0x4BD8, ['pointer64', ['_CONTEXT']]],
            'ContextFlags': [0x4BE0, ['unsigned long']],
            'ExtendedState': [0x4BE8, ['pointer64', ['_XSAVE_AREA']]],
            'Mailbox': [0x4C00, ['pointer64', ['_REQUEST_MAILBOX']]],
            'RequestMailbox': [0x4C80, ['array', 1, ['_REQUEST_MAILBOX']]],
        },
    ],
    '_SINGLE_LIST_ENTRY32': [
        0x4,
        {
            'Next': [0x0, ['unsigned long']],
        },
    ],
    '_KTHREAD': [
        0x368,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'CycleTime': [0x18, ['unsigned long long']],
            'QuantumTarget': [0x20, ['unsigned long long']],
            'InitialStack': [0x28, ['pointer64', ['void']]],
            'StackLimit': [0x30, ['pointer64', ['void']]],
            'KernelStack': [0x38, ['pointer64', ['void']]],
            'ThreadLock': [0x40, ['unsigned long long']],
            'WaitRegister': [0x48, ['_KWAIT_STATUS_REGISTER']],
            'Running': [0x49, ['unsigned char']],
            'Alerted': [0x4A, ['array', 2, ['unsigned char']]],
            'KernelStackResident': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReadyTransition': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessReadyQueue': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WaitNext': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SystemAffinityActive': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Alertable': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'GdiFlushActive': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'UserStackWalkActive': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ApcInterruptRequest': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'ForceDeferSchedule': [
                0x4C,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'QuantumEndMigrate': [
                0x4C,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'UmsDirectedSwitchEnable': [
                0x4C,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'TimerActive': [
                0x4C,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'SystemThread': [
                0x4C,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved': [
                0x4C,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'MiscFlags': [0x4C, ['long']],
            'ApcState': [0x50, ['_KAPC_STATE']],
            'ApcStateFill': [0x50, ['array', 43, ['unsigned char']]],
            'Priority': [0x7B, ['unsigned char']],
            'NextProcessor': [0x7C, ['unsigned long']],
            'DeferredProcessor': [0x80, ['unsigned long']],
            'ApcQueueLock': [0x88, ['unsigned long long']],
            'WaitStatus': [0x90, ['long long']],
            'WaitBlockList': [0x98, ['pointer64', ['_KWAIT_BLOCK']]],
            'WaitListEntry': [0xA0, ['_LIST_ENTRY']],
            'SwapListEntry': [0xA0, ['_SINGLE_LIST_ENTRY']],
            'Queue': [0xB0, ['pointer64', ['_KQUEUE']]],
            'Teb': [0xB8, ['pointer64', ['void']]],
            'Timer': [0xC0, ['_KTIMER']],
            'AutoAlignment': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DisableBoost': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'EtwStackTraceApc1Inserted': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'EtwStackTraceApc2Inserted': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'CalloutActive': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ApcQueueable': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'EnableStackSwap': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'GuiThread': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'UmsPerformingSyscall': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'VdmSafe': [
                0x100,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'UmsDispatched': [
                0x100,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedFlags': [
                0x100,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ThreadFlags': [0x100, ['long']],
            'Spare0': [0x104, ['unsigned long']],
            'WaitBlock': [0x108, ['array', 4, ['_KWAIT_BLOCK']]],
            'WaitBlockFill4': [0x108, ['array', 44, ['unsigned char']]],
            'ContextSwitches': [0x134, ['unsigned long']],
            'WaitBlockFill5': [0x108, ['array', 92, ['unsigned char']]],
            'State': [0x164, ['unsigned char']],
            'NpxState': [0x165, ['unsigned char']],
            'WaitIrql': [0x166, ['unsigned char']],
            'WaitMode': [0x167, ['unsigned char']],
            'WaitBlockFill6': [0x108, ['array', 140, ['unsigned char']]],
            'WaitTime': [0x194, ['unsigned long']],
            'WaitBlockFill7': [0x108, ['array', 168, ['unsigned char']]],
            'TebMappedLowVa': [0x1B0, ['pointer64', ['void']]],
            'Ucb': [0x1B8, ['pointer64', ['_UMS_CONTROL_BLOCK']]],
            'WaitBlockFill8': [0x108, ['array', 188, ['unsigned char']]],
            'KernelApcDisable': [0x1C4, ['short']],
            'SpecialApcDisable': [0x1C6, ['short']],
            'CombinedApcDisable': [0x1C4, ['unsigned long']],
            'QueueListEntry': [0x1C8, ['_LIST_ENTRY']],
            'TrapFrame': [0x1D8, ['pointer64', ['_KTRAP_FRAME']]],
            'FirstArgument': [0x1E0, ['pointer64', ['void']]],
            'CallbackStack': [0x1E8, ['pointer64', ['void']]],
            'CallbackDepth': [0x1E8, ['unsigned long long']],
            'ApcStateIndex': [0x1F0, ['unsigned char']],
            'BasePriority': [0x1F1, ['unsigned char']],
            'PriorityDecrement': [0x1F2, ['unsigned char']],
            'ForegroundBoost': [
                0x1F2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'UnusualBoost': [
                0x1F2,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Preempted': [0x1F3, ['unsigned char']],
            'AdjustReason': [0x1F4, ['unsigned char']],
            'AdjustIncrement': [0x1F5, ['unsigned char']],
            'PreviousMode': [0x1F6, ['unsigned char']],
            'Saturation': [0x1F7, ['unsigned char']],
            'SystemCallNumber': [0x1F8, ['unsigned long']],
            'FreezeCount': [0x1FC, ['unsigned long']],
            'UserAffinity': [0x200, ['_GROUP_AFFINITY']],
            'Process': [0x210, ['pointer64', ['_KPROCESS']]],
            'Affinity': [0x218, ['_GROUP_AFFINITY']],
            'IdealProcessor': [0x228, ['unsigned long']],
            'UserIdealProcessor': [0x22C, ['unsigned long']],
            'ApcStatePointer': [
                0x230,
                ['array', 2, ['pointer64', ['_KAPC_STATE']]],
            ],
            'SavedApcState': [0x240, ['_KAPC_STATE']],
            'SavedApcStateFill': [0x240, ['array', 43, ['unsigned char']]],
            'WaitReason': [0x26B, ['unsigned char']],
            'SuspendCount': [0x26C, ['unsigned char']],
            'Spare1': [0x26D, ['unsigned char']],
            'CodePatchInProgress': [0x26E, ['unsigned char']],
            'Win32Thread': [0x270, ['pointer64', ['void']]],
            'StackBase': [0x278, ['pointer64', ['void']]],
            'SuspendApc': [0x280, ['_KAPC']],
            'SuspendApcFill0': [0x280, ['array', 1, ['unsigned char']]],
            'ResourceIndex': [0x281, ['unsigned char']],
            'SuspendApcFill1': [0x280, ['array', 3, ['unsigned char']]],
            'QuantumReset': [0x283, ['unsigned char']],
            'SuspendApcFill2': [0x280, ['array', 4, ['unsigned char']]],
            'KernelTime': [0x284, ['unsigned long']],
            'SuspendApcFill3': [0x280, ['array', 64, ['unsigned char']]],
            'WaitPrcb': [0x2C0, ['pointer64', ['_KPRCB']]],
            'SuspendApcFill4': [0x280, ['array', 72, ['unsigned char']]],
            'LegoData': [0x2C8, ['pointer64', ['void']]],
            'SuspendApcFill5': [0x280, ['array', 83, ['unsigned char']]],
            'LargeStack': [0x2D3, ['unsigned char']],
            'UserTime': [0x2D4, ['unsigned long']],
            'SuspendSemaphore': [0x2D8, ['_KSEMAPHORE']],
            'SuspendSemaphorefill': [0x2D8, ['array', 28, ['unsigned char']]],
            'SListFaultCount': [0x2F4, ['unsigned long']],
            'ThreadListEntry': [0x2F8, ['_LIST_ENTRY']],
            'MutantListHead': [0x308, ['_LIST_ENTRY']],
            'SListFaultAddress': [0x318, ['pointer64', ['void']]],
            'ReadOperationCount': [0x320, ['long long']],
            'WriteOperationCount': [0x328, ['long long']],
            'OtherOperationCount': [0x330, ['long long']],
            'ReadTransferCount': [0x338, ['long long']],
            'WriteTransferCount': [0x340, ['long long']],
            'OtherTransferCount': [0x348, ['long long']],
            'ThreadCounters': [0x350, ['pointer64', ['_KTHREAD_COUNTERS']]],
            'StateSaveArea': [0x358, ['pointer64', ['_XSAVE_FORMAT']]],
            'XStateSave': [0x360, ['pointer64', ['_XSTATE_SAVE']]],
        },
    ],
    '_KERNEL_STACK_CONTROL': [
        0x50,
        {
            'Current': [0x0, ['_KERNEL_STACK_SEGMENT']],
            'Previous': [0x28, ['_KERNEL_STACK_SEGMENT']],
        },
    ],
    '_UMS_CONTROL_BLOCK': [
        0x98,
        {
            'UmsContext': [0x0, ['pointer64', ['_RTL_UMS_CONTEXT']]],
            'CompletionListEntry': [
                0x8,
                ['pointer64', ['_SINGLE_LIST_ENTRY']],
            ],
            'CompletionListEvent': [0x10, ['pointer64', ['_KEVENT']]],
            'ServiceSequenceNumber': [0x18, ['unsigned long']],
            'UmsQueue': [0x20, ['_KQUEUE']],
            'QueueEntry': [0x60, ['_LIST_ENTRY']],
            'YieldingUmsContext': [0x70, ['pointer64', ['_RTL_UMS_CONTEXT']]],
            'YieldingParam': [0x78, ['pointer64', ['void']]],
            'UmsTeb': [0x80, ['pointer64', ['void']]],
            'PrimaryFlags': [0x88, ['unsigned long']],
            'UmsContextHeaderReady': [
                0x88,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'UmsAssociatedQueue': [0x20, ['pointer64', ['_KQUEUE']]],
            'UmsQueueListEntry': [0x28, ['pointer64', ['_LIST_ENTRY']]],
            'UmsContextHeader': [
                0x30,
                ['pointer64', ['_KUMS_CONTEXT_HEADER']],
            ],
            'UmsWaitGate': [0x38, ['_KGATE']],
            'StagingArea': [0x50, ['pointer64', ['void']]],
            'Flags': [0x58, ['long']],
            'UmsForceQueueTermination': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'UmsAssociatedQueueUsed': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'UmsThreadParked': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'UmsPrimaryDeliveredContext': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'UmsPerformingSingleStep': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'TebSelector': [0x90, ['unsigned short']],
        },
    ],
    '_KSPIN_LOCK_QUEUE': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_KSPIN_LOCK_QUEUE']]],
            'Lock': [0x8, ['pointer64', ['unsigned long long']]],
        },
    ],
    '_FAST_MUTEX': [
        0x38,
        {
            'Count': [0x0, ['long']],
            'Owner': [0x8, ['pointer64', ['_KTHREAD']]],
            'Contention': [0x10, ['unsigned long']],
            'Event': [0x18, ['_KEVENT']],
            'OldIrql': [0x30, ['unsigned long']],
        },
    ],
    '_KEVENT': [
        0x18,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '__unnamed_11c8': [
        0x10,
        {
            'Depth': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Sequence': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=25,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NextEntry': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=25,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'HeaderType': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Init': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=61,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Region': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=61,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '__unnamed_11cd': [
        0x10,
        {
            'Depth': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Sequence': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'HeaderType': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Init': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NextEntry': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '__unnamed_11d0': [
        0x10,
        {
            'Depth': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Sequence': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'HeaderType': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NextEntry': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_SLIST_HEADER': [
        0x10,
        {
            'Alignment': [0x0, ['unsigned long long']],
            'Region': [0x8, ['unsigned long long']],
            'Header8': [0x0, ['__unnamed_11c8']],
            'Header16': [0x0, ['__unnamed_11cd']],
            'HeaderX64': [0x0, ['__unnamed_11d0']],
        },
    ],
    '_LOOKASIDE_LIST_EX': [
        0x60,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE_POOL']],
        },
    ],
    '_SLIST_ENTRY': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
        },
    ],
    '_NPAGED_LOOKASIDE_LIST': [
        0x80,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE']],
        },
    ],
    '_PAGED_LOOKASIDE_LIST': [
        0x80,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE']],
        },
    ],
    '_QUAD': [
        0x8,
        {
            'UseThisFieldToCopy': [0x0, ['long long']],
            'DoNotUseThisField': [0x0, ['double']],
        },
    ],
    '_IO_STATUS_BLOCK': [
        0x10,
        {
            'Status': [0x0, ['long']],
            'Pointer': [0x0, ['pointer64', ['void']]],
            'Information': [0x8, ['unsigned long long']],
        },
    ],
    '_IO_STATUS_BLOCK32': [
        0x8,
        {
            'Status': [0x0, ['long']],
            'Information': [0x4, ['unsigned long']],
        },
    ],
    '_EX_PUSH_LOCK': [
        0x8,
        {
            'Locked': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Waiting': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Waking': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'MultipleShared': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Shared': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Value': [0x0, ['unsigned long long']],
            'Ptr': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_PROCESSOR_NUMBER': [
        0x4,
        {
            'Group': [0x0, ['unsigned short']],
            'Number': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
        },
    ],
    '_EX_PUSH_LOCK_CACHE_AWARE': [
        0x100,
        {
            'Locks': [0x0, ['array', 32, ['pointer64', ['_EX_PUSH_LOCK']]]],
        },
    ],
    '_PP_LOOKASIDE_LIST': [
        0x10,
        {
            'P': [0x0, ['pointer64', ['_GENERAL_LOOKASIDE']]],
            'L': [0x8, ['pointer64', ['_GENERAL_LOOKASIDE']]],
        },
    ],
    '_GENERAL_LOOKASIDE': [
        0x80,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
            'SingleListHead': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Depth': [0x10, ['unsigned short']],
            'MaximumDepth': [0x12, ['unsigned short']],
            'TotalAllocates': [0x14, ['unsigned long']],
            'AllocateMisses': [0x18, ['unsigned long']],
            'AllocateHits': [0x18, ['unsigned long']],
            'TotalFrees': [0x1C, ['unsigned long']],
            'FreeMisses': [0x20, ['unsigned long']],
            'FreeHits': [0x20, ['unsigned long']],
            'Type': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPool',
                            1: 'PagedPool',
                            2: 'NonPagedPoolMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'Tag': [0x28, ['unsigned long']],
            'Size': [0x2C, ['unsigned long']],
            'AllocateEx': [0x30, ['pointer64', ['void']]],
            'Allocate': [0x30, ['pointer64', ['void']]],
            'FreeEx': [0x38, ['pointer64', ['void']]],
            'Free': [0x38, ['pointer64', ['void']]],
            'ListEntry': [0x40, ['_LIST_ENTRY']],
            'LastTotalAllocates': [0x50, ['unsigned long']],
            'LastAllocateMisses': [0x54, ['unsigned long']],
            'LastAllocateHits': [0x54, ['unsigned long']],
            'Future': [0x58, ['array', 2, ['unsigned long']]],
        },
    ],
    '_EX_FAST_REF': [
        0x8,
        {
            'Object': [0x0, ['pointer64', ['void']]],
            'RefCnt': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Value': [0x0, ['unsigned long long']],
        },
    ],
    '_EX_PUSH_LOCK_WAIT_BLOCK': [
        0x40,
        {
            'WakeEvent': [0x0, ['_KEVENT']],
            'Next': [0x18, ['pointer64', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'Last': [0x20, ['pointer64', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'Previous': [0x28, ['pointer64', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'ShareCount': [0x30, ['long']],
            'Flags': [0x34, ['long']],
        },
    ],
    '_ETHREAD': [
        0x4A8,
        {
            'Tcb': [0x0, ['_KTHREAD']],
            'CreateTime': [0x368, ['_LARGE_INTEGER']],
            'ExitTime': [0x370, ['_LARGE_INTEGER']],
            'KeyedWaitChain': [0x370, ['_LIST_ENTRY']],
            'ExitStatus': [0x380, ['long']],
            'PostBlockList': [0x388, ['_LIST_ENTRY']],
            'ForwardLinkShadow': [0x388, ['pointer64', ['void']]],
            'StartAddress': [0x390, ['pointer64', ['void']]],
            'TerminationPort': [0x398, ['pointer64', ['_TERMINATION_PORT']]],
            'ReaperLink': [0x398, ['pointer64', ['_ETHREAD']]],
            'KeyedWaitValue': [0x398, ['pointer64', ['void']]],
            'ActiveTimerListLock': [0x3A0, ['unsigned long long']],
            'ActiveTimerListHead': [0x3A8, ['_LIST_ENTRY']],
            'Cid': [0x3B8, ['_CLIENT_ID']],
            'KeyedWaitSemaphore': [0x3C8, ['_KSEMAPHORE']],
            'AlpcWaitSemaphore': [0x3C8, ['_KSEMAPHORE']],
            'ClientSecurity': [0x3E8, ['_PS_CLIENT_SECURITY_CONTEXT']],
            'IrpList': [0x3F0, ['_LIST_ENTRY']],
            'TopLevelIrp': [0x400, ['unsigned long long']],
            'DeviceToVerify': [0x408, ['pointer64', ['_DEVICE_OBJECT']]],
            'CpuQuotaApc': [0x410, ['pointer64', ['_PSP_CPU_QUOTA_APC']]],
            'Win32StartAddress': [0x418, ['pointer64', ['void']]],
            'LegacyPowerObject': [0x420, ['pointer64', ['void']]],
            'ThreadListEntry': [0x428, ['_LIST_ENTRY']],
            'RundownProtect': [0x438, ['_EX_RUNDOWN_REF']],
            'ThreadLock': [0x440, ['_EX_PUSH_LOCK']],
            'ReadClusterSize': [0x448, ['unsigned long']],
            'MmLockOrdering': [0x44C, ['long']],
            'CrossThreadFlags': [0x450, ['unsigned long']],
            'Terminated': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ThreadInserted': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HideFromDebugger': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ActiveImpersonationInfo': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'HardErrorsAreDisabled': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'BreakOnTermination': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SkipCreationMsg': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SkipTerminationMsg': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'CopyTokenOnOpen': [
                0x450,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'ThreadIoPriority': [
                0x450,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'ThreadPagePriority': [
                0x450,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'RundownFail': [
                0x450,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'NeedsWorkingSetAging': [
                0x450,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'SameThreadPassiveFlags': [0x454, ['unsigned long']],
            'ActiveExWorker': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ExWorkerCanWaitUser': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'MemoryMaker': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ClonedThread': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'KeyedEventInUse': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'RateApcState': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SelfTerminate': [
                0x454,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SameThreadApcFlags': [0x458, ['unsigned long']],
            'Spare': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'StartAddressInvalid': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'EtwPageFaultCalloutActive': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetExclusive': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetShared': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemCacheWorkingSetExclusive': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemCacheWorkingSetShared': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetExclusive': [
                0x458,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetShared': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessAddressSpaceExclusive': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessAddressSpaceShared': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'SuppressSymbolLoad': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Prefetching': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsDynamicMemoryShared': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsChangeControlAreaExclusive': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsChangeControlAreaShared': [
                0x459,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OwnsPagedPoolWorkingSetExclusive': [
                0x45A,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'OwnsPagedPoolWorkingSetShared': [
                0x45A,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemPtesWorkingSetExclusive': [
                0x45A,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemPtesWorkingSetShared': [
                0x45A,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'TrimTrigger': [
                0x45A,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Spare1': [
                0x45A,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'PriorityRegionActive': [0x45B, ['unsigned char']],
            'CacheManagerActive': [0x45C, ['unsigned char']],
            'DisablePageFaultClustering': [0x45D, ['unsigned char']],
            'ActiveFaultCount': [0x45E, ['unsigned char']],
            'LockOrderState': [0x45F, ['unsigned char']],
            'AlpcMessageId': [0x460, ['unsigned long long']],
            'AlpcMessage': [0x468, ['pointer64', ['void']]],
            'AlpcReceiveAttributeSet': [0x468, ['unsigned long']],
            'AlpcWaitListEntry': [0x470, ['_LIST_ENTRY']],
            'CacheManagerCount': [0x480, ['unsigned long']],
            'IoBoostCount': [0x484, ['unsigned long']],
            'IrpListLock': [0x488, ['unsigned long long']],
            'ReservedForSynchTracking': [0x490, ['pointer64', ['void']]],
            'CmCallbackListHead': [0x498, ['_SINGLE_LIST_ENTRY']],
            'KernelStackReference': [0x4A0, ['unsigned long']],
        },
    ],
    '_EPROCESS': [
        0x4E8,
        {
            'Pcb': [0x0, ['_KPROCESS']],
            'ProcessLock': [0x160, ['_EX_PUSH_LOCK']],
            'CreateTime': [0x168, ['_LARGE_INTEGER']],
            'ExitTime': [0x170, ['_LARGE_INTEGER']],
            'RundownProtect': [0x178, ['_EX_RUNDOWN_REF']],
            'UniqueProcessId': [0x180, ['pointer64', ['void']]],
            'ActiveProcessLinks': [0x188, ['_LIST_ENTRY']],
            'ProcessQuotaUsage': [0x198, ['array', 2, ['unsigned long long']]],
            'ProcessQuotaPeak': [0x1A8, ['array', 2, ['unsigned long long']]],
            'CommitCharge': [0x1B8, ['unsigned long long']],
            'QuotaBlock': [0x1C0, ['pointer64', ['_EPROCESS_QUOTA_BLOCK']]],
            'CpuQuotaBlock': [0x1C8, ['pointer64', ['_PS_CPU_QUOTA_BLOCK']]],
            'PeakVirtualSize': [0x1D0, ['unsigned long long']],
            'VirtualSize': [0x1D8, ['unsigned long long']],
            'SessionProcessLinks': [0x1E0, ['_LIST_ENTRY']],
            'DebugPort': [0x1F0, ['pointer64', ['void']]],
            'ExceptionPortData': [0x1F8, ['pointer64', ['void']]],
            'ExceptionPortValue': [0x1F8, ['unsigned long long']],
            'ExceptionPortState': [
                0x1F8,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ObjectTable': [0x200, ['pointer64', ['_HANDLE_TABLE']]],
            'Token': [0x208, ['_EX_FAST_REF']],
            'WorkingSetPage': [0x210, ['unsigned long long']],
            'AddressCreationLock': [0x218, ['_EX_PUSH_LOCK']],
            'RotateInProgress': [0x220, ['pointer64', ['_ETHREAD']]],
            'ForkInProgress': [0x228, ['pointer64', ['_ETHREAD']]],
            'HardwareTrigger': [0x230, ['unsigned long long']],
            'PhysicalVadRoot': [0x238, ['pointer64', ['_MM_AVL_TABLE']]],
            'CloneRoot': [0x240, ['pointer64', ['void']]],
            'NumberOfPrivatePages': [0x248, ['unsigned long long']],
            'NumberOfLockedPages': [0x250, ['unsigned long long']],
            'Win32Process': [0x258, ['pointer64', ['void']]],
            'Job': [0x260, ['pointer64', ['_EJOB']]],
            'SectionObject': [0x268, ['pointer64', ['void']]],
            'SectionBaseAddress': [0x270, ['pointer64', ['void']]],
            'Cookie': [0x278, ['unsigned long']],
            'UmsScheduledThreads': [0x27C, ['unsigned long']],
            'WorkingSetWatch': [0x280, ['pointer64', ['_PAGEFAULT_HISTORY']]],
            'Win32WindowStation': [0x288, ['pointer64', ['void']]],
            'InheritedFromUniqueProcessId': [0x290, ['pointer64', ['void']]],
            'LdtInformation': [0x298, ['pointer64', ['void']]],
            'Spare': [0x2A0, ['pointer64', ['void']]],
            'ConsoleHostProcess': [0x2A8, ['unsigned long long']],
            'DeviceMap': [0x2B0, ['pointer64', ['void']]],
            'EtwDataSource': [0x2B8, ['pointer64', ['void']]],
            'FreeTebHint': [0x2C0, ['pointer64', ['void']]],
            'FreeUmsTebHint': [0x2C8, ['pointer64', ['void']]],
            'PageDirectoryPte': [0x2D0, ['_HARDWARE_PTE']],
            'Filler': [0x2D0, ['unsigned long long']],
            'Session': [0x2D8, ['pointer64', ['void']]],
            'ImageFileName': [0x2E0, ['array', 15, ['unsigned char']]],
            'PriorityClass': [0x2EF, ['unsigned char']],
            'JobLinks': [0x2F0, ['_LIST_ENTRY']],
            'LockedPagesList': [0x300, ['pointer64', ['void']]],
            'ThreadListHead': [0x308, ['_LIST_ENTRY']],
            'SecurityPort': [0x318, ['pointer64', ['void']]],
            'Wow64Process': [0x320, ['pointer64', ['void']]],
            'ActiveThreads': [0x328, ['unsigned long']],
            'ImagePathHash': [0x32C, ['unsigned long']],
            'DefaultHardErrorProcessing': [0x330, ['unsigned long']],
            'LastThreadExitStatus': [0x334, ['long']],
            'Peb': [0x338, ['pointer64', ['_PEB']]],
            'PrefetchTrace': [0x340, ['_EX_FAST_REF']],
            'ReadOperationCount': [0x348, ['_LARGE_INTEGER']],
            'WriteOperationCount': [0x350, ['_LARGE_INTEGER']],
            'OtherOperationCount': [0x358, ['_LARGE_INTEGER']],
            'ReadTransferCount': [0x360, ['_LARGE_INTEGER']],
            'WriteTransferCount': [0x368, ['_LARGE_INTEGER']],
            'OtherTransferCount': [0x370, ['_LARGE_INTEGER']],
            'CommitChargeLimit': [0x378, ['unsigned long long']],
            'CommitChargePeak': [0x380, ['unsigned long long']],
            'AweInfo': [0x388, ['pointer64', ['void']]],
            'SeAuditProcessCreationInfo': [
                0x390,
                ['_SE_AUDIT_PROCESS_CREATION_INFO'],
            ],
            'Vm': [0x398, ['_MMSUPPORT']],
            'MmProcessLinks': [0x420, ['_LIST_ENTRY']],
            'HighestUserAddress': [0x430, ['pointer64', ['void']]],
            'ModifiedPageCount': [0x438, ['unsigned long']],
            'Flags2': [0x43C, ['unsigned long']],
            'JobNotReallyActive': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AccountingFolded': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'NewProcessReported': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ExitProcessReported': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ReportCommitChanges': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'LastReportMemory': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'ReportPhysicalPageChanges': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'HandleTableRundown': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'NeedsHandleRundown': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'RefTraceEnabled': [
                0x43C,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'NumaAware': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'ProtectedProcess': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultPagePriority': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'PrimaryTokenFrozen': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessVerifierTarget': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'StackRandomizationDisabled': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'AffinityPermanent': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'AffinityUpdateEnable': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'PropagateNode': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'ExplicitAffinity': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare1': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'ForceRelocateImages': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'DisallowStrippedImages': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'LowVaAccessible': [
                0x43C,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'Flags': [0x440, ['unsigned long']],
            'CreateReported': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoDebugInherit': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessExiting': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessDelete': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow64SplitPages': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'VmDeleted': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'OutswapEnabled': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Outswapped': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ForkFailed': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Wow64VaSpace4Gb': [
                0x440,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'AddressSpaceInitialized': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolution': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'BreakOnTermination': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'DeprioritizeViews': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteWatch': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInSession': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'OverrideAddressSpace': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'HasAddressSpace': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'LaunchPrefetched': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'InjectInpageErrors': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'VmTopDown': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageNotifyDone': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'PdeUpdateNeeded': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'VdmAllowed': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'CrossSessionCreate': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInserted': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultIoPriority': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessSelfDelete': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolutionLink': [
                0x440,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ExitStatus': [0x444, ['long']],
            'VadRoot': [0x448, ['_MM_AVL_TABLE']],
            'AlpcContext': [0x488, ['_ALPC_PROCESS_CONTEXT']],
            'TimerResolutionLink': [0x4A8, ['_LIST_ENTRY']],
            'RequestedTimerResolution': [0x4B8, ['unsigned long']],
            'ActiveThreadsHighWatermark': [0x4BC, ['unsigned long']],
            'SmallestTimerResolution': [0x4C0, ['unsigned long']],
            'TimerResolutionStackRecord': [
                0x4C8,
                ['pointer64', ['_PO_DIAG_STACK_RECORD']],
            ],
            'SequenceNumber': [0x4D0, ['unsigned long long']],
            'CreateInterruptTime': [0x4D8, ['unsigned long long']],
            'CreateUnbiasedInterruptTime': [0x4E0, ['unsigned long long']],
        },
    ],
    '_KPROCESS': [
        0x160,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'ProfileListHead': [0x18, ['_LIST_ENTRY']],
            'DirectoryTableBase': [0x28, ['unsigned long long']],
            'ThreadListHead': [0x30, ['_LIST_ENTRY']],
            'ProcessLock': [0x40, ['unsigned long long']],
            'Affinity': [0x48, ['_KAFFINITY_EX']],
            'ReadyListHead': [0x70, ['_LIST_ENTRY']],
            'SwapListEntry': [0x80, ['_SINGLE_LIST_ENTRY']],
            'ActiveProcessors': [0x88, ['_KAFFINITY_EX']],
            'AutoAlignment': [
                0xB0,
                ['BitField', dict(start_bit=0, end_bit=1, native_type='long')],
            ],
            'DisableBoost': [
                0xB0,
                ['BitField', dict(start_bit=1, end_bit=2, native_type='long')],
            ],
            'DisableQuantum': [
                0xB0,
                ['BitField', dict(start_bit=2, end_bit=3, native_type='long')],
            ],
            'ActiveGroupsMask': [
                0xB0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags': [
                0xB0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=32, native_type='long'),
                ],
            ],
            'ProcessFlags': [0xB0, ['long']],
            'BasePriority': [0xB4, ['unsigned char']],
            'QuantumReset': [0xB5, ['unsigned char']],
            'Visited': [0xB6, ['unsigned char']],
            'Unused3': [0xB7, ['unsigned char']],
            'ThreadSeed': [0xB8, ['array', 4, ['unsigned long']]],
            'IdealNode': [0xC8, ['array', 4, ['unsigned short']]],
            'IdealGlobalNode': [0xD0, ['unsigned short']],
            'Flags': [0xD2, ['_KEXECUTE_OPTIONS']],
            'Unused1': [0xD3, ['unsigned char']],
            'Unused2': [0xD4, ['unsigned long']],
            'Unused4': [0xD8, ['unsigned long']],
            'StackCount': [0xDC, ['_KSTACK_COUNT']],
            'ProcessListEntry': [0xE0, ['_LIST_ENTRY']],
            'CycleTime': [0xF0, ['unsigned long long']],
            'KernelTime': [0xF8, ['unsigned long']],
            'UserTime': [0xFC, ['unsigned long']],
            'InstrumentationCallback': [0x100, ['pointer64', ['void']]],
            'LdtSystemDescriptor': [0x108, ['_KGDTENTRY64']],
            'LdtBaseAddress': [0x118, ['pointer64', ['void']]],
            'LdtProcessLock': [0x120, ['_KGUARDED_MUTEX']],
            'LdtFreeSelectorHint': [0x158, ['unsigned short']],
            'LdtTableLength': [0x15A, ['unsigned short']],
        },
    ],
    '__unnamed_12d4': [
        0x2C,
        {
            'InitialPrivilegeSet': [0x0, ['_INITIAL_PRIVILEGE_SET']],
            'PrivilegeSet': [0x0, ['_PRIVILEGE_SET']],
        },
    ],
    '_ACCESS_STATE': [
        0xA0,
        {
            'OperationID': [0x0, ['_LUID']],
            'SecurityEvaluated': [0x8, ['unsigned char']],
            'GenerateAudit': [0x9, ['unsigned char']],
            'GenerateOnClose': [0xA, ['unsigned char']],
            'PrivilegesAllocated': [0xB, ['unsigned char']],
            'Flags': [0xC, ['unsigned long']],
            'RemainingDesiredAccess': [0x10, ['unsigned long']],
            'PreviouslyGrantedAccess': [0x14, ['unsigned long']],
            'OriginalDesiredAccess': [0x18, ['unsigned long']],
            'SubjectSecurityContext': [0x20, ['_SECURITY_SUBJECT_CONTEXT']],
            'SecurityDescriptor': [0x40, ['pointer64', ['void']]],
            'AuxData': [0x48, ['pointer64', ['void']]],
            'Privileges': [0x50, ['__unnamed_12d4']],
            'AuditPrivileges': [0x7C, ['unsigned char']],
            'ObjectName': [0x80, ['_UNICODE_STRING']],
            'ObjectTypeName': [0x90, ['_UNICODE_STRING']],
        },
    ],
    '_AUX_ACCESS_DATA': [
        0xD8,
        {
            'PrivilegesUsed': [0x0, ['pointer64', ['_PRIVILEGE_SET']]],
            'GenericMapping': [0x8, ['_GENERIC_MAPPING']],
            'AccessesToAudit': [0x18, ['unsigned long']],
            'MaximumAuditMask': [0x1C, ['unsigned long']],
            'TransactionId': [0x20, ['_GUID']],
            'NewSecurityDescriptor': [0x30, ['pointer64', ['void']]],
            'ExistingSecurityDescriptor': [0x38, ['pointer64', ['void']]],
            'ParentSecurityDescriptor': [0x40, ['pointer64', ['void']]],
            'DeRefSecurityDescriptor': [0x48, ['pointer64', ['void']]],
            'SDLock': [0x50, ['pointer64', ['void']]],
            'AccessReasons': [0x58, ['_ACCESS_REASONS']],
        },
    ],
    '__unnamed_12e3': [
        0x8,
        {
            'MasterIrp': [0x0, ['pointer64', ['_IRP']]],
            'IrpCount': [0x0, ['long']],
            'SystemBuffer': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_12e8': [
        0x10,
        {
            'UserApcRoutine': [0x0, ['pointer64', ['void']]],
            'IssuingProcess': [0x0, ['pointer64', ['void']]],
            'UserApcContext': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_12ea': [
        0x10,
        {
            'AsynchronousParameters': [0x0, ['__unnamed_12e8']],
            'AllocationSize': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_12f5': [
        0x50,
        {
            'DeviceQueueEntry': [0x0, ['_KDEVICE_QUEUE_ENTRY']],
            'DriverContext': [0x0, ['array', 4, ['pointer64', ['void']]]],
            'Thread': [0x20, ['pointer64', ['_ETHREAD']]],
            'AuxiliaryBuffer': [0x28, ['pointer64', ['unsigned char']]],
            'ListEntry': [0x30, ['_LIST_ENTRY']],
            'CurrentStackLocation': [
                0x40,
                ['pointer64', ['_IO_STACK_LOCATION']],
            ],
            'PacketType': [0x40, ['unsigned long']],
            'OriginalFileObject': [0x48, ['pointer64', ['_FILE_OBJECT']]],
        },
    ],
    '__unnamed_12f7': [
        0x58,
        {
            'Overlay': [0x0, ['__unnamed_12f5']],
            'Apc': [0x0, ['_KAPC']],
            'CompletionKey': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_IRP': [
        0xD0,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['unsigned short']],
            'MdlAddress': [0x8, ['pointer64', ['_MDL']]],
            'Flags': [0x10, ['unsigned long']],
            'AssociatedIrp': [0x18, ['__unnamed_12e3']],
            'ThreadListEntry': [0x20, ['_LIST_ENTRY']],
            'IoStatus': [0x30, ['_IO_STATUS_BLOCK']],
            'RequestorMode': [0x40, ['unsigned char']],
            'PendingReturned': [0x41, ['unsigned char']],
            'StackCount': [0x42, ['unsigned char']],
            'CurrentLocation': [0x43, ['unsigned char']],
            'Cancel': [0x44, ['unsigned char']],
            'CancelIrql': [0x45, ['unsigned char']],
            'ApcEnvironment': [0x46, ['unsigned char']],
            'AllocationFlags': [0x47, ['unsigned char']],
            'UserIosb': [0x48, ['pointer64', ['_IO_STATUS_BLOCK']]],
            'UserEvent': [0x50, ['pointer64', ['_KEVENT']]],
            'Overlay': [0x58, ['__unnamed_12ea']],
            'CancelRoutine': [0x68, ['pointer64', ['void']]],
            'UserBuffer': [0x70, ['pointer64', ['void']]],
            'Tail': [0x78, ['__unnamed_12f7']],
        },
    ],
    '__unnamed_12fe': [
        0x20,
        {
            'SecurityContext': [0x0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x8, ['unsigned long']],
            'FileAttributes': [0x10, ['unsigned short']],
            'ShareAccess': [0x12, ['unsigned short']],
            'EaLength': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1302': [
        0x20,
        {
            'SecurityContext': [0x0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x8, ['unsigned long']],
            'Reserved': [0x10, ['unsigned short']],
            'ShareAccess': [0x12, ['unsigned short']],
            'Parameters': [
                0x18,
                ['pointer64', ['_NAMED_PIPE_CREATE_PARAMETERS']],
            ],
        },
    ],
    '__unnamed_1306': [
        0x20,
        {
            'SecurityContext': [0x0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x8, ['unsigned long']],
            'Reserved': [0x10, ['unsigned short']],
            'ShareAccess': [0x12, ['unsigned short']],
            'Parameters': [
                0x18,
                ['pointer64', ['_MAILSLOT_CREATE_PARAMETERS']],
            ],
        },
    ],
    '__unnamed_1308': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Key': [0x8, ['unsigned long']],
            'ByteOffset': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_130c': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'FileName': [0x8, ['pointer64', ['_UNICODE_STRING']]],
            'FileInformationClass': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'FileDirectoryInformation',
                            2: 'FileFullDirectoryInformation',
                            3: 'FileBothDirectoryInformation',
                            4: 'FileBasicInformation',
                            5: 'FileStandardInformation',
                            6: 'FileInternalInformation',
                            7: 'FileEaInformation',
                            8: 'FileAccessInformation',
                            9: 'FileNameInformation',
                            10: 'FileRenameInformation',
                            11: 'FileLinkInformation',
                            12: 'FileNamesInformation',
                            13: 'FileDispositionInformation',
                            14: 'FilePositionInformation',
                            15: 'FileFullEaInformation',
                            16: 'FileModeInformation',
                            17: 'FileAlignmentInformation',
                            18: 'FileAllInformation',
                            19: 'FileAllocationInformation',
                            20: 'FileEndOfFileInformation',
                            21: 'FileAlternateNameInformation',
                            22: 'FileStreamInformation',
                            23: 'FilePipeInformation',
                            24: 'FilePipeLocalInformation',
                            25: 'FilePipeRemoteInformation',
                            26: 'FileMailslotQueryInformation',
                            27: 'FileMailslotSetInformation',
                            28: 'FileCompressionInformation',
                            29: 'FileObjectIdInformation',
                            30: 'FileCompletionInformation',
                            31: 'FileMoveClusterInformation',
                            32: 'FileQuotaInformation',
                            33: 'FileReparsePointInformation',
                            34: 'FileNetworkOpenInformation',
                            35: 'FileAttributeTagInformation',
                            36: 'FileTrackingInformation',
                            37: 'FileIdBothDirectoryInformation',
                            38: 'FileIdFullDirectoryInformation',
                            39: 'FileValidDataLengthInformation',
                            40: 'FileShortNameInformation',
                            41: 'FileIoCompletionNotificationInformation',
                            42: 'FileIoStatusBlockRangeInformation',
                            43: 'FileIoPriorityHintInformation',
                            44: 'FileSfioReserveInformation',
                            45: 'FileSfioVolumeInformation',
                            46: 'FileHardLinkInformation',
                            47: 'FileProcessIdsUsingFileInformation',
                            48: 'FileNormalizedNameInformation',
                            49: 'FileNetworkPhysicalNameInformation',
                            50: 'FileIdGlobalTxDirectoryInformation',
                            51: 'FileIsRemoteDeviceInformation',
                            52: 'FileAttributeCacheInformation',
                            53: 'FileNumaNodeInformation',
                            54: 'FileStandardLinkInformation',
                            55: 'FileRemoteProtocolInformation',
                            56: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileIndex': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_130e': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'CompletionFilter': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1310': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'FileInformationClass': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'FileDirectoryInformation',
                            2: 'FileFullDirectoryInformation',
                            3: 'FileBothDirectoryInformation',
                            4: 'FileBasicInformation',
                            5: 'FileStandardInformation',
                            6: 'FileInternalInformation',
                            7: 'FileEaInformation',
                            8: 'FileAccessInformation',
                            9: 'FileNameInformation',
                            10: 'FileRenameInformation',
                            11: 'FileLinkInformation',
                            12: 'FileNamesInformation',
                            13: 'FileDispositionInformation',
                            14: 'FilePositionInformation',
                            15: 'FileFullEaInformation',
                            16: 'FileModeInformation',
                            17: 'FileAlignmentInformation',
                            18: 'FileAllInformation',
                            19: 'FileAllocationInformation',
                            20: 'FileEndOfFileInformation',
                            21: 'FileAlternateNameInformation',
                            22: 'FileStreamInformation',
                            23: 'FilePipeInformation',
                            24: 'FilePipeLocalInformation',
                            25: 'FilePipeRemoteInformation',
                            26: 'FileMailslotQueryInformation',
                            27: 'FileMailslotSetInformation',
                            28: 'FileCompressionInformation',
                            29: 'FileObjectIdInformation',
                            30: 'FileCompletionInformation',
                            31: 'FileMoveClusterInformation',
                            32: 'FileQuotaInformation',
                            33: 'FileReparsePointInformation',
                            34: 'FileNetworkOpenInformation',
                            35: 'FileAttributeTagInformation',
                            36: 'FileTrackingInformation',
                            37: 'FileIdBothDirectoryInformation',
                            38: 'FileIdFullDirectoryInformation',
                            39: 'FileValidDataLengthInformation',
                            40: 'FileShortNameInformation',
                            41: 'FileIoCompletionNotificationInformation',
                            42: 'FileIoStatusBlockRangeInformation',
                            43: 'FileIoPriorityHintInformation',
                            44: 'FileSfioReserveInformation',
                            45: 'FileSfioVolumeInformation',
                            46: 'FileHardLinkInformation',
                            47: 'FileProcessIdsUsingFileInformation',
                            48: 'FileNormalizedNameInformation',
                            49: 'FileNetworkPhysicalNameInformation',
                            50: 'FileIdGlobalTxDirectoryInformation',
                            51: 'FileIsRemoteDeviceInformation',
                            52: 'FileAttributeCacheInformation',
                            53: 'FileNumaNodeInformation',
                            54: 'FileStandardLinkInformation',
                            55: 'FileRemoteProtocolInformation',
                            56: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1312': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'FileInformationClass': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'FileDirectoryInformation',
                            2: 'FileFullDirectoryInformation',
                            3: 'FileBothDirectoryInformation',
                            4: 'FileBasicInformation',
                            5: 'FileStandardInformation',
                            6: 'FileInternalInformation',
                            7: 'FileEaInformation',
                            8: 'FileAccessInformation',
                            9: 'FileNameInformation',
                            10: 'FileRenameInformation',
                            11: 'FileLinkInformation',
                            12: 'FileNamesInformation',
                            13: 'FileDispositionInformation',
                            14: 'FilePositionInformation',
                            15: 'FileFullEaInformation',
                            16: 'FileModeInformation',
                            17: 'FileAlignmentInformation',
                            18: 'FileAllInformation',
                            19: 'FileAllocationInformation',
                            20: 'FileEndOfFileInformation',
                            21: 'FileAlternateNameInformation',
                            22: 'FileStreamInformation',
                            23: 'FilePipeInformation',
                            24: 'FilePipeLocalInformation',
                            25: 'FilePipeRemoteInformation',
                            26: 'FileMailslotQueryInformation',
                            27: 'FileMailslotSetInformation',
                            28: 'FileCompressionInformation',
                            29: 'FileObjectIdInformation',
                            30: 'FileCompletionInformation',
                            31: 'FileMoveClusterInformation',
                            32: 'FileQuotaInformation',
                            33: 'FileReparsePointInformation',
                            34: 'FileNetworkOpenInformation',
                            35: 'FileAttributeTagInformation',
                            36: 'FileTrackingInformation',
                            37: 'FileIdBothDirectoryInformation',
                            38: 'FileIdFullDirectoryInformation',
                            39: 'FileValidDataLengthInformation',
                            40: 'FileShortNameInformation',
                            41: 'FileIoCompletionNotificationInformation',
                            42: 'FileIoStatusBlockRangeInformation',
                            43: 'FileIoPriorityHintInformation',
                            44: 'FileSfioReserveInformation',
                            45: 'FileSfioVolumeInformation',
                            46: 'FileHardLinkInformation',
                            47: 'FileProcessIdsUsingFileInformation',
                            48: 'FileNormalizedNameInformation',
                            49: 'FileNetworkPhysicalNameInformation',
                            50: 'FileIdGlobalTxDirectoryInformation',
                            51: 'FileIsRemoteDeviceInformation',
                            52: 'FileAttributeCacheInformation',
                            53: 'FileNumaNodeInformation',
                            54: 'FileStandardLinkInformation',
                            55: 'FileRemoteProtocolInformation',
                            56: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileObject': [0x10, ['pointer64', ['_FILE_OBJECT']]],
            'ReplaceIfExists': [0x18, ['unsigned char']],
            'AdvanceOnly': [0x19, ['unsigned char']],
            'ClusterCount': [0x18, ['unsigned long']],
            'DeleteHandle': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1314': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'EaList': [0x8, ['pointer64', ['void']]],
            'EaListLength': [0x10, ['unsigned long']],
            'EaIndex': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1316': [
        0x4,
        {
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_131a': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'FsInformationClass': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'FileFsVolumeInformation',
                            2: 'FileFsLabelInformation',
                            3: 'FileFsSizeInformation',
                            4: 'FileFsDeviceInformation',
                            5: 'FileFsAttributeInformation',
                            6: 'FileFsControlInformation',
                            7: 'FileFsFullSizeInformation',
                            8: 'FileFsObjectIdInformation',
                            9: 'FileFsDriverPathInformation',
                            10: 'FileFsVolumeFlagsInformation',
                            11: 'FileFsSectorSizeInformation',
                            12: 'FileFsMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_131c': [
        0x20,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x8, ['unsigned long']],
            'FsControlCode': [0x10, ['unsigned long']],
            'Type3InputBuffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_131e': [
        0x18,
        {
            'Length': [0x0, ['pointer64', ['_LARGE_INTEGER']]],
            'Key': [0x8, ['unsigned long']],
            'ByteOffset': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1320': [
        0x20,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x8, ['unsigned long']],
            'IoControlCode': [0x10, ['unsigned long']],
            'Type3InputBuffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1322': [
        0x10,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1324': [
        0x10,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'SecurityDescriptor': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1328': [
        0x10,
        {
            'Vpb': [0x0, ['pointer64', ['_VPB']]],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_132c': [
        0x8,
        {
            'Srb': [0x0, ['pointer64', ['_SCSI_REQUEST_BLOCK']]],
        },
    ],
    '__unnamed_1330': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'StartSid': [0x8, ['pointer64', ['void']]],
            'SidList': [0x10, ['pointer64', ['_FILE_GET_QUOTA_INFORMATION']]],
            'SidListLength': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1334': [
        0x4,
        {
            'Type': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'BusRelations',
                            1: 'EjectionRelations',
                            2: 'PowerRelations',
                            3: 'RemovalRelations',
                            4: 'TargetDeviceRelation',
                            5: 'SingleBusRelations',
                            6: 'TransportRelations',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_133a': [
        0x20,
        {
            'InterfaceType': [0x0, ['pointer64', ['_GUID']]],
            'Size': [0x8, ['unsigned short']],
            'Version': [0xA, ['unsigned short']],
            'Interface': [0x10, ['pointer64', ['_INTERFACE']]],
            'InterfaceSpecificData': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_133e': [
        0x8,
        {
            'Capabilities': [0x0, ['pointer64', ['_DEVICE_CAPABILITIES']]],
        },
    ],
    '__unnamed_1342': [
        0x8,
        {
            'IoResourceRequirementList': [
                0x0,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
        },
    ],
    '__unnamed_1344': [
        0x20,
        {
            'WhichSpace': [0x0, ['unsigned long']],
            'Buffer': [0x8, ['pointer64', ['void']]],
            'Offset': [0x10, ['unsigned long']],
            'Length': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1346': [
        0x1,
        {
            'Lock': [0x0, ['unsigned char']],
        },
    ],
    '__unnamed_134a': [
        0x4,
        {
            'IdType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'BusQueryDeviceID',
                            1: 'BusQueryHardwareIDs',
                            2: 'BusQueryCompatibleIDs',
                            3: 'BusQueryInstanceID',
                            4: 'BusQueryDeviceSerialNumber',
                            5: 'BusQueryContainerID',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_134e': [
        0x10,
        {
            'DeviceTextType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DeviceTextDescription',
                            1: 'DeviceTextLocationInformation',
                        },
                    ),
                ],
            ],
            'LocaleId': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1352': [
        0x10,
        {
            'InPath': [0x0, ['unsigned char']],
            'Reserved': [0x1, ['array', 3, ['unsigned char']]],
            'Type': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DeviceUsageTypeUndefined',
                            1: 'DeviceUsageTypePaging',
                            2: 'DeviceUsageTypeHibernation',
                            3: 'DeviceUsageTypeDumpFile',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1356': [
        0x4,
        {
            'PowerState': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_135a': [
        0x8,
        {
            'PowerSequence': [0x0, ['pointer64', ['_POWER_SEQUENCE']]],
        },
    ],
    '__unnamed_1362': [
        0x20,
        {
            'SystemContext': [0x0, ['unsigned long']],
            'SystemPowerStateContext': [0x0, ['_SYSTEM_POWER_STATE_CONTEXT']],
            'Type': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'SystemPowerState', 1: 'DevicePowerState'},
                    ),
                ],
            ],
            'State': [0x10, ['_POWER_STATE']],
            'ShutdownType': [
                0x18,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerActionNone',
                            1: 'PowerActionReserved',
                            2: 'PowerActionSleep',
                            3: 'PowerActionHibernate',
                            4: 'PowerActionShutdown',
                            5: 'PowerActionShutdownReset',
                            6: 'PowerActionShutdownOff',
                            7: 'PowerActionWarmEject',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1366': [
        0x10,
        {
            'AllocatedResources': [0x0, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'AllocatedResourcesTranslated': [
                0x8,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
        },
    ],
    '__unnamed_1368': [
        0x20,
        {
            'ProviderId': [0x0, ['unsigned long long']],
            'DataPath': [0x8, ['pointer64', ['void']]],
            'BufferSize': [0x10, ['unsigned long']],
            'Buffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_136a': [
        0x20,
        {
            'Argument1': [0x0, ['pointer64', ['void']]],
            'Argument2': [0x8, ['pointer64', ['void']]],
            'Argument3': [0x10, ['pointer64', ['void']]],
            'Argument4': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_136c': [
        0x20,
        {
            'Create': [0x0, ['__unnamed_12fe']],
            'CreatePipe': [0x0, ['__unnamed_1302']],
            'CreateMailslot': [0x0, ['__unnamed_1306']],
            'Read': [0x0, ['__unnamed_1308']],
            'Write': [0x0, ['__unnamed_1308']],
            'QueryDirectory': [0x0, ['__unnamed_130c']],
            'NotifyDirectory': [0x0, ['__unnamed_130e']],
            'QueryFile': [0x0, ['__unnamed_1310']],
            'SetFile': [0x0, ['__unnamed_1312']],
            'QueryEa': [0x0, ['__unnamed_1314']],
            'SetEa': [0x0, ['__unnamed_1316']],
            'QueryVolume': [0x0, ['__unnamed_131a']],
            'SetVolume': [0x0, ['__unnamed_131a']],
            'FileSystemControl': [0x0, ['__unnamed_131c']],
            'LockControl': [0x0, ['__unnamed_131e']],
            'DeviceIoControl': [0x0, ['__unnamed_1320']],
            'QuerySecurity': [0x0, ['__unnamed_1322']],
            'SetSecurity': [0x0, ['__unnamed_1324']],
            'MountVolume': [0x0, ['__unnamed_1328']],
            'VerifyVolume': [0x0, ['__unnamed_1328']],
            'Scsi': [0x0, ['__unnamed_132c']],
            'QueryQuota': [0x0, ['__unnamed_1330']],
            'SetQuota': [0x0, ['__unnamed_1316']],
            'QueryDeviceRelations': [0x0, ['__unnamed_1334']],
            'QueryInterface': [0x0, ['__unnamed_133a']],
            'DeviceCapabilities': [0x0, ['__unnamed_133e']],
            'FilterResourceRequirements': [0x0, ['__unnamed_1342']],
            'ReadWriteConfig': [0x0, ['__unnamed_1344']],
            'SetLock': [0x0, ['__unnamed_1346']],
            'QueryId': [0x0, ['__unnamed_134a']],
            'QueryDeviceText': [0x0, ['__unnamed_134e']],
            'UsageNotification': [0x0, ['__unnamed_1352']],
            'WaitWake': [0x0, ['__unnamed_1356']],
            'PowerSequence': [0x0, ['__unnamed_135a']],
            'Power': [0x0, ['__unnamed_1362']],
            'StartDevice': [0x0, ['__unnamed_1366']],
            'WMI': [0x0, ['__unnamed_1368']],
            'Others': [0x0, ['__unnamed_136a']],
        },
    ],
    '_IO_STACK_LOCATION': [
        0x48,
        {
            'MajorFunction': [0x0, ['unsigned char']],
            'MinorFunction': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned char']],
            'Control': [0x3, ['unsigned char']],
            'Parameters': [0x8, ['__unnamed_136c']],
            'DeviceObject': [0x28, ['pointer64', ['_DEVICE_OBJECT']]],
            'FileObject': [0x30, ['pointer64', ['_FILE_OBJECT']]],
            'CompletionRoutine': [0x38, ['pointer64', ['void']]],
            'Context': [0x40, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1382': [
        0x48,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Wcb': [0x0, ['_WAIT_CONTEXT_BLOCK']],
        },
    ],
    '_DEVICE_OBJECT': [
        0x150,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['unsigned short']],
            'ReferenceCount': [0x4, ['long']],
            'DriverObject': [0x8, ['pointer64', ['_DRIVER_OBJECT']]],
            'NextDevice': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'AttachedDevice': [0x18, ['pointer64', ['_DEVICE_OBJECT']]],
            'CurrentIrp': [0x20, ['pointer64', ['_IRP']]],
            'Timer': [0x28, ['pointer64', ['_IO_TIMER']]],
            'Flags': [0x30, ['unsigned long']],
            'Characteristics': [0x34, ['unsigned long']],
            'Vpb': [0x38, ['pointer64', ['_VPB']]],
            'DeviceExtension': [0x40, ['pointer64', ['void']]],
            'DeviceType': [0x48, ['unsigned long']],
            'StackSize': [0x4C, ['unsigned char']],
            'Queue': [0x50, ['__unnamed_1382']],
            'AlignmentRequirement': [0x98, ['unsigned long']],
            'DeviceQueue': [0xA0, ['_KDEVICE_QUEUE']],
            'Dpc': [0xC8, ['_KDPC']],
            'ActiveThreadCount': [0x108, ['unsigned long']],
            'SecurityDescriptor': [0x110, ['pointer64', ['void']]],
            'DeviceLock': [0x118, ['_KEVENT']],
            'SectorSize': [0x130, ['unsigned short']],
            'Spare1': [0x132, ['unsigned short']],
            'DeviceObjectExtension': [
                0x138,
                ['pointer64', ['_DEVOBJ_EXTENSION']],
            ],
            'Reserved': [0x140, ['pointer64', ['void']]],
        },
    ],
    '_KDPC': [
        0x40,
        {
            'Type': [0x0, ['unsigned char']],
            'Importance': [0x1, ['unsigned char']],
            'Number': [0x2, ['unsigned short']],
            'DpcListEntry': [0x8, ['_LIST_ENTRY']],
            'DeferredRoutine': [0x18, ['pointer64', ['void']]],
            'DeferredContext': [0x20, ['pointer64', ['void']]],
            'SystemArgument1': [0x28, ['pointer64', ['void']]],
            'SystemArgument2': [0x30, ['pointer64', ['void']]],
            'DpcData': [0x38, ['pointer64', ['void']]],
        },
    ],
    '_IO_DRIVER_CREATE_CONTEXT': [
        0x20,
        {
            'Size': [0x0, ['short']],
            'ExtraCreateParameter': [0x8, ['pointer64', ['_ECP_LIST']]],
            'DeviceObjectHint': [0x10, ['pointer64', ['void']]],
            'TxnParameters': [0x18, ['pointer64', ['_TXN_PARAMETER_BLOCK']]],
        },
    ],
    '_IO_PRIORITY_INFO': [
        0x10,
        {
            'Size': [0x0, ['unsigned long']],
            'ThreadPriority': [0x4, ['unsigned long']],
            'PagePriority': [0x8, ['unsigned long']],
            'IoPriority': [
                0xC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IoPriorityVeryLow',
                            1: 'IoPriorityLow',
                            2: 'IoPriorityNormal',
                            3: 'IoPriorityHigh',
                            4: 'IoPriorityCritical',
                            5: 'MaxIoPriorityTypes',
                        },
                    ),
                ],
            ],
        },
    ],
    '_OBJECT_ATTRIBUTES': [
        0x30,
        {
            'Length': [0x0, ['unsigned long']],
            'RootDirectory': [0x8, ['pointer64', ['void']]],
            'ObjectName': [0x10, ['pointer64', ['_UNICODE_STRING']]],
            'Attributes': [0x18, ['unsigned long']],
            'SecurityDescriptor': [0x20, ['pointer64', ['void']]],
            'SecurityQualityOfService': [0x28, ['pointer64', ['void']]],
        },
    ],
    '_OBJECT_HANDLE_INFORMATION': [
        0x8,
        {
            'HandleAttributes': [0x0, ['unsigned long']],
            'GrantedAccess': [0x4, ['unsigned long']],
        },
    ],
    '_EVENT_DATA_DESCRIPTOR': [
        0x10,
        {
            'Ptr': [0x0, ['unsigned long long']],
            'Size': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
            'Type': [0xC, ['unsigned char']],
            'Reserved1': [0xD, ['unsigned char']],
            'Reserved2': [0xE, ['unsigned short']],
        },
    ],
    '_EVENT_DESCRIPTOR': [
        0x10,
        {
            'Id': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned char']],
            'Channel': [0x3, ['unsigned char']],
            'Level': [0x4, ['unsigned char']],
            'Opcode': [0x5, ['unsigned char']],
            'Task': [0x6, ['unsigned short']],
            'Keyword': [0x8, ['unsigned long long']],
        },
    ],
    '_PERFINFO_GROUPMASK': [
        0x20,
        {
            'Masks': [0x0, ['array', 8, ['unsigned long']]],
        },
    ],
    '_FILE_OBJECT': [
        0xD8,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'Vpb': [0x10, ['pointer64', ['_VPB']]],
            'FsContext': [0x18, ['pointer64', ['void']]],
            'FsContext2': [0x20, ['pointer64', ['void']]],
            'SectionObjectPointer': [
                0x28,
                ['pointer64', ['_SECTION_OBJECT_POINTERS']],
            ],
            'PrivateCacheMap': [0x30, ['pointer64', ['void']]],
            'FinalStatus': [0x38, ['long']],
            'RelatedFileObject': [0x40, ['pointer64', ['_FILE_OBJECT']]],
            'LockOperation': [0x48, ['unsigned char']],
            'DeletePending': [0x49, ['unsigned char']],
            'ReadAccess': [0x4A, ['unsigned char']],
            'WriteAccess': [0x4B, ['unsigned char']],
            'DeleteAccess': [0x4C, ['unsigned char']],
            'SharedRead': [0x4D, ['unsigned char']],
            'SharedWrite': [0x4E, ['unsigned char']],
            'SharedDelete': [0x4F, ['unsigned char']],
            'Flags': [0x50, ['unsigned long']],
            'FileName': [0x58, ['_UNICODE_STRING']],
            'CurrentByteOffset': [0x68, ['_LARGE_INTEGER']],
            'Waiters': [0x70, ['unsigned long']],
            'Busy': [0x74, ['unsigned long']],
            'LastLock': [0x78, ['pointer64', ['void']]],
            'Lock': [0x80, ['_KEVENT']],
            'Event': [0x98, ['_KEVENT']],
            'CompletionContext': [
                0xB0,
                ['pointer64', ['_IO_COMPLETION_CONTEXT']],
            ],
            'IrpListLock': [0xB8, ['unsigned long long']],
            'IrpList': [0xC0, ['_LIST_ENTRY']],
            'FileObjectExtension': [0xD0, ['pointer64', ['void']]],
        },
    ],
    '_EX_RUNDOWN_REF': [
        0x8,
        {
            'Count': [0x0, ['unsigned long long']],
            'Ptr': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_MM_PAGE_ACCESS_INFO_HEADER': [
        0x48,
        {
            'Link': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Type': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'MmPteAccessType',
                            1: 'MmCcReadAheadType',
                            2: 'MmPfnRepurposeType',
                            3: 'MmMaximumPageAccessType',
                        },
                    ),
                ],
            ],
            'EmptySequenceNumber': [0xC, ['unsigned long']],
            'CurrentFileIndex': [0xC, ['unsigned long']],
            'CreateTime': [0x10, ['unsigned long long']],
            'EmptyTime': [0x18, ['unsigned long long']],
            'TempEntry': [0x18, ['pointer64', ['_MM_PAGE_ACCESS_INFO']]],
            'PageEntry': [0x20, ['pointer64', ['_MM_PAGE_ACCESS_INFO']]],
            'FileEntry': [0x28, ['pointer64', ['unsigned long long']]],
            'FirstFileEntry': [0x30, ['pointer64', ['unsigned long long']]],
            'Process': [0x38, ['pointer64', ['_EPROCESS']]],
            'SessionId': [0x40, ['unsigned long']],
            'PageFrameEntry': [0x20, ['pointer64', ['unsigned long long']]],
            'LastPageFrameEntry': [
                0x28,
                ['pointer64', ['unsigned long long']],
            ],
        },
    ],
    '_WHEA_ERROR_PACKET_V2': [
        0x50,
        {
            'Signature': [0x0, ['unsigned long']],
            'Version': [0x4, ['unsigned long']],
            'Length': [0x8, ['unsigned long']],
            'Flags': [0xC, ['_WHEA_ERROR_PACKET_FLAGS']],
            'ErrorType': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrTypeProcessor',
                            1: 'WheaErrTypeMemory',
                            2: 'WheaErrTypePCIExpress',
                            3: 'WheaErrTypeNMI',
                            4: 'WheaErrTypePCIXBus',
                            5: 'WheaErrTypePCIXDevice',
                            6: 'WheaErrTypeGeneric',
                        },
                    ),
                ],
            ],
            'ErrorSeverity': [
                0x14,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrSevRecoverable',
                            1: 'WheaErrSevFatal',
                            2: 'WheaErrSevCorrected',
                            3: 'WheaErrSevInformational',
                        },
                    ),
                ],
            ],
            'ErrorSourceId': [0x18, ['unsigned long']],
            'ErrorSourceType': [
                0x1C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrSrcTypeMCE',
                            1: 'WheaErrSrcTypeCMC',
                            2: 'WheaErrSrcTypeCPE',
                            3: 'WheaErrSrcTypeNMI',
                            4: 'WheaErrSrcTypePCIe',
                            5: 'WheaErrSrcTypeGeneric',
                            6: 'WheaErrSrcTypeINIT',
                            7: 'WheaErrSrcTypeBOOT',
                            8: 'WheaErrSrcTypeSCIGeneric',
                            9: 'WheaErrSrcTypeIPFMCA',
                            10: 'WheaErrSrcTypeIPFCMC',
                            11: 'WheaErrSrcTypeIPFCPE',
                            12: 'WheaErrSrcTypeMax',
                        },
                    ),
                ],
            ],
            'NotifyType': [0x20, ['_GUID']],
            'Context': [0x30, ['unsigned long long']],
            'DataFormat': [
                0x38,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaDataFormatIPFSalRecord',
                            1: 'WheaDataFormatXPFMCA',
                            2: 'WheaDataFormatMemory',
                            3: 'WheaDataFormatPCIExpress',
                            4: 'WheaDataFormatNMIPort',
                            5: 'WheaDataFormatPCIXBus',
                            6: 'WheaDataFormatPCIXDevice',
                            7: 'WheaDataFormatGeneric',
                            8: 'WheaDataFormatMax',
                        },
                    ),
                ],
            ],
            'Reserved1': [0x3C, ['unsigned long']],
            'DataOffset': [0x40, ['unsigned long']],
            'DataLength': [0x44, ['unsigned long']],
            'PshedDataOffset': [0x48, ['unsigned long']],
            'PshedDataLength': [0x4C, ['unsigned long']],
        },
    ],
    '_WHEA_ERROR_RECORD': [
        0xC8,
        {
            'Header': [0x0, ['_WHEA_ERROR_RECORD_HEADER']],
            'SectionDescriptor': [
                0x80,
                ['array', 1, ['_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR']],
            ],
        },
    ],
    '_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR': [
        0x48,
        {
            'SectionOffset': [0x0, ['unsigned long']],
            'SectionLength': [0x4, ['unsigned long']],
            'Revision': [0x8, ['_WHEA_REVISION']],
            'ValidBits': [
                0xA,
                ['_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS'],
            ],
            'Reserved': [0xB, ['unsigned char']],
            'Flags': [0xC, ['_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS']],
            'SectionType': [0x10, ['_GUID']],
            'FRUId': [0x20, ['_GUID']],
            'SectionSeverity': [
                0x30,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrSevRecoverable',
                            1: 'WheaErrSevFatal',
                            2: 'WheaErrSevCorrected',
                            3: 'WheaErrSevInformational',
                        },
                    ),
                ],
            ],
            'FRUText': [0x34, ['array', 20, ['unsigned char']]],
        },
    ],
    '_GUID': [
        0x10,
        {
            'Data1': [0x0, ['unsigned long']],
            'Data2': [0x4, ['unsigned short']],
            'Data3': [0x6, ['unsigned short']],
            'Data4': [0x8, ['array', 8, ['unsigned char']]],
        },
    ],
    '_FSRTL_ADVANCED_FCB_HEADER': [
        0x58,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteSize': [0x2, ['short']],
            'Flags': [0x4, ['unsigned char']],
            'IsFastIoPossible': [0x5, ['unsigned char']],
            'Flags2': [0x6, ['unsigned char']],
            'Reserved': [
                0x7,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Version': [
                0x7,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Resource': [0x8, ['pointer64', ['_ERESOURCE']]],
            'PagingIoResource': [0x10, ['pointer64', ['_ERESOURCE']]],
            'AllocationSize': [0x18, ['_LARGE_INTEGER']],
            'FileSize': [0x20, ['_LARGE_INTEGER']],
            'ValidDataLength': [0x28, ['_LARGE_INTEGER']],
            'FastMutex': [0x30, ['pointer64', ['_FAST_MUTEX']]],
            'FilterContexts': [0x38, ['_LIST_ENTRY']],
            'PushLock': [0x48, ['_EX_PUSH_LOCK']],
            'FileContextSupportPointer': [
                0x50,
                ['pointer64', ['pointer64', ['void']]],
            ],
        },
    ],
    '_iobuf': [
        0x30,
        {
            '_ptr': [0x0, ['pointer64', ['unsigned char']]],
            '_cnt': [0x8, ['long']],
            '_base': [0x10, ['pointer64', ['unsigned char']]],
            '_flag': [0x18, ['long']],
            '_file': [0x1C, ['long']],
            '_charbuf': [0x20, ['long']],
            '_bufsiz': [0x24, ['long']],
            '_tmpfname': [0x28, ['pointer64', ['unsigned char']]],
        },
    ],
    '__unnamed_14ee': [
        0x8,
        {
            'Long': [0x0, ['unsigned long long']],
            'VolatileLong': [0x0, ['unsigned long long']],
            'Hard': [0x0, ['_MMPTE_HARDWARE']],
            'Flush': [0x0, ['_HARDWARE_PTE']],
            'Proto': [0x0, ['_MMPTE_PROTOTYPE']],
            'Soft': [0x0, ['_MMPTE_SOFTWARE']],
            'TimeStamp': [0x0, ['_MMPTE_TIMESTAMP']],
            'Trans': [0x0, ['_MMPTE_TRANSITION']],
            'Subsect': [0x0, ['_MMPTE_SUBSECTION']],
            'List': [0x0, ['_MMPTE_LIST']],
        },
    ],
    '_MMPTE': [
        0x8,
        {
            'u': [0x0, ['__unnamed_14ee']],
        },
    ],
    '__unnamed_14ff': [
        0x10,
        {
            'I386': [0x0, ['_I386_LOADER_BLOCK']],
            'Ia64': [0x0, ['_IA64_LOADER_BLOCK']],
        },
    ],
    '_LOADER_PARAMETER_BLOCK': [
        0xF0,
        {
            'OsMajorVersion': [0x0, ['unsigned long']],
            'OsMinorVersion': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
            'LoadOrderListHead': [0x10, ['_LIST_ENTRY']],
            'MemoryDescriptorListHead': [0x20, ['_LIST_ENTRY']],
            'BootDriverListHead': [0x30, ['_LIST_ENTRY']],
            'KernelStack': [0x40, ['unsigned long long']],
            'Prcb': [0x48, ['unsigned long long']],
            'Process': [0x50, ['unsigned long long']],
            'Thread': [0x58, ['unsigned long long']],
            'RegistryLength': [0x60, ['unsigned long']],
            'RegistryBase': [0x68, ['pointer64', ['void']]],
            'ConfigurationRoot': [
                0x70,
                ['pointer64', ['_CONFIGURATION_COMPONENT_DATA']],
            ],
            'ArcBootDeviceName': [0x78, ['pointer64', ['unsigned char']]],
            'ArcHalDeviceName': [0x80, ['pointer64', ['unsigned char']]],
            'NtBootPathName': [0x88, ['pointer64', ['unsigned char']]],
            'NtHalPathName': [0x90, ['pointer64', ['unsigned char']]],
            'LoadOptions': [0x98, ['pointer64', ['unsigned char']]],
            'NlsData': [0xA0, ['pointer64', ['_NLS_DATA_BLOCK']]],
            'ArcDiskInformation': [
                0xA8,
                ['pointer64', ['_ARC_DISK_INFORMATION']],
            ],
            'OemFontFile': [0xB0, ['pointer64', ['void']]],
            'Extension': [
                0xB8,
                ['pointer64', ['_LOADER_PARAMETER_EXTENSION']],
            ],
            'u': [0xC0, ['__unnamed_14ff']],
            'FirmwareInformation': [
                0xD0,
                ['_FIRMWARE_INFORMATION_LOADER_BLOCK'],
            ],
        },
    ],
    '_KLOCK_QUEUE_HANDLE': [
        0x18,
        {
            'LockQueue': [0x0, ['_KSPIN_LOCK_QUEUE']],
            'OldIrql': [0x10, ['unsigned char']],
        },
    ],
    '_MMPFNLIST': [
        0x28,
        {
            'Total': [0x0, ['unsigned long long']],
            'ListName': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ZeroedPageList',
                            1: 'FreePageList',
                            2: 'StandbyPageList',
                            3: 'ModifiedPageList',
                            4: 'ModifiedNoWritePageList',
                            5: 'BadPageList',
                            6: 'ActiveAndValid',
                            7: 'TransitionPage',
                        },
                    ),
                ],
            ],
            'Flink': [0x10, ['unsigned long long']],
            'Blink': [0x18, ['unsigned long long']],
            'Lock': [0x20, ['unsigned long long']],
        },
    ],
    '__unnamed_152e': [
        0x8,
        {
            'Flink': [0x0, ['unsigned long long']],
            'WsIndex': [0x0, ['unsigned long']],
            'Event': [0x0, ['pointer64', ['_KEVENT']]],
            'Next': [0x0, ['pointer64', ['void']]],
            'VolatileNext': [0x0, ['pointer64', ['void']]],
            'KernelStackOwner': [0x0, ['pointer64', ['_KTHREAD']]],
            'NextStackPfn': [0x0, ['_SINGLE_LIST_ENTRY']],
        },
    ],
    '__unnamed_1530': [
        0x8,
        {
            'Blink': [0x0, ['unsigned long long']],
            'ImageProtoPte': [0x0, ['pointer64', ['_MMPTE']]],
            'ShareCount': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_1533': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'VolatileReferenceCount': [0x0, ['short']],
            'ShortFlags': [0x2, ['unsigned short']],
        },
    ],
    '__unnamed_1535': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'e1': [0x2, ['_MMPFNENTRY']],
            'e2': [0x0, ['__unnamed_1533']],
        },
    ],
    '__unnamed_153d': [
        0x8,
        {
            'PteFrame': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=52,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=52,
                        end_bit=55,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PfnImageVerified': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=55,
                        end_bit=56,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'AweAllocation': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=56,
                        end_bit=57,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PrototypePte': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=57,
                        end_bit=58,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageColor': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=58,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_MMPFN': [
        0x30,
        {
            'u1': [0x0, ['__unnamed_152e']],
            'u2': [0x8, ['__unnamed_1530']],
            'PteAddress': [0x10, ['pointer64', ['_MMPTE']]],
            'VolatilePteAddress': [0x10, ['pointer64', ['void']]],
            'Lock': [0x10, ['long']],
            'PteLong': [0x10, ['unsigned long long']],
            'u3': [0x18, ['__unnamed_1535']],
            'UsedPageTableEntries': [0x1C, ['unsigned short']],
            'VaType': [0x1E, ['unsigned char']],
            'ViewCount': [0x1F, ['unsigned char']],
            'OriginalPte': [0x20, ['_MMPTE']],
            'AweReferenceCount': [0x20, ['long']],
            'u4': [0x28, ['__unnamed_153d']],
        },
    ],
    '_MI_COLOR_BASE': [
        0x10,
        {
            'ColorPointer': [0x0, ['pointer64', ['unsigned short']]],
            'ColorMask': [0x8, ['unsigned short']],
            'ColorNode': [0xA, ['unsigned short']],
        },
    ],
    '_MMSUPPORT': [
        0x88,
        {
            'WorkingSetMutex': [0x0, ['_EX_PUSH_LOCK']],
            'ExitGate': [0x8, ['pointer64', ['_KGATE']]],
            'AccessLog': [0x10, ['pointer64', ['void']]],
            'WorkingSetExpansionLinks': [0x18, ['_LIST_ENTRY']],
            'AgeDistribution': [0x28, ['array', 7, ['unsigned long']]],
            'MinimumWorkingSetSize': [0x44, ['unsigned long']],
            'WorkingSetSize': [0x48, ['unsigned long']],
            'WorkingSetPrivateSize': [0x4C, ['unsigned long']],
            'MaximumWorkingSetSize': [0x50, ['unsigned long']],
            'ChargedWslePages': [0x54, ['unsigned long']],
            'ActualWslePages': [0x58, ['unsigned long']],
            'WorkingSetSizeOverhead': [0x5C, ['unsigned long']],
            'PeakWorkingSetSize': [0x60, ['unsigned long']],
            'HardFaultCount': [0x64, ['unsigned long']],
            'VmWorkingSetList': [0x68, ['pointer64', ['_MMWSL']]],
            'NextPageColor': [0x70, ['unsigned short']],
            'LastTrimStamp': [0x72, ['unsigned short']],
            'PageFaultCount': [0x74, ['unsigned long']],
            'RepurposeCount': [0x78, ['unsigned long']],
            'Spare': [0x7C, ['array', 2, ['unsigned long']]],
            'Flags': [0x84, ['_MMSUPPORT_FLAGS']],
        },
    ],
    '_MMWSL': [
        0x488,
        {
            'FirstFree': [0x0, ['unsigned long']],
            'FirstDynamic': [0x4, ['unsigned long']],
            'LastEntry': [0x8, ['unsigned long']],
            'NextSlot': [0xC, ['unsigned long']],
            'Wsle': [0x10, ['pointer64', ['_MMWSLE']]],
            'LowestPagableAddress': [0x18, ['pointer64', ['void']]],
            'LastInitializedWsle': [0x20, ['unsigned long']],
            'NextAgingSlot': [0x24, ['unsigned long']],
            'NumberOfCommittedPageTables': [0x28, ['unsigned long']],
            'VadBitMapHint': [0x2C, ['unsigned long']],
            'NonDirectCount': [0x30, ['unsigned long']],
            'LastVadBit': [0x34, ['unsigned long']],
            'MaximumLastVadBit': [0x38, ['unsigned long']],
            'LastAllocationSizeHint': [0x3C, ['unsigned long']],
            'LastAllocationSize': [0x40, ['unsigned long']],
            'NonDirectHash': [0x48, ['pointer64', ['_MMWSLE_NONDIRECT_HASH']]],
            'HashTableStart': [0x50, ['pointer64', ['_MMWSLE_HASH']]],
            'HighestPermittedHashAddress': [
                0x58,
                ['pointer64', ['_MMWSLE_HASH']],
            ],
            'MaximumUserPageTablePages': [0x60, ['unsigned long']],
            'MaximumUserPageDirectoryPages': [0x64, ['unsigned long']],
            'CommittedPageTables': [0x68, ['pointer64', ['unsigned long']]],
            'NumberOfCommittedPageDirectories': [0x70, ['unsigned long']],
            'CommittedPageDirectories': [
                0x78,
                ['array', 128, ['unsigned long long']],
            ],
            'NumberOfCommittedPageDirectoryParents': [
                0x478,
                ['unsigned long'],
            ],
            'CommittedPageDirectoryParents': [
                0x480,
                ['array', 1, ['unsigned long long']],
            ],
        },
    ],
    '__unnamed_156b': [
        0x8,
        {
            'VirtualAddress': [0x0, ['pointer64', ['void']]],
            'Long': [0x0, ['unsigned long long']],
            'e1': [0x0, ['_MMWSLENTRY']],
            'e2': [0x0, ['_MMWSLE_FREE_ENTRY']],
        },
    ],
    '_MMWSLE': [
        0x8,
        {
            'u1': [0x0, ['__unnamed_156b']],
        },
    ],
    '__unnamed_1577': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MMSECTION_FLAGS']],
        },
    ],
    '__unnamed_1581': [
        0x10,
        {
            'NumberOfSystemCacheViews': [0x0, ['unsigned long']],
            'ImageRelocationStartBit': [0x0, ['unsigned long']],
            'WritableUserReferences': [0x4, ['long']],
            'ImageRelocationSizeIn64k': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'Unused': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'BitMap64': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageActive': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'SubsectionRoot': [
                0x8,
                ['pointer64', ['_MM_SUBSECTION_AVL_TABLE']],
            ],
            'SeImageStub': [
                0x8,
                ['pointer64', ['_MI_IMAGE_SECURITY_REFERENCE']],
            ],
        },
    ],
    '__unnamed_1583': [
        0x10,
        {
            'e2': [0x0, ['__unnamed_1581']],
        },
    ],
    '_CONTROL_AREA': [
        0x80,
        {
            'Segment': [0x0, ['pointer64', ['_SEGMENT']]],
            'DereferenceList': [0x8, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0x18, ['unsigned long long']],
            'NumberOfPfnReferences': [0x20, ['unsigned long long']],
            'NumberOfMappedViews': [0x28, ['unsigned long long']],
            'NumberOfUserReferences': [0x30, ['unsigned long long']],
            'u': [0x38, ['__unnamed_1577']],
            'FlushInProgressCount': [0x3C, ['unsigned long']],
            'FilePointer': [0x40, ['_EX_FAST_REF']],
            'ControlAreaLock': [0x48, ['long']],
            'ModifiedWriteCount': [0x4C, ['unsigned long']],
            'StartingFrame': [0x4C, ['unsigned long']],
            'WaitList': [0x50, ['pointer64', ['_MI_CONTROL_AREA_WAIT_BLOCK']]],
            'u2': [0x58, ['__unnamed_1583']],
            'LockedPages': [0x68, ['unsigned long long']],
            'ViewList': [0x70, ['_LIST_ENTRY']],
        },
    ],
    '_MM_STORE_KEY': [
        0x8,
        {
            'KeyLow': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=60,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'KeyHigh': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=60,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'EntireKey': [0x0, ['unsigned long long']],
        },
    ],
    '_MMPAGING_FILE': [
        0x90,
        {
            'Size': [0x0, ['unsigned long long']],
            'MaximumSize': [0x8, ['unsigned long long']],
            'MinimumSize': [0x10, ['unsigned long long']],
            'FreeSpace': [0x18, ['unsigned long long']],
            'PeakUsage': [0x20, ['unsigned long long']],
            'HighestPage': [0x28, ['unsigned long long']],
            'File': [0x30, ['pointer64', ['_FILE_OBJECT']]],
            'Entry': [
                0x38,
                ['array', 2, ['pointer64', ['_MMMOD_WRITER_MDL_ENTRY']]],
            ],
            'PageFileName': [0x48, ['_UNICODE_STRING']],
            'Bitmap': [0x58, ['pointer64', ['_RTL_BITMAP']]],
            'EvictStoreBitmap': [0x60, ['pointer64', ['_RTL_BITMAP']]],
            'BitmapHint': [0x68, ['unsigned long']],
            'LastAllocationSize': [0x6C, ['unsigned long']],
            'ToBeEvictedCount': [0x70, ['unsigned long']],
            'PageFileNumber': [
                0x74,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'BootPartition': [
                0x74,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'Spare0': [
                0x74,
                [
                    'BitField',
                    dict(
                        start_bit=5, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AdriftMdls': [
                0x76,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'Spare1': [
                0x76,
                [
                    'BitField',
                    dict(
                        start_bit=1, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'FileHandle': [0x78, ['pointer64', ['void']]],
            'Lock': [0x80, ['unsigned long long']],
            'LockOwner': [0x88, ['pointer64', ['_ETHREAD']]],
        },
    ],
    '_MM_AVL_TABLE': [
        0x40,
        {
            'BalancedRoot': [0x0, ['_MMADDRESS_NODE']],
            'DepthOfTree': [
                0x28,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x28,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NumberGenericTableElements': [
                0x28,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NodeHint': [0x30, ['pointer64', ['void']]],
            'NodeFreeHint': [0x38, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_15bf': [
        0x8,
        {
            'Balance': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='long long'),
                ],
            ],
            'Parent': [0x0, ['pointer64', ['_MMVAD']]],
        },
    ],
    '__unnamed_15c2': [
        0x8,
        {
            'LongFlags': [0x0, ['unsigned long long']],
            'VadFlags': [0x0, ['_MMVAD_FLAGS']],
        },
    ],
    '__unnamed_15c5': [
        0x8,
        {
            'LongFlags3': [0x0, ['unsigned long long']],
            'VadFlags3': [0x0, ['_MMVAD_FLAGS3']],
        },
    ],
    '_MMVAD_SHORT': [
        0x40,
        {
            'u1': [0x0, ['__unnamed_15bf']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_15c2']],
            'PushLock': [0x30, ['_EX_PUSH_LOCK']],
            'u5': [0x38, ['__unnamed_15c5']],
        },
    ],
    '__unnamed_15cd': [
        0x8,
        {
            'Balance': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='long long'),
                ],
            ],
            'Parent': [0x0, ['pointer64', ['_MMADDRESS_NODE']]],
        },
    ],
    '_MMADDRESS_NODE': [
        0x28,
        {
            'u1': [0x0, ['__unnamed_15cd']],
            'LeftChild': [0x8, ['pointer64', ['_MMADDRESS_NODE']]],
            'RightChild': [0x10, ['pointer64', ['_MMADDRESS_NODE']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
        },
    ],
    '__unnamed_15d2': [
        0x4,
        {
            'LongFlags2': [0x0, ['unsigned long']],
            'VadFlags2': [0x0, ['_MMVAD_FLAGS2']],
        },
    ],
    '_MMVAD': [
        0x78,
        {
            'u1': [0x0, ['__unnamed_15bf']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_15c2']],
            'PushLock': [0x30, ['_EX_PUSH_LOCK']],
            'u5': [0x38, ['__unnamed_15c5']],
            'u2': [0x40, ['__unnamed_15d2']],
            'Subsection': [0x48, ['pointer64', ['_SUBSECTION']]],
            'MappedSubsection': [0x48, ['pointer64', ['_MSUBSECTION']]],
            'FirstPrototypePte': [0x50, ['pointer64', ['_MMPTE']]],
            'LastContiguousPte': [0x58, ['pointer64', ['_MMPTE']]],
            'ViewLinks': [0x60, ['_LIST_ENTRY']],
            'VadsProcess': [0x70, ['pointer64', ['_EPROCESS']]],
        },
    ],
    '__unnamed_15dd': [
        0x38,
        {
            'Mdl': [0x0, ['_MDL']],
            'Page': [0x30, ['array', 1, ['unsigned long long']]],
        },
    ],
    '_MI_PAGEFILE_TRACES': [
        0x68,
        {
            'Status': [0x0, ['long']],
            'Priority': [0x4, ['unsigned char']],
            'IrpPriority': [0x5, ['unsigned char']],
            'CurrentTime': [0x8, ['_LARGE_INTEGER']],
            'AvailablePages': [0x10, ['unsigned long long']],
            'ModifiedPagesTotal': [0x18, ['unsigned long long']],
            'ModifiedPagefilePages': [0x20, ['unsigned long long']],
            'ModifiedNoWritePages': [0x28, ['unsigned long long']],
            'MdlHack': [0x30, ['__unnamed_15dd']],
        },
    ],
    '__unnamed_15e3': [
        0x10,
        {
            'IoStatus': [0x0, ['_IO_STATUS_BLOCK']],
        },
    ],
    '__unnamed_15e5': [
        0x8,
        {
            'KeepForever': [0x0, ['unsigned long long']],
        },
    ],
    '_MMMOD_WRITER_MDL_ENTRY': [
        0xA0,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'u': [0x10, ['__unnamed_15e3']],
            'Irp': [0x20, ['pointer64', ['_IRP']]],
            'u1': [0x28, ['__unnamed_15e5']],
            'PagingFile': [0x30, ['pointer64', ['_MMPAGING_FILE']]],
            'File': [0x38, ['pointer64', ['_FILE_OBJECT']]],
            'ControlArea': [0x40, ['pointer64', ['_CONTROL_AREA']]],
            'FileResource': [0x48, ['pointer64', ['_ERESOURCE']]],
            'WriteOffset': [0x50, ['_LARGE_INTEGER']],
            'IssueTime': [0x58, ['_LARGE_INTEGER']],
            'PointerMdl': [0x60, ['pointer64', ['_MDL']]],
            'Mdl': [0x68, ['_MDL']],
            'Page': [0x98, ['array', 1, ['unsigned long long']]],
        },
    ],
    '_MDL': [
        0x30,
        {
            'Next': [0x0, ['pointer64', ['_MDL']]],
            'Size': [0x8, ['short']],
            'MdlFlags': [0xA, ['short']],
            'Process': [0x10, ['pointer64', ['_EPROCESS']]],
            'MappedSystemVa': [0x18, ['pointer64', ['void']]],
            'StartVa': [0x20, ['pointer64', ['void']]],
            'ByteCount': [0x28, ['unsigned long']],
            'ByteOffset': [0x2C, ['unsigned long']],
        },
    ],
    '_HHIVE': [
        0x598,
        {
            'Signature': [0x0, ['unsigned long']],
            'GetCellRoutine': [0x8, ['pointer64', ['void']]],
            'ReleaseCellRoutine': [0x10, ['pointer64', ['void']]],
            'Allocate': [0x18, ['pointer64', ['void']]],
            'Free': [0x20, ['pointer64', ['void']]],
            'FileSetSize': [0x28, ['pointer64', ['void']]],
            'FileWrite': [0x30, ['pointer64', ['void']]],
            'FileRead': [0x38, ['pointer64', ['void']]],
            'FileFlush': [0x40, ['pointer64', ['void']]],
            'HiveLoadFailure': [0x48, ['pointer64', ['void']]],
            'BaseBlock': [0x50, ['pointer64', ['_HBASE_BLOCK']]],
            'DirtyVector': [0x58, ['_RTL_BITMAP']],
            'DirtyCount': [0x68, ['unsigned long']],
            'DirtyAlloc': [0x6C, ['unsigned long']],
            'BaseBlockAlloc': [0x70, ['unsigned long']],
            'Cluster': [0x74, ['unsigned long']],
            'Flat': [0x78, ['unsigned char']],
            'ReadOnly': [0x79, ['unsigned char']],
            'DirtyFlag': [0x7A, ['unsigned char']],
            'HvBinHeadersUse': [0x7C, ['unsigned long']],
            'HvFreeCellsUse': [0x80, ['unsigned long']],
            'HvUsedCellsUse': [0x84, ['unsigned long']],
            'CmUsedCellsUse': [0x88, ['unsigned long']],
            'HiveFlags': [0x8C, ['unsigned long']],
            'CurrentLog': [0x90, ['unsigned long']],
            'LogSize': [0x94, ['array', 2, ['unsigned long']]],
            'RefreshCount': [0x9C, ['unsigned long']],
            'StorageTypeCount': [0xA0, ['unsigned long']],
            'Version': [0xA4, ['unsigned long']],
            'Storage': [0xA8, ['array', 2, ['_DUAL']]],
        },
    ],
    '_CM_VIEW_OF_FILE': [
        0x58,
        {
            'MappedViewLinks': [0x0, ['_LIST_ENTRY']],
            'PinnedViewLinks': [0x10, ['_LIST_ENTRY']],
            'FlushedViewLinks': [0x20, ['_LIST_ENTRY']],
            'CmHive': [0x30, ['pointer64', ['_CMHIVE']]],
            'Bcb': [0x38, ['pointer64', ['void']]],
            'ViewAddress': [0x40, ['pointer64', ['void']]],
            'FileOffset': [0x48, ['unsigned long']],
            'Size': [0x4C, ['unsigned long']],
            'UseCount': [0x50, ['unsigned long']],
        },
    ],
    '_CMHIVE': [
        0xBE8,
        {
            'Hive': [0x0, ['_HHIVE']],
            'FileHandles': [0x598, ['array', 6, ['pointer64', ['void']]]],
            'NotifyList': [0x5C8, ['_LIST_ENTRY']],
            'HiveList': [0x5D8, ['_LIST_ENTRY']],
            'PreloadedHiveList': [0x5E8, ['_LIST_ENTRY']],
            'HiveRundown': [0x5F8, ['_EX_RUNDOWN_REF']],
            'ParseCacheEntries': [0x600, ['_LIST_ENTRY']],
            'KcbCacheTable': [
                0x610,
                ['pointer64', ['_CM_KEY_HASH_TABLE_ENTRY']],
            ],
            'KcbCacheTableSize': [0x618, ['unsigned long']],
            'Identity': [0x61C, ['unsigned long']],
            'HiveLock': [0x620, ['pointer64', ['_FAST_MUTEX']]],
            'ViewLock': [0x628, ['_EX_PUSH_LOCK']],
            'ViewLockOwner': [0x630, ['pointer64', ['_KTHREAD']]],
            'ViewLockLast': [0x638, ['unsigned long']],
            'ViewUnLockLast': [0x63C, ['unsigned long']],
            'WriterLock': [0x640, ['pointer64', ['_FAST_MUTEX']]],
            'FlusherLock': [0x648, ['pointer64', ['_ERESOURCE']]],
            'FlushDirtyVector': [0x650, ['_RTL_BITMAP']],
            'FlushOffsetArray': [0x660, ['pointer64', ['CMP_OFFSET_ARRAY']]],
            'FlushOffsetArrayCount': [0x668, ['unsigned long']],
            'FlushHiveTruncated': [0x66C, ['unsigned long']],
            'FlushLock2': [0x670, ['pointer64', ['_FAST_MUTEX']]],
            'SecurityLock': [0x678, ['_EX_PUSH_LOCK']],
            'MappedViewList': [0x680, ['_LIST_ENTRY']],
            'PinnedViewList': [0x690, ['_LIST_ENTRY']],
            'FlushedViewList': [0x6A0, ['_LIST_ENTRY']],
            'MappedViewCount': [0x6B0, ['unsigned short']],
            'PinnedViewCount': [0x6B2, ['unsigned short']],
            'UseCount': [0x6B4, ['unsigned long']],
            'ViewsPerHive': [0x6B8, ['unsigned long']],
            'FileObject': [0x6C0, ['pointer64', ['_FILE_OBJECT']]],
            'LastShrinkHiveSize': [0x6C8, ['unsigned long']],
            'ActualFileSize': [0x6D0, ['_LARGE_INTEGER']],
            'FileFullPath': [0x6D8, ['_UNICODE_STRING']],
            'FileUserName': [0x6E8, ['_UNICODE_STRING']],
            'HiveRootPath': [0x6F8, ['_UNICODE_STRING']],
            'SecurityCount': [0x708, ['unsigned long']],
            'SecurityCacheSize': [0x70C, ['unsigned long']],
            'SecurityHitHint': [0x710, ['long']],
            'SecurityCache': [
                0x718,
                ['pointer64', ['_CM_KEY_SECURITY_CACHE_ENTRY']],
            ],
            'SecurityHash': [0x720, ['array', 64, ['_LIST_ENTRY']]],
            'UnloadEventCount': [0xB20, ['unsigned long']],
            'UnloadEventArray': [
                0xB28,
                ['pointer64', ['pointer64', ['_KEVENT']]],
            ],
            'RootKcb': [0xB30, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'Frozen': [0xB38, ['unsigned char']],
            'UnloadWorkItem': [0xB40, ['pointer64', ['_CM_WORKITEM']]],
            'UnloadWorkItemHolder': [0xB48, ['_CM_WORKITEM']],
            'GrowOnlyMode': [0xB70, ['unsigned char']],
            'GrowOffset': [0xB74, ['unsigned long']],
            'KcbConvertListHead': [0xB78, ['_LIST_ENTRY']],
            'KnodeConvertListHead': [0xB88, ['_LIST_ENTRY']],
            'CellRemapArray': [0xB98, ['pointer64', ['_CM_CELL_REMAP_BLOCK']]],
            'Flags': [0xBA0, ['unsigned long']],
            'TrustClassEntry': [0xBA8, ['_LIST_ENTRY']],
            'FlushCount': [0xBB8, ['unsigned long']],
            'CmRm': [0xBC0, ['pointer64', ['_CM_RM']]],
            'CmRmInitFailPoint': [0xBC8, ['unsigned long']],
            'CmRmInitFailStatus': [0xBCC, ['long']],
            'CreatorOwner': [0xBD0, ['pointer64', ['_KTHREAD']]],
            'RundownThread': [0xBD8, ['pointer64', ['_KTHREAD']]],
            'LastWriteTime': [0xBE0, ['_LARGE_INTEGER']],
        },
    ],
    '_CM_KEY_CONTROL_BLOCK': [
        0x128,
        {
            'RefCount': [0x0, ['unsigned long']],
            'ExtFlags': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'PrivateAlloc': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'Delete': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'HiveUnloaded': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'Decommissioned': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'LockTablePresent': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'TotalLevels': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'DelayedDeref': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DelayedClose': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Parking': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'KeyHash': [0x10, ['_CM_KEY_HASH']],
            'ConvKey': [0x10, ['unsigned long']],
            'NextHash': [0x18, ['pointer64', ['_CM_KEY_HASH']]],
            'KeyHive': [0x20, ['pointer64', ['_HHIVE']]],
            'KeyCell': [0x28, ['unsigned long']],
            'KcbPushlock': [0x30, ['_EX_PUSH_LOCK']],
            'Owner': [0x38, ['pointer64', ['_KTHREAD']]],
            'SharedCount': [0x38, ['long']],
            'SlotHint': [0x40, ['unsigned long']],
            'ParentKcb': [0x48, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'NameBlock': [0x50, ['pointer64', ['_CM_NAME_CONTROL_BLOCK']]],
            'CachedSecurity': [
                0x58,
                ['pointer64', ['_CM_KEY_SECURITY_CACHE']],
            ],
            'ValueCache': [0x60, ['_CACHED_CHILD_LIST']],
            'IndexHint': [0x70, ['pointer64', ['_CM_INDEX_HINT_BLOCK']]],
            'HashKey': [0x70, ['unsigned long']],
            'SubKeyCount': [0x70, ['unsigned long']],
            'KeyBodyListHead': [0x78, ['_LIST_ENTRY']],
            'FreeListEntry': [0x78, ['_LIST_ENTRY']],
            'KeyBodyArray': [
                0x88,
                ['array', 4, ['pointer64', ['_CM_KEY_BODY']]],
            ],
            'KcbLastWriteTime': [0xA8, ['_LARGE_INTEGER']],
            'KcbMaxNameLen': [0xB0, ['unsigned short']],
            'KcbMaxValueNameLen': [0xB2, ['unsigned short']],
            'KcbMaxValueDataLen': [0xB4, ['unsigned long']],
            'KcbUserFlags': [
                0xB8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'KcbVirtControlFlags': [
                0xB8,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'KcbDebug': [
                0xB8,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'Flags': [
                0xB8,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'RealKeyName': [0xC0, ['pointer64', ['unsigned char']]],
            'KCBUoWListHead': [0xC8, ['_LIST_ENTRY']],
            'DelayQueueEntry': [0xD8, ['_LIST_ENTRY']],
            'Stolen': [0xD8, ['pointer64', ['unsigned char']]],
            'TransKCBOwner': [0xE8, ['pointer64', ['_CM_TRANS']]],
            'KCBLock': [0xF0, ['_CM_INTENT_LOCK']],
            'KeyLock': [0x100, ['_CM_INTENT_LOCK']],
            'TransValueCache': [0x110, ['_CHILD_LIST']],
            'TransValueListOwner': [0x118, ['pointer64', ['_CM_TRANS']]],
            'FullKCBName': [0x120, ['pointer64', ['_UNICODE_STRING']]],
        },
    ],
    '_CM_KEY_HASH_TABLE_ENTRY': [
        0x18,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'Owner': [0x8, ['pointer64', ['_KTHREAD']]],
            'Entry': [0x10, ['pointer64', ['_CM_KEY_HASH']]],
        },
    ],
    '__unnamed_1669': [
        0xC,
        {
            'Failure': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: '_None',
                            1: '_CmInitializeHive',
                            2: '_HvInitializeHive',
                            3: '_HvpBuildMap',
                            4: '_HvpBuildMapAndCopy',
                            5: '_HvpInitMap',
                            6: '_HvLoadHive',
                            7: '_HvpReadFileImageAndBuildMap',
                            8: '_HvpRecoverData',
                            9: '_HvpRecoverWholeHive',
                            10: '_HvpMapFileImageAndBuildMap',
                            11: '_CmpValidateHiveSecurityDescriptors',
                            12: '_HvpEnlistBinInMap',
                            13: '_CmCheckRegistry',
                            14: '_CmRegistryIO',
                            15: '_CmCheckRegistry2',
                            16: '_CmpCheckKey',
                            17: '_CmpCheckValueList',
                            18: '_HvCheckHive',
                            19: '_HvCheckBin',
                        },
                    ),
                ],
            ],
            'Status': [0x4, ['long']],
            'Point': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_166c': [
        0x18,
        {
            'Action': [0x0, ['unsigned long']],
            'Handle': [0x8, ['pointer64', ['void']]],
            'Status': [0x10, ['long']],
        },
    ],
    '__unnamed_166e': [
        0x8,
        {
            'CheckStack': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1670': [
        0x20,
        {
            'Cell': [0x0, ['unsigned long']],
            'CellPoint': [0x8, ['pointer64', ['_CELL_DATA']]],
            'RootPoint': [0x10, ['pointer64', ['void']]],
            'Index': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1672': [
        0x18,
        {
            'List': [0x0, ['pointer64', ['_CELL_DATA']]],
            'Index': [0x8, ['unsigned long']],
            'Cell': [0xC, ['unsigned long']],
            'CellPoint': [0x10, ['pointer64', ['_CELL_DATA']]],
        },
    ],
    '__unnamed_1676': [
        0x10,
        {
            'Space': [0x0, ['unsigned long']],
            'MapPoint': [0x4, ['unsigned long']],
            'BinPoint': [0x8, ['pointer64', ['_HBIN']]],
        },
    ],
    '__unnamed_167a': [
        0x10,
        {
            'Bin': [0x0, ['pointer64', ['_HBIN']]],
            'CellPoint': [0x8, ['pointer64', ['_HCELL']]],
        },
    ],
    '__unnamed_167c': [
        0x4,
        {
            'FileOffset': [0x0, ['unsigned long']],
        },
    ],
    '_HIVE_LOAD_FAILURE': [
        0x160,
        {
            'Hive': [0x0, ['pointer64', ['_HHIVE']]],
            'Index': [0x8, ['unsigned long']],
            'RecoverableIndex': [0xC, ['unsigned long']],
            'Locations': [0x10, ['array', 8, ['__unnamed_1669']]],
            'RecoverableLocations': [0x70, ['array', 8, ['__unnamed_1669']]],
            'RegistryIO': [0xD0, ['__unnamed_166c']],
            'CheckRegistry2': [0xE8, ['__unnamed_166e']],
            'CheckKey': [0xF0, ['__unnamed_1670']],
            'CheckValueList': [0x110, ['__unnamed_1672']],
            'CheckHive': [0x128, ['__unnamed_1676']],
            'CheckHive1': [0x138, ['__unnamed_1676']],
            'CheckBin': [0x148, ['__unnamed_167a']],
            'RecoverData': [0x158, ['__unnamed_167c']],
        },
    ],
    '_PCW_COUNTER_DESCRIPTOR': [
        0x8,
        {
            'Id': [0x0, ['unsigned short']],
            'StructIndex': [0x2, ['unsigned short']],
            'Offset': [0x4, ['unsigned short']],
            'Size': [0x6, ['unsigned short']],
        },
    ],
    '_PCW_REGISTRATION_INFORMATION': [
        0x30,
        {
            'Version': [0x0, ['unsigned long']],
            'Name': [0x8, ['pointer64', ['_UNICODE_STRING']]],
            'CounterCount': [0x10, ['unsigned long']],
            'Counters': [0x18, ['pointer64', ['_PCW_COUNTER_DESCRIPTOR']]],
            'Callback': [0x20, ['pointer64', ['void']]],
            'CallbackContext': [0x28, ['pointer64', ['void']]],
        },
    ],
    '_PCW_PROCESSOR_INFO': [
        0x80,
        {
            'IdleTime': [0x0, ['unsigned long long']],
            'AvailableTime': [0x8, ['unsigned long long']],
            'UserTime': [0x10, ['unsigned long long']],
            'KernelTime': [0x18, ['unsigned long long']],
            'Interrupts': [0x20, ['unsigned long']],
            'DpcTime': [0x28, ['unsigned long long']],
            'InterruptTime': [0x30, ['unsigned long long']],
            'DpcCount': [0x38, ['unsigned long']],
            'DpcRate': [0x3C, ['unsigned long']],
            'C1Time': [0x40, ['unsigned long long']],
            'C2Time': [0x48, ['unsigned long long']],
            'C3Time': [0x50, ['unsigned long long']],
            'C1Transitions': [0x58, ['unsigned long long']],
            'C2Transitions': [0x60, ['unsigned long long']],
            'C3Transitions': [0x68, ['unsigned long long']],
            'ParkingStatus': [0x70, ['unsigned long']],
            'CurrentFrequency': [0x74, ['unsigned long']],
            'PercentMaxFrequency': [0x78, ['unsigned long']],
            'StateFlags': [0x7C, ['unsigned long']],
        },
    ],
    '_PCW_DATA': [
        0x10,
        {
            'Data': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned long']],
        },
    ],
    '_ETW_PERF_COUNTERS': [
        0x18,
        {
            'TotalActiveSessions': [0x0, ['long']],
            'TotalBufferMemoryNonPagedPool': [0x4, ['long']],
            'TotalBufferMemoryPagedPool': [0x8, ['long']],
            'TotalGuidsEnabled': [0xC, ['long']],
            'TotalGuidsNotEnabled': [0x10, ['long']],
            'TotalGuidsPreEnabled': [0x14, ['long']],
        },
    ],
    '_ETW_SESSION_PERF_COUNTERS': [
        0x18,
        {
            'BufferMemoryPagedPool': [0x0, ['long']],
            'BufferMemoryNonPagedPool': [0x4, ['long']],
            'EventsLoggedCount': [0x8, ['unsigned long long']],
            'EventsLost': [0x10, ['long']],
            'NumConsumers': [0x14, ['long']],
        },
    ],
    '_CONTEXT32_UPDATE': [
        0x4,
        {
            'NumberEntries': [0x0, ['unsigned long']],
        },
    ],
    '_KTIMER_TABLE': [
        0x2200,
        {
            'TimerExpiry': [0x0, ['array', 64, ['pointer64', ['_KTIMER']]]],
            'TimerEntries': [0x200, ['array', 256, ['_KTIMER_TABLE_ENTRY']]],
        },
    ],
    '_KTIMER_TABLE_ENTRY': [
        0x20,
        {
            'Lock': [0x0, ['unsigned long long']],
            'Entry': [0x8, ['_LIST_ENTRY']],
            'Time': [0x18, ['_ULARGE_INTEGER']],
        },
    ],
    '_KAFFINITY_EX': [
        0x28,
        {
            'Count': [0x0, ['unsigned short']],
            'Size': [0x2, ['unsigned short']],
            'Reserved': [0x4, ['unsigned long']],
            'Bitmap': [0x8, ['array', 4, ['unsigned long long']]],
        },
    ],
    '_KAFFINITY_ENUMERATION_CONTEXT': [
        0x18,
        {
            'Affinity': [0x0, ['pointer64', ['_KAFFINITY_EX']]],
            'CurrentMask': [0x8, ['unsigned long long']],
            'CurrentIndex': [0x10, ['unsigned short']],
        },
    ],
    '_GROUP_AFFINITY': [
        0x10,
        {
            'Mask': [0x0, ['unsigned long long']],
            'Group': [0x8, ['unsigned short']],
            'Reserved': [0xA, ['array', 3, ['unsigned short']]],
        },
    ],
    '_KTRAP_FRAME': [
        0x190,
        {
            'P1Home': [0x0, ['unsigned long long']],
            'P2Home': [0x8, ['unsigned long long']],
            'P3Home': [0x10, ['unsigned long long']],
            'P4Home': [0x18, ['unsigned long long']],
            'P5': [0x20, ['unsigned long long']],
            'PreviousMode': [0x28, ['unsigned char']],
            'PreviousIrql': [0x29, ['unsigned char']],
            'FaultIndicator': [0x2A, ['unsigned char']],
            'ExceptionActive': [0x2B, ['unsigned char']],
            'MxCsr': [0x2C, ['unsigned long']],
            'Rax': [0x30, ['unsigned long long']],
            'Rcx': [0x38, ['unsigned long long']],
            'Rdx': [0x40, ['unsigned long long']],
            'R8': [0x48, ['unsigned long long']],
            'R9': [0x50, ['unsigned long long']],
            'R10': [0x58, ['unsigned long long']],
            'R11': [0x60, ['unsigned long long']],
            'GsBase': [0x68, ['unsigned long long']],
            'GsSwap': [0x68, ['unsigned long long']],
            'Xmm0': [0x70, ['_M128A']],
            'Xmm1': [0x80, ['_M128A']],
            'Xmm2': [0x90, ['_M128A']],
            'Xmm3': [0xA0, ['_M128A']],
            'Xmm4': [0xB0, ['_M128A']],
            'Xmm5': [0xC0, ['_M128A']],
            'FaultAddress': [0xD0, ['unsigned long long']],
            'ContextRecord': [0xD0, ['unsigned long long']],
            'TimeStampCKCL': [0xD0, ['unsigned long long']],
            'Dr0': [0xD8, ['unsigned long long']],
            'Dr1': [0xE0, ['unsigned long long']],
            'Dr2': [0xE8, ['unsigned long long']],
            'Dr3': [0xF0, ['unsigned long long']],
            'Dr6': [0xF8, ['unsigned long long']],
            'Dr7': [0x100, ['unsigned long long']],
            'DebugControl': [0x108, ['unsigned long long']],
            'LastBranchToRip': [0x110, ['unsigned long long']],
            'LastBranchFromRip': [0x118, ['unsigned long long']],
            'LastExceptionToRip': [0x120, ['unsigned long long']],
            'LastExceptionFromRip': [0x128, ['unsigned long long']],
            'LastBranchControl': [0x108, ['unsigned long long']],
            'LastBranchMSR': [0x110, ['unsigned long']],
            'SegDs': [0x130, ['unsigned short']],
            'SegEs': [0x132, ['unsigned short']],
            'SegFs': [0x134, ['unsigned short']],
            'SegGs': [0x136, ['unsigned short']],
            'TrapFrame': [0x138, ['unsigned long long']],
            'Rbx': [0x140, ['unsigned long long']],
            'Rdi': [0x148, ['unsigned long long']],
            'Rsi': [0x150, ['unsigned long long']],
            'Rbp': [0x158, ['unsigned long long']],
            'ErrorCode': [0x160, ['unsigned long long']],
            'ExceptionFrame': [0x160, ['unsigned long long']],
            'TimeStampKlog': [0x160, ['unsigned long long']],
            'Rip': [0x168, ['unsigned long long']],
            'SegCs': [0x170, ['unsigned short']],
            'Fill0': [0x172, ['unsigned char']],
            'Logging': [0x173, ['unsigned char']],
            'Fill1': [0x174, ['array', 2, ['unsigned short']]],
            'EFlags': [0x178, ['unsigned long']],
            'Fill2': [0x17C, ['unsigned long']],
            'Rsp': [0x180, ['unsigned long long']],
            'SegSs': [0x188, ['unsigned short']],
            'Fill3': [0x18A, ['unsigned short']],
            'CodePatchCycle': [0x18C, ['long']],
        },
    ],
    '_XSTATE_SAVE': [
        0x38,
        {
            'Prev': [0x0, ['pointer64', ['_XSTATE_SAVE']]],
            'Thread': [0x8, ['pointer64', ['_KTHREAD']]],
            'Level': [0x10, ['unsigned char']],
            'XStateContext': [0x18, ['_XSTATE_CONTEXT']],
        },
    ],
    '_XSAVE_AREA': [
        0x240,
        {
            'LegacyState': [0x0, ['_XSAVE_FORMAT']],
            'Header': [0x200, ['_XSAVE_AREA_HEADER']],
        },
    ],
    '_KEXCEPTION_FRAME': [
        0x140,
        {
            'P1Home': [0x0, ['unsigned long long']],
            'P2Home': [0x8, ['unsigned long long']],
            'P3Home': [0x10, ['unsigned long long']],
            'P4Home': [0x18, ['unsigned long long']],
            'P5': [0x20, ['unsigned long long']],
            'InitialStack': [0x28, ['unsigned long long']],
            'Xmm6': [0x30, ['_M128A']],
            'Xmm7': [0x40, ['_M128A']],
            'Xmm8': [0x50, ['_M128A']],
            'Xmm9': [0x60, ['_M128A']],
            'Xmm10': [0x70, ['_M128A']],
            'Xmm11': [0x80, ['_M128A']],
            'Xmm12': [0x90, ['_M128A']],
            'Xmm13': [0xA0, ['_M128A']],
            'Xmm14': [0xB0, ['_M128A']],
            'Xmm15': [0xC0, ['_M128A']],
            'TrapFrame': [0xD0, ['unsigned long long']],
            'CallbackStack': [0xD8, ['unsigned long long']],
            'OutputBuffer': [0xE0, ['unsigned long long']],
            'OutputLength': [0xE8, ['unsigned long long']],
            'MxCsr': [0xF0, ['unsigned long long']],
            'Rbp': [0xF8, ['unsigned long long']],
            'Rbx': [0x100, ['unsigned long long']],
            'Rdi': [0x108, ['unsigned long long']],
            'Rsi': [0x110, ['unsigned long long']],
            'R12': [0x118, ['unsigned long long']],
            'R13': [0x120, ['unsigned long long']],
            'R14': [0x128, ['unsigned long long']],
            'R15': [0x130, ['unsigned long long']],
            'Return': [0x138, ['unsigned long long']],
        },
    ],
    '_PNP_DEVICE_COMPLETION_QUEUE': [
        0x50,
        {
            'DispatchedList': [0x0, ['_LIST_ENTRY']],
            'DispatchedCount': [0x10, ['unsigned long']],
            'CompletedList': [0x18, ['_LIST_ENTRY']],
            'CompletedSemaphore': [0x28, ['_KSEMAPHORE']],
            'SpinLock': [0x48, ['unsigned long long']],
        },
    ],
    '_KSEMAPHORE': [
        0x20,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'Limit': [0x18, ['long']],
        },
    ],
    '_DEVOBJ_EXTENSION': [
        0x70,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['unsigned short']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'PowerFlags': [0x10, ['unsigned long']],
            'Dope': [0x18, ['pointer64', ['_DEVICE_OBJECT_POWER_EXTENSION']]],
            'ExtensionFlags': [0x20, ['unsigned long']],
            'DeviceNode': [0x28, ['pointer64', ['void']]],
            'AttachedTo': [0x30, ['pointer64', ['_DEVICE_OBJECT']]],
            'StartIoCount': [0x38, ['long']],
            'StartIoKey': [0x3C, ['long']],
            'StartIoFlags': [0x40, ['unsigned long']],
            'Vpb': [0x48, ['pointer64', ['_VPB']]],
            'DependentList': [0x50, ['_LIST_ENTRY']],
            'ProviderList': [0x60, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1763': [
        0x8,
        {
            'LegacyDeviceNode': [0x0, ['pointer64', ['_DEVICE_NODE']]],
            'PendingDeviceRelations': [
                0x0,
                ['pointer64', ['_DEVICE_RELATIONS']],
            ],
            'Information': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1765': [
        0x8,
        {
            'NextResourceDeviceNode': [0x0, ['pointer64', ['_DEVICE_NODE']]],
        },
    ],
    '__unnamed_1769': [
        0x20,
        {
            'DockStatus': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DOCK_NOTDOCKDEVICE',
                            1: 'DOCK_QUIESCENT',
                            2: 'DOCK_ARRIVING',
                            3: 'DOCK_DEPARTING',
                            4: 'DOCK_EJECTIRP_COMPLETED',
                        },
                    ),
                ],
            ],
            'ListEntry': [0x8, ['_LIST_ENTRY']],
            'SerialNumber': [0x18, ['pointer64', ['unsigned short']]],
        },
    ],
    '_DEVICE_NODE': [
        0x268,
        {
            'Sibling': [0x0, ['pointer64', ['_DEVICE_NODE']]],
            'Child': [0x8, ['pointer64', ['_DEVICE_NODE']]],
            'Parent': [0x10, ['pointer64', ['_DEVICE_NODE']]],
            'LastChild': [0x18, ['pointer64', ['_DEVICE_NODE']]],
            'PhysicalDeviceObject': [0x20, ['pointer64', ['_DEVICE_OBJECT']]],
            'InstancePath': [0x28, ['_UNICODE_STRING']],
            'ServiceName': [0x38, ['_UNICODE_STRING']],
            'PendingIrp': [0x48, ['pointer64', ['_IRP']]],
            'Level': [0x50, ['unsigned long']],
            'Notify': [0x58, ['_PO_DEVICE_NOTIFY']],
            'PoIrpManager': [0xC0, ['_PO_IRP_MANAGER']],
            'State': [
                0xE0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            768: 'DeviceNodeUnspecified',
                            769: 'DeviceNodeUninitialized',
                            770: 'DeviceNodeInitialized',
                            771: 'DeviceNodeDriversAdded',
                            772: 'DeviceNodeResourcesAssigned',
                            773: 'DeviceNodeStartPending',
                            774: 'DeviceNodeStartCompletion',
                            775: 'DeviceNodeStartPostWork',
                            776: 'DeviceNodeStarted',
                            777: 'DeviceNodeQueryStopped',
                            778: 'DeviceNodeStopped',
                            779: 'DeviceNodeRestartCompletion',
                            780: 'DeviceNodeEnumeratePending',
                            781: 'DeviceNodeEnumerateCompletion',
                            782: 'DeviceNodeAwaitingQueuedDeletion',
                            783: 'DeviceNodeAwaitingQueuedRemoval',
                            784: 'DeviceNodeQueryRemoved',
                            785: 'DeviceNodeRemovePendingCloses',
                            786: 'DeviceNodeRemoved',
                            787: 'DeviceNodeDeletePendingCloses',
                            788: 'DeviceNodeDeleted',
                            789: 'MaxDeviceNodeState',
                        },
                    ),
                ],
            ],
            'PreviousState': [
                0xE4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            768: 'DeviceNodeUnspecified',
                            769: 'DeviceNodeUninitialized',
                            770: 'DeviceNodeInitialized',
                            771: 'DeviceNodeDriversAdded',
                            772: 'DeviceNodeResourcesAssigned',
                            773: 'DeviceNodeStartPending',
                            774: 'DeviceNodeStartCompletion',
                            775: 'DeviceNodeStartPostWork',
                            776: 'DeviceNodeStarted',
                            777: 'DeviceNodeQueryStopped',
                            778: 'DeviceNodeStopped',
                            779: 'DeviceNodeRestartCompletion',
                            780: 'DeviceNodeEnumeratePending',
                            781: 'DeviceNodeEnumerateCompletion',
                            782: 'DeviceNodeAwaitingQueuedDeletion',
                            783: 'DeviceNodeAwaitingQueuedRemoval',
                            784: 'DeviceNodeQueryRemoved',
                            785: 'DeviceNodeRemovePendingCloses',
                            786: 'DeviceNodeRemoved',
                            787: 'DeviceNodeDeletePendingCloses',
                            788: 'DeviceNodeDeleted',
                            789: 'MaxDeviceNodeState',
                        },
                    ),
                ],
            ],
            'StateHistory': [
                0xE8,
                [
                    'array',
                    -80,
                    [
                        'Enumeration',
                        dict(
                            target='long',
                            choices={
                                768: 'DeviceNodeUnspecified',
                                769: 'DeviceNodeUninitialized',
                                770: 'DeviceNodeInitialized',
                                771: 'DeviceNodeDriversAdded',
                                772: 'DeviceNodeResourcesAssigned',
                                773: 'DeviceNodeStartPending',
                                774: 'DeviceNodeStartCompletion',
                                775: 'DeviceNodeStartPostWork',
                                776: 'DeviceNodeStarted',
                                777: 'DeviceNodeQueryStopped',
                                778: 'DeviceNodeStopped',
                                779: 'DeviceNodeRestartCompletion',
                                780: 'DeviceNodeEnumeratePending',
                                781: 'DeviceNodeEnumerateCompletion',
                                782: 'DeviceNodeAwaitingQueuedDeletion',
                                783: 'DeviceNodeAwaitingQueuedRemoval',
                                784: 'DeviceNodeQueryRemoved',
                                785: 'DeviceNodeRemovePendingCloses',
                                786: 'DeviceNodeRemoved',
                                787: 'DeviceNodeDeletePendingCloses',
                                788: 'DeviceNodeDeleted',
                                789: 'MaxDeviceNodeState',
                            },
                        ),
                    ],
                ],
            ],
            'StateHistoryEntry': [0x138, ['unsigned long']],
            'CompletionStatus': [0x13C, ['long']],
            'Flags': [0x140, ['unsigned long']],
            'UserFlags': [0x144, ['unsigned long']],
            'Problem': [0x148, ['unsigned long']],
            'ResourceList': [0x150, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'ResourceListTranslated': [
                0x158,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
            'DuplicatePDO': [0x160, ['pointer64', ['_DEVICE_OBJECT']]],
            'ResourceRequirements': [
                0x168,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'InterfaceType': [
                0x170,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Internal',
                            1: 'Isa',
                            2: 'Eisa',
                            3: 'MicroChannel',
                            4: 'TurboChannel',
                            5: 'PCIBus',
                            6: 'VMEBus',
                            7: 'NuBus',
                            8: 'PCMCIABus',
                            9: 'CBus',
                            10: 'MPIBus',
                            11: 'MPSABus',
                            12: 'ProcessorInternal',
                            13: 'InternalPowerBus',
                            14: 'PNPISABus',
                            15: 'PNPBus',
                            16: 'Vmcs',
                            17: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0x174, ['unsigned long']],
            'ChildInterfaceType': [
                0x178,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Internal',
                            1: 'Isa',
                            2: 'Eisa',
                            3: 'MicroChannel',
                            4: 'TurboChannel',
                            5: 'PCIBus',
                            6: 'VMEBus',
                            7: 'NuBus',
                            8: 'PCMCIABus',
                            9: 'CBus',
                            10: 'MPIBus',
                            11: 'MPSABus',
                            12: 'ProcessorInternal',
                            13: 'InternalPowerBus',
                            14: 'PNPISABus',
                            15: 'PNPBus',
                            16: 'Vmcs',
                            17: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'ChildBusNumber': [0x17C, ['unsigned long']],
            'ChildBusTypeIndex': [0x180, ['unsigned short']],
            'RemovalPolicy': [0x182, ['unsigned char']],
            'HardwareRemovalPolicy': [0x183, ['unsigned char']],
            'TargetDeviceNotify': [0x188, ['_LIST_ENTRY']],
            'DeviceArbiterList': [0x198, ['_LIST_ENTRY']],
            'DeviceTranslatorList': [0x1A8, ['_LIST_ENTRY']],
            'NoTranslatorMask': [0x1B8, ['unsigned short']],
            'QueryTranslatorMask': [0x1BA, ['unsigned short']],
            'NoArbiterMask': [0x1BC, ['unsigned short']],
            'QueryArbiterMask': [0x1BE, ['unsigned short']],
            'OverUsed1': [0x1C0, ['__unnamed_1763']],
            'OverUsed2': [0x1C8, ['__unnamed_1765']],
            'BootResources': [0x1D0, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'BootResourcesTranslated': [
                0x1D8,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
            'CapabilityFlags': [0x1E0, ['unsigned long']],
            'DockInfo': [0x1E8, ['__unnamed_1769']],
            'DisableableDepends': [0x208, ['unsigned long']],
            'PendedSetInterfaceState': [0x210, ['_LIST_ENTRY']],
            'LegacyBusListEntry': [0x220, ['_LIST_ENTRY']],
            'DriverUnloadRetryCount': [0x230, ['unsigned long']],
            'PreviousParent': [0x238, ['pointer64', ['_DEVICE_NODE']]],
            'DeletedChildren': [0x240, ['unsigned long']],
            'NumaNodeIndex': [0x244, ['unsigned long']],
            'ContainerID': [0x248, ['_GUID']],
            'OverrideFlags': [0x258, ['unsigned char']],
            'RequiresUnloadedDriver': [0x259, ['unsigned char']],
            'PendingEjectRelations': [
                0x260,
                ['pointer64', ['_PENDING_RELATIONS_LIST_ENTRY']],
            ],
        },
    ],
    '_KNODE': [
        0xC0,
        {
            'PagedPoolSListHead': [0x0, ['_SLIST_HEADER']],
            'NonPagedPoolSListHead': [0x10, ['array', 3, ['_SLIST_HEADER']]],
            'Affinity': [0x40, ['_GROUP_AFFINITY']],
            'ProximityId': [0x50, ['unsigned long']],
            'NodeNumber': [0x54, ['unsigned short']],
            'PrimaryNodeNumber': [0x56, ['unsigned short']],
            'MaximumProcessors': [0x58, ['unsigned char']],
            'Color': [0x59, ['unsigned char']],
            'Flags': [0x5A, ['_flags']],
            'NodePad0': [0x5B, ['unsigned char']],
            'Seed': [0x5C, ['unsigned long']],
            'MmShiftedColor': [0x60, ['unsigned long']],
            'FreeCount': [0x68, ['array', 2, ['unsigned long long']]],
            'Right': [0x78, ['unsigned long']],
            'Left': [0x7C, ['unsigned long']],
            'CachedKernelStacks': [0x80, ['_CACHED_KSTACK_LIST']],
            'ParkLock': [0xA0, ['long']],
            'NodePad1': [0xA4, ['unsigned long']],
        },
    ],
    '_PNP_ASSIGN_RESOURCES_CONTEXT': [
        0x10,
        {
            'IncludeFailedDevices': [0x0, ['unsigned long']],
            'DeviceCount': [0x4, ['unsigned long']],
            'DeviceList': [
                0x8,
                ['array', 1, ['pointer64', ['_DEVICE_OBJECT']]],
            ],
        },
    ],
    '_PNP_RESOURCE_REQUEST': [
        0x40,
        {
            'PhysicalDevice': [0x0, ['pointer64', ['_DEVICE_OBJECT']]],
            'Flags': [0x8, ['unsigned long']],
            'AllocationType': [
                0xC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ArbiterRequestLegacyReported',
                            1: 'ArbiterRequestHalReported',
                            2: 'ArbiterRequestLegacyAssigned',
                            3: 'ArbiterRequestPnpDetected',
                            4: 'ArbiterRequestPnpEnumerated',
                            -1: 'ArbiterRequestUndefined',
                        },
                    ),
                ],
            ],
            'Priority': [0x10, ['unsigned long']],
            'Position': [0x14, ['unsigned long']],
            'ResourceRequirements': [
                0x18,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'ReqList': [0x20, ['pointer64', ['void']]],
            'ResourceAssignment': [0x28, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'TranslatedResourceAssignment': [
                0x30,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
            'Status': [0x38, ['long']],
        },
    ],
    '_IO_RESOURCE_REQUIREMENTS_LIST': [
        0x48,
        {
            'ListSize': [0x0, ['unsigned long']],
            'InterfaceType': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Internal',
                            1: 'Isa',
                            2: 'Eisa',
                            3: 'MicroChannel',
                            4: 'TurboChannel',
                            5: 'PCIBus',
                            6: 'VMEBus',
                            7: 'NuBus',
                            8: 'PCMCIABus',
                            9: 'CBus',
                            10: 'MPIBus',
                            11: 'MPSABus',
                            12: 'ProcessorInternal',
                            13: 'InternalPowerBus',
                            14: 'PNPISABus',
                            15: 'PNPBus',
                            16: 'Vmcs',
                            17: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0x8, ['unsigned long']],
            'SlotNumber': [0xC, ['unsigned long']],
            'Reserved': [0x10, ['array', 3, ['unsigned long']]],
            'AlternativeLists': [0x1C, ['unsigned long']],
            'List': [0x20, ['array', 1, ['_IO_RESOURCE_LIST']]],
        },
    ],
    '_EXCEPTION_RECORD64': [
        0x98,
        {
            'ExceptionCode': [0x0, ['long']],
            'ExceptionFlags': [0x4, ['unsigned long']],
            'ExceptionRecord': [0x8, ['unsigned long long']],
            'ExceptionAddress': [0x10, ['unsigned long long']],
            'NumberParameters': [0x18, ['unsigned long']],
            '__unusedAlignment': [0x1C, ['unsigned long']],
            'ExceptionInformation': [
                0x20,
                ['array', 15, ['unsigned long long']],
            ],
        },
    ],
    '_EXCEPTION_RECORD32': [
        0x50,
        {
            'ExceptionCode': [0x0, ['long']],
            'ExceptionFlags': [0x4, ['unsigned long']],
            'ExceptionRecord': [0x8, ['unsigned long']],
            'ExceptionAddress': [0xC, ['unsigned long']],
            'NumberParameters': [0x10, ['unsigned long']],
            'ExceptionInformation': [0x14, ['array', 15, ['unsigned long']]],
        },
    ],
    '_DBGKM_EXCEPTION64': [
        0xA0,
        {
            'ExceptionRecord': [0x0, ['_EXCEPTION_RECORD64']],
            'FirstChance': [0x98, ['unsigned long']],
        },
    ],
    '_DBGKM_EXCEPTION32': [
        0x54,
        {
            'ExceptionRecord': [0x0, ['_EXCEPTION_RECORD32']],
            'FirstChance': [0x50, ['unsigned long']],
        },
    ],
    '_DBGKD_LOAD_SYMBOLS64': [
        0x28,
        {
            'PathNameLength': [0x0, ['unsigned long']],
            'BaseOfDll': [0x8, ['unsigned long long']],
            'ProcessId': [0x10, ['unsigned long long']],
            'CheckSum': [0x18, ['unsigned long']],
            'SizeOfImage': [0x1C, ['unsigned long']],
            'UnloadSymbols': [0x20, ['unsigned char']],
        },
    ],
    '_DBGKD_LOAD_SYMBOLS32': [
        0x18,
        {
            'PathNameLength': [0x0, ['unsigned long']],
            'BaseOfDll': [0x4, ['unsigned long']],
            'ProcessId': [0x8, ['unsigned long']],
            'CheckSum': [0xC, ['unsigned long']],
            'SizeOfImage': [0x10, ['unsigned long']],
            'UnloadSymbols': [0x14, ['unsigned char']],
        },
    ],
    '_DBGKD_READ_MEMORY64': [
        0x10,
        {
            'TargetBaseAddress': [0x0, ['unsigned long long']],
            'TransferCount': [0x8, ['unsigned long']],
            'ActualBytesRead': [0xC, ['unsigned long']],
        },
    ],
    '_DBGKD_READ_MEMORY32': [
        0xC,
        {
            'TargetBaseAddress': [0x0, ['unsigned long']],
            'TransferCount': [0x4, ['unsigned long']],
            'ActualBytesRead': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_WRITE_MEMORY64': [
        0x10,
        {
            'TargetBaseAddress': [0x0, ['unsigned long long']],
            'TransferCount': [0x8, ['unsigned long']],
            'ActualBytesWritten': [0xC, ['unsigned long']],
        },
    ],
    '_DBGKD_WRITE_MEMORY32': [
        0xC,
        {
            'TargetBaseAddress': [0x0, ['unsigned long']],
            'TransferCount': [0x4, ['unsigned long']],
            'ActualBytesWritten': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_WRITE_BREAKPOINT64': [
        0x10,
        {
            'BreakPointAddress': [0x0, ['unsigned long long']],
            'BreakPointHandle': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_WRITE_BREAKPOINT32': [
        0x8,
        {
            'BreakPointAddress': [0x0, ['unsigned long']],
            'BreakPointHandle': [0x4, ['unsigned long']],
        },
    ],
    '_DBGKD_READ_WRITE_IO64': [
        0x10,
        {
            'IoAddress': [0x0, ['unsigned long long']],
            'DataSize': [0x8, ['unsigned long']],
            'DataValue': [0xC, ['unsigned long']],
        },
    ],
    '_DBGKD_READ_WRITE_IO32': [
        0xC,
        {
            'DataSize': [0x0, ['unsigned long']],
            'IoAddress': [0x4, ['unsigned long']],
            'DataValue': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_READ_WRITE_IO_EXTENDED64': [
        0x20,
        {
            'DataSize': [0x0, ['unsigned long']],
            'InterfaceType': [0x4, ['unsigned long']],
            'BusNumber': [0x8, ['unsigned long']],
            'AddressSpace': [0xC, ['unsigned long']],
            'IoAddress': [0x10, ['unsigned long long']],
            'DataValue': [0x18, ['unsigned long']],
        },
    ],
    '_DBGKD_READ_WRITE_IO_EXTENDED32': [
        0x18,
        {
            'DataSize': [0x0, ['unsigned long']],
            'InterfaceType': [0x4, ['unsigned long']],
            'BusNumber': [0x8, ['unsigned long']],
            'AddressSpace': [0xC, ['unsigned long']],
            'IoAddress': [0x10, ['unsigned long']],
            'DataValue': [0x14, ['unsigned long']],
        },
    ],
    '_DBGKD_SET_SPECIAL_CALL32': [
        0x4,
        {
            'SpecialCall': [0x0, ['unsigned long']],
        },
    ],
    '_DBGKD_SET_SPECIAL_CALL64': [
        0x8,
        {
            'SpecialCall': [0x0, ['unsigned long long']],
        },
    ],
    '_DBGKD_SET_INTERNAL_BREAKPOINT32': [
        0x8,
        {
            'BreakpointAddress': [0x0, ['unsigned long']],
            'Flags': [0x4, ['unsigned long']],
        },
    ],
    '_DBGKD_SET_INTERNAL_BREAKPOINT64': [
        0x10,
        {
            'BreakpointAddress': [0x0, ['unsigned long long']],
            'Flags': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_GET_INTERNAL_BREAKPOINT64': [
        0x20,
        {
            'BreakpointAddress': [0x0, ['unsigned long long']],
            'Flags': [0x8, ['unsigned long']],
            'Calls': [0xC, ['unsigned long']],
            'MaxCallsPerPeriod': [0x10, ['unsigned long']],
            'MinInstructions': [0x14, ['unsigned long']],
            'MaxInstructions': [0x18, ['unsigned long']],
            'TotalInstructions': [0x1C, ['unsigned long']],
        },
    ],
    '_DBGKD_GET_INTERNAL_BREAKPOINT32': [
        0x1C,
        {
            'BreakpointAddress': [0x0, ['unsigned long']],
            'Flags': [0x4, ['unsigned long']],
            'Calls': [0x8, ['unsigned long']],
            'MaxCallsPerPeriod': [0xC, ['unsigned long']],
            'MinInstructions': [0x10, ['unsigned long']],
            'MaxInstructions': [0x14, ['unsigned long']],
            'TotalInstructions': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1811': [
        0x28,
        {
            'ReadMemory': [0x0, ['_DBGKD_READ_MEMORY64']],
            'WriteMemory': [0x0, ['_DBGKD_WRITE_MEMORY64']],
            'GetContext': [0x0, ['_DBGKD_GET_CONTEXT']],
            'SetContext': [0x0, ['_DBGKD_SET_CONTEXT']],
            'WriteBreakPoint': [0x0, ['_DBGKD_WRITE_BREAKPOINT64']],
            'RestoreBreakPoint': [0x0, ['_DBGKD_RESTORE_BREAKPOINT']],
            'Continue': [0x0, ['_DBGKD_CONTINUE']],
            'Continue2': [0x0, ['_DBGKD_CONTINUE2']],
            'ReadWriteIo': [0x0, ['_DBGKD_READ_WRITE_IO64']],
            'ReadWriteIoExtended': [0x0, ['_DBGKD_READ_WRITE_IO_EXTENDED64']],
            'QuerySpecialCalls': [0x0, ['_DBGKD_QUERY_SPECIAL_CALLS']],
            'SetSpecialCall': [0x0, ['_DBGKD_SET_SPECIAL_CALL64']],
            'SetInternalBreakpoint': [
                0x0,
                ['_DBGKD_SET_INTERNAL_BREAKPOINT64'],
            ],
            'GetInternalBreakpoint': [
                0x0,
                ['_DBGKD_GET_INTERNAL_BREAKPOINT64'],
            ],
            'GetVersion64': [0x0, ['_DBGKD_GET_VERSION64']],
            'BreakPointEx': [0x0, ['_DBGKD_BREAKPOINTEX']],
            'ReadWriteMsr': [0x0, ['_DBGKD_READ_WRITE_MSR']],
            'SearchMemory': [0x0, ['_DBGKD_SEARCH_MEMORY']],
            'GetSetBusData': [0x0, ['_DBGKD_GET_SET_BUS_DATA']],
            'FillMemory': [0x0, ['_DBGKD_FILL_MEMORY']],
            'QueryMemory': [0x0, ['_DBGKD_QUERY_MEMORY']],
            'SwitchPartition': [0x0, ['_DBGKD_SWITCH_PARTITION']],
        },
    ],
    '_DBGKD_MANIPULATE_STATE64': [
        0x38,
        {
            'ApiNumber': [0x0, ['unsigned long']],
            'ProcessorLevel': [0x4, ['unsigned short']],
            'Processor': [0x6, ['unsigned short']],
            'ReturnStatus': [0x8, ['long']],
            'u': [0x10, ['__unnamed_1811']],
        },
    ],
    '__unnamed_1818': [
        0x28,
        {
            'ReadMemory': [0x0, ['_DBGKD_READ_MEMORY32']],
            'WriteMemory': [0x0, ['_DBGKD_WRITE_MEMORY32']],
            'ReadMemory64': [0x0, ['_DBGKD_READ_MEMORY64']],
            'WriteMemory64': [0x0, ['_DBGKD_WRITE_MEMORY64']],
            'GetContext': [0x0, ['_DBGKD_GET_CONTEXT']],
            'SetContext': [0x0, ['_DBGKD_SET_CONTEXT']],
            'WriteBreakPoint': [0x0, ['_DBGKD_WRITE_BREAKPOINT32']],
            'RestoreBreakPoint': [0x0, ['_DBGKD_RESTORE_BREAKPOINT']],
            'Continue': [0x0, ['_DBGKD_CONTINUE']],
            'Continue2': [0x0, ['_DBGKD_CONTINUE2']],
            'ReadWriteIo': [0x0, ['_DBGKD_READ_WRITE_IO32']],
            'ReadWriteIoExtended': [0x0, ['_DBGKD_READ_WRITE_IO_EXTENDED32']],
            'QuerySpecialCalls': [0x0, ['_DBGKD_QUERY_SPECIAL_CALLS']],
            'SetSpecialCall': [0x0, ['_DBGKD_SET_SPECIAL_CALL32']],
            'SetInternalBreakpoint': [
                0x0,
                ['_DBGKD_SET_INTERNAL_BREAKPOINT32'],
            ],
            'GetInternalBreakpoint': [
                0x0,
                ['_DBGKD_GET_INTERNAL_BREAKPOINT32'],
            ],
            'GetVersion32': [0x0, ['_DBGKD_GET_VERSION32']],
            'BreakPointEx': [0x0, ['_DBGKD_BREAKPOINTEX']],
            'ReadWriteMsr': [0x0, ['_DBGKD_READ_WRITE_MSR']],
            'SearchMemory': [0x0, ['_DBGKD_SEARCH_MEMORY']],
        },
    ],
    '_DBGKD_MANIPULATE_STATE32': [
        0x34,
        {
            'ApiNumber': [0x0, ['unsigned long']],
            'ProcessorLevel': [0x4, ['unsigned short']],
            'Processor': [0x6, ['unsigned short']],
            'ReturnStatus': [0x8, ['long']],
            'u': [0xC, ['__unnamed_1818']],
        },
    ],
    '_DBGKD_READ_WRITE_MSR': [
        0xC,
        {
            'Msr': [0x0, ['unsigned long']],
            'DataValueLow': [0x4, ['unsigned long']],
            'DataValueHigh': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_BREAKPOINTEX': [
        0x8,
        {
            'BreakPointCount': [0x0, ['unsigned long']],
            'ContinueStatus': [0x4, ['long']],
        },
    ],
    '_DBGKD_SEARCH_MEMORY': [
        0x18,
        {
            'SearchAddress': [0x0, ['unsigned long long']],
            'FoundAddress': [0x0, ['unsigned long long']],
            'SearchLength': [0x8, ['unsigned long long']],
            'PatternLength': [0x10, ['unsigned long']],
        },
    ],
    '_DBGKD_RESTORE_BREAKPOINT': [
        0x4,
        {
            'BreakPointHandle': [0x0, ['unsigned long']],
        },
    ],
    '_DBGKD_CONTINUE': [
        0x4,
        {
            'ContinueStatus': [0x0, ['long']],
        },
    ],
    '_DBGKD_CONTINUE2': [
        0x20,
        {
            'ContinueStatus': [0x0, ['long']],
            'ControlSet': [0x4, ['_AMD64_DBGKD_CONTROL_SET']],
            'AnyControlSet': [0x4, ['_DBGKD_ANY_CONTROL_SET']],
        },
    ],
    '_CPU_INFO': [
        0x10,
        {
            'Eax': [0x0, ['unsigned long']],
            'Ebx': [0x4, ['unsigned long']],
            'Ecx': [0x8, ['unsigned long']],
            'Edx': [0xC, ['unsigned long']],
        },
    ],
    '_KSYSTEM_TIME': [
        0xC,
        {
            'LowPart': [0x0, ['unsigned long']],
            'High1Time': [0x4, ['long']],
            'High2Time': [0x8, ['long']],
        },
    ],
    '_VOLUME_CACHE_MAP': [
        0x38,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteCode': [0x2, ['short']],
            'UseCount': [0x4, ['unsigned long']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'VolumeCacheMapLinks': [0x10, ['_LIST_ENTRY']],
            'Flags': [0x20, ['unsigned long']],
            'DirtyPages': [0x28, ['unsigned long long']],
            'PagesQueuedToDisk': [0x30, ['unsigned long']],
        },
    ],
    '_SHARED_CACHE_MAP': [
        0x1F8,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteSize': [0x2, ['short']],
            'OpenCount': [0x4, ['unsigned long']],
            'FileSize': [0x8, ['_LARGE_INTEGER']],
            'BcbList': [0x10, ['_LIST_ENTRY']],
            'SectionSize': [0x20, ['_LARGE_INTEGER']],
            'ValidDataLength': [0x28, ['_LARGE_INTEGER']],
            'ValidDataGoal': [0x30, ['_LARGE_INTEGER']],
            'InitialVacbs': [0x38, ['array', 4, ['pointer64', ['_VACB']]]],
            'Vacbs': [0x58, ['pointer64', ['pointer64', ['_VACB']]]],
            'FileObjectFastRef': [0x60, ['_EX_FAST_REF']],
            'VacbLock': [0x68, ['_EX_PUSH_LOCK']],
            'DirtyPages': [0x70, ['unsigned long']],
            'LoggedStreamLinks': [0x78, ['_LIST_ENTRY']],
            'SharedCacheMapLinks': [0x88, ['_LIST_ENTRY']],
            'Flags': [0x98, ['unsigned long']],
            'Status': [0x9C, ['long']],
            'Mbcb': [0xA0, ['pointer64', ['_MBCB']]],
            'Section': [0xA8, ['pointer64', ['void']]],
            'CreateEvent': [0xB0, ['pointer64', ['_KEVENT']]],
            'WaitOnActiveCount': [0xB8, ['pointer64', ['_KEVENT']]],
            'PagesToWrite': [0xC0, ['unsigned long']],
            'BeyondLastFlush': [0xC8, ['long long']],
            'Callbacks': [0xD0, ['pointer64', ['_CACHE_MANAGER_CALLBACKS']]],
            'LazyWriteContext': [0xD8, ['pointer64', ['void']]],
            'PrivateList': [0xE0, ['_LIST_ENTRY']],
            'LogHandle': [0xF0, ['pointer64', ['void']]],
            'FlushToLsnRoutine': [0xF8, ['pointer64', ['void']]],
            'DirtyPageThreshold': [0x100, ['unsigned long']],
            'LazyWritePassCount': [0x104, ['unsigned long']],
            'UninitializeEvent': [
                0x108,
                ['pointer64', ['_CACHE_UNINITIALIZE_EVENT']],
            ],
            'BcbLock': [0x110, ['_KGUARDED_MUTEX']],
            'LastUnmapBehindOffset': [0x148, ['_LARGE_INTEGER']],
            'Event': [0x150, ['_KEVENT']],
            'HighWaterMappingOffset': [0x168, ['_LARGE_INTEGER']],
            'PrivateCacheMap': [0x170, ['_PRIVATE_CACHE_MAP']],
            'WriteBehindWorkQueueEntry': [0x1D8, ['pointer64', ['void']]],
            'VolumeCacheMap': [0x1E0, ['pointer64', ['_VOLUME_CACHE_MAP']]],
            'ProcImagePathHash': [0x1E8, ['unsigned long']],
            'WritesInProgress': [0x1EC, ['unsigned long']],
            'PipelinedReadAheadSize': [0x1F0, ['unsigned long']],
        },
    ],
    '__unnamed_188a': [
        0x8,
        {
            'FileOffset': [0x0, ['_LARGE_INTEGER']],
            'ActiveCount': [0x0, ['unsigned short']],
        },
    ],
    '_VACB': [
        0x30,
        {
            'BaseAddress': [0x0, ['pointer64', ['void']]],
            'SharedCacheMap': [0x8, ['pointer64', ['_SHARED_CACHE_MAP']]],
            'Overlay': [0x10, ['__unnamed_188a']],
            'Links': [0x18, ['_LIST_ENTRY']],
            'ArrayHead': [0x28, ['pointer64', ['_VACB_ARRAY_HEADER']]],
        },
    ],
    '_KGUARDED_MUTEX': [
        0x38,
        {
            'Count': [0x0, ['long']],
            'Owner': [0x8, ['pointer64', ['_KTHREAD']]],
            'Contention': [0x10, ['unsigned long']],
            'Gate': [0x18, ['_KGATE']],
            'KernelApcDisable': [0x30, ['short']],
            'SpecialApcDisable': [0x32, ['short']],
            'CombinedApcDisable': [0x30, ['unsigned long']],
        },
    ],
    '__unnamed_18a8': [
        0x8,
        {
            'FileObject': [0x0, ['pointer64', ['_FILE_OBJECT']]],
        },
    ],
    '__unnamed_18aa': [
        0x8,
        {
            'SharedCacheMap': [0x0, ['pointer64', ['_SHARED_CACHE_MAP']]],
        },
    ],
    '__unnamed_18ac': [
        0x8,
        {
            'Event': [0x0, ['pointer64', ['_KEVENT']]],
        },
    ],
    '__unnamed_18ae': [
        0x4,
        {
            'Reason': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_18b0': [
        0x8,
        {
            'Read': [0x0, ['__unnamed_18a8']],
            'Write': [0x0, ['__unnamed_18aa']],
            'Event': [0x0, ['__unnamed_18ac']],
            'Notification': [0x0, ['__unnamed_18ae']],
        },
    ],
    '_WORK_QUEUE_ENTRY': [
        0x20,
        {
            'WorkQueueLinks': [0x0, ['_LIST_ENTRY']],
            'Parameters': [0x10, ['__unnamed_18b0']],
            'Function': [0x18, ['unsigned char']],
        },
    ],
    'VACB_LEVEL_ALLOCATION_LIST': [
        0x20,
        {
            'VacbLevelList': [0x0, ['_LIST_ENTRY']],
            'VacbLevelWithBcbListHeads': [0x10, ['pointer64', ['void']]],
            'VacbLevelsAllocated': [0x18, ['unsigned long']],
        },
    ],
    '_VACB_LEVEL_REFERENCE': [
        0x8,
        {
            'Reference': [0x0, ['long']],
            'SpecialReference': [0x4, ['long']],
        },
    ],
    '_CACHE_UNINITIALIZE_EVENT': [
        0x20,
        {
            'Next': [0x0, ['pointer64', ['_CACHE_UNINITIALIZE_EVENT']]],
            'Event': [0x8, ['_KEVENT']],
        },
    ],
    '_HEAP_LIST_LOOKUP': [
        0x38,
        {
            'ExtendedLookup': [0x0, ['pointer64', ['_HEAP_LIST_LOOKUP']]],
            'ArraySize': [0x8, ['unsigned long']],
            'ExtraItem': [0xC, ['unsigned long']],
            'ItemCount': [0x10, ['unsigned long']],
            'OutOfRangeItems': [0x14, ['unsigned long']],
            'BaseIndex': [0x18, ['unsigned long']],
            'ListHead': [0x20, ['pointer64', ['_LIST_ENTRY']]],
            'ListsInUseUlong': [0x28, ['pointer64', ['unsigned long']]],
            'ListHints': [0x30, ['pointer64', ['pointer64', ['_LIST_ENTRY']]]],
        },
    ],
    '_HEAP': [
        0x208,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'SegmentSignature': [0x10, ['unsigned long']],
            'SegmentFlags': [0x14, ['unsigned long']],
            'SegmentListEntry': [0x18, ['_LIST_ENTRY']],
            'Heap': [0x28, ['pointer64', ['_HEAP']]],
            'BaseAddress': [0x30, ['pointer64', ['void']]],
            'NumberOfPages': [0x38, ['unsigned long']],
            'FirstEntry': [0x40, ['pointer64', ['_HEAP_ENTRY']]],
            'LastValidEntry': [0x48, ['pointer64', ['_HEAP_ENTRY']]],
            'NumberOfUnCommittedPages': [0x50, ['unsigned long']],
            'NumberOfUnCommittedRanges': [0x54, ['unsigned long']],
            'SegmentAllocatorBackTraceIndex': [0x58, ['unsigned short']],
            'Reserved': [0x5A, ['unsigned short']],
            'UCRSegmentList': [0x60, ['_LIST_ENTRY']],
            'Flags': [0x70, ['unsigned long']],
            'ForceFlags': [0x74, ['unsigned long']],
            'CompatibilityFlags': [0x78, ['unsigned long']],
            'EncodeFlagMask': [0x7C, ['unsigned long']],
            'Encoding': [0x80, ['_HEAP_ENTRY']],
            'PointerKey': [0x90, ['unsigned long long']],
            'Interceptor': [0x98, ['unsigned long']],
            'VirtualMemoryThreshold': [0x9C, ['unsigned long']],
            'Signature': [0xA0, ['unsigned long']],
            'SegmentReserve': [0xA8, ['unsigned long long']],
            'SegmentCommit': [0xB0, ['unsigned long long']],
            'DeCommitFreeBlockThreshold': [0xB8, ['unsigned long long']],
            'DeCommitTotalFreeThreshold': [0xC0, ['unsigned long long']],
            'TotalFreeSize': [0xC8, ['unsigned long long']],
            'MaximumAllocationSize': [0xD0, ['unsigned long long']],
            'ProcessHeapsListIndex': [0xD8, ['unsigned short']],
            'HeaderValidateLength': [0xDA, ['unsigned short']],
            'HeaderValidateCopy': [0xE0, ['pointer64', ['void']]],
            'NextAvailableTagIndex': [0xE8, ['unsigned short']],
            'MaximumTagIndex': [0xEA, ['unsigned short']],
            'TagEntries': [0xF0, ['pointer64', ['_HEAP_TAG_ENTRY']]],
            'UCRList': [0xF8, ['_LIST_ENTRY']],
            'AlignRound': [0x108, ['unsigned long long']],
            'AlignMask': [0x110, ['unsigned long long']],
            'VirtualAllocdBlocks': [0x118, ['_LIST_ENTRY']],
            'SegmentList': [0x128, ['_LIST_ENTRY']],
            'AllocatorBackTraceIndex': [0x138, ['unsigned short']],
            'NonDedicatedListLength': [0x13C, ['unsigned long']],
            'BlocksIndex': [0x140, ['pointer64', ['void']]],
            'UCRIndex': [0x148, ['pointer64', ['void']]],
            'PseudoTagEntries': [
                0x150,
                ['pointer64', ['_HEAP_PSEUDO_TAG_ENTRY']],
            ],
            'FreeLists': [0x158, ['_LIST_ENTRY']],
            'LockVariable': [0x168, ['pointer64', ['_HEAP_LOCK']]],
            'CommitRoutine': [0x170, ['pointer64', ['void']]],
            'FrontEndHeap': [0x178, ['pointer64', ['void']]],
            'FrontHeapLockCount': [0x180, ['unsigned short']],
            'FrontEndHeapType': [0x182, ['unsigned char']],
            'Counters': [0x188, ['_HEAP_COUNTERS']],
            'TuningParameters': [0x1F8, ['_HEAP_TUNING_PARAMETERS']],
        },
    ],
    '__unnamed_1901': [
        0x28,
        {
            'CriticalSection': [0x0, ['_RTL_CRITICAL_SECTION']],
        },
    ],
    '_HEAP_LOCK': [
        0x28,
        {
            'Lock': [0x0, ['__unnamed_1901']],
        },
    ],
    '_RTL_CRITICAL_SECTION': [
        0x28,
        {
            'DebugInfo': [0x0, ['pointer64', ['_RTL_CRITICAL_SECTION_DEBUG']]],
            'LockCount': [0x8, ['long']],
            'RecursionCount': [0xC, ['long']],
            'OwningThread': [0x10, ['pointer64', ['void']]],
            'LockSemaphore': [0x18, ['pointer64', ['void']]],
            'SpinCount': [0x20, ['unsigned long long']],
        },
    ],
    '_HEAP_ENTRY': [
        0x10,
        {
            'PreviousBlockPrivateData': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned short']],
            'Flags': [0xA, ['unsigned char']],
            'SmallTagIndex': [0xB, ['unsigned char']],
            'PreviousSize': [0xC, ['unsigned short']],
            'SegmentOffset': [0xE, ['unsigned char']],
            'LFHFlags': [0xE, ['unsigned char']],
            'UnusedBytes': [0xF, ['unsigned char']],
            'CompactHeader': [0x8, ['unsigned long long']],
            'Reserved': [0x0, ['pointer64', ['void']]],
            'FunctionIndex': [0x8, ['unsigned short']],
            'ContextValue': [0xA, ['unsigned short']],
            'InterceptorValue': [0x8, ['unsigned long']],
            'UnusedBytesLength': [0xC, ['unsigned short']],
            'EntryOffset': [0xE, ['unsigned char']],
            'ExtendedBlockSignature': [0xF, ['unsigned char']],
            'ReservedForAlignment': [0x0, ['pointer64', ['void']]],
            'Code1': [0x8, ['unsigned long']],
            'Code2': [0xC, ['unsigned short']],
            'Code3': [0xE, ['unsigned char']],
            'Code4': [0xF, ['unsigned char']],
            'AgregateCode': [0x8, ['unsigned long long']],
        },
    ],
    '_HEAP_SEGMENT': [
        0x70,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'SegmentSignature': [0x10, ['unsigned long']],
            'SegmentFlags': [0x14, ['unsigned long']],
            'SegmentListEntry': [0x18, ['_LIST_ENTRY']],
            'Heap': [0x28, ['pointer64', ['_HEAP']]],
            'BaseAddress': [0x30, ['pointer64', ['void']]],
            'NumberOfPages': [0x38, ['unsigned long']],
            'FirstEntry': [0x40, ['pointer64', ['_HEAP_ENTRY']]],
            'LastValidEntry': [0x48, ['pointer64', ['_HEAP_ENTRY']]],
            'NumberOfUnCommittedPages': [0x50, ['unsigned long']],
            'NumberOfUnCommittedRanges': [0x54, ['unsigned long']],
            'SegmentAllocatorBackTraceIndex': [0x58, ['unsigned short']],
            'Reserved': [0x5A, ['unsigned short']],
            'UCRSegmentList': [0x60, ['_LIST_ENTRY']],
        },
    ],
    '_HEAP_FREE_ENTRY': [
        0x20,
        {
            'PreviousBlockPrivateData': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned short']],
            'Flags': [0xA, ['unsigned char']],
            'SmallTagIndex': [0xB, ['unsigned char']],
            'PreviousSize': [0xC, ['unsigned short']],
            'SegmentOffset': [0xE, ['unsigned char']],
            'LFHFlags': [0xE, ['unsigned char']],
            'UnusedBytes': [0xF, ['unsigned char']],
            'CompactHeader': [0x8, ['unsigned long long']],
            'Reserved': [0x0, ['pointer64', ['void']]],
            'FunctionIndex': [0x8, ['unsigned short']],
            'ContextValue': [0xA, ['unsigned short']],
            'InterceptorValue': [0x8, ['unsigned long']],
            'UnusedBytesLength': [0xC, ['unsigned short']],
            'EntryOffset': [0xE, ['unsigned char']],
            'ExtendedBlockSignature': [0xF, ['unsigned char']],
            'ReservedForAlignment': [0x0, ['pointer64', ['void']]],
            'Code1': [0x8, ['unsigned long']],
            'Code2': [0xC, ['unsigned short']],
            'Code3': [0xE, ['unsigned char']],
            'Code4': [0xF, ['unsigned char']],
            'AgregateCode': [0x8, ['unsigned long long']],
            'FreeList': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_PEB': [
        0x380,
        {
            'InheritedAddressSpace': [0x0, ['unsigned char']],
            'ReadImageFileExecOptions': [0x1, ['unsigned char']],
            'BeingDebugged': [0x2, ['unsigned char']],
            'BitField': [0x3, ['unsigned char']],
            'ImageUsesLargePages': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'IsProtectedProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'IsLegacyProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'IsImageDynamicallyRelocated': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'SkipPatchingUser32Forwarders': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Mutant': [0x8, ['pointer64', ['void']]],
            'ImageBaseAddress': [0x10, ['pointer64', ['void']]],
            'Ldr': [0x18, ['pointer64', ['_PEB_LDR_DATA']]],
            'ProcessParameters': [
                0x20,
                ['pointer64', ['_RTL_USER_PROCESS_PARAMETERS']],
            ],
            'SubSystemData': [0x28, ['pointer64', ['void']]],
            'ProcessHeap': [0x30, ['pointer64', ['void']]],
            'FastPebLock': [0x38, ['pointer64', ['_RTL_CRITICAL_SECTION']]],
            'AtlThunkSListPtr': [0x40, ['pointer64', ['void']]],
            'IFEOKey': [0x48, ['pointer64', ['void']]],
            'CrossProcessFlags': [0x50, ['unsigned long']],
            'ProcessInJob': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ProcessInitializing': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingVEH': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingVCH': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingFTH': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ReservedBits0': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'KernelCallbackTable': [0x58, ['pointer64', ['void']]],
            'UserSharedInfoPtr': [0x58, ['pointer64', ['void']]],
            'SystemReserved': [0x60, ['array', 1, ['unsigned long']]],
            'AtlThunkSListPtr32': [0x64, ['unsigned long']],
            'ApiSetMap': [0x68, ['pointer64', ['void']]],
            'TlsExpansionCounter': [0x70, ['unsigned long']],
            'TlsBitmap': [0x78, ['pointer64', ['void']]],
            'TlsBitmapBits': [0x80, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x88, ['pointer64', ['void']]],
            'HotpatchInformation': [0x90, ['pointer64', ['void']]],
            'ReadOnlyStaticServerData': [
                0x98,
                ['pointer64', ['pointer64', ['void']]],
            ],
            'AnsiCodePageData': [0xA0, ['pointer64', ['void']]],
            'OemCodePageData': [0xA8, ['pointer64', ['void']]],
            'UnicodeCaseTableData': [0xB0, ['pointer64', ['void']]],
            'NumberOfProcessors': [0xB8, ['unsigned long']],
            'NtGlobalFlag': [0xBC, ['unsigned long']],
            'CriticalSectionTimeout': [0xC0, ['_LARGE_INTEGER']],
            'HeapSegmentReserve': [0xC8, ['unsigned long long']],
            'HeapSegmentCommit': [0xD0, ['unsigned long long']],
            'HeapDeCommitTotalFreeThreshold': [0xD8, ['unsigned long long']],
            'HeapDeCommitFreeBlockThreshold': [0xE0, ['unsigned long long']],
            'NumberOfHeaps': [0xE8, ['unsigned long']],
            'MaximumNumberOfHeaps': [0xEC, ['unsigned long']],
            'ProcessHeaps': [0xF0, ['pointer64', ['pointer64', ['void']]]],
            'GdiSharedHandleTable': [0xF8, ['pointer64', ['void']]],
            'ProcessStarterHelper': [0x100, ['pointer64', ['void']]],
            'GdiDCAttributeList': [0x108, ['unsigned long']],
            'LoaderLock': [0x110, ['pointer64', ['_RTL_CRITICAL_SECTION']]],
            'OSMajorVersion': [0x118, ['unsigned long']],
            'OSMinorVersion': [0x11C, ['unsigned long']],
            'OSBuildNumber': [0x120, ['unsigned short']],
            'OSCSDVersion': [0x122, ['unsigned short']],
            'OSPlatformId': [0x124, ['unsigned long']],
            'ImageSubsystem': [0x128, ['unsigned long']],
            'ImageSubsystemMajorVersion': [0x12C, ['unsigned long']],
            'ImageSubsystemMinorVersion': [0x130, ['unsigned long']],
            'ActiveProcessAffinityMask': [0x138, ['unsigned long long']],
            'GdiHandleBuffer': [0x140, ['array', 60, ['unsigned long']]],
            'PostProcessInitRoutine': [0x230, ['pointer64', ['void']]],
            'TlsExpansionBitmap': [0x238, ['pointer64', ['void']]],
            'TlsExpansionBitmapBits': [
                0x240,
                ['array', 32, ['unsigned long']],
            ],
            'SessionId': [0x2C0, ['unsigned long']],
            'AppCompatFlags': [0x2C8, ['_ULARGE_INTEGER']],
            'AppCompatFlagsUser': [0x2D0, ['_ULARGE_INTEGER']],
            'pShimData': [0x2D8, ['pointer64', ['void']]],
            'AppCompatInfo': [0x2E0, ['pointer64', ['void']]],
            'CSDVersion': [0x2E8, ['_UNICODE_STRING']],
            'ActivationContextData': [
                0x2F8,
                ['pointer64', ['_ACTIVATION_CONTEXT_DATA']],
            ],
            'ProcessAssemblyStorageMap': [
                0x300,
                ['pointer64', ['_ASSEMBLY_STORAGE_MAP']],
            ],
            'SystemDefaultActivationContextData': [
                0x308,
                ['pointer64', ['_ACTIVATION_CONTEXT_DATA']],
            ],
            'SystemAssemblyStorageMap': [
                0x310,
                ['pointer64', ['_ASSEMBLY_STORAGE_MAP']],
            ],
            'MinimumStackCommit': [0x318, ['unsigned long long']],
            'FlsCallback': [0x320, ['pointer64', ['_FLS_CALLBACK_INFO']]],
            'FlsListHead': [0x328, ['_LIST_ENTRY']],
            'FlsBitmap': [0x338, ['pointer64', ['void']]],
            'FlsBitmapBits': [0x340, ['array', 4, ['unsigned long']]],
            'FlsHighIndex': [0x350, ['unsigned long']],
            'WerRegistrationData': [0x358, ['pointer64', ['void']]],
            'WerShipAssertPtr': [0x360, ['pointer64', ['void']]],
            'pContextData': [0x368, ['pointer64', ['void']]],
            'pImageHeaderHash': [0x370, ['pointer64', ['void']]],
            'TracingFlags': [0x378, ['unsigned long']],
            'HeapTracingEnabled': [
                0x378,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'CritSecTracingEnabled': [
                0x378,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SpareTracingBits': [
                0x378,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_PEB_LDR_DATA': [
        0x58,
        {
            'Length': [0x0, ['unsigned long']],
            'Initialized': [0x4, ['unsigned char']],
            'SsHandle': [0x8, ['pointer64', ['void']]],
            'InLoadOrderModuleList': [0x10, ['_LIST_ENTRY']],
            'InMemoryOrderModuleList': [0x20, ['_LIST_ENTRY']],
            'InInitializationOrderModuleList': [0x30, ['_LIST_ENTRY']],
            'EntryInProgress': [0x40, ['pointer64', ['void']]],
            'ShutdownInProgress': [0x48, ['unsigned char']],
            'ShutdownThreadId': [0x50, ['pointer64', ['void']]],
        },
    ],
    '_LDR_DATA_TABLE_ENTRY': [
        0xE0,
        {
            'InLoadOrderLinks': [0x0, ['_LIST_ENTRY']],
            'InMemoryOrderLinks': [0x10, ['_LIST_ENTRY']],
            'InInitializationOrderLinks': [0x20, ['_LIST_ENTRY']],
            'DllBase': [0x30, ['pointer64', ['void']]],
            'EntryPoint': [0x38, ['pointer64', ['void']]],
            'SizeOfImage': [0x40, ['unsigned long']],
            'FullDllName': [0x48, ['_UNICODE_STRING']],
            'BaseDllName': [0x58, ['_UNICODE_STRING']],
            'Flags': [0x68, ['unsigned long']],
            'LoadCount': [0x6C, ['unsigned short']],
            'TlsIndex': [0x6E, ['unsigned short']],
            'HashLinks': [0x70, ['_LIST_ENTRY']],
            'SectionPointer': [0x70, ['pointer64', ['void']]],
            'CheckSum': [0x78, ['unsigned long']],
            'TimeDateStamp': [0x80, ['unsigned long']],
            'LoadedImports': [0x80, ['pointer64', ['void']]],
            'EntryPointActivationContext': [
                0x88,
                ['pointer64', ['_ACTIVATION_CONTEXT']],
            ],
            'PatchInformation': [0x90, ['pointer64', ['void']]],
            'ForwarderLinks': [0x98, ['_LIST_ENTRY']],
            'ServiceTagLinks': [0xA8, ['_LIST_ENTRY']],
            'StaticLinks': [0xB8, ['_LIST_ENTRY']],
            'ContextInformation': [0xC8, ['pointer64', ['void']]],
            'OriginalBase': [0xD0, ['unsigned long long']],
            'LoadTime': [0xD8, ['_LARGE_INTEGER']],
        },
    ],
    '_HEAP_SUBSEGMENT': [
        0x30,
        {
            'LocalInfo': [0x0, ['pointer64', ['_HEAP_LOCAL_SEGMENT_INFO']]],
            'UserBlocks': [0x8, ['pointer64', ['_HEAP_USERDATA_HEADER']]],
            'AggregateExchg': [0x10, ['_INTERLOCK_SEQ']],
            'BlockSize': [0x18, ['unsigned short']],
            'Flags': [0x1A, ['unsigned short']],
            'BlockCount': [0x1C, ['unsigned short']],
            'SizeIndex': [0x1E, ['unsigned char']],
            'AffinityIndex': [0x1F, ['unsigned char']],
            'Alignment': [0x18, ['array', 2, ['unsigned long']]],
            'SFreeListEntry': [0x20, ['_SINGLE_LIST_ENTRY']],
            'Lock': [0x28, ['unsigned long']],
        },
    ],
    '__unnamed_197f': [
        0x4,
        {
            'DataLength': [0x0, ['short']],
            'TotalLength': [0x2, ['short']],
        },
    ],
    '__unnamed_1981': [
        0x4,
        {
            's1': [0x0, ['__unnamed_197f']],
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1983': [
        0x4,
        {
            'Type': [0x0, ['short']],
            'DataInfoOffset': [0x2, ['short']],
        },
    ],
    '__unnamed_1985': [
        0x4,
        {
            's2': [0x0, ['__unnamed_1983']],
            'ZeroInit': [0x0, ['unsigned long']],
        },
    ],
    '_PORT_MESSAGE': [
        0x28,
        {
            'u1': [0x0, ['__unnamed_1981']],
            'u2': [0x4, ['__unnamed_1985']],
            'ClientId': [0x8, ['_CLIENT_ID']],
            'DoNotUseThisField': [0x8, ['double']],
            'MessageId': [0x18, ['unsigned long']],
            'ClientViewSize': [0x20, ['unsigned long long']],
            'CallbackId': [0x20, ['unsigned long']],
        },
    ],
    '_ALPC_MESSAGE_ATTRIBUTES': [
        0x8,
        {
            'AllocatedAttributes': [0x0, ['unsigned long']],
            'ValidAttributes': [0x4, ['unsigned long']],
        },
    ],
    '_ALPC_HANDLE_ENTRY': [
        0x8,
        {
            'Object': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_BLOB_TYPE': [
        0x38,
        {
            'ResourceId': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'BLOB_TYPE_UNKNOWN',
                            1: 'BLOB_TYPE_CONNECTION_INFO',
                            2: 'BLOB_TYPE_MESSAGE',
                            3: 'BLOB_TYPE_SECURITY_CONTEXT',
                            4: 'BLOB_TYPE_SECTION',
                            5: 'BLOB_TYPE_REGION',
                            6: 'BLOB_TYPE_VIEW',
                            7: 'BLOB_TYPE_RESERVE',
                            8: 'BLOB_TYPE_DIRECT_TRANSFER',
                            9: 'BLOB_TYPE_HANDLE_DATA',
                            10: 'BLOB_TYPE_MAX_ID',
                        },
                    ),
                ],
            ],
            'PoolTag': [0x4, ['unsigned long']],
            'Flags': [0x8, ['unsigned long']],
            'CreatedObjects': [0xC, ['unsigned long']],
            'DeletedObjects': [0x10, ['unsigned long']],
            'DeleteProcedure': [0x18, ['pointer64', ['void']]],
            'DestroyProcedure': [0x20, ['pointer64', ['void']]],
            'UsualSize': [0x28, ['unsigned long long']],
            'LookasideIndex': [0x30, ['unsigned long']],
        },
    ],
    '__unnamed_199e': [
        0x1,
        {
            'ReferenceCache': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Lookaside': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Initializing': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Deleted': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '__unnamed_19a0': [
        0x1,
        {
            's1': [0x0, ['__unnamed_199e']],
            'Flags': [0x0, ['unsigned char']],
        },
    ],
    '_BLOB': [
        0x20,
        {
            'ResourceList': [0x0, ['_LIST_ENTRY']],
            'FreeListEntry': [0x0, ['_SLIST_ENTRY']],
            'u1': [0x10, ['__unnamed_19a0']],
            'ResourceId': [0x11, ['unsigned char']],
            'CachedReferences': [0x12, ['short']],
            'ReferenceCount': [0x14, ['long']],
            'Lock': [0x18, ['_EX_PUSH_LOCK']],
        },
    ],
    '__unnamed_19b3': [
        0x4,
        {
            'Internal': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Secure': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_19b5': [
        0x4,
        {
            's1': [0x0, ['__unnamed_19b3']],
        },
    ],
    '_KALPC_SECTION': [
        0x48,
        {
            'SectionObject': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned long long']],
            'HandleTable': [0x10, ['pointer64', ['_ALPC_HANDLE_TABLE']]],
            'SectionHandle': [0x18, ['pointer64', ['void']]],
            'OwnerProcess': [0x20, ['pointer64', ['_EPROCESS']]],
            'OwnerPort': [0x28, ['pointer64', ['_ALPC_PORT']]],
            'u1': [0x30, ['__unnamed_19b5']],
            'NumberOfRegions': [0x34, ['unsigned long']],
            'RegionListHead': [0x38, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_19bb': [
        0x4,
        {
            'Secure': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_19bd': [
        0x4,
        {
            's1': [0x0, ['__unnamed_19bb']],
        },
    ],
    '_KALPC_REGION': [
        0x58,
        {
            'RegionListEntry': [0x0, ['_LIST_ENTRY']],
            'Section': [0x10, ['pointer64', ['_KALPC_SECTION']]],
            'Offset': [0x18, ['unsigned long long']],
            'Size': [0x20, ['unsigned long long']],
            'ViewSize': [0x28, ['unsigned long long']],
            'u1': [0x30, ['__unnamed_19bd']],
            'NumberOfViews': [0x34, ['unsigned long']],
            'ViewListHead': [0x38, ['_LIST_ENTRY']],
            'ReadOnlyView': [0x48, ['pointer64', ['_KALPC_VIEW']]],
            'ReadWriteView': [0x50, ['pointer64', ['_KALPC_VIEW']]],
        },
    ],
    '__unnamed_19c3': [
        0x4,
        {
            'WriteAccess': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AutoRelease': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ForceUnlink': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_19c5': [
        0x4,
        {
            's1': [0x0, ['__unnamed_19c3']],
        },
    ],
    '_KALPC_VIEW': [
        0x60,
        {
            'ViewListEntry': [0x0, ['_LIST_ENTRY']],
            'Region': [0x10, ['pointer64', ['_KALPC_REGION']]],
            'OwnerPort': [0x18, ['pointer64', ['_ALPC_PORT']]],
            'OwnerProcess': [0x20, ['pointer64', ['_EPROCESS']]],
            'Address': [0x28, ['pointer64', ['void']]],
            'Size': [0x30, ['unsigned long long']],
            'SecureViewHandle': [0x38, ['pointer64', ['void']]],
            'WriteAccessHandle': [0x40, ['pointer64', ['void']]],
            'u1': [0x48, ['__unnamed_19c5']],
            'NumberOfOwnerMessages': [0x4C, ['unsigned long']],
            'ProcessViewListEntry': [0x50, ['_LIST_ENTRY']],
        },
    ],
    '_ALPC_COMMUNICATION_INFO': [
        0x40,
        {
            'ConnectionPort': [0x0, ['pointer64', ['_ALPC_PORT']]],
            'ServerCommunicationPort': [0x8, ['pointer64', ['_ALPC_PORT']]],
            'ClientCommunicationPort': [0x10, ['pointer64', ['_ALPC_PORT']]],
            'CommunicationList': [0x18, ['_LIST_ENTRY']],
            'HandleTable': [0x28, ['_ALPC_HANDLE_TABLE']],
        },
    ],
    '__unnamed_19e1': [
        0x4,
        {
            'Initialized': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Type': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ConnectionPending': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ConnectionRefused': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Disconnected': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Closed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'NoFlushOnClose': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ReturnExtendedInfo': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Waitable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'DynamicSecurity': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'Wow64CompletionList': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'Lpc': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'LpcToLpc': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'HasCompletionList': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'HadCompletionList': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'EnableCompletionList': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '__unnamed_19e3': [
        0x4,
        {
            's1': [0x0, ['__unnamed_19e1']],
            'State': [0x0, ['unsigned long']],
        },
    ],
    '_ALPC_PORT': [
        0x1A0,
        {
            'PortListEntry': [0x0, ['_LIST_ENTRY']],
            'CommunicationInfo': [
                0x10,
                ['pointer64', ['_ALPC_COMMUNICATION_INFO']],
            ],
            'OwnerProcess': [0x18, ['pointer64', ['_EPROCESS']]],
            'CompletionPort': [0x20, ['pointer64', ['void']]],
            'CompletionKey': [0x28, ['pointer64', ['void']]],
            'CompletionPacketLookaside': [
                0x30,
                ['pointer64', ['_ALPC_COMPLETION_PACKET_LOOKASIDE']],
            ],
            'PortContext': [0x38, ['pointer64', ['void']]],
            'StaticSecurity': [0x40, ['_SECURITY_CLIENT_CONTEXT']],
            'MainQueue': [0x88, ['_LIST_ENTRY']],
            'PendingQueue': [0x98, ['_LIST_ENTRY']],
            'LargeMessageQueue': [0xA8, ['_LIST_ENTRY']],
            'WaitQueue': [0xB8, ['_LIST_ENTRY']],
            'Semaphore': [0xC8, ['pointer64', ['_KSEMAPHORE']]],
            'DummyEvent': [0xC8, ['pointer64', ['_KEVENT']]],
            'PortAttributes': [0xD0, ['_ALPC_PORT_ATTRIBUTES']],
            'Lock': [0x118, ['_EX_PUSH_LOCK']],
            'ResourceListLock': [0x120, ['_EX_PUSH_LOCK']],
            'ResourceListHead': [0x128, ['_LIST_ENTRY']],
            'CompletionList': [
                0x138,
                ['pointer64', ['_ALPC_COMPLETION_LIST']],
            ],
            'MessageZone': [0x140, ['pointer64', ['_ALPC_MESSAGE_ZONE']]],
            'CallbackObject': [0x148, ['pointer64', ['_CALLBACK_OBJECT']]],
            'CallbackContext': [0x150, ['pointer64', ['void']]],
            'CanceledQueue': [0x158, ['_LIST_ENTRY']],
            'SequenceNo': [0x168, ['long']],
            'u1': [0x16C, ['__unnamed_19e3']],
            'TargetQueuePort': [0x170, ['pointer64', ['_ALPC_PORT']]],
            'TargetSequencePort': [0x178, ['pointer64', ['_ALPC_PORT']]],
            'CachedMessage': [0x180, ['pointer64', ['_KALPC_MESSAGE']]],
            'MainQueueLength': [0x188, ['unsigned long']],
            'PendingQueueLength': [0x18C, ['unsigned long']],
            'LargeMessageQueueLength': [0x190, ['unsigned long']],
            'CanceledQueueLength': [0x194, ['unsigned long']],
            'WaitQueueLength': [0x198, ['unsigned long']],
        },
    ],
    '_OBJECT_TYPE': [
        0xD0,
        {
            'TypeList': [0x0, ['_LIST_ENTRY']],
            'Name': [0x10, ['_UNICODE_STRING']],
            'DefaultObject': [0x20, ['pointer64', ['void']]],
            'Index': [0x28, ['unsigned char']],
            'TotalNumberOfObjects': [0x2C, ['unsigned long']],
            'TotalNumberOfHandles': [0x30, ['unsigned long']],
            'HighWaterNumberOfObjects': [0x34, ['unsigned long']],
            'HighWaterNumberOfHandles': [0x38, ['unsigned long']],
            'TypeInfo': [0x40, ['_OBJECT_TYPE_INITIALIZER']],
            'TypeLock': [0xB0, ['_EX_PUSH_LOCK']],
            'Key': [0xB8, ['unsigned long']],
            'CallbackList': [0xC0, ['_LIST_ENTRY']],
        },
    ],
    '_PORT_MESSAGE32': [
        0x18,
        {
            'u1': [0x0, ['__unnamed_1981']],
            'u2': [0x4, ['__unnamed_1985']],
            'ClientId': [0x8, ['_CLIENT_ID32']],
            'DoNotUseThisField': [0x8, ['double']],
            'MessageId': [0x10, ['unsigned long']],
            'ClientViewSize': [0x14, ['unsigned long']],
            'CallbackId': [0x14, ['unsigned long']],
        },
    ],
    '__unnamed_1a02': [
        0x4,
        {
            'QueueType': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'QueuePortType': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Canceled': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Ready': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ReleaseMessage': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'SharedQuota': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'ReplyWaitReply': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'OwnerPortReference': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'ReserveReference': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'ReceiverReference': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'ViewAttributeRetrieved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'InDispatch': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1a04': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1a02']],
            'State': [0x0, ['unsigned long']],
        },
    ],
    '_KALPC_MESSAGE': [
        0x100,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'ExtensionBuffer': [0x10, ['pointer64', ['void']]],
            'ExtensionBufferSize': [0x18, ['unsigned long long']],
            'QuotaProcess': [0x20, ['pointer64', ['_EPROCESS']]],
            'QuotaBlock': [0x20, ['pointer64', ['void']]],
            'SequenceNo': [0x28, ['long']],
            'u1': [0x2C, ['__unnamed_1a04']],
            'CancelSequencePort': [0x30, ['pointer64', ['_ALPC_PORT']]],
            'CancelQueuePort': [0x38, ['pointer64', ['_ALPC_PORT']]],
            'CancelSequenceNo': [0x40, ['long']],
            'CancelListEntry': [0x48, ['_LIST_ENTRY']],
            'WaitingThread': [0x58, ['pointer64', ['_ETHREAD']]],
            'Reserve': [0x60, ['pointer64', ['_KALPC_RESERVE']]],
            'PortQueue': [0x68, ['pointer64', ['_ALPC_PORT']]],
            'OwnerPort': [0x70, ['pointer64', ['_ALPC_PORT']]],
            'MessageAttributes': [0x78, ['_KALPC_MESSAGE_ATTRIBUTES']],
            'DataUserVa': [0xB0, ['pointer64', ['void']]],
            'DataSystemVa': [0xB8, ['pointer64', ['void']]],
            'CommunicationInfo': [
                0xC0,
                ['pointer64', ['_ALPC_COMMUNICATION_INFO']],
            ],
            'ConnectionPort': [0xC8, ['pointer64', ['_ALPC_PORT']]],
            'ServerThread': [0xD0, ['pointer64', ['_ETHREAD']]],
            'PortMessage': [0xD8, ['_PORT_MESSAGE']],
        },
    ],
    '_REMOTE_PORT_VIEW': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'ViewSize': [0x8, ['unsigned long long']],
            'ViewBase': [0x10, ['pointer64', ['void']]],
        },
    ],
    '_KALPC_RESERVE': [
        0x28,
        {
            'OwnerPort': [0x0, ['pointer64', ['_ALPC_PORT']]],
            'HandleTable': [0x8, ['pointer64', ['_ALPC_HANDLE_TABLE']]],
            'Handle': [0x10, ['pointer64', ['void']]],
            'Message': [0x18, ['pointer64', ['_KALPC_MESSAGE']]],
            'Active': [0x20, ['long']],
        },
    ],
    '_KALPC_HANDLE_DATA': [
        0x10,
        {
            'Flags': [0x0, ['unsigned long']],
            'ObjectType': [0x4, ['unsigned long']],
            'DuplicateContext': [
                0x8,
                ['pointer64', ['_OB_DUPLICATE_OBJECT_STATE']],
            ],
        },
    ],
    '_KALPC_MESSAGE_ATTRIBUTES': [
        0x38,
        {
            'ClientContext': [0x0, ['pointer64', ['void']]],
            'ServerContext': [0x8, ['pointer64', ['void']]],
            'PortContext': [0x10, ['pointer64', ['void']]],
            'CancelPortContext': [0x18, ['pointer64', ['void']]],
            'SecurityData': [0x20, ['pointer64', ['_KALPC_SECURITY_DATA']]],
            'View': [0x28, ['pointer64', ['_KALPC_VIEW']]],
            'HandleData': [0x30, ['pointer64', ['_KALPC_HANDLE_DATA']]],
        },
    ],
    '__unnamed_1a42': [
        0x4,
        {
            'Revoked': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Impersonated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_1a44': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1a42']],
        },
    ],
    '_KALPC_SECURITY_DATA': [
        0x70,
        {
            'HandleTable': [0x0, ['pointer64', ['_ALPC_HANDLE_TABLE']]],
            'ContextHandle': [0x8, ['pointer64', ['void']]],
            'OwningProcess': [0x10, ['pointer64', ['_EPROCESS']]],
            'OwnerPort': [0x18, ['pointer64', ['_ALPC_PORT']]],
            'DynamicSecurity': [0x20, ['_SECURITY_CLIENT_CONTEXT']],
            'u1': [0x68, ['__unnamed_1a44']],
        },
    ],
    '_IO_MINI_COMPLETION_PACKET_USER': [
        0x50,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'PacketType': [0x10, ['unsigned long']],
            'KeyContext': [0x18, ['pointer64', ['void']]],
            'ApcContext': [0x20, ['pointer64', ['void']]],
            'IoStatus': [0x28, ['long']],
            'IoStatusInformation': [0x30, ['unsigned long long']],
            'MiniPacketCallback': [0x38, ['pointer64', ['void']]],
            'Context': [0x40, ['pointer64', ['void']]],
            'Allocated': [0x48, ['unsigned char']],
        },
    ],
    '_ALPC_DISPATCH_CONTEXT': [
        0x38,
        {
            'PortObject': [0x0, ['pointer64', ['_ALPC_PORT']]],
            'Message': [0x8, ['pointer64', ['_KALPC_MESSAGE']]],
            'CommunicationInfo': [
                0x10,
                ['pointer64', ['_ALPC_COMMUNICATION_INFO']],
            ],
            'TargetThread': [0x18, ['pointer64', ['_ETHREAD']]],
            'TargetPort': [0x20, ['pointer64', ['_ALPC_PORT']]],
            'Flags': [0x28, ['unsigned long']],
            'TotalLength': [0x2C, ['unsigned short']],
            'Type': [0x2E, ['unsigned short']],
            'DataInfoOffset': [0x30, ['unsigned short']],
        },
    ],
    '_DRIVER_OBJECT': [
        0x150,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'Flags': [0x10, ['unsigned long']],
            'DriverStart': [0x18, ['pointer64', ['void']]],
            'DriverSize': [0x20, ['unsigned long']],
            'DriverSection': [0x28, ['pointer64', ['void']]],
            'DriverExtension': [0x30, ['pointer64', ['_DRIVER_EXTENSION']]],
            'DriverName': [0x38, ['_UNICODE_STRING']],
            'HardwareDatabase': [0x48, ['pointer64', ['_UNICODE_STRING']]],
            'FastIoDispatch': [0x50, ['pointer64', ['_FAST_IO_DISPATCH']]],
            'DriverInit': [0x58, ['pointer64', ['void']]],
            'DriverStartIo': [0x60, ['pointer64', ['void']]],
            'DriverUnload': [0x68, ['pointer64', ['void']]],
            'MajorFunction': [0x70, ['array', 28, ['pointer64', ['void']]]],
        },
    ],
    '_FILE_SEGMENT_ELEMENT': [
        0x8,
        {
            'Buffer': [0x0, ['pointer64', ['void']]],
            'Alignment': [0x0, ['unsigned long long']],
        },
    ],
    '_RELATIVE_SYMLINK_INFO': [
        0x20,
        {
            'ExposedNamespaceLength': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned short']],
            'DeviceNameLength': [0x4, ['unsigned short']],
            'Reserved': [0x6, ['unsigned short']],
            'InteriorMountPoint': [
                0x8,
                ['pointer64', ['_RELATIVE_SYMLINK_INFO']],
            ],
            'OpenedName': [0x10, ['_UNICODE_STRING']],
        },
    ],
    '_ECP_LIST': [
        0x18,
        {
            'Signature': [0x0, ['unsigned long']],
            'Flags': [0x4, ['unsigned long']],
            'EcpList': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_IOP_FILE_OBJECT_EXTENSION': [
        0x48,
        {
            'FoExtFlags': [0x0, ['unsigned long']],
            'FoExtPerTypeExtension': [
                0x8,
                ['array', 7, ['pointer64', ['void']]],
            ],
            'FoIoPriorityHint': [
                0x40,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IopIoPriorityNotSet',
                            1: 'IopIoPriorityVeryLow',
                            2: 'IopIoPriorityLow',
                            3: 'IopIoPriorityNormal',
                            4: 'IopIoPriorityHigh',
                            5: 'IopIoPriorityCritical',
                            6: 'MaxIopIoPriorityTypes',
                        },
                    ),
                ],
            ],
        },
    ],
    '_OPEN_PACKET': [
        0xB8,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'FileObject': [0x8, ['pointer64', ['_FILE_OBJECT']]],
            'FinalStatus': [0x10, ['long']],
            'Information': [0x18, ['unsigned long long']],
            'ParseCheck': [0x20, ['unsigned long']],
            'RelatedFileObject': [0x28, ['pointer64', ['_FILE_OBJECT']]],
            'OriginalAttributes': [
                0x30,
                ['pointer64', ['_OBJECT_ATTRIBUTES']],
            ],
            'AllocationSize': [0x38, ['_LARGE_INTEGER']],
            'CreateOptions': [0x40, ['unsigned long']],
            'FileAttributes': [0x44, ['unsigned short']],
            'ShareAccess': [0x46, ['unsigned short']],
            'EaBuffer': [0x48, ['pointer64', ['void']]],
            'EaLength': [0x50, ['unsigned long']],
            'Options': [0x54, ['unsigned long']],
            'Disposition': [0x58, ['unsigned long']],
            'BasicInformation': [
                0x60,
                ['pointer64', ['_FILE_BASIC_INFORMATION']],
            ],
            'NetworkInformation': [
                0x68,
                ['pointer64', ['_FILE_NETWORK_OPEN_INFORMATION']],
            ],
            'CreateFileType': [
                0x70,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'CreateFileTypeNone',
                            1: 'CreateFileTypeNamedPipe',
                            2: 'CreateFileTypeMailslot',
                        },
                    ),
                ],
            ],
            'MailslotOrPipeParameters': [0x78, ['pointer64', ['void']]],
            'Override': [0x80, ['unsigned char']],
            'QueryOnly': [0x81, ['unsigned char']],
            'DeleteOnly': [0x82, ['unsigned char']],
            'FullAttributes': [0x83, ['unsigned char']],
            'LocalFileObject': [0x88, ['pointer64', ['_DUMMY_FILE_OBJECT']]],
            'InternalFlags': [0x90, ['unsigned long']],
            'DriverCreateContext': [0x98, ['_IO_DRIVER_CREATE_CONTEXT']],
        },
    ],
    '_ETW_SYSTEMTIME': [
        0x10,
        {
            'Year': [0x0, ['unsigned short']],
            'Month': [0x2, ['unsigned short']],
            'DayOfWeek': [0x4, ['unsigned short']],
            'Day': [0x6, ['unsigned short']],
            'Hour': [0x8, ['unsigned short']],
            'Minute': [0xA, ['unsigned short']],
            'Second': [0xC, ['unsigned short']],
            'Milliseconds': [0xE, ['unsigned short']],
        },
    ],
    '_TIME_FIELDS': [
        0x10,
        {
            'Year': [0x0, ['short']],
            'Month': [0x2, ['short']],
            'Day': [0x4, ['short']],
            'Hour': [0x6, ['short']],
            'Minute': [0x8, ['short']],
            'Second': [0xA, ['short']],
            'Milliseconds': [0xC, ['short']],
            'Weekday': [0xE, ['short']],
        },
    ],
    '_RTL_RB_TREE': [
        0x10,
        {
            'Root': [0x0, ['pointer64', ['_RTL_BALANCED_NODE']]],
            'Min': [0x8, ['pointer64', ['_RTL_BALANCED_NODE']]],
        },
    ],
    '_RTL_BALANCED_NODE': [
        0x18,
        {
            'Children': [
                0x0,
                ['array', 2, ['pointer64', ['_RTL_BALANCED_NODE']]],
            ],
            'Left': [0x0, ['pointer64', ['_RTL_BALANCED_NODE']]],
            'Right': [0x8, ['pointer64', ['_RTL_BALANCED_NODE']]],
            'Red': [
                0x10,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Balance': [
                0x10,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'ParentValue': [0x10, ['unsigned long long']],
        },
    ],
    '_RTL_AVL_TREE': [
        0x8,
        {
            'Root': [0x0, ['pointer64', ['_RTL_BALANCED_NODE']]],
        },
    ],
    '_WMI_LOGGER_CONTEXT': [
        0x340,
        {
            'LoggerId': [0x0, ['unsigned long']],
            'BufferSize': [0x4, ['unsigned long']],
            'MaximumEventSize': [0x8, ['unsigned long']],
            'CollectionOn': [0xC, ['long']],
            'LoggerMode': [0x10, ['unsigned long']],
            'AcceptNewEvents': [0x14, ['long']],
            'GetCpuClock': [0x18, ['pointer64', ['void']]],
            'StartTime': [0x20, ['_LARGE_INTEGER']],
            'LogFileHandle': [0x28, ['pointer64', ['void']]],
            'LoggerThread': [0x30, ['pointer64', ['_ETHREAD']]],
            'LoggerStatus': [0x38, ['long']],
            'NBQHead': [0x40, ['pointer64', ['void']]],
            'OverflowNBQHead': [0x48, ['pointer64', ['void']]],
            'QueueBlockFreeList': [0x50, ['_SLIST_HEADER']],
            'GlobalList': [0x60, ['_LIST_ENTRY']],
            'BatchedBufferList': [0x70, ['pointer64', ['_WMI_BUFFER_HEADER']]],
            'CurrentBuffer': [0x70, ['_EX_FAST_REF']],
            'LoggerName': [0x78, ['_UNICODE_STRING']],
            'LogFileName': [0x88, ['_UNICODE_STRING']],
            'LogFilePattern': [0x98, ['_UNICODE_STRING']],
            'NewLogFileName': [0xA8, ['_UNICODE_STRING']],
            'ClockType': [0xB8, ['unsigned long']],
            'MaximumFileSize': [0xBC, ['unsigned long']],
            'LastFlushedBuffer': [0xC0, ['unsigned long']],
            'FlushTimer': [0xC4, ['unsigned long']],
            'FlushThreshold': [0xC8, ['unsigned long']],
            'ByteOffset': [0xD0, ['_LARGE_INTEGER']],
            'MinimumBuffers': [0xD8, ['unsigned long']],
            'BuffersAvailable': [0xDC, ['long']],
            'NumberOfBuffers': [0xE0, ['long']],
            'MaximumBuffers': [0xE4, ['unsigned long']],
            'EventsLost': [0xE8, ['unsigned long']],
            'BuffersWritten': [0xEC, ['unsigned long']],
            'LogBuffersLost': [0xF0, ['unsigned long']],
            'RealTimeBuffersDelivered': [0xF4, ['unsigned long']],
            'RealTimeBuffersLost': [0xF8, ['unsigned long']],
            'SequencePtr': [0x100, ['pointer64', ['long']]],
            'LocalSequence': [0x108, ['unsigned long']],
            'InstanceGuid': [0x10C, ['_GUID']],
            'FileCounter': [0x11C, ['long']],
            'BufferCallback': [0x120, ['pointer64', ['void']]],
            'PoolType': [
                0x128,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPool',
                            1: 'PagedPool',
                            2: 'NonPagedPoolMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'ReferenceTime': [0x130, ['_ETW_REF_CLOCK']],
            'Consumers': [0x140, ['_LIST_ENTRY']],
            'NumConsumers': [0x150, ['unsigned long']],
            'TransitionConsumer': [
                0x158,
                ['pointer64', ['_ETW_REALTIME_CONSUMER']],
            ],
            'RealtimeLogfileHandle': [0x160, ['pointer64', ['void']]],
            'RealtimeLogfileName': [0x168, ['_UNICODE_STRING']],
            'RealtimeWriteOffset': [0x178, ['_LARGE_INTEGER']],
            'RealtimeReadOffset': [0x180, ['_LARGE_INTEGER']],
            'RealtimeLogfileSize': [0x188, ['_LARGE_INTEGER']],
            'RealtimeLogfileUsage': [0x190, ['unsigned long long']],
            'RealtimeMaximumFileSize': [0x198, ['unsigned long long']],
            'RealtimeBuffersSaved': [0x1A0, ['unsigned long']],
            'RealtimeReferenceTime': [0x1A8, ['_ETW_REF_CLOCK']],
            'NewRTEventsLost': [
                0x1B8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'EtwRtEventNoLoss',
                            1: 'EtwRtEventLost',
                            2: 'EtwRtBufferLost',
                            3: 'EtwRtBackupLost',
                            4: 'EtwRtEventLossMax',
                        },
                    ),
                ],
            ],
            'LoggerEvent': [0x1C0, ['_KEVENT']],
            'FlushEvent': [0x1D8, ['_KEVENT']],
            'FlushTimeOutTimer': [0x1F0, ['_KTIMER']],
            'FlushDpc': [0x230, ['_KDPC']],
            'LoggerMutex': [0x270, ['_KMUTANT']],
            'LoggerLock': [0x2A8, ['_EX_PUSH_LOCK']],
            'BufferListSpinLock': [0x2B0, ['unsigned long long']],
            'BufferListPushLock': [0x2B0, ['_EX_PUSH_LOCK']],
            'ClientSecurityContext': [0x2B8, ['_SECURITY_CLIENT_CONTEXT']],
            'TokenAccessInformation': [
                0x300,
                ['pointer64', ['_TOKEN_ACCESS_INFORMATION']],
            ],
            'SecurityDescriptor': [0x308, ['_EX_FAST_REF']],
            'BufferSequenceNumber': [0x310, ['long long']],
            'Flags': [0x318, ['unsigned long']],
            'Persistent': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AutoLogger': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'FsReady': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'RealTime': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'KernelTrace': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'NoMoreEnable': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'StackTracing': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ErrorLogged': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'RealtimeLoggerContextFreed': [
                0x318,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'RequestFlag': [0x31C, ['unsigned long']],
            'RequestNewFie': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'RequestUpdateFile': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'RequestFlush': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'RequestDisableRealtime': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'RequestDisconnectConsumer': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'RequestConnectConsumer': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'HookIdMap': [0x320, ['_RTL_BITMAP']],
            'DisallowedGuids': [0x330, ['_DISALLOWED_GUIDS']],
        },
    ],
    '_ETW_LOGGER_HANDLE': [
        0x1,
        {
            'DereferenceAndLeave': [0x0, ['unsigned char']],
        },
    ],
    '_ETW_BUFFER_HANDLE': [
        0x10,
        {
            'TraceBuffer': [0x0, ['pointer64', ['_WMI_BUFFER_HEADER']]],
            'BufferFastRef': [0x8, ['pointer64', ['_EX_FAST_REF']]],
        },
    ],
    '_SYSTEM_TRACE_HEADER': [
        0x20,
        {
            'Marker': [0x0, ['unsigned long']],
            'Version': [0x0, ['unsigned short']],
            'HeaderType': [0x2, ['unsigned char']],
            'Flags': [0x3, ['unsigned char']],
            'Header': [0x4, ['unsigned long']],
            'Packet': [0x4, ['_WMI_TRACE_PACKET']],
            'ThreadId': [0x8, ['unsigned long']],
            'ProcessId': [0xC, ['unsigned long']],
            'SystemTime': [0x10, ['_LARGE_INTEGER']],
            'KernelTime': [0x18, ['unsigned long']],
            'UserTime': [0x1C, ['unsigned long']],
        },
    ],
    '_PERFINFO_TRACE_HEADER': [
        0x18,
        {
            'Marker': [0x0, ['unsigned long']],
            'Version': [0x0, ['unsigned short']],
            'HeaderType': [0x2, ['unsigned char']],
            'Flags': [0x3, ['unsigned char']],
            'Header': [0x4, ['unsigned long']],
            'Packet': [0x4, ['_WMI_TRACE_PACKET']],
            'TS': [0x8, ['unsigned long long']],
            'SystemTime': [0x8, ['_LARGE_INTEGER']],
            'Data': [0x10, ['array', 1, ['unsigned char']]],
        },
    ],
    '_NBQUEUE_BLOCK': [
        0x20,
        {
            'SListEntry': [0x0, ['_SLIST_ENTRY']],
            'Next': [0x10, ['unsigned long long']],
            'Data': [0x18, ['unsigned long long']],
        },
    ],
    '_TlgProvider_t': [
        0x40,
        {
            'LevelPlus1': [0x0, ['unsigned long']],
            'ProviderMetadataPtr': [0x8, ['pointer64', ['unsigned short']]],
            'KeywordAny': [0x10, ['unsigned long long']],
            'KeywordAll': [0x18, ['unsigned long long']],
            'RegHandle': [0x20, ['unsigned long long']],
            'EnableCallback': [0x28, ['pointer64', ['void']]],
            'CallbackContext': [0x30, ['pointer64', ['void']]],
            'AnnotationFunc': [0x38, ['pointer64', ['void']]],
        },
    ],
    '_EVENT_FILTER_DESCRIPTOR': [
        0x10,
        {
            'Ptr': [0x0, ['unsigned long long']],
            'Size': [0x8, ['unsigned long']],
            'Type': [0xC, ['unsigned long']],
        },
    ],
    '_TlgProviderMetadata_t': [
        0x13,
        {
            'Type': [0x0, ['unsigned char']],
            'ProviderId': [0x1, ['_GUID']],
            'RemainingSize': [0x11, ['unsigned short']],
        },
    ],
    '_SID': [
        0xC,
        {
            'Revision': [0x0, ['unsigned char']],
            'SubAuthorityCount': [0x1, ['unsigned char']],
            'IdentifierAuthority': [0x2, ['_SID_IDENTIFIER_AUTHORITY']],
            'SubAuthority': [0x8, ['array', 1, ['unsigned long']]],
        },
    ],
    '_KMUTANT': [
        0x38,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'MutantListEntry': [0x18, ['_LIST_ENTRY']],
            'OwnerThread': [0x28, ['pointer64', ['_KTHREAD']]],
            'Abandoned': [0x30, ['unsigned char']],
            'ApcDisable': [0x31, ['unsigned char']],
        },
    ],
    '_ETW_LAST_ENABLE_INFO': [
        0x10,
        {
            'EnableFlags': [0x0, ['_LARGE_INTEGER']],
            'LoggerId': [0x8, ['unsigned short']],
            'Level': [0xA, ['unsigned char']],
            'Enabled': [
                0xB,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'InternalFlag': [
                0xB,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_TRACE_ENABLE_CONTEXT': [
        0x8,
        {
            'LoggerId': [0x0, ['unsigned short']],
            'Level': [0x2, ['unsigned char']],
            'InternalFlag': [0x3, ['unsigned char']],
            'EnableFlags': [0x4, ['unsigned long']],
        },
    ],
    '_TRACE_ENABLE_CONTEXT_EX': [
        0x10,
        {
            'LoggerId': [0x0, ['unsigned short']],
            'Level': [0x2, ['unsigned char']],
            'InternalFlag': [0x3, ['unsigned char']],
            'EnableFlags': [0x4, ['unsigned long']],
            'EnableFlagsHigh': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '_ETW_GUID_ENTRY': [
        0x1B0,
        {
            'GuidList': [0x0, ['_LIST_ENTRY']],
            'RefCount': [0x10, ['long']],
            'Guid': [0x14, ['_GUID']],
            'RegListHead': [0x28, ['_LIST_ENTRY']],
            'SecurityDescriptor': [0x38, ['pointer64', ['void']]],
            'LastEnable': [0x40, ['_ETW_LAST_ENABLE_INFO']],
            'MatchId': [0x40, ['unsigned long long']],
            'ProviderEnableInfo': [0x50, ['_TRACE_ENABLE_INFO']],
            'EnableInfo': [0x70, ['array', 8, ['_TRACE_ENABLE_INFO']]],
            'FilterData': [
                0x170,
                ['array', 8, ['pointer64', ['_EVENT_FILTER_HEADER']]],
            ],
        },
    ],
    '_TRACE_ENABLE_INFO': [
        0x20,
        {
            'IsEnabled': [0x0, ['unsigned long']],
            'Level': [0x4, ['unsigned char']],
            'Reserved1': [0x5, ['unsigned char']],
            'LoggerId': [0x6, ['unsigned short']],
            'EnableProperty': [0x8, ['unsigned long']],
            'Reserved2': [0xC, ['unsigned long']],
            'MatchAnyKeyword': [0x10, ['unsigned long long']],
            'MatchAllKeyword': [0x18, ['unsigned long long']],
        },
    ],
    '_LUID_AND_ATTRIBUTES': [
        0xC,
        {
            'Luid': [0x0, ['_LUID']],
            'Attributes': [0x8, ['unsigned long']],
        },
    ],
    '_TOKEN': [
        0x310,
        {
            'TokenSource': [0x0, ['_TOKEN_SOURCE']],
            'TokenId': [0x10, ['_LUID']],
            'AuthenticationId': [0x18, ['_LUID']],
            'ParentTokenId': [0x20, ['_LUID']],
            'ExpirationTime': [0x28, ['_LARGE_INTEGER']],
            'TokenLock': [0x30, ['pointer64', ['_ERESOURCE']]],
            'ModifiedId': [0x38, ['_LUID']],
            'Privileges': [0x40, ['_SEP_TOKEN_PRIVILEGES']],
            'AuditPolicy': [0x58, ['_SEP_AUDIT_POLICY']],
            'SessionId': [0x74, ['unsigned long']],
            'UserAndGroupCount': [0x78, ['unsigned long']],
            'RestrictedSidCount': [0x7C, ['unsigned long']],
            'VariableLength': [0x80, ['unsigned long']],
            'DynamicCharged': [0x84, ['unsigned long']],
            'DynamicAvailable': [0x88, ['unsigned long']],
            'DefaultOwnerIndex': [0x8C, ['unsigned long']],
            'UserAndGroups': [0x90, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'RestrictedSids': [0x98, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'PrimaryGroup': [0xA0, ['pointer64', ['void']]],
            'DynamicPart': [0xA8, ['pointer64', ['unsigned long']]],
            'DefaultDacl': [0xB0, ['pointer64', ['_ACL']]],
            'TokenType': [
                0xB8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={1: 'TokenPrimary', 2: 'TokenImpersonation'},
                    ),
                ],
            ],
            'ImpersonationLevel': [
                0xBC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'SecurityAnonymous',
                            1: 'SecurityIdentification',
                            2: 'SecurityImpersonation',
                            3: 'SecurityDelegation',
                        },
                    ),
                ],
            ],
            'TokenFlags': [0xC0, ['unsigned long']],
            'TokenInUse': [0xC4, ['unsigned char']],
            'IntegrityLevelIndex': [0xC8, ['unsigned long']],
            'MandatoryPolicy': [0xCC, ['unsigned long']],
            'LogonSession': [
                0xD0,
                ['pointer64', ['_SEP_LOGON_SESSION_REFERENCES']],
            ],
            'OriginatingLogonSession': [0xD8, ['_LUID']],
            'SidHash': [0xE0, ['_SID_AND_ATTRIBUTES_HASH']],
            'RestrictedSidHash': [0x1F0, ['_SID_AND_ATTRIBUTES_HASH']],
            'pSecurityAttributes': [
                0x300,
                ['pointer64', ['_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION']],
            ],
            'VariablePart': [0x308, ['unsigned long long']],
        },
    ],
    '_SEP_LOGON_SESSION_REFERENCES': [
        0x50,
        {
            'Next': [0x0, ['pointer64', ['_SEP_LOGON_SESSION_REFERENCES']]],
            'LogonId': [0x8, ['_LUID']],
            'BuddyLogonId': [0x10, ['_LUID']],
            'ReferenceCount': [0x18, ['unsigned long']],
            'Flags': [0x1C, ['unsigned long']],
            'pDeviceMap': [0x20, ['pointer64', ['_DEVICE_MAP']]],
            'Token': [0x28, ['pointer64', ['void']]],
            'AccountName': [0x30, ['_UNICODE_STRING']],
            'AuthorityName': [0x40, ['_UNICODE_STRING']],
        },
    ],
    '_OBJECT_HEADER': [
        0x38,
        {
            'PointerCount': [0x0, ['long long']],
            'HandleCount': [0x8, ['long long']],
            'NextToFree': [0x8, ['pointer64', ['void']]],
            'Lock': [0x10, ['_EX_PUSH_LOCK']],
            'TypeIndex': [0x18, ['unsigned char']],
            'TraceFlags': [0x19, ['unsigned char']],
            'InfoMask': [0x1A, ['unsigned char']],
            'Flags': [0x1B, ['unsigned char']],
            'ObjectCreateInfo': [
                0x20,
                ['pointer64', ['_OBJECT_CREATE_INFORMATION']],
            ],
            'QuotaBlockCharged': [0x20, ['pointer64', ['void']]],
            'SecurityDescriptor': [0x28, ['pointer64', ['void']]],
            'Body': [0x30, ['_QUAD']],
        },
    ],
    '_OBJECT_HEADER_QUOTA_INFO': [
        0x20,
        {
            'PagedPoolCharge': [0x0, ['unsigned long']],
            'NonPagedPoolCharge': [0x4, ['unsigned long']],
            'SecurityDescriptorCharge': [0x8, ['unsigned long']],
            'SecurityDescriptorQuotaBlock': [0x10, ['pointer64', ['void']]],
            'Reserved': [0x18, ['unsigned long long']],
        },
    ],
    '_OBJECT_HEADER_PROCESS_INFO': [
        0x10,
        {
            'ExclusiveProcess': [0x0, ['pointer64', ['_EPROCESS']]],
            'Reserved': [0x8, ['unsigned long long']],
        },
    ],
    '_OBJECT_HEADER_HANDLE_INFO': [
        0x10,
        {
            'HandleCountDataBase': [
                0x0,
                ['pointer64', ['_OBJECT_HANDLE_COUNT_DATABASE']],
            ],
            'SingleEntry': [0x0, ['_OBJECT_HANDLE_COUNT_ENTRY']],
        },
    ],
    '_OBJECT_HEADER_NAME_INFO': [
        0x20,
        {
            'Directory': [0x0, ['pointer64', ['_OBJECT_DIRECTORY']]],
            'Name': [0x8, ['_UNICODE_STRING']],
            'ReferenceCount': [0x18, ['long']],
        },
    ],
    '_OBJECT_HEADER_CREATOR_INFO': [
        0x20,
        {
            'TypeList': [0x0, ['_LIST_ENTRY']],
            'CreatorUniqueProcess': [0x10, ['pointer64', ['void']]],
            'CreatorBackTraceIndex': [0x18, ['unsigned short']],
            'Reserved': [0x1A, ['unsigned short']],
        },
    ],
    '_OBP_LOOKUP_CONTEXT': [
        0x20,
        {
            'Directory': [0x0, ['pointer64', ['_OBJECT_DIRECTORY']]],
            'Object': [0x8, ['pointer64', ['void']]],
            'HashValue': [0x10, ['unsigned long']],
            'HashIndex': [0x14, ['unsigned short']],
            'DirectoryLocked': [0x16, ['unsigned char']],
            'LockedExclusive': [0x17, ['unsigned char']],
            'LockStateSignature': [0x18, ['unsigned long']],
        },
    ],
    '_OBJECT_DIRECTORY': [
        0x150,
        {
            'HashBuckets': [
                0x0,
                ['array', 37, ['pointer64', ['_OBJECT_DIRECTORY_ENTRY']]],
            ],
            'Lock': [0x128, ['_EX_PUSH_LOCK']],
            'DeviceMap': [0x130, ['pointer64', ['_DEVICE_MAP']]],
            'SessionId': [0x138, ['unsigned long']],
            'NamespaceEntry': [0x140, ['pointer64', ['void']]],
            'Flags': [0x148, ['unsigned long']],
        },
    ],
    '_PS_CLIENT_SECURITY_CONTEXT': [
        0x8,
        {
            'ImpersonationData': [0x0, ['unsigned long long']],
            'ImpersonationToken': [0x0, ['pointer64', ['void']]],
            'ImpersonationLevel': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'EffectiveOnly': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_DBGKD_ANY_CONTROL_SET': [
        0x1C,
        {
            'X86ControlSet': [0x0, ['_X86_DBGKD_CONTROL_SET']],
            'AlphaControlSet': [0x0, ['unsigned long']],
            'IA64ControlSet': [0x0, ['_IA64_DBGKD_CONTROL_SET']],
            'Amd64ControlSet': [0x0, ['_AMD64_DBGKD_CONTROL_SET']],
            'ArmControlSet': [0x0, ['_ARM_DBGKD_CONTROL_SET']],
            'PpcControlSet': [0x0, ['_PPC_DBGKD_CONTROL_SET']],
        },
    ],
    '_MMVAD_FLAGS3': [
        0x8,
        {
            'PreferredNode': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=6,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Teb': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=6,
                        end_bit=7,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=7,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SequentialAccess': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=9,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'LastSequentialTrim': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=24,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Spare2': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'LargePageCreating': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=32,
                        end_bit=33,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Spare3': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=33,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_MI_VERIFIER_POOL_HEADER': [
        0x8,
        {
            'VerifierPoolEntry': [0x0, ['pointer64', ['_VI_POOL_ENTRY']]],
        },
    ],
    '_HBASE_BLOCK': [
        0x1000,
        {
            'Signature': [0x0, ['unsigned long']],
            'Sequence1': [0x4, ['unsigned long']],
            'Sequence2': [0x8, ['unsigned long']],
            'TimeStamp': [0xC, ['_LARGE_INTEGER']],
            'Major': [0x14, ['unsigned long']],
            'Minor': [0x18, ['unsigned long']],
            'Type': [0x1C, ['unsigned long']],
            'Format': [0x20, ['unsigned long']],
            'RootCell': [0x24, ['unsigned long']],
            'Length': [0x28, ['unsigned long']],
            'Cluster': [0x2C, ['unsigned long']],
            'FileName': [0x30, ['array', 64, ['unsigned char']]],
            'RmId': [0x70, ['_GUID']],
            'LogId': [0x80, ['_GUID']],
            'Flags': [0x90, ['unsigned long']],
            'TmId': [0x94, ['_GUID']],
            'GuidSignature': [0xA4, ['unsigned long']],
            'Reserved1': [0xA8, ['array', 85, ['unsigned long']]],
            'CheckSum': [0x1FC, ['unsigned long']],
            'Reserved2': [0x200, ['array', 882, ['unsigned long']]],
            'ThawTmId': [0xFC8, ['_GUID']],
            'ThawRmId': [0xFD8, ['_GUID']],
            'ThawLogId': [0xFE8, ['_GUID']],
            'BootType': [0xFF8, ['unsigned long']],
            'BootRecover': [0xFFC, ['unsigned long']],
        },
    ],
    '_ERESOURCE': [
        0x68,
        {
            'SystemResourcesList': [0x0, ['_LIST_ENTRY']],
            'OwnerTable': [0x10, ['pointer64', ['_OWNER_ENTRY']]],
            'ActiveCount': [0x18, ['short']],
            'Flag': [0x1A, ['unsigned short']],
            'SharedWaiters': [0x20, ['pointer64', ['_KSEMAPHORE']]],
            'ExclusiveWaiters': [0x28, ['pointer64', ['_KEVENT']]],
            'OwnerEntry': [0x30, ['_OWNER_ENTRY']],
            'ActiveEntries': [0x40, ['unsigned long']],
            'ContentionCount': [0x44, ['unsigned long']],
            'NumberOfSharedWaiters': [0x48, ['unsigned long']],
            'NumberOfExclusiveWaiters': [0x4C, ['unsigned long']],
            'Reserved2': [0x50, ['pointer64', ['void']]],
            'Address': [0x58, ['pointer64', ['void']]],
            'CreatorBackTraceIndex': [0x58, ['unsigned long long']],
            'SpinLock': [0x60, ['unsigned long long']],
        },
    ],
    '_ARM_DBGKD_CONTROL_SET': [
        0xC,
        {
            'Continue': [0x0, ['unsigned long']],
            'CurrentSymbolStart': [0x4, ['unsigned long']],
            'CurrentSymbolEnd': [0x8, ['unsigned long']],
        },
    ],
    '_LPCP_MESSAGE': [
        0x50,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'FreeEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Reserved0': [0x8, ['unsigned long']],
            'SenderPort': [0x10, ['pointer64', ['void']]],
            'RepliedToThread': [0x18, ['pointer64', ['_ETHREAD']]],
            'PortContext': [0x20, ['pointer64', ['void']]],
            'Request': [0x28, ['_PORT_MESSAGE']],
        },
    ],
    '_HARDWARE_PTE': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Write': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Owner': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'WriteThrough': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CacheDisable': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Accessed': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=6,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Dirty': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=6,
                        end_bit=7,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'LargePage': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=7,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Global': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=9,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFrameNumber': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=48,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=48,
                        end_bit=52,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SoftwareWsIndex': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=52,
                        end_bit=63,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NoExecute': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=63,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_DUAL': [
        0x278,
        {
            'Length': [0x0, ['unsigned long']],
            'Map': [0x8, ['pointer64', ['_HMAP_DIRECTORY']]],
            'SmallDir': [0x10, ['pointer64', ['_HMAP_TABLE']]],
            'Guard': [0x18, ['unsigned long']],
            'FreeDisplay': [0x20, ['array', 24, ['_FREE_DISPLAY']]],
            'FreeSummary': [0x260, ['unsigned long']],
            'FreeBins': [0x268, ['_LIST_ENTRY']],
        },
    ],
    '_ALPC_PORT_ATTRIBUTES': [
        0x48,
        {
            'Flags': [0x0, ['unsigned long']],
            'SecurityQos': [0x4, ['_SECURITY_QUALITY_OF_SERVICE']],
            'MaxMessageLength': [0x10, ['unsigned long long']],
            'MemoryBandwidth': [0x18, ['unsigned long long']],
            'MaxPoolUsage': [0x20, ['unsigned long long']],
            'MaxSectionSize': [0x28, ['unsigned long long']],
            'MaxViewSize': [0x30, ['unsigned long long']],
            'MaxTotalSectionSize': [0x38, ['unsigned long long']],
            'DupObjectTypes': [0x40, ['unsigned long']],
            'Reserved': [0x44, ['unsigned long']],
        },
    ],
    '_CM_INDEX_HINT_BLOCK': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'HashKey': [0x4, ['array', 1, ['unsigned long']]],
        },
    ],
    '_KQUEUE': [
        0x40,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'EntryListHead': [0x18, ['_LIST_ENTRY']],
            'CurrentCount': [0x28, ['unsigned long']],
            'MaximumCount': [0x2C, ['unsigned long']],
            'ThreadListHead': [0x30, ['_LIST_ENTRY']],
        },
    ],
    '_KSTACK_COUNT': [
        0x4,
        {
            'Value': [0x0, ['long']],
            'State': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'StackCount': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_DISPATCHER_HEADER': [
        0x18,
        {
            'Type': [0x0, ['unsigned char']],
            'TimerControlFlags': [0x1, ['unsigned char']],
            'Absolute': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Coalescable': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'KeepShifting': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'EncodedTolerableDelay': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Abandoned': [0x1, ['unsigned char']],
            'Signalling': [0x1, ['unsigned char']],
            'ThreadControlFlags': [0x2, ['unsigned char']],
            'CpuThrottled': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'CycleProfiling': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'CounterProfiling': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Hand': [0x2, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'TimerMiscFlags': [0x3, ['unsigned char']],
            'Index': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Inserted': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'Expired': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'DebugActive': [0x3, ['unsigned char']],
            'ActiveDR7': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Instrumented': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Reserved2': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'UmsScheduled': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'UmsPrimary': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'DpcActive': [0x3, ['unsigned char']],
            'Lock': [0x0, ['long']],
            'SignalState': [0x4, ['long']],
            'WaitListHead': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_VI_POOL_ENTRY': [
        0x20,
        {
            'PageHeader': [0x0, ['_VI_POOL_PAGE_HEADER']],
            'InUse': [0x0, ['_VI_POOL_ENTRY_INUSE']],
            'NextFree': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
        },
    ],
    '_MM_PAGE_ACCESS_INFO': [
        0x8,
        {
            'Flags': [0x0, ['_MM_PAGE_ACCESS_INFO_FLAGS']],
            'FileOffset': [0x0, ['unsigned long long']],
            'VirtualAddress': [0x0, ['pointer64', ['void']]],
            'PointerProtoPte': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_MI_CONTROL_AREA_WAIT_BLOCK': [
        0x28,
        {
            'Next': [0x0, ['pointer64', ['_MI_CONTROL_AREA_WAIT_BLOCK']]],
            'WaitReason': [0x8, ['unsigned long']],
            'WaitResponse': [0xC, ['unsigned long']],
            'Gate': [0x10, ['_KGATE']],
        },
    ],
    '_TraceLoggingMetadata_t': [
        0x10,
        {
            'Signature': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned short']],
            'Version': [0x6, ['unsigned char']],
            'Flags': [0x7, ['unsigned char']],
            'Magic': [0x8, ['unsigned long long']],
        },
    ],
    '_HEAP_COUNTERS': [
        0x70,
        {
            'TotalMemoryReserved': [0x0, ['unsigned long long']],
            'TotalMemoryCommitted': [0x8, ['unsigned long long']],
            'TotalMemoryLargeUCR': [0x10, ['unsigned long long']],
            'TotalSizeInVirtualBlocks': [0x18, ['unsigned long long']],
            'TotalSegments': [0x20, ['unsigned long']],
            'TotalUCRs': [0x24, ['unsigned long']],
            'CommittOps': [0x28, ['unsigned long']],
            'DeCommitOps': [0x2C, ['unsigned long']],
            'LockAcquires': [0x30, ['unsigned long']],
            'LockCollisions': [0x34, ['unsigned long']],
            'CommitRate': [0x38, ['unsigned long']],
            'DecommittRate': [0x3C, ['unsigned long']],
            'CommitFailures': [0x40, ['unsigned long']],
            'InBlockCommitFailures': [0x44, ['unsigned long']],
            'CompactHeapCalls': [0x48, ['unsigned long']],
            'CompactedUCRs': [0x4C, ['unsigned long']],
            'AllocAndFreeOps': [0x50, ['unsigned long']],
            'InBlockDeccommits': [0x54, ['unsigned long']],
            'InBlockDeccomitSize': [0x58, ['unsigned long long']],
            'HighWatermarkSize': [0x60, ['unsigned long long']],
            'LastPolledSize': [0x68, ['unsigned long long']],
        },
    ],
    '_CM_KEY_HASH': [
        0x20,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x8, ['pointer64', ['_CM_KEY_HASH']]],
            'KeyHive': [0x10, ['pointer64', ['_HHIVE']]],
            'KeyCell': [0x18, ['unsigned long']],
        },
    ],
    '_SYSPTES_HEADER': [
        0x28,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Count': [0x10, ['unsigned long long']],
            'NumberOfEntries': [0x18, ['unsigned long long']],
            'NumberOfEntriesPeak': [0x20, ['unsigned long long']],
        },
    ],
    '_EXCEPTION_RECORD': [
        0x98,
        {
            'ExceptionCode': [0x0, ['long']],
            'ExceptionFlags': [0x4, ['unsigned long']],
            'ExceptionRecord': [0x8, ['pointer64', ['_EXCEPTION_RECORD']]],
            'ExceptionAddress': [0x10, ['pointer64', ['void']]],
            'NumberParameters': [0x18, ['unsigned long']],
            'ExceptionInformation': [
                0x20,
                ['array', 15, ['unsigned long long']],
            ],
        },
    ],
    '_PENDING_RELATIONS_LIST_ENTRY': [
        0x68,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'WorkItem': [0x10, ['_WORK_QUEUE_ITEM']],
            'DeviceEvent': [0x30, ['pointer64', ['_PNP_DEVICE_EVENT_ENTRY']]],
            'DeviceObject': [0x38, ['pointer64', ['_DEVICE_OBJECT']]],
            'RelationsList': [0x40, ['pointer64', ['_RELATION_LIST']]],
            'EjectIrp': [0x48, ['pointer64', ['_IRP']]],
            'Lock': [
                0x50,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IRPLOCK_CANCELABLE',
                            1: 'IRPLOCK_CANCEL_STARTED',
                            2: 'IRPLOCK_CANCEL_COMPLETE',
                            3: 'IRPLOCK_COMPLETED',
                        },
                    ),
                ],
            ],
            'Problem': [0x54, ['unsigned long']],
            'ProfileChangingEject': [0x58, ['unsigned char']],
            'DisplaySafeRemovalDialog': [0x59, ['unsigned char']],
            'LightestSleepState': [
                0x5C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'DockInterface': [0x60, ['pointer64', ['DOCK_INTERFACE']]],
        },
    ],
    '_I386_LOADER_BLOCK': [
        0x10,
        {
            'CommonDataArea': [0x0, ['pointer64', ['void']]],
            'MachineType': [0x8, ['unsigned long']],
            'VirtualBias': [0xC, ['unsigned long']],
        },
    ],
    '_TOKEN_ACCESS_INFORMATION': [
        0x30,
        {
            'SidHash': [0x0, ['pointer64', ['_SID_AND_ATTRIBUTES_HASH']]],
            'RestrictedSidHash': [
                0x8,
                ['pointer64', ['_SID_AND_ATTRIBUTES_HASH']],
            ],
            'Privileges': [0x10, ['pointer64', ['_TOKEN_PRIVILEGES']]],
            'AuthenticationId': [0x18, ['_LUID']],
            'TokenType': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={1: 'TokenPrimary', 2: 'TokenImpersonation'},
                    ),
                ],
            ],
            'ImpersonationLevel': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'SecurityAnonymous',
                            1: 'SecurityIdentification',
                            2: 'SecurityImpersonation',
                            3: 'SecurityDelegation',
                        },
                    ),
                ],
            ],
            'MandatoryPolicy': [0x28, ['_TOKEN_MANDATORY_POLICY']],
            'Flags': [0x2C, ['unsigned long']],
        },
    ],
    '_CELL_DATA': [
        0x50,
        {
            'u': [0x0, ['_u']],
        },
    ],
    '_ARC_DISK_INFORMATION': [
        0x10,
        {
            'DiskSignatures': [0x0, ['_LIST_ENTRY']],
        },
    ],
    '_INITIAL_PRIVILEGE_SET': [
        0x2C,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Control': [0x4, ['unsigned long']],
            'Privilege': [0x8, ['array', 3, ['_LUID_AND_ATTRIBUTES']]],
        },
    ],
    '_HEAP_TUNING_PARAMETERS': [
        0x10,
        {
            'CommittThresholdShift': [0x0, ['unsigned long']],
            'MaxPreCommittThreshold': [0x8, ['unsigned long long']],
        },
    ],
    '_MMWSLE_NONDIRECT_HASH': [
        0x10,
        {
            'Key': [0x0, ['pointer64', ['void']]],
            'Index': [0x8, ['unsigned long']],
        },
    ],
    '_HMAP_DIRECTORY': [
        0x2000,
        {
            'Directory': [
                0x0,
                ['array', 1024, ['pointer64', ['_HMAP_TABLE']]],
            ],
        },
    ],
    '_KAPC': [
        0x58,
        {
            'Type': [0x0, ['unsigned char']],
            'SpareByte0': [0x1, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'SpareByte1': [0x3, ['unsigned char']],
            'SpareLong0': [0x4, ['unsigned long']],
            'Thread': [0x8, ['pointer64', ['_KTHREAD']]],
            'ApcListEntry': [0x10, ['_LIST_ENTRY']],
            'KernelRoutine': [0x20, ['pointer64', ['void']]],
            'RundownRoutine': [0x28, ['pointer64', ['void']]],
            'NormalRoutine': [0x30, ['pointer64', ['void']]],
            'NormalContext': [0x38, ['pointer64', ['void']]],
            'SystemArgument1': [0x40, ['pointer64', ['void']]],
            'SystemArgument2': [0x48, ['pointer64', ['void']]],
            'ApcStateIndex': [0x50, ['unsigned char']],
            'ApcMode': [0x51, ['unsigned char']],
            'Inserted': [0x52, ['unsigned char']],
        },
    ],
    '_HANDLE_TABLE': [
        0x68,
        {
            'TableCode': [0x0, ['unsigned long long']],
            'QuotaProcess': [0x8, ['pointer64', ['_EPROCESS']]],
            'UniqueProcessId': [0x10, ['pointer64', ['void']]],
            'HandleLock': [0x18, ['_EX_PUSH_LOCK']],
            'HandleTableList': [0x20, ['_LIST_ENTRY']],
            'HandleContentionEvent': [0x30, ['_EX_PUSH_LOCK']],
            'DebugInfo': [0x38, ['pointer64', ['_HANDLE_TRACE_DEBUG_INFO']]],
            'ExtraInfoPages': [0x40, ['long']],
            'Flags': [0x44, ['unsigned long']],
            'StrictFIFO': [
                0x44,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'FirstFreeHandle': [0x48, ['unsigned long']],
            'LastFreeHandleEntry': [
                0x50,
                ['pointer64', ['_HANDLE_TABLE_ENTRY']],
            ],
            'HandleCount': [0x58, ['unsigned long']],
            'NextHandleNeedingPool': [0x5C, ['unsigned long']],
            'HandleCountHighWatermark': [0x60, ['unsigned long']],
        },
    ],
    '_POOL_TRACKER_BIG_PAGES': [
        0x18,
        {
            'Va': [0x0, ['pointer64', ['void']]],
            'Key': [0x8, ['unsigned long']],
            'PoolType': [0xC, ['unsigned long']],
            'NumberOfBytes': [0x10, ['unsigned long long']],
        },
    ],
    '_MMVAD_FLAGS2': [
        0x4,
        {
            'FileOffset': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'SecNoChange': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'OneSecured': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'MultipleSecured': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'LongVad': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'ExtendableFile': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'Inherit': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_TEB_ACTIVE_FRAME': [
        0x18,
        {
            'Flags': [0x0, ['unsigned long']],
            'Previous': [0x8, ['pointer64', ['_TEB_ACTIVE_FRAME']]],
            'Context': [0x10, ['pointer64', ['_TEB_ACTIVE_FRAME_CONTEXT']]],
        },
    ],
    '_FILE_GET_QUOTA_INFORMATION': [
        0x14,
        {
            'NextEntryOffset': [0x0, ['unsigned long']],
            'SidLength': [0x4, ['unsigned long']],
            'Sid': [0x8, ['_SID']],
        },
    ],
    '_ACCESS_REASONS': [
        0x80,
        {
            'Data': [0x0, ['array', 32, ['unsigned long']]],
        },
    ],
    '_CM_KEY_BODY': [
        0x58,
        {
            'Type': [0x0, ['unsigned long']],
            'KeyControlBlock': [0x8, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'NotifyBlock': [0x10, ['pointer64', ['_CM_NOTIFY_BLOCK']]],
            'ProcessID': [0x18, ['pointer64', ['void']]],
            'KeyBodyList': [0x20, ['_LIST_ENTRY']],
            'Flags': [
                0x30,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'HandleTags': [
                0x30,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'KtmTrans': [0x38, ['pointer64', ['void']]],
            'KtmUow': [0x40, ['pointer64', ['_GUID']]],
            'ContextListHead': [0x48, ['_LIST_ENTRY']],
        },
    ],
    '_KWAIT_BLOCK': [
        0x30,
        {
            'WaitListEntry': [0x0, ['_LIST_ENTRY']],
            'Thread': [0x10, ['pointer64', ['_KTHREAD']]],
            'Object': [0x18, ['pointer64', ['void']]],
            'NextWaitBlock': [0x20, ['pointer64', ['_KWAIT_BLOCK']]],
            'WaitKey': [0x28, ['unsigned short']],
            'WaitType': [0x2A, ['unsigned char']],
            'BlockState': [0x2B, ['unsigned char']],
            'SpareLong': [0x2C, ['long']],
        },
    ],
    '_MMPTE_PROTOTYPE': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ReadOnly': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=9,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ProtoAddress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=16, end_bit=64, native_type='long long'),
                ],
            ],
        },
    ],
    '_WHEA_ERROR_PACKET_FLAGS': [
        0x4,
        {
            'PreviousError': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Reserved1': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HypervisorError': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Simulated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'PlatformPfaControl': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'PlatformDirectedOffline': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Reserved2': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_THERMAL_INFORMATION_EX': [
        0x78,
        {
            'ThermalStamp': [0x0, ['unsigned long']],
            'ThermalConstant1': [0x4, ['unsigned long']],
            'ThermalConstant2': [0x8, ['unsigned long']],
            'Processors': [0x10, ['_KAFFINITY_EX']],
            'SamplingPeriod': [0x38, ['unsigned long']],
            'CurrentTemperature': [0x3C, ['unsigned long']],
            'PassiveTripPoint': [0x40, ['unsigned long']],
            'CriticalTripPoint': [0x44, ['unsigned long']],
            'ActiveTripPointCount': [0x48, ['unsigned char']],
            'ActiveTripPoint': [0x4C, ['array', 10, ['unsigned long']]],
            'S4TransitionTripPoint': [0x74, ['unsigned long']],
        },
    ],
    '__unnamed_1cdf': [
        0x4,
        {
            'FilePointerIndex': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'HardFault': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Image': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1ce1': [
        0x4,
        {
            'FilePointerIndex': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'HardFault': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Spare1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_MM_PAGE_ACCESS_INFO_FLAGS': [
        0x4,
        {
            'File': [0x0, ['__unnamed_1cdf']],
            'Private': [0x0, ['__unnamed_1ce1']],
        },
    ],
    '_VI_VERIFIER_ISSUE': [
        0x20,
        {
            'IssueType': [0x0, ['unsigned long long']],
            'Address': [0x8, ['pointer64', ['void']]],
            'Parameters': [0x10, ['array', 2, ['unsigned long long']]],
        },
    ],
    '_MMSUBSECTION_FLAGS': [
        0x4,
        {
            'SubsectionAccessed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'StartingSector4132': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=6, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'SubsectionStatic': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'GlobalMemory': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'DirtyPages': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'Spare': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'SectorEndOffset': [
                0x2,
                [
                    'BitField',
                    dict(
                        start_bit=4, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
        },
    ],
    '_EXCEPTION_POINTERS': [
        0x10,
        {
            'ExceptionRecord': [0x0, ['pointer64', ['_EXCEPTION_RECORD']]],
            'ContextRecord': [0x8, ['pointer64', ['_CONTEXT']]],
        },
    ],
    '_OBJECT_REF_INFO': [
        0x28,
        {
            'ObjectHeader': [0x0, ['pointer64', ['_OBJECT_HEADER']]],
            'NextRef': [0x8, ['pointer64', ['void']]],
            'ImageFileName': [0x10, ['array', 16, ['unsigned char']]],
            'NextPos': [0x20, ['unsigned short']],
            'MaxStacks': [0x22, ['unsigned short']],
            'StackInfo': [0x24, ['array', 0, ['_OBJECT_REF_STACK_INFO']]],
        },
    ],
    '_HBIN': [
        0x20,
        {
            'Signature': [0x0, ['unsigned long']],
            'FileOffset': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long']],
            'Reserved1': [0xC, ['array', 2, ['unsigned long']]],
            'TimeStamp': [0x14, ['_LARGE_INTEGER']],
            'Spare': [0x1C, ['unsigned long']],
        },
    ],
    '_MI_IMAGE_SECURITY_REFERENCE': [
        0x18,
        {
            'SecurityContext': [0x0, ['_IMAGE_SECURITY_CONTEXT']],
            'DynamicRelocations': [0x8, ['pointer64', ['void']]],
            'ReferenceCount': [0x10, ['long']],
        },
    ],
    '_HEAP_TAG_ENTRY': [
        0x48,
        {
            'Allocs': [0x0, ['unsigned long']],
            'Frees': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long long']],
            'TagIndex': [0x10, ['unsigned short']],
            'CreatorBackTraceIndex': [0x12, ['unsigned short']],
            'TagName': [0x14, ['array', 24, ['wchar']]],
        },
    ],
    '_SECURITY_QUALITY_OF_SERVICE': [
        0xC,
        {
            'Length': [0x0, ['unsigned long']],
            'ImpersonationLevel': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'SecurityAnonymous',
                            1: 'SecurityIdentification',
                            2: 'SecurityImpersonation',
                            3: 'SecurityDelegation',
                        },
                    ),
                ],
            ],
            'ContextTrackingMode': [0x8, ['unsigned char']],
            'EffectiveOnly': [0x9, ['unsigned char']],
        },
    ],
    '__unnamed_1d02': [
        0x10,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'Secured': [0x0, ['_MMADDRESS_LIST']],
        },
    ],
    '__unnamed_1d08': [
        0x8,
        {
            'Banked': [0x0, ['pointer64', ['_MMBANKED_SECTION']]],
            'ExtendedInfo': [0x0, ['pointer64', ['_MMEXTEND_INFO']]],
        },
    ],
    '_MMVAD_LONG': [
        0x90,
        {
            'u1': [0x0, ['__unnamed_15bf']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_15c2']],
            'PushLock': [0x30, ['_EX_PUSH_LOCK']],
            'u5': [0x38, ['__unnamed_15c5']],
            'u2': [0x40, ['__unnamed_15d2']],
            'Subsection': [0x48, ['pointer64', ['_SUBSECTION']]],
            'FirstPrototypePte': [0x50, ['pointer64', ['_MMPTE']]],
            'LastContiguousPte': [0x58, ['pointer64', ['_MMPTE']]],
            'ViewLinks': [0x60, ['_LIST_ENTRY']],
            'VadsProcess': [0x70, ['pointer64', ['_EPROCESS']]],
            'u3': [0x78, ['__unnamed_1d02']],
            'u4': [0x88, ['__unnamed_1d08']],
        },
    ],
    '_MMWSLE_FREE_ENTRY': [
        0x8,
        {
            'MustBeZero': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PreviousFree': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NextFree': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=32,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_NT_TIB': [
        0x38,
        {
            'ExceptionList': [
                0x0,
                ['pointer64', ['_EXCEPTION_REGISTRATION_RECORD']],
            ],
            'StackBase': [0x8, ['pointer64', ['void']]],
            'StackLimit': [0x10, ['pointer64', ['void']]],
            'SubSystemTib': [0x18, ['pointer64', ['void']]],
            'FiberData': [0x20, ['pointer64', ['void']]],
            'Version': [0x20, ['unsigned long']],
            'ArbitraryUserPointer': [0x28, ['pointer64', ['void']]],
            'Self': [0x30, ['pointer64', ['_NT_TIB']]],
        },
    ],
    '_WHEA_REVISION': [
        0x2,
        {
            'MinorRevision': [0x0, ['unsigned char']],
            'MajorRevision': [0x1, ['unsigned char']],
            'AsUSHORT': [0x0, ['unsigned short']],
        },
    ],
    '_EJOB': [
        0x1C8,
        {
            'Event': [0x0, ['_KEVENT']],
            'JobLinks': [0x18, ['_LIST_ENTRY']],
            'ProcessListHead': [0x28, ['_LIST_ENTRY']],
            'JobLock': [0x38, ['_ERESOURCE']],
            'TotalUserTime': [0xA0, ['_LARGE_INTEGER']],
            'TotalKernelTime': [0xA8, ['_LARGE_INTEGER']],
            'ThisPeriodTotalUserTime': [0xB0, ['_LARGE_INTEGER']],
            'ThisPeriodTotalKernelTime': [0xB8, ['_LARGE_INTEGER']],
            'TotalPageFaultCount': [0xC0, ['unsigned long']],
            'TotalProcesses': [0xC4, ['unsigned long']],
            'ActiveProcesses': [0xC8, ['unsigned long']],
            'TotalTerminatedProcesses': [0xCC, ['unsigned long']],
            'PerProcessUserTimeLimit': [0xD0, ['_LARGE_INTEGER']],
            'PerJobUserTimeLimit': [0xD8, ['_LARGE_INTEGER']],
            'MinimumWorkingSetSize': [0xE0, ['unsigned long long']],
            'MaximumWorkingSetSize': [0xE8, ['unsigned long long']],
            'LimitFlags': [0xF0, ['unsigned long']],
            'ActiveProcessLimit': [0xF4, ['unsigned long']],
            'Affinity': [0xF8, ['_KAFFINITY_EX']],
            'PriorityClass': [0x120, ['unsigned char']],
            'AccessState': [0x128, ['pointer64', ['_JOB_ACCESS_STATE']]],
            'UIRestrictionsClass': [0x130, ['unsigned long']],
            'EndOfJobTimeAction': [0x134, ['unsigned long']],
            'CompletionPort': [0x138, ['pointer64', ['void']]],
            'CompletionKey': [0x140, ['pointer64', ['void']]],
            'SessionId': [0x148, ['unsigned long']],
            'SchedulingClass': [0x14C, ['unsigned long']],
            'ReadOperationCount': [0x150, ['unsigned long long']],
            'WriteOperationCount': [0x158, ['unsigned long long']],
            'OtherOperationCount': [0x160, ['unsigned long long']],
            'ReadTransferCount': [0x168, ['unsigned long long']],
            'WriteTransferCount': [0x170, ['unsigned long long']],
            'OtherTransferCount': [0x178, ['unsigned long long']],
            'ProcessMemoryLimit': [0x180, ['unsigned long long']],
            'JobMemoryLimit': [0x188, ['unsigned long long']],
            'PeakProcessMemoryUsed': [0x190, ['unsigned long long']],
            'PeakJobMemoryUsed': [0x198, ['unsigned long long']],
            'CurrentJobMemoryUsed': [0x1A0, ['unsigned long long']],
            'MemoryLimitsLock': [0x1A8, ['_EX_PUSH_LOCK']],
            'JobSetLinks': [0x1B0, ['_LIST_ENTRY']],
            'MemberLevel': [0x1C0, ['unsigned long']],
            'JobFlags': [0x1C4, ['unsigned long']],
        },
    ],
    '__unnamed_1d1c': [
        0x4,
        {
            'AsULONG': [0x0, ['unsigned long']],
            'AllowScaling': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Disabled': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HvMaxCState': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_PPM_IDLE_STATES': [
        0xA0,
        {
            'Count': [0x0, ['unsigned long']],
            'Flags': [0x4, ['__unnamed_1d1c']],
            'TargetState': [0x8, ['unsigned long']],
            'ActualState': [0xC, ['unsigned long']],
            'OldState': [0x10, ['unsigned long']],
            'TargetProcessors': [0x18, ['_KAFFINITY_EX']],
            'State': [0x40, ['array', 1, ['_PPM_IDLE_STATE']]],
        },
    ],
    '__unnamed_1d25': [
        0x18,
        {
            'EfiInformation': [0x0, ['_EFI_FIRMWARE_INFORMATION']],
            'PcatInformation': [0x0, ['_PCAT_FIRMWARE_INFORMATION']],
        },
    ],
    '_FIRMWARE_INFORMATION_LOADER_BLOCK': [
        0x20,
        {
            'FirmwareTypeEfi': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'u': [0x8, ['__unnamed_1d25']],
        },
    ],
    '_HEAP_UCR_DESCRIPTOR': [
        0x30,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'SegmentEntry': [0x10, ['_LIST_ENTRY']],
            'Address': [0x20, ['pointer64', ['void']]],
            'Size': [0x28, ['unsigned long long']],
        },
    ],
    '_ETW_REALTIME_CONSUMER': [
        0x88,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'ProcessHandle': [0x10, ['pointer64', ['void']]],
            'ProcessObject': [0x18, ['pointer64', ['_EPROCESS']]],
            'NextNotDelivered': [0x20, ['pointer64', ['void']]],
            'RealtimeConnectContext': [0x28, ['pointer64', ['void']]],
            'DisconnectEvent': [0x30, ['pointer64', ['_KEVENT']]],
            'DataAvailableEvent': [0x38, ['pointer64', ['_KEVENT']]],
            'UserBufferCount': [0x40, ['pointer64', ['unsigned long']]],
            'UserBufferListHead': [
                0x48,
                ['pointer64', ['_SINGLE_LIST_ENTRY']],
            ],
            'BuffersLost': [0x50, ['unsigned long']],
            'EmptyBuffersCount': [0x54, ['unsigned long']],
            'LoggerId': [0x58, ['unsigned long']],
            'ShutDownRequested': [0x5C, ['unsigned char']],
            'NewBuffersLost': [0x5D, ['unsigned char']],
            'Disconnected': [0x5E, ['unsigned char']],
            'ReservedBufferSpaceBitMap': [0x60, ['_RTL_BITMAP']],
            'ReservedBufferSpace': [0x70, ['pointer64', ['unsigned char']]],
            'ReservedBufferSpaceSize': [0x78, ['unsigned long']],
            'UserPagesAllocated': [0x7C, ['unsigned long']],
            'UserPagesReused': [0x80, ['unsigned long']],
            'Wow': [0x84, ['unsigned char']],
        },
    ],
    '_POOL_DESCRIPTOR': [
        0x1140,
        {
            'PoolType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPool',
                            1: 'PagedPool',
                            2: 'NonPagedPoolMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'PagedLock': [0x8, ['_KGUARDED_MUTEX']],
            'NonPagedLock': [0x8, ['unsigned long long']],
            'RunningAllocs': [0x40, ['long']],
            'RunningDeAllocs': [0x44, ['long']],
            'TotalBigPages': [0x48, ['long']],
            'ThreadsProcessingDeferrals': [0x4C, ['long']],
            'TotalBytes': [0x50, ['unsigned long long']],
            'PoolIndex': [0x80, ['unsigned long']],
            'TotalPages': [0xC0, ['long']],
            'PendingFrees': [0x100, ['pointer64', ['pointer64', ['void']]]],
            'PendingFreeDepth': [0x108, ['long']],
            'ListHeads': [0x140, ['array', 256, ['_LIST_ENTRY']]],
        },
    ],
    '_TOKEN_MANDATORY_POLICY': [
        0x4,
        {
            'Policy': [0x0, ['unsigned long']],
        },
    ],
    '_KGATE': [
        0x18,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '_WHEA_ERROR_RECORD_HEADER': [
        0x80,
        {
            'Signature': [0x0, ['unsigned long']],
            'Revision': [0x4, ['_WHEA_REVISION']],
            'SignatureEnd': [0x6, ['unsigned long']],
            'SectionCount': [0xA, ['unsigned short']],
            'Severity': [
                0xC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrSevRecoverable',
                            1: 'WheaErrSevFatal',
                            2: 'WheaErrSevCorrected',
                            3: 'WheaErrSevInformational',
                        },
                    ),
                ],
            ],
            'ValidBits': [0x10, ['_WHEA_ERROR_RECORD_HEADER_VALIDBITS']],
            'Length': [0x14, ['unsigned long']],
            'Timestamp': [0x18, ['_WHEA_TIMESTAMP']],
            'PlatformId': [0x20, ['_GUID']],
            'PartitionId': [0x30, ['_GUID']],
            'CreatorId': [0x40, ['_GUID']],
            'NotifyType': [0x50, ['_GUID']],
            'RecordId': [0x60, ['unsigned long long']],
            'Flags': [0x68, ['_WHEA_ERROR_RECORD_HEADER_FLAGS']],
            'PersistenceInfo': [0x6C, ['_WHEA_PERSISTENCE_INFO']],
            'Reserved': [0x74, ['array', 12, ['unsigned char']]],
        },
    ],
    '_ALPC_PROCESS_CONTEXT': [
        0x20,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'ViewListHead': [0x8, ['_LIST_ENTRY']],
            'PagedPoolQuotaCache': [0x18, ['unsigned long long']],
        },
    ],
    '_DRIVER_EXTENSION': [
        0x38,
        {
            'DriverObject': [0x0, ['pointer64', ['_DRIVER_OBJECT']]],
            'AddDevice': [0x8, ['pointer64', ['void']]],
            'Count': [0x10, ['unsigned long']],
            'ServiceKeyName': [0x18, ['_UNICODE_STRING']],
            'ClientDriverExtension': [
                0x28,
                ['pointer64', ['_IO_CLIENT_EXTENSION']],
            ],
            'FsFilterCallbacks': [
                0x30,
                ['pointer64', ['_FS_FILTER_CALLBACKS']],
            ],
        },
    ],
    '_PRIVILEGE_SET': [
        0x14,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Control': [0x4, ['unsigned long']],
            'Privilege': [0x8, ['array', 1, ['_LUID_AND_ATTRIBUTES']]],
        },
    ],
    '_CM_NOTIFY_BLOCK': [
        0x58,
        {
            'HiveList': [0x0, ['_LIST_ENTRY']],
            'PostList': [0x10, ['_LIST_ENTRY']],
            'KeyControlBlock': [
                0x20,
                ['pointer64', ['_CM_KEY_CONTROL_BLOCK']],
            ],
            'KeyBody': [0x28, ['pointer64', ['_CM_KEY_BODY']]],
            'Filter': [
                0x30,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=30, native_type='unsigned long'),
                ],
            ],
            'WatchTree': [
                0x30,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'NotifyPending': [
                0x30,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'SubjectContext': [0x38, ['_SECURITY_SUBJECT_CONTEXT']],
        },
    ],
    '_KINTERRUPT': [
        0xA0,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'InterruptListEntry': [0x8, ['_LIST_ENTRY']],
            'ServiceRoutine': [0x18, ['pointer64', ['void']]],
            'MessageServiceRoutine': [0x20, ['pointer64', ['void']]],
            'MessageIndex': [0x28, ['unsigned long']],
            'ServiceContext': [0x30, ['pointer64', ['void']]],
            'SpinLock': [0x38, ['unsigned long long']],
            'TickCount': [0x40, ['unsigned long']],
            'ActualLock': [0x48, ['pointer64', ['unsigned long long']]],
            'DispatchAddress': [0x50, ['pointer64', ['void']]],
            'Vector': [0x58, ['unsigned long']],
            'Irql': [0x5C, ['unsigned char']],
            'SynchronizeIrql': [0x5D, ['unsigned char']],
            'FloatingSave': [0x5E, ['unsigned char']],
            'Connected': [0x5F, ['unsigned char']],
            'Number': [0x60, ['unsigned long']],
            'ShareVector': [0x64, ['unsigned char']],
            'Pad': [0x65, ['array', 3, ['unsigned char']]],
            'Mode': [
                0x68,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'LevelSensitive', 1: 'Latched'},
                    ),
                ],
            ],
            'Polarity': [
                0x6C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'InterruptPolarityUnknown',
                            1: 'InterruptActiveHigh',
                            2: 'InterruptActiveLow',
                        },
                    ),
                ],
            ],
            'ServiceCount': [0x70, ['unsigned long']],
            'DispatchCount': [0x74, ['unsigned long']],
            'Rsvd1': [0x78, ['unsigned long long']],
            'TrapFrame': [0x80, ['pointer64', ['_KTRAP_FRAME']]],
            'Reserved': [0x88, ['pointer64', ['void']]],
            'DispatchCode': [0x90, ['array', 4, ['unsigned long']]],
        },
    ],
    '_HANDLE_TABLE_ENTRY': [
        0x10,
        {
            'Object': [0x0, ['pointer64', ['void']]],
            'ObAttributes': [0x0, ['unsigned long']],
            'InfoTable': [0x0, ['pointer64', ['_HANDLE_TABLE_ENTRY_INFO']]],
            'Value': [0x0, ['unsigned long long']],
            'GrantedAccess': [0x8, ['unsigned long']],
            'GrantedAccessIndex': [0x8, ['unsigned short']],
            'CreatorBackTraceIndex': [0xA, ['unsigned short']],
            'NextFreeTableEntry': [0x8, ['unsigned long']],
        },
    ],
    '_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION': [
        0x30,
        {
            'SecurityAttributeCount': [0x0, ['unsigned long']],
            'SecurityAttributesList': [0x8, ['_LIST_ENTRY']],
            'WorkingSecurityAttributeCount': [0x18, ['unsigned long']],
            'WorkingSecurityAttributesList': [0x20, ['_LIST_ENTRY']],
        },
    ],
    '_IMAGE_FILE_HEADER': [
        0x14,
        {
            'Machine': [0x0, ['unsigned short']],
            'NumberOfSections': [0x2, ['unsigned short']],
            'TimeDateStamp': [0x4, ['unsigned long']],
            'PointerToSymbolTable': [0x8, ['unsigned long']],
            'NumberOfSymbols': [0xC, ['unsigned long']],
            'SizeOfOptionalHeader': [0x10, ['unsigned short']],
            'Characteristics': [0x12, ['unsigned short']],
        },
    ],
    '_MMEXTEND_INFO': [
        0x10,
        {
            'CommittedSize': [0x0, ['unsigned long long']],
            'ReferenceCount': [0x8, ['unsigned long']],
        },
    ],
    '_HIVE_LIST_ENTRY': [
        0x88,
        {
            'FileName': [0x0, ['pointer64', ['unsigned short']]],
            'BaseName': [0x8, ['pointer64', ['unsigned short']]],
            'RegRootName': [0x10, ['pointer64', ['unsigned short']]],
            'CmHive': [0x18, ['pointer64', ['_CMHIVE']]],
            'HHiveFlags': [0x20, ['unsigned long']],
            'CmHiveFlags': [0x24, ['unsigned long']],
            'CmKcbCacheSize': [0x28, ['unsigned long']],
            'CmHive2': [0x30, ['pointer64', ['_CMHIVE']]],
            'HiveMounted': [0x38, ['unsigned char']],
            'ThreadFinished': [0x39, ['unsigned char']],
            'ThreadStarted': [0x3A, ['unsigned char']],
            'Allocate': [0x3B, ['unsigned char']],
            'WinPERequired': [0x3C, ['unsigned char']],
            'StartEvent': [0x40, ['_KEVENT']],
            'FinishedEvent': [0x58, ['_KEVENT']],
            'MountLock': [0x70, ['_KEVENT']],
        },
    ],
    '_CONTEXT': [
        0x4D0,
        {
            'P1Home': [0x0, ['unsigned long long']],
            'P2Home': [0x8, ['unsigned long long']],
            'P3Home': [0x10, ['unsigned long long']],
            'P4Home': [0x18, ['unsigned long long']],
            'P5Home': [0x20, ['unsigned long long']],
            'P6Home': [0x28, ['unsigned long long']],
            'ContextFlags': [0x30, ['unsigned long']],
            'MxCsr': [0x34, ['unsigned long']],
            'SegCs': [0x38, ['unsigned short']],
            'SegDs': [0x3A, ['unsigned short']],
            'SegEs': [0x3C, ['unsigned short']],
            'SegFs': [0x3E, ['unsigned short']],
            'SegGs': [0x40, ['unsigned short']],
            'SegSs': [0x42, ['unsigned short']],
            'EFlags': [0x44, ['unsigned long']],
            'Dr0': [0x48, ['unsigned long long']],
            'Dr1': [0x50, ['unsigned long long']],
            'Dr2': [0x58, ['unsigned long long']],
            'Dr3': [0x60, ['unsigned long long']],
            'Dr6': [0x68, ['unsigned long long']],
            'Dr7': [0x70, ['unsigned long long']],
            'Rax': [0x78, ['unsigned long long']],
            'Rcx': [0x80, ['unsigned long long']],
            'Rdx': [0x88, ['unsigned long long']],
            'Rbx': [0x90, ['unsigned long long']],
            'Rsp': [0x98, ['unsigned long long']],
            'Rbp': [0xA0, ['unsigned long long']],
            'Rsi': [0xA8, ['unsigned long long']],
            'Rdi': [0xB0, ['unsigned long long']],
            'R8': [0xB8, ['unsigned long long']],
            'R9': [0xC0, ['unsigned long long']],
            'R10': [0xC8, ['unsigned long long']],
            'R11': [0xD0, ['unsigned long long']],
            'R12': [0xD8, ['unsigned long long']],
            'R13': [0xE0, ['unsigned long long']],
            'R14': [0xE8, ['unsigned long long']],
            'R15': [0xF0, ['unsigned long long']],
            'Rip': [0xF8, ['unsigned long long']],
            'FltSave': [0x100, ['_XSAVE_FORMAT']],
            'Header': [0x100, ['array', 2, ['_M128A']]],
            'Legacy': [0x120, ['array', 8, ['_M128A']]],
            'Xmm0': [0x1A0, ['_M128A']],
            'Xmm1': [0x1B0, ['_M128A']],
            'Xmm2': [0x1C0, ['_M128A']],
            'Xmm3': [0x1D0, ['_M128A']],
            'Xmm4': [0x1E0, ['_M128A']],
            'Xmm5': [0x1F0, ['_M128A']],
            'Xmm6': [0x200, ['_M128A']],
            'Xmm7': [0x210, ['_M128A']],
            'Xmm8': [0x220, ['_M128A']],
            'Xmm9': [0x230, ['_M128A']],
            'Xmm10': [0x240, ['_M128A']],
            'Xmm11': [0x250, ['_M128A']],
            'Xmm12': [0x260, ['_M128A']],
            'Xmm13': [0x270, ['_M128A']],
            'Xmm14': [0x280, ['_M128A']],
            'Xmm15': [0x290, ['_M128A']],
            'VectorRegister': [0x300, ['array', 26, ['_M128A']]],
            'VectorControl': [0x4A0, ['unsigned long long']],
            'DebugControl': [0x4A8, ['unsigned long long']],
            'LastBranchToRip': [0x4B0, ['unsigned long long']],
            'LastBranchFromRip': [0x4B8, ['unsigned long long']],
            'LastExceptionToRip': [0x4C0, ['unsigned long long']],
            'LastExceptionFromRip': [0x4C8, ['unsigned long long']],
        },
    ],
    '_ALPC_HANDLE_TABLE': [
        0x18,
        {
            'Handles': [0x0, ['pointer64', ['_ALPC_HANDLE_ENTRY']]],
            'TotalHandles': [0x8, ['unsigned long']],
            'Flags': [0xC, ['unsigned long']],
            'Lock': [0x10, ['_EX_PUSH_LOCK']],
        },
    ],
    '_MMPTE_HARDWARE': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Dirty1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Owner': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'WriteThrough': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CacheDisable': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Accessed': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=6,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Dirty': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=6,
                        end_bit=7,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'LargePage': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=7,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Global': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=9,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Write': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFrameNumber': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=48,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=48,
                        end_bit=52,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SoftwareWsIndex': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=52,
                        end_bit=63,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NoExecute': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=63,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_IO_COMPLETION_CONTEXT': [
        0x10,
        {
            'Port': [0x0, ['pointer64', ['void']]],
            'Key': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_IOV_FORCED_PENDING_TRACE': [
        0x200,
        {
            'Irp': [0x0, ['pointer64', ['_IRP']]],
            'Thread': [0x8, ['pointer64', ['_ETHREAD']]],
            'StackTrace': [0x10, ['array', 62, ['pointer64', ['void']]]],
        },
    ],
    '_DBGKD_SET_CONTEXT': [
        0x4,
        {
            'ContextFlags': [0x0, ['unsigned long']],
        },
    ],
    '_VI_POOL_ENTRY_INUSE': [
        0x20,
        {
            'VirtualAddress': [0x0, ['pointer64', ['void']]],
            'CallingAddress': [0x8, ['pointer64', ['void']]],
            'NumberOfBytes': [0x10, ['unsigned long long']],
            'Tag': [0x18, ['unsigned long long']],
        },
    ],
    '_ALPC_COMPLETION_LIST': [
        0x98,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'OwnerProcess': [0x10, ['pointer64', ['_EPROCESS']]],
            'Mdl': [0x18, ['pointer64', ['_MDL']]],
            'UserVa': [0x20, ['pointer64', ['void']]],
            'UserLimit': [0x28, ['pointer64', ['void']]],
            'DataUserVa': [0x30, ['pointer64', ['void']]],
            'SystemVa': [0x38, ['pointer64', ['void']]],
            'TotalSize': [0x40, ['unsigned long long']],
            'Header': [0x48, ['pointer64', ['_ALPC_COMPLETION_LIST_HEADER']]],
            'List': [0x50, ['pointer64', ['void']]],
            'ListSize': [0x58, ['unsigned long long']],
            'Bitmap': [0x60, ['pointer64', ['void']]],
            'BitmapSize': [0x68, ['unsigned long long']],
            'Data': [0x70, ['pointer64', ['void']]],
            'DataSize': [0x78, ['unsigned long long']],
            'BitmapLimit': [0x80, ['unsigned long']],
            'BitmapNextHint': [0x84, ['unsigned long']],
            'ConcurrencyCount': [0x88, ['unsigned long']],
            'AttributeFlags': [0x8C, ['unsigned long']],
            'AttributeSize': [0x90, ['unsigned long']],
        },
    ],
    '_INTERFACE': [
        0x20,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x8, ['pointer64', ['void']]],
            'InterfaceReference': [0x10, ['pointer64', ['void']]],
            'InterfaceDereference': [0x18, ['pointer64', ['void']]],
        },
    ],
    '_ACL': [
        0x8,
        {
            'AclRevision': [0x0, ['unsigned char']],
            'Sbz1': [0x1, ['unsigned char']],
            'AclSize': [0x2, ['unsigned short']],
            'AceCount': [0x4, ['unsigned short']],
            'Sbz2': [0x6, ['unsigned short']],
        },
    ],
    '_LAZY_WRITER': [
        0x88,
        {
            'ScanDpc': [0x0, ['_KDPC']],
            'ScanTimer': [0x40, ['_KTIMER']],
            'ScanActive': [0x80, ['unsigned char']],
            'OtherWork': [0x81, ['unsigned char']],
            'PendingTeardownScan': [0x82, ['unsigned char']],
            'PendingPeriodicScan': [0x83, ['unsigned char']],
            'PendingLowMemoryScan': [0x84, ['unsigned char']],
            'PendingPowerScan': [0x85, ['unsigned char']],
        },
    ],
    '_PI_BUS_EXTENSION': [
        0x70,
        {
            'Flags': [0x0, ['unsigned long']],
            'NumberCSNs': [0x4, ['unsigned char']],
            'ReadDataPort': [0x8, ['pointer64', ['unsigned char']]],
            'DataPortMapped': [0x10, ['unsigned char']],
            'AddressPort': [0x18, ['pointer64', ['unsigned char']]],
            'AddrPortMapped': [0x20, ['unsigned char']],
            'CommandPort': [0x28, ['pointer64', ['unsigned char']]],
            'CmdPortMapped': [0x30, ['unsigned char']],
            'NextSlotNumber': [0x34, ['unsigned long']],
            'DeviceList': [0x38, ['_SINGLE_LIST_ENTRY']],
            'CardList': [0x40, ['_SINGLE_LIST_ENTRY']],
            'PhysicalBusDevice': [0x48, ['pointer64', ['_DEVICE_OBJECT']]],
            'FunctionalBusDevice': [0x50, ['pointer64', ['_DEVICE_OBJECT']]],
            'AttachedDevice': [0x58, ['pointer64', ['_DEVICE_OBJECT']]],
            'BusNumber': [0x60, ['unsigned long']],
            'SystemPowerState': [
                0x64,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'DevicePowerState': [
                0x68,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerDeviceUnspecified',
                            1: 'PowerDeviceD0',
                            2: 'PowerDeviceD1',
                            3: 'PowerDeviceD2',
                            4: 'PowerDeviceD3',
                            5: 'PowerDeviceMaximum',
                        },
                    ),
                ],
            ],
        },
    ],
    '_SID_AND_ATTRIBUTES': [
        0x10,
        {
            'Sid': [0x0, ['pointer64', ['void']]],
            'Attributes': [0x8, ['unsigned long']],
        },
    ],
    '_SID_IDENTIFIER_AUTHORITY': [
        0x6,
        {
            'Value': [0x0, ['array', 6, ['unsigned char']]],
        },
    ],
    '_IO_WORKITEM': [
        0x40,
        {
            'WorkItem': [0x0, ['_WORK_QUEUE_ITEM']],
            'Routine': [0x20, ['pointer64', ['void']]],
            'IoObject': [0x28, ['pointer64', ['void']]],
            'Context': [0x30, ['pointer64', ['void']]],
            'Type': [0x38, ['unsigned long']],
        },
    ],
    '_CM_RM': [
        0x88,
        {
            'RmListEntry': [0x0, ['_LIST_ENTRY']],
            'TransactionListHead': [0x10, ['_LIST_ENTRY']],
            'TmHandle': [0x20, ['pointer64', ['void']]],
            'Tm': [0x28, ['pointer64', ['void']]],
            'RmHandle': [0x30, ['pointer64', ['void']]],
            'KtmRm': [0x38, ['pointer64', ['void']]],
            'RefCount': [0x40, ['unsigned long']],
            'ContainerNum': [0x44, ['unsigned long']],
            'ContainerSize': [0x48, ['unsigned long long']],
            'CmHive': [0x50, ['pointer64', ['_CMHIVE']]],
            'LogFileObject': [0x58, ['pointer64', ['void']]],
            'MarshallingContext': [0x60, ['pointer64', ['void']]],
            'RmFlags': [0x68, ['unsigned long']],
            'LogStartStatus1': [0x6C, ['long']],
            'LogStartStatus2': [0x70, ['long']],
            'BaseLsn': [0x78, ['unsigned long long']],
            'RmLock': [0x80, ['pointer64', ['_ERESOURCE']]],
        },
    ],
    '_CHILD_LIST': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['unsigned long']],
        },
    ],
    '_MMVAD_FLAGS': [
        0x8,
        {
            'CommitCharge': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=51,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NoChange': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=51,
                        end_bit=52,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'VadType': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=52,
                        end_bit=55,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'MemCommit': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=55,
                        end_bit=56,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=56,
                        end_bit=61,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=61,
                        end_bit=63,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PrivateMemory': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=63,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_MMWSLE_HASH': [
        0x4,
        {
            'Index': [0x0, ['unsigned long']],
        },
    ],
    '_UNEXPECTED_INTERRUPT': [
        0x10,
        {
            'PushImmOp': [0x0, ['unsigned char']],
            'PushImm': [0x1, ['unsigned long']],
            'PushRbp': [0x5, ['unsigned char']],
            'JmpOp': [0x6, ['unsigned char']],
            'JmpOffset': [0x7, ['long']],
        },
    ],
    '_DBGKD_FILL_MEMORY': [
        0x10,
        {
            'Address': [0x0, ['unsigned long long']],
            'Length': [0x8, ['unsigned long']],
            'Flags': [0xC, ['unsigned short']],
            'PatternLength': [0xE, ['unsigned short']],
        },
    ],
    '_HEAP_STOP_ON_VALUES': [
        0x30,
        {
            'AllocAddress': [0x0, ['unsigned long long']],
            'AllocTag': [0x8, ['_HEAP_STOP_ON_TAG']],
            'ReAllocAddress': [0x10, ['unsigned long long']],
            'ReAllocTag': [0x18, ['_HEAP_STOP_ON_TAG']],
            'FreeAddress': [0x20, ['unsigned long long']],
            'FreeTag': [0x28, ['_HEAP_STOP_ON_TAG']],
        },
    ],
    '_HEAP_PSEUDO_TAG_ENTRY': [
        0x10,
        {
            'Allocs': [0x0, ['unsigned long']],
            'Frees': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long long']],
        },
    ],
    '_CALL_HASH_ENTRY': [
        0x28,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'CallersAddress': [0x10, ['pointer64', ['void']]],
            'CallersCaller': [0x18, ['pointer64', ['void']]],
            'CallCount': [0x20, ['unsigned long']],
        },
    ],
    '_VF_TRACKER_STAMP': [
        0x10,
        {
            'Thread': [0x0, ['pointer64', ['void']]],
            'Flags': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OldIrql': [
                0x9,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'NewIrql': [
                0xA,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Processor': [
                0xB,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_VI_TRACK_IRQL': [
        0x38,
        {
            'Thread': [0x0, ['pointer64', ['void']]],
            'OldIrql': [0x8, ['unsigned char']],
            'NewIrql': [0x9, ['unsigned char']],
            'Processor': [0xA, ['unsigned short']],
            'TickCount': [0xC, ['unsigned long']],
            'StackTrace': [0x10, ['array', 5, ['pointer64', ['void']]]],
        },
    ],
    '_PNP_DEVICE_EVENT_ENTRY': [
        0x90,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Argument': [0x10, ['unsigned long']],
            'CallerEvent': [0x18, ['pointer64', ['_KEVENT']]],
            'Callback': [0x20, ['pointer64', ['void']]],
            'Context': [0x28, ['pointer64', ['void']]],
            'VetoType': [
                0x30,
                [
                    'pointer64',
                    [
                        'Enumeration',
                        dict(
                            target='long',
                            choices={
                                0: 'PNP_VetoTypeUnknown',
                                1: 'PNP_VetoLegacyDevice',
                                2: 'PNP_VetoPendingClose',
                                3: 'PNP_VetoWindowsApp',
                                4: 'PNP_VetoWindowsService',
                                5: 'PNP_VetoOutstandingOpen',
                                6: 'PNP_VetoDevice',
                                7: 'PNP_VetoDriver',
                                8: 'PNP_VetoIllegalDeviceRequest',
                                9: 'PNP_VetoInsufficientPower',
                                10: 'PNP_VetoNonDisableable',
                                11: 'PNP_VetoLegacyDriver',
                                12: 'PNP_VetoInsufficientRights',
                            },
                        ),
                    ],
                ],
            ],
            'VetoName': [0x38, ['pointer64', ['_UNICODE_STRING']]],
            'Data': [0x40, ['_PLUGPLAY_EVENT_BLOCK']],
        },
    ],
    '_HEAP_STOP_ON_TAG': [
        0x4,
        {
            'HeapAndTagIndex': [0x0, ['unsigned long']],
            'TagIndex': [0x0, ['unsigned short']],
            'HeapIndex': [0x2, ['unsigned short']],
        },
    ],
    '_DBGKD_GET_CONTEXT': [
        0x4,
        {
            'Unused': [0x0, ['unsigned long']],
        },
    ],
    '_TEB_ACTIVE_FRAME_CONTEXT': [
        0x10,
        {
            'Flags': [0x0, ['unsigned long']],
            'FrameName': [0x8, ['pointer64', ['unsigned char']]],
        },
    ],
    '_NLS_DATA_BLOCK': [
        0x18,
        {
            'AnsiCodePageData': [0x0, ['pointer64', ['void']]],
            'OemCodePageData': [0x8, ['pointer64', ['void']]],
            'UnicodeCaseTableData': [0x10, ['pointer64', ['void']]],
        },
    ],
    '_ALIGNED_AFFINITY_SUMMARY': [
        0x80,
        {
            'CpuSet': [0x0, ['_KAFFINITY_EX']],
            'SMTSet': [0x28, ['_KAFFINITY_EX']],
        },
    ],
    '_XSTATE_CONFIGURATION': [
        0x210,
        {
            'EnabledFeatures': [0x0, ['unsigned long long']],
            'Size': [0x8, ['unsigned long']],
            'OptimizedSave': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Features': [0x10, ['array', 64, ['_XSTATE_FEATURE']]],
        },
    ],
    '_CM_KEY_SECURITY_CACHE': [
        0x38,
        {
            'Cell': [0x0, ['unsigned long']],
            'ConvKey': [0x4, ['unsigned long']],
            'List': [0x8, ['_LIST_ENTRY']],
            'DescriptorLength': [0x18, ['unsigned long']],
            'RealRefCount': [0x1C, ['unsigned long']],
            'Descriptor': [0x20, ['_SECURITY_DESCRIPTOR_RELATIVE']],
        },
    ],
    '_MMPTE_SOFTWARE': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFileLow': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Transition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'UsedPageTableEntries': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=22,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'InStore': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22,
                        end_bit=23,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFileHigh': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=32,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_RTL_UMS_CONTEXT': [
        0x540,
        {
            'Link': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Context': [0x10, ['_CONTEXT']],
            'Teb': [0x4E0, ['pointer64', ['void']]],
            'UserContext': [0x4E8, ['pointer64', ['void']]],
            'ScheduledThread': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'HasQuantumReq': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HasAffinityReq': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'HasPriorityReq': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Suspended': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'VolatileContext': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Terminated': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'DebugActive': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'RunningOnSelfThread': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'DenyRunningOnSelfThread': [
                0x4F0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags': [
                0x4F0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'Flags': [0x4F0, ['long']],
            'KernelUpdateLock': [
                0x4F8,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x4F8,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PrimaryClientID': [
                0x4F8,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ContextLock': [0x4F8, ['unsigned long long']],
            'QuantumValue': [0x500, ['unsigned long long']],
            'AffinityMask': [0x508, ['_GROUP_AFFINITY']],
            'Priority': [0x518, ['long']],
            'PrimaryUmsContext': [0x520, ['pointer64', ['_RTL_UMS_CONTEXT']]],
            'SwitchCount': [0x528, ['unsigned long']],
            'KernelYieldCount': [0x52C, ['unsigned long']],
            'MixedYieldCount': [0x530, ['unsigned long']],
            'YieldCount': [0x534, ['unsigned long']],
        },
    ],
    '_CM_RESOURCE_LIST': [
        0x28,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['array', 1, ['_CM_FULL_RESOURCE_DESCRIPTOR']]],
        },
    ],
    '_TOKEN_PRIVILEGES': [
        0x10,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Privileges': [0x4, ['array', 1, ['_LUID_AND_ATTRIBUTES']]],
        },
    ],
    '_POOL_TRACKER_TABLE': [
        0x28,
        {
            'Key': [0x0, ['long']],
            'NonPagedAllocs': [0x4, ['long']],
            'NonPagedFrees': [0x8, ['long']],
            'NonPagedBytes': [0x10, ['unsigned long long']],
            'PagedAllocs': [0x18, ['unsigned long']],
            'PagedFrees': [0x1C, ['unsigned long']],
            'PagedBytes': [0x20, ['unsigned long long']],
        },
    ],
    '_MM_SUBSECTION_AVL_TABLE': [
        0x38,
        {
            'BalancedRoot': [0x0, ['_MMSUBSECTION_NODE']],
            'DepthOfTree': [
                0x28,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x28,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NumberGenericTableElements': [
                0x28,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NodeHint': [0x30, ['pointer64', ['void']]],
        },
    ],
    '_HANDLE_TABLE_ENTRY_INFO': [
        0x4,
        {
            'AuditMask': [0x0, ['unsigned long']],
        },
    ],
    '_CM_FULL_RESOURCE_DESCRIPTOR': [
        0x24,
        {
            'InterfaceType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Internal',
                            1: 'Isa',
                            2: 'Eisa',
                            3: 'MicroChannel',
                            4: 'TurboChannel',
                            5: 'PCIBus',
                            6: 'VMEBus',
                            7: 'NuBus',
                            8: 'PCMCIABus',
                            9: 'CBus',
                            10: 'MPIBus',
                            11: 'MPSABus',
                            12: 'ProcessorInternal',
                            13: 'InternalPowerBus',
                            14: 'PNPISABus',
                            15: 'PNPBus',
                            16: 'Vmcs',
                            17: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0x4, ['unsigned long']],
            'PartialResourceList': [0x8, ['_CM_PARTIAL_RESOURCE_LIST']],
        },
    ],
    '_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS': [
        0x4,
        {
            'Primary': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ContainmentWarning': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Reset': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ThresholdExceeded': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ResourceNotAvailable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'LatentError': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_WMI_BUFFER_HEADER': [
        0x48,
        {
            'BufferSize': [0x0, ['unsigned long']],
            'SavedOffset': [0x4, ['unsigned long']],
            'CurrentOffset': [0x8, ['unsigned long']],
            'ReferenceCount': [0xC, ['long']],
            'TimeStamp': [0x10, ['_LARGE_INTEGER']],
            'SequenceNumber': [0x18, ['long long']],
            'Padding0': [0x20, ['array', 2, ['unsigned long']]],
            'SlistEntry': [0x20, ['_SINGLE_LIST_ENTRY']],
            'NextBuffer': [0x20, ['pointer64', ['_WMI_BUFFER_HEADER']]],
            'ClientContext': [0x28, ['_ETW_BUFFER_CONTEXT']],
            'State': [
                0x2C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'EtwBufferStateFree',
                            1: 'EtwBufferStateGeneralLogging',
                            2: 'EtwBufferStateCSwitch',
                            3: 'EtwBufferStateFlush',
                            4: 'EtwBufferStateMaximum',
                        },
                    ),
                ],
            ],
            'Offset': [0x30, ['unsigned long']],
            'BufferFlag': [0x34, ['unsigned short']],
            'BufferType': [0x36, ['unsigned short']],
            'Padding1': [0x38, ['array', 4, ['unsigned long']]],
            'ReferenceTime': [0x38, ['_ETW_REF_CLOCK']],
            'GlobalEntry': [0x38, ['_LIST_ENTRY']],
            'Pointer0': [0x38, ['pointer64', ['void']]],
            'Pointer1': [0x40, ['pointer64', ['void']]],
        },
    ],
    '_POWER_SEQUENCE': [
        0xC,
        {
            'SequenceD1': [0x0, ['unsigned long']],
            'SequenceD2': [0x4, ['unsigned long']],
            'SequenceD3': [0x8, ['unsigned long']],
        },
    ],
    '_PROCESSOR_POWER_STATE': [
        0x100,
        {
            'IdleStates': [0x0, ['pointer64', ['_PPM_IDLE_STATES']]],
            'IdleTimeLast': [0x8, ['unsigned long long']],
            'IdleTimeTotal': [0x10, ['unsigned long long']],
            'IdleTimeEntry': [0x18, ['unsigned long long']],
            'IdleAccounting': [0x20, ['pointer64', ['_PROC_IDLE_ACCOUNTING']]],
            'Hypervisor': [
                0x28,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ProcHypervisorNone',
                            1: 'ProcHypervisorPresent',
                            2: 'ProcHypervisorPower',
                        },
                    ),
                ],
            ],
            'PerfHistoryTotal': [0x2C, ['unsigned long']],
            'ThermalConstraint': [0x30, ['unsigned char']],
            'PerfHistoryCount': [0x31, ['unsigned char']],
            'PerfHistorySlot': [0x32, ['unsigned char']],
            'Reserved': [0x33, ['unsigned char']],
            'LastSysTime': [0x34, ['unsigned long']],
            'WmiDispatchPtr': [0x38, ['unsigned long long']],
            'WmiInterfaceEnabled': [0x40, ['long']],
            'FFHThrottleStateInfo': [0x48, ['_PPM_FFH_THROTTLE_STATE_INFO']],
            'PerfActionDpc': [0x68, ['_KDPC']],
            'PerfActionMask': [0xA8, ['long']],
            'IdleCheck': [0xB0, ['_PROC_IDLE_SNAP']],
            'PerfCheck': [0xC0, ['_PROC_IDLE_SNAP']],
            'Domain': [0xD0, ['pointer64', ['_PROC_PERF_DOMAIN']]],
            'PerfConstraint': [0xD8, ['pointer64', ['_PROC_PERF_CONSTRAINT']]],
            'Load': [0xE0, ['pointer64', ['_PROC_PERF_LOAD']]],
            'PerfHistory': [0xE8, ['pointer64', ['_PROC_HISTORY_ENTRY']]],
            'Utility': [0xF0, ['unsigned long']],
            'OverUtilizedHistory': [0xF4, ['unsigned long']],
            'AffinityCount': [0xF8, ['unsigned long']],
            'AffinityHistory': [0xFC, ['unsigned long']],
        },
    ],
    '_OBJECT_REF_STACK_INFO': [
        0xC,
        {
            'Sequence': [0x0, ['unsigned long']],
            'Index': [0x4, ['unsigned short']],
            'NumTraces': [0x6, ['unsigned short']],
            'Tag': [0x8, ['unsigned long']],
        },
    ],
    '_PPC_DBGKD_CONTROL_SET': [
        0xC,
        {
            'Continue': [0x0, ['unsigned long']],
            'CurrentSymbolStart': [0x4, ['unsigned long']],
            'CurrentSymbolEnd': [0x8, ['unsigned long']],
        },
    ],
    '_MMPFNENTRY': [
        0x2,
        {
            'PageLocation': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'WriteInProgress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Modified': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'ReadInProgress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'CacheAttribute': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Priority': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Rom': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'InPageError': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'KernelStack': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'RemovalRequested': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'ParityError': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_SEGMENT_OBJECT': [
        0x40,
        {
            'BaseAddress': [0x0, ['pointer64', ['void']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'SizeOfSegment': [0x10, ['_LARGE_INTEGER']],
            'NonExtendedPtes': [0x18, ['unsigned long']],
            'ImageCommitment': [0x1C, ['unsigned long']],
            'ControlArea': [0x20, ['pointer64', ['_CONTROL_AREA']]],
            'Subsection': [0x28, ['pointer64', ['_SUBSECTION']]],
            'MmSectionFlags': [0x30, ['pointer64', ['_MMSECTION_FLAGS']]],
            'MmSubSectionFlags': [
                0x38,
                ['pointer64', ['_MMSUBSECTION_FLAGS']],
            ],
        },
    ],
    '_PCW_CALLBACK_INFORMATION': [
        0x28,
        {
            'AddCounter': [0x0, ['_PCW_COUNTER_INFORMATION']],
            'RemoveCounter': [0x0, ['_PCW_COUNTER_INFORMATION']],
            'EnumerateInstances': [0x0, ['_PCW_MASK_INFORMATION']],
            'CollectData': [0x0, ['_PCW_MASK_INFORMATION']],
        },
    ],
    '_TOKEN_SOURCE': [
        0x10,
        {
            'SourceName': [0x0, ['array', 8, ['unsigned char']]],
            'SourceIdentifier': [0x8, ['_LUID']],
        },
    ],
    '_DBGKD_QUERY_MEMORY': [
        0x18,
        {
            'Address': [0x0, ['unsigned long long']],
            'Reserved': [0x8, ['unsigned long long']],
            'AddressSpace': [0x10, ['unsigned long']],
            'Flags': [0x14, ['unsigned long']],
        },
    ],
    'DOCK_INTERFACE': [
        0x30,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x8, ['pointer64', ['void']]],
            'InterfaceReference': [0x10, ['pointer64', ['void']]],
            'InterfaceDereference': [0x18, ['pointer64', ['void']]],
            'ProfileDepartureSetMode': [0x20, ['pointer64', ['void']]],
            'ProfileDepartureUpdate': [0x28, ['pointer64', ['void']]],
        },
    ],
    'CMP_OFFSET_ARRAY': [
        0x18,
        {
            'FileOffset': [0x0, ['unsigned long']],
            'DataBuffer': [0x8, ['pointer64', ['void']]],
            'DataLength': [0x10, ['unsigned long']],
        },
    ],
    '_MMSUPPORT_FLAGS': [
        0x4,
        {
            'WorkingSetType': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'ModwriterAttached': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'TrimHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'MaximumWorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'ForceTrim': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'MinimumWorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'SessionMaster': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'TrimmerState': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'PageStealers': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'MemoryPriority': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'WsleDeleted': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'VmExiting': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'ExpansionFailed': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Available': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_IMAGE_OPTIONAL_HEADER64': [
        0xF0,
        {
            'Magic': [0x0, ['unsigned short']],
            'MajorLinkerVersion': [0x2, ['unsigned char']],
            'MinorLinkerVersion': [0x3, ['unsigned char']],
            'SizeOfCode': [0x4, ['unsigned long']],
            'SizeOfInitializedData': [0x8, ['unsigned long']],
            'SizeOfUninitializedData': [0xC, ['unsigned long']],
            'AddressOfEntryPoint': [0x10, ['unsigned long']],
            'BaseOfCode': [0x14, ['unsigned long']],
            'ImageBase': [0x18, ['unsigned long long']],
            'SectionAlignment': [0x20, ['unsigned long']],
            'FileAlignment': [0x24, ['unsigned long']],
            'MajorOperatingSystemVersion': [0x28, ['unsigned short']],
            'MinorOperatingSystemVersion': [0x2A, ['unsigned short']],
            'MajorImageVersion': [0x2C, ['unsigned short']],
            'MinorImageVersion': [0x2E, ['unsigned short']],
            'MajorSubsystemVersion': [0x30, ['unsigned short']],
            'MinorSubsystemVersion': [0x32, ['unsigned short']],
            'Win32VersionValue': [0x34, ['unsigned long']],
            'SizeOfImage': [0x38, ['unsigned long']],
            'SizeOfHeaders': [0x3C, ['unsigned long']],
            'CheckSum': [0x40, ['unsigned long']],
            'Subsystem': [0x44, ['unsigned short']],
            'DllCharacteristics': [0x46, ['unsigned short']],
            'SizeOfStackReserve': [0x48, ['unsigned long long']],
            'SizeOfStackCommit': [0x50, ['unsigned long long']],
            'SizeOfHeapReserve': [0x58, ['unsigned long long']],
            'SizeOfHeapCommit': [0x60, ['unsigned long long']],
            'LoaderFlags': [0x68, ['unsigned long']],
            'NumberOfRvaAndSizes': [0x6C, ['unsigned long']],
            'DataDirectory': [0x70, ['array', 16, ['_IMAGE_DATA_DIRECTORY']]],
        },
    ],
    '_ALPC_COMPLETION_PACKET_LOOKASIDE': [
        0x50,
        {
            'Lock': [0x0, ['unsigned long long']],
            'Size': [0x8, ['unsigned long']],
            'ActiveCount': [0xC, ['unsigned long']],
            'PendingNullCount': [0x10, ['unsigned long']],
            'PendingCheckCompletionListCount': [0x14, ['unsigned long']],
            'PendingDelete': [0x18, ['unsigned long']],
            'FreeListHead': [0x20, ['_SINGLE_LIST_ENTRY']],
            'CompletionPort': [0x28, ['pointer64', ['void']]],
            'CompletionKey': [0x30, ['pointer64', ['void']]],
            'Entry': [
                0x38,
                ['array', 1, ['_ALPC_COMPLETION_PACKET_LOOKASIDE_ENTRY']],
            ],
        },
    ],
    '_TERMINATION_PORT': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_TERMINATION_PORT']]],
            'Port': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_MEMORY_ALLOCATION_DESCRIPTOR': [
        0x28,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'MemoryType': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'LoaderExceptionBlock',
                            1: 'LoaderSystemBlock',
                            2: 'LoaderFree',
                            3: 'LoaderBad',
                            4: 'LoaderLoadedProgram',
                            5: 'LoaderFirmwareTemporary',
                            6: 'LoaderFirmwarePermanent',
                            7: 'LoaderOsloaderHeap',
                            8: 'LoaderOsloaderStack',
                            9: 'LoaderSystemCode',
                            10: 'LoaderHalCode',
                            11: 'LoaderBootDriver',
                            12: 'LoaderConsoleInDriver',
                            13: 'LoaderConsoleOutDriver',
                            14: 'LoaderStartupDpcStack',
                            15: 'LoaderStartupKernelStack',
                            16: 'LoaderStartupPanicStack',
                            17: 'LoaderStartupPcrPage',
                            18: 'LoaderStartupPdrPage',
                            19: 'LoaderRegistryData',
                            20: 'LoaderMemoryData',
                            21: 'LoaderNlsData',
                            22: 'LoaderSpecialMemory',
                            23: 'LoaderBBTMemory',
                            24: 'LoaderReserve',
                            25: 'LoaderXIPRom',
                            26: 'LoaderHALCachedMemory',
                            27: 'LoaderLargePageFiller',
                            28: 'LoaderErrorLogMemory',
                            29: 'LoaderMaximum',
                        },
                    ),
                ],
            ],
            'BasePage': [0x18, ['unsigned long long']],
            'PageCount': [0x20, ['unsigned long long']],
        },
    ],
    '_CM_INTENT_LOCK': [
        0x10,
        {
            'OwnerCount': [0x0, ['unsigned long']],
            'OwnerTable': [0x8, ['pointer64', ['pointer64', ['_CM_KCB_UOW']]]],
        },
    ],
    '_PROC_IDLE_ACCOUNTING': [
        0x2C0,
        {
            'StateCount': [0x0, ['unsigned long']],
            'TotalTransitions': [0x4, ['unsigned long']],
            'ResetCount': [0x8, ['unsigned long']],
            'StartTime': [0x10, ['unsigned long long']],
            'BucketLimits': [0x18, ['array', 16, ['unsigned long long']]],
            'State': [0x98, ['array', 1, ['_PROC_IDLE_STATE_ACCOUNTING']]],
        },
    ],
    '_THERMAL_INFORMATION': [
        0x58,
        {
            'ThermalStamp': [0x0, ['unsigned long']],
            'ThermalConstant1': [0x4, ['unsigned long']],
            'ThermalConstant2': [0x8, ['unsigned long']],
            'Processors': [0x10, ['unsigned long long']],
            'SamplingPeriod': [0x18, ['unsigned long']],
            'CurrentTemperature': [0x1C, ['unsigned long']],
            'PassiveTripPoint': [0x20, ['unsigned long']],
            'CriticalTripPoint': [0x24, ['unsigned long']],
            'ActiveTripPointCount': [0x28, ['unsigned char']],
            'ActiveTripPoint': [0x2C, ['array', 10, ['unsigned long']]],
        },
    ],
    '_MAPPED_FILE_SEGMENT': [
        0x30,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'SegmentFlags': [0xC, ['_SEGMENT_FLAGS']],
            'NumberOfCommittedPages': [0x10, ['unsigned long long']],
            'SizeOfSegment': [0x18, ['unsigned long long']],
            'ExtendInfo': [0x20, ['pointer64', ['_MMEXTEND_INFO']]],
            'BasedAddress': [0x20, ['pointer64', ['void']]],
            'SegmentLock': [0x28, ['_EX_PUSH_LOCK']],
        },
    ],
    '_TEB64': [
        0x1818,
        {
            'NtTib': [0x0, ['_NT_TIB64']],
            'EnvironmentPointer': [0x38, ['unsigned long long']],
            'ClientId': [0x40, ['_CLIENT_ID64']],
            'ActiveRpcHandle': [0x50, ['unsigned long long']],
            'ThreadLocalStoragePointer': [0x58, ['unsigned long long']],
            'ProcessEnvironmentBlock': [0x60, ['unsigned long long']],
            'LastErrorValue': [0x68, ['unsigned long']],
            'CountOfOwnedCriticalSections': [0x6C, ['unsigned long']],
            'CsrClientThread': [0x70, ['unsigned long long']],
            'Win32ThreadInfo': [0x78, ['unsigned long long']],
            'User32Reserved': [0x80, ['array', 26, ['unsigned long']]],
            'UserReserved': [0xE8, ['array', 5, ['unsigned long']]],
            'WOW32Reserved': [0x100, ['unsigned long long']],
            'CurrentLocale': [0x108, ['unsigned long']],
            'FpSoftwareStatusRegister': [0x10C, ['unsigned long']],
            'SystemReserved1': [0x110, ['array', 54, ['unsigned long long']]],
            'ExceptionCode': [0x2C0, ['long']],
            'ActivationContextStackPointer': [0x2C8, ['unsigned long long']],
            'SpareBytes': [0x2D0, ['array', 24, ['unsigned char']]],
            'TxFsContext': [0x2E8, ['unsigned long']],
            'GdiTebBatch': [0x2F0, ['_GDI_TEB_BATCH64']],
            'RealClientId': [0x7D8, ['_CLIENT_ID64']],
            'GdiCachedProcessHandle': [0x7E8, ['unsigned long long']],
            'GdiClientPID': [0x7F0, ['unsigned long']],
            'GdiClientTID': [0x7F4, ['unsigned long']],
            'GdiThreadLocalInfo': [0x7F8, ['unsigned long long']],
            'Win32ClientInfo': [0x800, ['array', 62, ['unsigned long long']]],
            'glDispatchTable': [0x9F0, ['array', 233, ['unsigned long long']]],
            'glReserved1': [0x1138, ['array', 29, ['unsigned long long']]],
            'glReserved2': [0x1220, ['unsigned long long']],
            'glSectionInfo': [0x1228, ['unsigned long long']],
            'glSection': [0x1230, ['unsigned long long']],
            'glTable': [0x1238, ['unsigned long long']],
            'glCurrentRC': [0x1240, ['unsigned long long']],
            'glContext': [0x1248, ['unsigned long long']],
            'LastStatusValue': [0x1250, ['unsigned long']],
            'StaticUnicodeString': [0x1258, ['_STRING64']],
            'StaticUnicodeBuffer': [0x1268, ['array', 261, ['wchar']]],
            'DeallocationStack': [0x1478, ['unsigned long long']],
            'TlsSlots': [0x1480, ['array', 64, ['unsigned long long']]],
            'TlsLinks': [0x1680, ['LIST_ENTRY64']],
            'Vdm': [0x1690, ['unsigned long long']],
            'ReservedForNtRpc': [0x1698, ['unsigned long long']],
            'DbgSsReserved': [0x16A0, ['array', 2, ['unsigned long long']]],
            'HardErrorMode': [0x16B0, ['unsigned long']],
            'Instrumentation': [0x16B8, ['array', 11, ['unsigned long long']]],
            'ActivityId': [0x1710, ['_GUID']],
            'SubProcessTag': [0x1720, ['unsigned long long']],
            'EtwLocalData': [0x1728, ['unsigned long long']],
            'EtwTraceData': [0x1730, ['unsigned long long']],
            'WinSockData': [0x1738, ['unsigned long long']],
            'GdiBatchCount': [0x1740, ['unsigned long']],
            'CurrentIdealProcessor': [0x1744, ['_PROCESSOR_NUMBER']],
            'IdealProcessorValue': [0x1744, ['unsigned long']],
            'ReservedPad0': [0x1744, ['unsigned char']],
            'ReservedPad1': [0x1745, ['unsigned char']],
            'ReservedPad2': [0x1746, ['unsigned char']],
            'IdealProcessor': [0x1747, ['unsigned char']],
            'GuaranteedStackBytes': [0x1748, ['unsigned long']],
            'ReservedForPerf': [0x1750, ['unsigned long long']],
            'ReservedForOle': [0x1758, ['unsigned long long']],
            'WaitingOnLoaderLock': [0x1760, ['unsigned long']],
            'SavedPriorityState': [0x1768, ['unsigned long long']],
            'SoftPatchPtr1': [0x1770, ['unsigned long long']],
            'ThreadPoolData': [0x1778, ['unsigned long long']],
            'TlsExpansionSlots': [0x1780, ['unsigned long long']],
            'DeallocationBStore': [0x1788, ['unsigned long long']],
            'BStoreLimit': [0x1790, ['unsigned long long']],
            'MuiGeneration': [0x1798, ['unsigned long']],
            'IsImpersonating': [0x179C, ['unsigned long']],
            'NlsCache': [0x17A0, ['unsigned long long']],
            'pShimData': [0x17A8, ['unsigned long long']],
            'HeapVirtualAffinity': [0x17B0, ['unsigned long']],
            'CurrentTransactionHandle': [0x17B8, ['unsigned long long']],
            'ActiveFrame': [0x17C0, ['unsigned long long']],
            'FlsData': [0x17C8, ['unsigned long long']],
            'PreferredLanguages': [0x17D0, ['unsigned long long']],
            'UserPrefLanguages': [0x17D8, ['unsigned long long']],
            'MergedPrefLanguages': [0x17E0, ['unsigned long long']],
            'MuiImpersonation': [0x17E8, ['unsigned long']],
            'CrossTebFlags': [0x17EC, ['unsigned short']],
            'SpareCrossTebBits': [
                0x17EC,
                [
                    'BitField',
                    dict(
                        start_bit=0, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'SameTebFlags': [0x17EE, ['unsigned short']],
            'SafeThunkCall': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'InDebugPrint': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'HasFiberData': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'SkipThreadAttach': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'WerInShipAssertCode': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'RanProcessInit': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'ClonedThread': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'SuppressDebugMsg': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'DisableUserStackWalk': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned short'),
                ],
            ],
            'RtlExceptionAttached': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=9, end_bit=10, native_type='unsigned short'
                    ),
                ],
            ],
            'InitialThread': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned short'
                    ),
                ],
            ],
            'SpareSameTebBits': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0x17F0, ['unsigned long long']],
            'TxnScopeExitCallback': [0x17F8, ['unsigned long long']],
            'TxnScopeContext': [0x1800, ['unsigned long long']],
            'LockCount': [0x1808, ['unsigned long']],
            'SpareUlong0': [0x180C, ['unsigned long']],
            'ResourceRetValue': [0x1810, ['unsigned long long']],
        },
    ],
    '_GDI_TEB_BATCH': [
        0x4E8,
        {
            'Offset': [0x0, ['unsigned long']],
            'HDC': [0x8, ['unsigned long long']],
            'Buffer': [0x10, ['array', 310, ['unsigned long']]],
        },
    ],
    '_MM_DRIVER_VERIFIER_DATA': [
        0xA0,
        {
            'Level': [0x0, ['unsigned long']],
            'RaiseIrqls': [0x4, ['unsigned long']],
            'AcquireSpinLocks': [0x8, ['unsigned long']],
            'SynchronizeExecutions': [0xC, ['unsigned long']],
            'AllocationsAttempted': [0x10, ['unsigned long']],
            'AllocationsSucceeded': [0x14, ['unsigned long']],
            'AllocationsSucceededSpecialPool': [0x18, ['unsigned long']],
            'AllocationsWithNoTag': [0x1C, ['unsigned long']],
            'TrimRequests': [0x20, ['unsigned long']],
            'Trims': [0x24, ['unsigned long']],
            'AllocationsFailed': [0x28, ['unsigned long']],
            'AllocationsFailedDeliberately': [0x2C, ['unsigned long']],
            'Loads': [0x30, ['unsigned long']],
            'Unloads': [0x34, ['unsigned long']],
            'UnTrackedPool': [0x38, ['unsigned long']],
            'UserTrims': [0x3C, ['unsigned long']],
            'CurrentPagedPoolAllocations': [0x40, ['unsigned long']],
            'CurrentNonPagedPoolAllocations': [0x44, ['unsigned long']],
            'PeakPagedPoolAllocations': [0x48, ['unsigned long']],
            'PeakNonPagedPoolAllocations': [0x4C, ['unsigned long']],
            'PagedBytes': [0x50, ['unsigned long long']],
            'NonPagedBytes': [0x58, ['unsigned long long']],
            'PeakPagedBytes': [0x60, ['unsigned long long']],
            'PeakNonPagedBytes': [0x68, ['unsigned long long']],
            'BurstAllocationsFailedDeliberately': [0x70, ['unsigned long']],
            'SessionTrims': [0x74, ['unsigned long']],
            'OptionChanges': [0x78, ['unsigned long']],
            'VerifyMode': [0x7C, ['unsigned long']],
            'PreviousBucketName': [0x80, ['_UNICODE_STRING']],
            'ActivityCounter': [0x90, ['unsigned long']],
            'PreviousActivityCounter': [0x94, ['unsigned long']],
            'WorkerTrimRequests': [0x98, ['unsigned long']],
        },
    ],
    '_VI_FAULT_TRACE': [
        0x48,
        {
            'Thread': [0x0, ['pointer64', ['_ETHREAD']]],
            'StackTrace': [0x8, ['array', 8, ['pointer64', ['void']]]],
        },
    ],
    '_GENERIC_MAPPING': [
        0x10,
        {
            'GenericRead': [0x0, ['unsigned long']],
            'GenericWrite': [0x4, ['unsigned long']],
            'GenericExecute': [0x8, ['unsigned long']],
            'GenericAll': [0xC, ['unsigned long']],
        },
    ],
    '_OBJECT_HANDLE_COUNT_DATABASE': [
        0x18,
        {
            'CountEntries': [0x0, ['unsigned long']],
            'HandleCountEntries': [
                0x8,
                ['array', 1, ['_OBJECT_HANDLE_COUNT_ENTRY']],
            ],
        },
    ],
    '_OWNER_ENTRY': [
        0x10,
        {
            'OwnerThread': [0x0, ['unsigned long long']],
            'IoPriorityBoosted': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'OwnerReferenced': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'OwnerCount': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'TableSize': [0x8, ['unsigned long']],
        },
    ],
    '_ETIMER': [
        0x110,
        {
            'KeTimer': [0x0, ['_KTIMER']],
            'TimerApc': [0x40, ['_KAPC']],
            'TimerDpc': [0x98, ['_KDPC']],
            'ActiveTimerListEntry': [0xD8, ['_LIST_ENTRY']],
            'Lock': [0xE8, ['unsigned long long']],
            'Period': [0xF0, ['long']],
            'ApcAssociated': [0xF4, ['unsigned char']],
            'WakeReason': [0xF8, ['pointer64', ['_DIAGNOSTIC_CONTEXT']]],
            'WakeTimerListEntry': [0x100, ['_LIST_ENTRY']],
        },
    ],
    '_FREE_DISPLAY': [
        0x18,
        {
            'RealVectorSize': [0x0, ['unsigned long']],
            'Display': [0x8, ['_RTL_BITMAP']],
        },
    ],
    '_POOL_BLOCK_HEAD': [
        0x20,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'List': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1e83': [
        0x8,
        {
            'Flags': [0x0, ['_MMSECURE_FLAGS']],
            'StartVa': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_MMADDRESS_LIST': [
        0x10,
        {
            'u1': [0x0, ['__unnamed_1e83']],
            'EndVa': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_XSTATE_FEATURE': [
        0x8,
        {
            'Offset': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned long']],
        },
    ],
    '_ARBITER_INSTANCE': [
        0x698,
        {
            'Signature': [0x0, ['unsigned long']],
            'MutexEvent': [0x8, ['pointer64', ['_KEVENT']]],
            'Name': [0x10, ['pointer64', ['unsigned short']]],
            'OrderingName': [0x18, ['pointer64', ['unsigned short']]],
            'ResourceType': [0x20, ['long']],
            'Allocation': [0x28, ['pointer64', ['_RTL_RANGE_LIST']]],
            'PossibleAllocation': [0x30, ['pointer64', ['_RTL_RANGE_LIST']]],
            'OrderingList': [0x38, ['_ARBITER_ORDERING_LIST']],
            'ReservedList': [0x48, ['_ARBITER_ORDERING_LIST']],
            'ReferenceCount': [0x58, ['long']],
            'Interface': [0x60, ['pointer64', ['_ARBITER_INTERFACE']]],
            'AllocationStackMaxSize': [0x68, ['unsigned long']],
            'AllocationStack': [
                0x70,
                ['pointer64', ['_ARBITER_ALLOCATION_STATE']],
            ],
            'UnpackRequirement': [0x78, ['pointer64', ['void']]],
            'PackResource': [0x80, ['pointer64', ['void']]],
            'UnpackResource': [0x88, ['pointer64', ['void']]],
            'ScoreRequirement': [0x90, ['pointer64', ['void']]],
            'TestAllocation': [0x98, ['pointer64', ['void']]],
            'RetestAllocation': [0xA0, ['pointer64', ['void']]],
            'CommitAllocation': [0xA8, ['pointer64', ['void']]],
            'RollbackAllocation': [0xB0, ['pointer64', ['void']]],
            'BootAllocation': [0xB8, ['pointer64', ['void']]],
            'QueryArbitrate': [0xC0, ['pointer64', ['void']]],
            'QueryConflict': [0xC8, ['pointer64', ['void']]],
            'AddReserved': [0xD0, ['pointer64', ['void']]],
            'StartArbiter': [0xD8, ['pointer64', ['void']]],
            'PreprocessEntry': [0xE0, ['pointer64', ['void']]],
            'AllocateEntry': [0xE8, ['pointer64', ['void']]],
            'GetNextAllocationRange': [0xF0, ['pointer64', ['void']]],
            'FindSuitableRange': [0xF8, ['pointer64', ['void']]],
            'AddAllocation': [0x100, ['pointer64', ['void']]],
            'BacktrackAllocation': [0x108, ['pointer64', ['void']]],
            'OverrideConflict': [0x110, ['pointer64', ['void']]],
            'InitializeRangeList': [0x118, ['pointer64', ['void']]],
            'TransactionInProgress': [0x120, ['unsigned char']],
            'TransactionEvent': [0x128, ['pointer64', ['_KEVENT']]],
            'Extension': [0x130, ['pointer64', ['void']]],
            'BusDeviceObject': [0x138, ['pointer64', ['_DEVICE_OBJECT']]],
            'ConflictCallbackContext': [0x140, ['pointer64', ['void']]],
            'ConflictCallback': [0x148, ['pointer64', ['void']]],
            'PdoDescriptionString': [0x150, ['array', 336, ['wchar']]],
            'PdoSymbolicNameString': [
                0x3F0,
                ['array', 672, ['unsigned char']],
            ],
            'PdoAddressString': [0x690, ['array', 1, ['wchar']]],
        },
    ],
    '_KDEVICE_QUEUE_ENTRY': [
        0x18,
        {
            'DeviceListEntry': [0x0, ['_LIST_ENTRY']],
            'SortKey': [0x10, ['unsigned long']],
            'Inserted': [0x14, ['unsigned char']],
        },
    ],
    '__unnamed_1edc': [
        0x4,
        {
            'UserData': [0x0, ['unsigned long']],
            'Next': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1ede': [
        0x8,
        {
            'Last': [0x0, ['unsigned long']],
            'u': [0x4, ['__unnamed_1edc']],
        },
    ],
    '__unnamed_1ee0': [
        0x4,
        {
            'u': [0x0, ['__unnamed_1edc']],
        },
    ],
    '__unnamed_1ee2': [
        0x8,
        {
            'OldCell': [0x0, ['__unnamed_1ede']],
            'NewCell': [0x0, ['__unnamed_1ee0']],
        },
    ],
    '_HCELL': [
        0xC,
        {
            'Size': [0x0, ['long']],
            'u': [0x4, ['__unnamed_1ee2']],
        },
    ],
    '_HMAP_TABLE': [
        0x4000,
        {
            'Table': [0x0, ['array', 512, ['_HMAP_ENTRY']]],
        },
    ],
    '_PROC_PERF_CONSTRAINT': [
        0x30,
        {
            'Prcb': [0x0, ['pointer64', ['_KPRCB']]],
            'PerfContext': [0x8, ['unsigned long long']],
            'PercentageCap': [0x10, ['unsigned long']],
            'ThermalCap': [0x14, ['unsigned long']],
            'TargetFrequency': [0x18, ['unsigned long']],
            'AcumulatedFullFrequency': [0x1C, ['unsigned long']],
            'AcumulatedZeroFrequency': [0x20, ['unsigned long']],
            'FrequencyHistoryTotal': [0x24, ['unsigned long']],
            'AverageFrequency': [0x28, ['unsigned long']],
        },
    ],
    '_IMAGE_DATA_DIRECTORY': [
        0x8,
        {
            'VirtualAddress': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned long']],
        },
    ],
    '_DEVICE_CAPABILITIES': [
        0x40,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'DeviceD1': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DeviceD2': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'LockSupported': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'EjectSupported': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Removable': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'DockDevice': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'UniqueID': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SilentInstall': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'RawDeviceOK': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'SurpriseRemovalOK': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'WakeFromD0': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'WakeFromD1': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'WakeFromD2': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'WakeFromD3': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'HardwareDisabled': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'NonDynamic': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'WarmEjectSupported': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'NoDisplayInUI': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved1': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'Address': [0x8, ['unsigned long']],
            'UINumber': [0xC, ['unsigned long']],
            'DeviceState': [
                0x10,
                [
                    'array',
                    -28,
                    [
                        'Enumeration',
                        dict(
                            target='long',
                            choices={
                                0: 'PowerDeviceUnspecified',
                                1: 'PowerDeviceD0',
                                2: 'PowerDeviceD1',
                                3: 'PowerDeviceD2',
                                4: 'PowerDeviceD3',
                                5: 'PowerDeviceMaximum',
                            },
                        ),
                    ],
                ],
            ],
            'SystemWake': [
                0x2C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    ),
                ],
            ],
            'DeviceWake': [
                0x30,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PowerDeviceUnspecified',
                            1: 'PowerDeviceD0',
                            2: 'PowerDeviceD1',
                            3: 'PowerDeviceD2',
                            4: 'PowerDeviceD3',
                            5: 'PowerDeviceMaximum',
                        },
                    ),
                ],
            ],
            'D1Latency': [0x34, ['unsigned long']],
            'D2Latency': [0x38, ['unsigned long']],
            'D3Latency': [0x3C, ['unsigned long']],
        },
    ],
    '_CACHED_KSTACK_LIST': [
        0x20,
        {
            'SListHead': [0x0, ['_SLIST_HEADER']],
            'MinimumFree': [0x10, ['long']],
            'Misses': [0x14, ['unsigned long']],
            'MissesLast': [0x18, ['unsigned long']],
            'Pad0': [0x1C, ['unsigned long']],
        },
    ],
    '__unnamed_1ef7': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Alignment': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1efb': [
        0x18,
        {
            'MinimumVector': [0x0, ['unsigned long']],
            'MaximumVector': [0x4, ['unsigned long']],
            'AffinityPolicy': [0x8, ['unsigned short']],
            'Group': [0xA, ['unsigned short']],
            'PriorityPolicy': [
                0xC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IrqPriorityUndefined',
                            1: 'IrqPriorityLow',
                            2: 'IrqPriorityNormal',
                            3: 'IrqPriorityHigh',
                        },
                    ),
                ],
            ],
            'TargetedProcessors': [0x10, ['unsigned long long']],
        },
    ],
    '__unnamed_1efd': [
        0x8,
        {
            'MinimumChannel': [0x0, ['unsigned long']],
            'MaximumChannel': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1eff': [
        0xC,
        {
            'Data': [0x0, ['array', 3, ['unsigned long']]],
        },
    ],
    '__unnamed_1f01': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'MinBusNumber': [0x4, ['unsigned long']],
            'MaxBusNumber': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1f03': [
        0xC,
        {
            'Priority': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1f05': [
        0x18,
        {
            'Length40': [0x0, ['unsigned long']],
            'Alignment40': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1f07': [
        0x18,
        {
            'Length48': [0x0, ['unsigned long']],
            'Alignment48': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1f09': [
        0x18,
        {
            'Length64': [0x0, ['unsigned long']],
            'Alignment64': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1f0b': [
        0x18,
        {
            'Port': [0x0, ['__unnamed_1ef7']],
            'Memory': [0x0, ['__unnamed_1ef7']],
            'Interrupt': [0x0, ['__unnamed_1efb']],
            'Dma': [0x0, ['__unnamed_1efd']],
            'Generic': [0x0, ['__unnamed_1ef7']],
            'DevicePrivate': [0x0, ['__unnamed_1eff']],
            'BusNumber': [0x0, ['__unnamed_1f01']],
            'ConfigData': [0x0, ['__unnamed_1f03']],
            'Memory40': [0x0, ['__unnamed_1f05']],
            'Memory48': [0x0, ['__unnamed_1f07']],
            'Memory64': [0x0, ['__unnamed_1f09']],
        },
    ],
    '_IO_RESOURCE_DESCRIPTOR': [
        0x20,
        {
            'Option': [0x0, ['unsigned char']],
            'Type': [0x1, ['unsigned char']],
            'ShareDisposition': [0x2, ['unsigned char']],
            'Spare1': [0x3, ['unsigned char']],
            'Flags': [0x4, ['unsigned short']],
            'Spare2': [0x6, ['unsigned short']],
            'u': [0x8, ['__unnamed_1f0b']],
        },
    ],
    '_POP_THERMAL_ZONE': [
        0x1E8,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'State': [0x10, ['unsigned char']],
            'Flags': [0x11, ['unsigned char']],
            'Mode': [0x12, ['unsigned char']],
            'PendingMode': [0x13, ['unsigned char']],
            'ActivePoint': [0x14, ['unsigned char']],
            'PendingActivePoint': [0x15, ['unsigned char']],
            'Throttle': [0x18, ['long']],
            'LastTime': [0x20, ['unsigned long long']],
            'SampleRate': [0x28, ['unsigned long']],
            'LastTemp': [0x2C, ['unsigned long']],
            'PassiveTimer': [0x30, ['_KTIMER']],
            'PassiveDpc': [0x70, ['_KDPC']],
            'OverThrottled': [0xB0, ['_POP_ACTION_TRIGGER']],
            'Irp': [0xC8, ['pointer64', ['_IRP']]],
            'Info': [0xD0, ['_THERMAL_INFORMATION_EX']],
            'InfoLastUpdateTime': [0x148, ['_LARGE_INTEGER']],
            'Metrics': [0x150, ['_POP_THERMAL_ZONE_METRICS']],
        },
    ],
    '_MMPTE_LIST': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'OneEntry': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'filler0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Transition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'filler1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'NextEntry': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=32,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_VI_POOL_PAGE_HEADER': [
        0x18,
        {
            'NextPage': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
            'VerifierEntry': [0x8, ['pointer64', ['void']]],
            'Signature': [0x10, ['unsigned long long']],
        },
    ],
    '_HANDLE_TRACE_DEBUG_INFO': [
        0xF0,
        {
            'RefCount': [0x0, ['long']],
            'TableSize': [0x4, ['unsigned long']],
            'BitMaskFlags': [0x8, ['unsigned long']],
            'CloseCompactionLock': [0x10, ['_FAST_MUTEX']],
            'CurrentStackIndex': [0x48, ['unsigned long']],
            'TraceDb': [0x50, ['array', 1, ['_HANDLE_TRACE_DB_ENTRY']]],
        },
    ],
    '_CM_WORKITEM': [
        0x28,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Private': [0x10, ['unsigned long']],
            'WorkerRoutine': [0x18, ['pointer64', ['void']]],
            'Parameter': [0x20, ['pointer64', ['void']]],
        },
    ],
    '_POP_THERMAL_ZONE_METRICS': [
        0x98,
        {
            'MetricsResource': [0x0, ['_ERESOURCE']],
            'ActiveCount': [0x68, ['unsigned long']],
            'PassiveCount': [0x6C, ['unsigned long']],
            'LastActiveStartTick': [0x70, ['_LARGE_INTEGER']],
            'AverageActiveTime': [0x78, ['_LARGE_INTEGER']],
            'LastPassiveStartTick': [0x80, ['_LARGE_INTEGER']],
            'AveragePassiveTime': [0x88, ['_LARGE_INTEGER']],
            'StartTickSinceLastReset': [0x90, ['_LARGE_INTEGER']],
        },
    ],
    '_CM_TRANS': [
        0xA8,
        {
            'TransactionListEntry': [0x0, ['_LIST_ENTRY']],
            'KCBUoWListHead': [0x10, ['_LIST_ENTRY']],
            'LazyCommitListEntry': [0x20, ['_LIST_ENTRY']],
            'KtmTrans': [0x30, ['pointer64', ['void']]],
            'CmRm': [0x38, ['pointer64', ['_CM_RM']]],
            'KtmEnlistmentObject': [0x40, ['pointer64', ['_KENLISTMENT']]],
            'KtmEnlistmentHandle': [0x48, ['pointer64', ['void']]],
            'KtmUow': [0x50, ['_GUID']],
            'StartLsn': [0x60, ['unsigned long long']],
            'TransState': [0x68, ['unsigned long']],
            'HiveCount': [0x6C, ['unsigned long']],
            'HiveArray': [0x70, ['array', 7, ['pointer64', ['_CMHIVE']]]],
        },
    ],
    '_WHEA_ERROR_RECORD_HEADER_VALIDBITS': [
        0x4,
        {
            'PlatformId': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Timestamp': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'PartitionId': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_CM_PARTIAL_RESOURCE_LIST': [
        0x1C,
        {
            'Version': [0x0, ['unsigned short']],
            'Revision': [0x2, ['unsigned short']],
            'Count': [0x4, ['unsigned long']],
            'PartialDescriptors': [
                0x8,
                ['array', 1, ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
        },
    ],
    '_RTL_RANGE_LIST': [
        0x20,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Flags': [0x10, ['unsigned long']],
            'Count': [0x14, ['unsigned long']],
            'Stamp': [0x18, ['unsigned long']],
        },
    ],
    '_OBJECT_CREATE_INFORMATION': [
        0x40,
        {
            'Attributes': [0x0, ['unsigned long']],
            'RootDirectory': [0x8, ['pointer64', ['void']]],
            'ProbeMode': [0x10, ['unsigned char']],
            'PagedPoolCharge': [0x14, ['unsigned long']],
            'NonPagedPoolCharge': [0x18, ['unsigned long']],
            'SecurityDescriptorCharge': [0x1C, ['unsigned long']],
            'SecurityDescriptor': [0x20, ['pointer64', ['void']]],
            'SecurityQos': [
                0x28,
                ['pointer64', ['_SECURITY_QUALITY_OF_SERVICE']],
            ],
            'SecurityQualityOfService': [
                0x30,
                ['_SECURITY_QUALITY_OF_SERVICE'],
            ],
        },
    ],
    '_RTL_CRITICAL_SECTION_DEBUG': [
        0x30,
        {
            'Type': [0x0, ['unsigned short']],
            'CreatorBackTraceIndex': [0x2, ['unsigned short']],
            'CriticalSection': [0x8, ['pointer64', ['_RTL_CRITICAL_SECTION']]],
            'ProcessLocksList': [0x10, ['_LIST_ENTRY']],
            'EntryCount': [0x20, ['unsigned long']],
            'ContentionCount': [0x24, ['unsigned long']],
            'Flags': [0x28, ['unsigned long']],
            'CreatorBackTraceIndexHigh': [0x2C, ['unsigned short']],
            'SpareUSHORT': [0x2E, ['unsigned short']],
        },
    ],
    '_POOL_HACKER': [
        0x30,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'Contents': [0x10, ['array', 8, ['unsigned long']]],
        },
    ],
    '_DISALLOWED_GUIDS': [
        0x10,
        {
            'Count': [0x0, ['unsigned short']],
            'Guids': [0x8, ['pointer64', ['_GUID']]],
        },
    ],
    '_PO_DIAG_STACK_RECORD': [
        0x10,
        {
            'StackDepth': [0x0, ['unsigned long']],
            'Stack': [0x8, ['array', 1, ['pointer64', ['void']]]],
        },
    ],
    '_SECTION_OBJECT_POINTERS': [
        0x18,
        {
            'DataSectionObject': [0x0, ['pointer64', ['void']]],
            'SharedCacheMap': [0x8, ['pointer64', ['void']]],
            'ImageSectionObject': [0x10, ['pointer64', ['void']]],
        },
    ],
    '_SEP_AUDIT_POLICY': [
        0x1C,
        {
            'AdtTokenPolicy': [0x0, ['_TOKEN_AUDIT_POLICY']],
            'PolicySetStatus': [0x1B, ['unsigned char']],
        },
    ],
    '__unnamed_1f48': [
        0x4,
        {
            'SnapSharedExportsFailed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_1f4a': [
        0x18,
        {
            'AllSharedExportThunks': [
                0x0,
                ['_VF_TARGET_ALL_SHARED_EXPORT_THUNKS'],
            ],
            'Flags': [0x0, ['__unnamed_1f48']],
        },
    ],
    '_VF_TARGET_DRIVER': [
        0x30,
        {
            'TreeNode': [0x0, ['_VF_AVL_TREE_NODE']],
            'u1': [0x10, ['__unnamed_1f4a']],
            'VerifiedData': [
                0x28,
                ['pointer64', ['_VF_TARGET_VERIFIED_DRIVER_DATA']],
            ],
        },
    ],
    '__unnamed_1f52': [
        0x14,
        {
            'ClassGuid': [0x0, ['_GUID']],
            'SymbolicLinkName': [0x10, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f54': [
        0x2,
        {
            'DeviceIds': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f56': [
        0x2,
        {
            'DeviceId': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f58': [
        0x10,
        {
            'NotificationStructure': [0x0, ['pointer64', ['void']]],
            'DeviceIds': [0x8, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f5a': [
        0x8,
        {
            'Notification': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1f5c': [
        0x8,
        {
            'NotificationCode': [0x0, ['unsigned long']],
            'NotificationData': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1f5e': [
        0x8,
        {
            'VetoType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PNP_VetoTypeUnknown',
                            1: 'PNP_VetoLegacyDevice',
                            2: 'PNP_VetoPendingClose',
                            3: 'PNP_VetoWindowsApp',
                            4: 'PNP_VetoWindowsService',
                            5: 'PNP_VetoOutstandingOpen',
                            6: 'PNP_VetoDevice',
                            7: 'PNP_VetoDriver',
                            8: 'PNP_VetoIllegalDeviceRequest',
                            9: 'PNP_VetoInsufficientPower',
                            10: 'PNP_VetoNonDisableable',
                            11: 'PNP_VetoLegacyDriver',
                            12: 'PNP_VetoInsufficientRights',
                        },
                    ),
                ],
            ],
            'DeviceIdVetoNameBuffer': [0x4, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f60': [
        0x10,
        {
            'BlockedDriverGuid': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_1f62': [
        0x2,
        {
            'ParentId': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f64': [
        0x20,
        {
            'PowerSettingGuid': [0x0, ['_GUID']],
            'Flags': [0x10, ['unsigned long']],
            'SessionId': [0x14, ['unsigned long']],
            'DataLength': [0x18, ['unsigned long']],
            'Data': [0x1C, ['array', 1, ['unsigned char']]],
        },
    ],
    '__unnamed_1f66': [
        0x20,
        {
            'DeviceClass': [0x0, ['__unnamed_1f52']],
            'TargetDevice': [0x0, ['__unnamed_1f54']],
            'InstallDevice': [0x0, ['__unnamed_1f56']],
            'CustomNotification': [0x0, ['__unnamed_1f58']],
            'ProfileNotification': [0x0, ['__unnamed_1f5a']],
            'PowerNotification': [0x0, ['__unnamed_1f5c']],
            'VetoNotification': [0x0, ['__unnamed_1f5e']],
            'BlockedDriverNotification': [0x0, ['__unnamed_1f60']],
            'InvalidIDNotification': [0x0, ['__unnamed_1f62']],
            'PowerSettingNotification': [0x0, ['__unnamed_1f64']],
            'PropertyChangeNotification': [0x0, ['__unnamed_1f56']],
        },
    ],
    '_PLUGPLAY_EVENT_BLOCK': [
        0x50,
        {
            'EventGuid': [0x0, ['_GUID']],
            'EventCategory': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'HardwareProfileChangeEvent',
                            1: 'TargetDeviceChangeEvent',
                            2: 'DeviceClassChangeEvent',
                            3: 'CustomDeviceEvent',
                            4: 'DeviceInstallEvent',
                            5: 'DeviceArrivalEvent',
                            6: 'VetoEvent',
                            7: 'BlockedDriverEvent',
                            8: 'InvalidIDEvent',
                            9: 'DevicePropertyChangeEvent',
                            10: 'DeviceInstanceRemovalEvent',
                            11: 'MaxPlugEventCategory',
                        },
                    ),
                ],
            ],
            'Result': [0x18, ['pointer64', ['unsigned long']]],
            'Flags': [0x20, ['unsigned long']],
            'TotalSize': [0x24, ['unsigned long']],
            'DeviceObject': [0x28, ['pointer64', ['void']]],
            'u': [0x30, ['__unnamed_1f66']],
        },
    ],
    '_VF_SUSPECT_DRIVER_ENTRY': [
        0x28,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'Loads': [0x10, ['unsigned long']],
            'Unloads': [0x14, ['unsigned long']],
            'BaseName': [0x18, ['_UNICODE_STRING']],
        },
    ],
    '_MMPTE_TIMESTAMP': [
        0x8,
        {
            'MustBeZero': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFileLow': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=5,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
                        end_bit=11,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Transition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'GlobalTimeStamp': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=32,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_SID_AND_ATTRIBUTES_HASH': [
        0x110,
        {
            'SidCount': [0x0, ['unsigned long']],
            'SidAttr': [0x8, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'Hash': [0x10, ['array', 32, ['unsigned long long']]],
        },
    ],
    '_XSTATE_CONTEXT': [
        0x20,
        {
            'Mask': [0x0, ['unsigned long long']],
            'Length': [0x8, ['unsigned long']],
            'Reserved1': [0xC, ['unsigned long']],
            'Area': [0x10, ['pointer64', ['_XSAVE_AREA']]],
            'Buffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '_XSAVE_FORMAT': [
        0x200,
        {
            'ControlWord': [0x0, ['unsigned short']],
            'StatusWord': [0x2, ['unsigned short']],
            'TagWord': [0x4, ['unsigned char']],
            'Reserved1': [0x5, ['unsigned char']],
            'ErrorOpcode': [0x6, ['unsigned short']],
            'ErrorOffset': [0x8, ['unsigned long']],
            'ErrorSelector': [0xC, ['unsigned short']],
            'Reserved2': [0xE, ['unsigned short']],
            'DataOffset': [0x10, ['unsigned long']],
            'DataSelector': [0x14, ['unsigned short']],
            'Reserved3': [0x16, ['unsigned short']],
            'MxCsr': [0x18, ['unsigned long']],
            'MxCsr_Mask': [0x1C, ['unsigned long']],
            'FloatRegisters': [0x20, ['array', 8, ['_M128A']]],
            'XmmRegisters': [0xA0, ['array', 16, ['_M128A']]],
            'Reserved4': [0x1A0, ['array', 96, ['unsigned char']]],
        },
    ],
    '_MBCB': [
        0xC0,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeIsInZone': [0x2, ['short']],
            'PagesToWrite': [0x4, ['unsigned long']],
            'DirtyPages': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
            'BitmapRanges': [0x10, ['_LIST_ENTRY']],
            'ResumeWritePage': [0x20, ['long long']],
            'MostRecentlyDirtiedPage': [0x28, ['long long']],
            'BitmapRange1': [0x30, ['_BITMAP_RANGE']],
            'BitmapRange2': [0x60, ['_BITMAP_RANGE']],
            'BitmapRange3': [0x90, ['_BITMAP_RANGE']],
        },
    ],
    '_PS_CPU_QUOTA_BLOCK': [
        0x4080,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'SessionId': [0x10, ['unsigned long']],
            'CpuShareWeight': [0x14, ['unsigned long']],
            'CapturedWeightData': [
                0x18,
                ['_PSP_CPU_SHARE_CAPTURED_WEIGHT_DATA'],
            ],
            'DuplicateInputMarker': [
                0x20,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x20,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'MiscFlags': [0x20, ['long']],
            'BlockCurrentGenerationLock': [0x0, ['unsigned long long']],
            'CyclesAccumulated': [0x8, ['unsigned long long']],
            'CycleCredit': [0x40, ['unsigned long long']],
            'BlockCurrentGeneration': [0x48, ['unsigned long']],
            'CpuCyclePercent': [0x4C, ['unsigned long']],
            'CyclesFinishedForCurrentGeneration': [0x50, ['unsigned char']],
            'Cpu': [0x80, ['array', 256, ['_PS_PER_CPU_QUOTA_CACHE_AWARE']]],
        },
    ],
    '__unnamed_1f82': [
        0x1,
        {
            'AsUCHAR': [0x0, ['unsigned char']],
            'NoDomainAccounting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'IncreasePolicy': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'DecreasePolicy': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    'PROCESSOR_PERFSTATE_POLICY': [
        0x1C,
        {
            'Revision': [0x0, ['unsigned long']],
            'MaxThrottle': [0x4, ['unsigned char']],
            'MinThrottle': [0x5, ['unsigned char']],
            'BusyAdjThreshold': [0x6, ['unsigned char']],
            'Spare': [0x7, ['unsigned char']],
            'Flags': [0x7, ['__unnamed_1f82']],
            'TimeCheck': [0x8, ['unsigned long']],
            'IncreaseTime': [0xC, ['unsigned long']],
            'DecreaseTime': [0x10, ['unsigned long']],
            'IncreasePercent': [0x14, ['unsigned long']],
            'DecreasePercent': [0x18, ['unsigned long']],
        },
    ],
    '_BUS_EXTENSION_LIST': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['void']]],
            'BusExtension': [0x8, ['pointer64', ['_PI_BUS_EXTENSION']]],
        },
    ],
    '_CACHED_CHILD_LIST': [
        0x10,
        {
            'Count': [0x0, ['unsigned long']],
            'ValueList': [0x8, ['unsigned long long']],
            'RealKcb': [0x8, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
        },
    ],
    '_KDEVICE_QUEUE': [
        0x28,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'DeviceListHead': [0x8, ['_LIST_ENTRY']],
            'Lock': [0x18, ['unsigned long long']],
            'Busy': [0x20, ['unsigned char']],
            'Reserved': [
                0x20,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='long long'),
                ],
            ],
            'Hint': [
                0x20,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=64, native_type='long long'),
                ],
            ],
        },
    ],
    '_SYSTEM_POWER_STATE_CONTEXT': [
        0x4,
        {
            'Reserved1': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'TargetSystemState': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=12, native_type='unsigned long'),
                ],
            ],
            'EffectiveSystemState': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'CurrentSystemState': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'IgnoreHibernationPath': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'PseudoTransition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved2': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ContextAsUlong': [0x0, ['unsigned long']],
        },
    ],
    '_OBJECT_TYPE_INITIALIZER': [
        0x70,
        {
            'Length': [0x0, ['unsigned short']],
            'ObjectTypeFlags': [0x2, ['unsigned char']],
            'CaseInsensitive': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'UnnamedObjectsOnly': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'UseDefaultObject': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'SecurityRequired': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'MaintainHandleCount': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'MaintainTypeList': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'SupportsObjectCallbacks': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'CacheAligned': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'ObjectTypeCode': [0x4, ['unsigned long']],
            'InvalidAttributes': [0x8, ['unsigned long']],
            'GenericMapping': [0xC, ['_GENERIC_MAPPING']],
            'ValidAccessMask': [0x1C, ['unsigned long']],
            'RetainAccess': [0x20, ['unsigned long']],
            'PoolType': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPool',
                            1: 'PagedPool',
                            2: 'NonPagedPoolMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'DefaultPagedPoolCharge': [0x28, ['unsigned long']],
            'DefaultNonPagedPoolCharge': [0x2C, ['unsigned long']],
            'DumpProcedure': [0x30, ['pointer64', ['void']]],
            'OpenProcedure': [0x38, ['pointer64', ['void']]],
            'CloseProcedure': [0x40, ['pointer64', ['void']]],
            'DeleteProcedure': [0x48, ['pointer64', ['void']]],
            'ParseProcedure': [0x50, ['pointer64', ['void']]],
            'SecurityProcedure': [0x58, ['pointer64', ['void']]],
            'QueryNameProcedure': [0x60, ['pointer64', ['void']]],
            'OkayToCloseProcedure': [0x68, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1fb7': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'SubsectionFlags': [0x0, ['_MMSUBSECTION_FLAGS']],
        },
    ],
    '_SUBSECTION': [
        0x38,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'SubsectionBase': [0x8, ['pointer64', ['_MMPTE']]],
            'NextSubsection': [0x10, ['pointer64', ['_SUBSECTION']]],
            'PtesInSubsection': [0x18, ['unsigned long']],
            'UnusedPtes': [0x20, ['unsigned long']],
            'GlobalPerSessionHead': [0x20, ['pointer64', ['_MM_AVL_TABLE']]],
            'u': [0x28, ['__unnamed_1fb7']],
            'StartingSector': [0x2C, ['unsigned long']],
            'NumberOfFullSectors': [0x30, ['unsigned long']],
        },
    ],
    '_KPROCESSOR_STATE': [
        0x5B0,
        {
            'SpecialRegisters': [0x0, ['_KSPECIAL_REGISTERS']],
            'ContextFrame': [0xE0, ['_CONTEXT']],
        },
    ],
    '_IO_CLIENT_EXTENSION': [
        0x10,
        {
            'NextExtension': [0x0, ['pointer64', ['_IO_CLIENT_EXTENSION']]],
            'ClientIdentificationAddress': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_PS_PER_CPU_QUOTA_CACHE_AWARE': [
        0x40,
        {
            'SortedListEntry': [0x0, ['_LIST_ENTRY']],
            'IdleOnlyListHead': [0x10, ['_LIST_ENTRY']],
            'CycleBaseAllowance': [0x20, ['unsigned long long']],
            'CyclesRemaining': [0x28, ['long long']],
            'CurrentGeneration': [0x30, ['unsigned long']],
        },
    ],
    '_ETW_BUFFER_CONTEXT': [
        0x4,
        {
            'ProcessorNumber': [0x0, ['unsigned char']],
            'Alignment': [0x1, ['unsigned char']],
            'ProcessorIndex': [0x0, ['unsigned short']],
            'LoggerId': [0x2, ['unsigned short']],
        },
    ],
    '_PROC_IDLE_SNAP': [
        0x10,
        {
            'Time': [0x0, ['unsigned long long']],
            'Idle': [0x8, ['unsigned long long']],
        },
    ],
    '_KERNEL_STACK_SEGMENT': [
        0x28,
        {
            'StackBase': [0x0, ['unsigned long long']],
            'StackLimit': [0x8, ['unsigned long long']],
            'KernelStack': [0x10, ['unsigned long long']],
            'InitialStack': [0x18, ['unsigned long long']],
            'ActualLimit': [0x20, ['unsigned long long']],
        },
    ],
    '_KEXECUTE_OPTIONS': [
        0x1,
        {
            'ExecuteDisable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ExecuteEnable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'DisableThunkEmulation': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Permanent': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ExecuteDispatchEnable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'ImageDispatchEnable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'DisableExceptionChainValidation': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'ExecuteOptions': [0x0, ['unsigned char']],
        },
    ],
    '_SEP_TOKEN_PRIVILEGES': [
        0x18,
        {
            'Present': [0x0, ['unsigned long long']],
            'Enabled': [0x8, ['unsigned long long']],
            'EnabledByDefault': [0x10, ['unsigned long long']],
        },
    ],
    '_WORK_QUEUE_ITEM': [
        0x20,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'WorkerRoutine': [0x10, ['pointer64', ['void']]],
            'Parameter': [0x18, ['pointer64', ['void']]],
        },
    ],
    '_ARBITER_ALLOCATION_STATE': [
        0x50,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
            'CurrentMinimum': [0x10, ['unsigned long long']],
            'CurrentMaximum': [0x18, ['unsigned long long']],
            'Entry': [0x20, ['pointer64', ['_ARBITER_LIST_ENTRY']]],
            'CurrentAlternative': [
                0x28,
                ['pointer64', ['_ARBITER_ALTERNATIVE']],
            ],
            'AlternativeCount': [0x30, ['unsigned long']],
            'Alternatives': [0x38, ['pointer64', ['_ARBITER_ALTERNATIVE']]],
            'Flags': [0x40, ['unsigned short']],
            'RangeAttributes': [0x42, ['unsigned char']],
            'RangeAvailableAttributes': [0x43, ['unsigned char']],
            'WorkSpace': [0x48, ['unsigned long long']],
        },
    ],
    '_VACB_ARRAY_HEADER': [
        0x10,
        {
            'VacbArrayIndex': [0x0, ['unsigned long']],
            'MappingCount': [0x4, ['unsigned long']],
            'HighestMappedIndex': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '_MMWSLENTRY': [
        0x8,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=1,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=1,
                        end_bit=2,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Hashed': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=2,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Direct': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=4,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4,
                        end_bit=9,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Age': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=12,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'VirtualPageNumber': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_DBGKD_SWITCH_PARTITION': [
        0x4,
        {
            'Partition': [0x0, ['unsigned long']],
        },
    ],
    '_REQUEST_MAILBOX': [
        0x40,
        {
            'Next': [0x0, ['pointer64', ['_REQUEST_MAILBOX']]],
            'RequestSummary': [0x8, ['long long']],
            'RequestPacket': [0x10, ['_KREQUEST_PACKET']],
        },
    ],
    '_DBGKD_GET_VERSION32': [
        0x28,
        {
            'MajorVersion': [0x0, ['unsigned short']],
            'MinorVersion': [0x2, ['unsigned short']],
            'ProtocolVersion': [0x4, ['unsigned short']],
            'Flags': [0x6, ['unsigned short']],
            'KernBase': [0x8, ['unsigned long']],
            'PsLoadedModuleList': [0xC, ['unsigned long']],
            'MachineType': [0x10, ['unsigned short']],
            'ThCallbackStack': [0x12, ['unsigned short']],
            'NextCallback': [0x14, ['unsigned short']],
            'FramePointer': [0x16, ['unsigned short']],
            'KiCallUserMode': [0x18, ['unsigned long']],
            'KeUserCallbackDispatcher': [0x1C, ['unsigned long']],
            'BreakpointWithStatus': [0x20, ['unsigned long']],
            'DebuggerDataList': [0x24, ['unsigned long']],
        },
    ],
    '_INTERLOCK_SEQ': [
        0x8,
        {
            'Depth': [0x0, ['unsigned short']],
            'FreeEntryOffset': [0x2, ['unsigned short']],
            'OffsetAndDepth': [0x0, ['unsigned long']],
            'Sequence': [0x4, ['unsigned long']],
            'Exchg': [0x0, ['long long']],
        },
    ],
    '_WHEA_TIMESTAMP': [
        0x8,
        {
            'Seconds': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=8,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Minutes': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Hours': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=24,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Precise': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24,
                        end_bit=25,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=25,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Day': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=32,
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Month': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
                        end_bit=48,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Year': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=48,
                        end_bit=56,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Century': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=56,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'AsLARGE_INTEGER': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '_PEB32': [
        0x248,
        {
            'InheritedAddressSpace': [0x0, ['unsigned char']],
            'ReadImageFileExecOptions': [0x1, ['unsigned char']],
            'BeingDebugged': [0x2, ['unsigned char']],
            'BitField': [0x3, ['unsigned char']],
            'ImageUsesLargePages': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'IsProtectedProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'IsLegacyProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'IsImageDynamicallyRelocated': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'SkipPatchingUser32Forwarders': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Mutant': [0x4, ['unsigned long']],
            'ImageBaseAddress': [0x8, ['unsigned long']],
            'Ldr': [0xC, ['unsigned long']],
            'ProcessParameters': [0x10, ['unsigned long']],
            'SubSystemData': [0x14, ['unsigned long']],
            'ProcessHeap': [0x18, ['unsigned long']],
            'FastPebLock': [0x1C, ['unsigned long']],
            'AtlThunkSListPtr': [0x20, ['unsigned long']],
            'IFEOKey': [0x24, ['unsigned long']],
            'CrossProcessFlags': [0x28, ['unsigned long']],
            'ProcessInJob': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ProcessInitializing': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingVEH': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingVCH': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ProcessUsingFTH': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ReservedBits0': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'KernelCallbackTable': [0x2C, ['unsigned long']],
            'UserSharedInfoPtr': [0x2C, ['unsigned long']],
            'SystemReserved': [0x30, ['array', 1, ['unsigned long']]],
            'AtlThunkSListPtr32': [0x34, ['unsigned long']],
            'ApiSetMap': [0x38, ['unsigned long']],
            'TlsExpansionCounter': [0x3C, ['unsigned long']],
            'TlsBitmap': [0x40, ['unsigned long']],
            'TlsBitmapBits': [0x44, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x4C, ['unsigned long']],
            'HotpatchInformation': [0x50, ['unsigned long']],
            'ReadOnlyStaticServerData': [0x54, ['unsigned long']],
            'AnsiCodePageData': [0x58, ['unsigned long']],
            'OemCodePageData': [0x5C, ['unsigned long']],
            'UnicodeCaseTableData': [0x60, ['unsigned long']],
            'NumberOfProcessors': [0x64, ['unsigned long']],
            'NtGlobalFlag': [0x68, ['unsigned long']],
            'CriticalSectionTimeout': [0x70, ['_LARGE_INTEGER']],
            'HeapSegmentReserve': [0x78, ['unsigned long']],
            'HeapSegmentCommit': [0x7C, ['unsigned long']],
            'HeapDeCommitTotalFreeThreshold': [0x80, ['unsigned long']],
            'HeapDeCommitFreeBlockThreshold': [0x84, ['unsigned long']],
            'NumberOfHeaps': [0x88, ['unsigned long']],
            'MaximumNumberOfHeaps': [0x8C, ['unsigned long']],
            'ProcessHeaps': [0x90, ['unsigned long']],
            'GdiSharedHandleTable': [0x94, ['unsigned long']],
            'ProcessStarterHelper': [0x98, ['unsigned long']],
            'GdiDCAttributeList': [0x9C, ['unsigned long']],
            'LoaderLock': [0xA0, ['unsigned long']],
            'OSMajorVersion': [0xA4, ['unsigned long']],
            'OSMinorVersion': [0xA8, ['unsigned long']],
            'OSBuildNumber': [0xAC, ['unsigned short']],
            'OSCSDVersion': [0xAE, ['unsigned short']],
            'OSPlatformId': [0xB0, ['unsigned long']],
            'ImageSubsystem': [0xB4, ['unsigned long']],
            'ImageSubsystemMajorVersion': [0xB8, ['unsigned long']],
            'ImageSubsystemMinorVersion': [0xBC, ['unsigned long']],
            'ActiveProcessAffinityMask': [0xC0, ['unsigned long']],
            'GdiHandleBuffer': [0xC4, ['array', 34, ['unsigned long']]],
            'PostProcessInitRoutine': [0x14C, ['unsigned long']],
            'TlsExpansionBitmap': [0x150, ['unsigned long']],
            'TlsExpansionBitmapBits': [
                0x154,
                ['array', 32, ['unsigned long']],
            ],
            'SessionId': [0x1D4, ['unsigned long']],
            'AppCompatFlags': [0x1D8, ['_ULARGE_INTEGER']],
            'AppCompatFlagsUser': [0x1E0, ['_ULARGE_INTEGER']],
            'pShimData': [0x1E8, ['unsigned long']],
            'AppCompatInfo': [0x1EC, ['unsigned long']],
            'CSDVersion': [0x1F0, ['_STRING32']],
            'ActivationContextData': [0x1F8, ['unsigned long']],
            'ProcessAssemblyStorageMap': [0x1FC, ['unsigned long']],
            'SystemDefaultActivationContextData': [0x200, ['unsigned long']],
            'SystemAssemblyStorageMap': [0x204, ['unsigned long']],
            'MinimumStackCommit': [0x208, ['unsigned long']],
            'FlsCallback': [0x20C, ['unsigned long']],
            'FlsListHead': [0x210, ['LIST_ENTRY32']],
            'FlsBitmap': [0x218, ['unsigned long']],
            'FlsBitmapBits': [0x21C, ['array', 4, ['unsigned long']]],
            'FlsHighIndex': [0x22C, ['unsigned long']],
            'WerRegistrationData': [0x230, ['unsigned long']],
            'WerShipAssertPtr': [0x234, ['unsigned long']],
            'pContextData': [0x238, ['unsigned long']],
            'pImageHeaderHash': [0x23C, ['unsigned long']],
            'TracingFlags': [0x240, ['unsigned long']],
            'HeapTracingEnabled': [
                0x240,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'CritSecTracingEnabled': [
                0x240,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SpareTracingBits': [
                0x240,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_VPB': [
        0x60,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'Flags': [0x4, ['unsigned short']],
            'VolumeLabelLength': [0x6, ['unsigned short']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'RealDevice': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'SerialNumber': [0x18, ['unsigned long']],
            'ReferenceCount': [0x1C, ['unsigned long']],
            'VolumeLabel': [0x20, ['array', 32, ['wchar']]],
        },
    ],
    '_CACHE_DESCRIPTOR': [
        0xC,
        {
            'Level': [0x0, ['unsigned char']],
            'Associativity': [0x1, ['unsigned char']],
            'LineSize': [0x2, ['unsigned short']],
            'Size': [0x4, ['unsigned long']],
            'Type': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'CacheUnified',
                            1: 'CacheInstruction',
                            2: 'CacheData',
                            3: 'CacheTrace',
                        },
                    ),
                ],
            ],
        },
    ],
}
