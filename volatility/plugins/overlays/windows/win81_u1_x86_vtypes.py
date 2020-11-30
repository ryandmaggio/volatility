ntkrpamp_types = {
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
            'AitSamplingValue': [0x248, ['unsigned long']],
            'AppCompatFlag': [0x24C, ['unsigned long']],
            'RNGSeedVersion': [0x250, ['unsigned long long']],
            'GlobalValidationRunlevel': [0x258, ['unsigned long']],
            'TimeZoneBiasStamp': [0x25C, ['long']],
            'Reserved2': [0x260, ['unsigned long']],
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
            'Reserved0': [0x269, ['array', 1, ['unsigned char']]],
            'NativeProcessorArchitecture': [0x26A, ['unsigned short']],
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
            'MitigationPolicies': [0x2D5, ['unsigned char']],
            'NXSupportPolicy': [
                0x2D5,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'SEHValidationPolicy': [
                0x2D5,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'CurDirDevicesSkippedForDlls': [
                0x2D5,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x2D5,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Reserved6': [0x2D6, ['array', 2, ['unsigned char']]],
            'ActiveConsoleId': [0x2D8, ['unsigned long']],
            'DismountCount': [0x2DC, ['unsigned long']],
            'ComPlusPackage': [0x2E0, ['unsigned long']],
            'LastSystemRITEventTickCount': [0x2E4, ['unsigned long']],
            'NumberOfPhysicalPages': [0x2E8, ['unsigned long']],
            'SafeBootMode': [0x2EC, ['unsigned char']],
            'Reserved12': [0x2ED, ['array', 3, ['unsigned char']]],
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
            'DbgLkgEnabled': [
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
            'DbgConsoleBrokerEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'DbgSecureBootEnabled': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SpareBits': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'DataFlagsPad': [0x2F4, ['array', 1, ['unsigned long']]],
            'TestRetInstruction': [0x2F8, ['unsigned long long']],
            'QpcFrequency': [0x300, ['long long']],
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
            'TimeUpdateLock': [0x340, ['unsigned long long']],
            'BaselineSystemTimeQpc': [0x348, ['unsigned long long']],
            'BaselineInterruptTimeQpc': [0x350, ['unsigned long long']],
            'QpcSystemTimeIncrement': [0x358, ['unsigned long long']],
            'QpcInterruptTimeIncrement': [0x360, ['unsigned long long']],
            'QpcSystemTimeIncrement32': [0x368, ['unsigned long']],
            'QpcInterruptTimeIncrement32': [0x36C, ['unsigned long']],
            'QpcSystemTimeIncrementShift': [0x370, ['unsigned char']],
            'QpcInterruptTimeIncrementShift': [0x371, ['unsigned char']],
            'UnparkedProcessorCount': [0x372, ['unsigned short']],
            'Reserved8': [0x374, ['array', 12, ['unsigned char']]],
            'UserModeGlobalLogger': [0x380, ['array', 16, ['unsigned short']]],
            'ImageFileExecutionOptions': [0x3A0, ['unsigned long']],
            'LangGenerationCount': [0x3A4, ['unsigned long']],
            'Reserved4': [0x3A8, ['unsigned long long']],
            'InterruptTimeBias': [0x3B0, ['unsigned long long']],
            'QpcBias': [0x3B8, ['unsigned long long']],
            'ActiveProcessorCount': [0x3C0, ['unsigned long']],
            'ActiveGroupCount': [0x3C4, ['unsigned char']],
            'Reserved9': [0x3C5, ['unsigned char']],
            'QpcData': [0x3C6, ['unsigned short']],
            'QpcBypassEnabled': [0x3C6, ['unsigned char']],
            'QpcShift': [0x3C7, ['unsigned char']],
            'TimeZoneBiasEffectiveStart': [0x3C8, ['_LARGE_INTEGER']],
            'TimeZoneBiasEffectiveEnd': [0x3D0, ['_LARGE_INTEGER']],
            'XState': [0x3D8, ['_XSTATE_CONFIGURATION']],
        },
    ],
    '__unnamed_107c': [
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
            'u': [0x0, ['__unnamed_107c']],
            'QuadPart': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_1080': [
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
            'u': [0x0, ['__unnamed_1080']],
            'QuadPart': [0x0, ['long long']],
        },
    ],
    '__unnamed_109b': [
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
    '__unnamed_109d': [
        0x4,
        {
            'Flags': [0x0, ['unsigned long']],
            's': [0x0, ['__unnamed_109b']],
        },
    ],
    '_TP_CALLBACK_ENVIRON_V3': [
        0x28,
        {
            'Version': [0x0, ['unsigned long']],
            'Pool': [0x4, ['pointer', ['_TP_POOL']]],
            'CleanupGroup': [0x8, ['pointer', ['_TP_CLEANUP_GROUP']]],
            'CleanupGroupCancelCallback': [0xC, ['pointer', ['void']]],
            'RaceDll': [0x10, ['pointer', ['void']]],
            'ActivationContext': [0x14, ['pointer', ['_ACTIVATION_CONTEXT']]],
            'FinalizationCallback': [0x18, ['pointer', ['void']]],
            'u': [0x1C, ['__unnamed_109d']],
            'CallbackPriority': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'TP_CALLBACK_PRIORITY_HIGH',
                            1: 'TP_CALLBACK_PRIORITY_NORMAL',
                            2: 'TP_CALLBACK_PRIORITY_LOW',
                            3: 'TP_CALLBACK_PRIORITY_COUNT',
                        },
                    ),
                ],
            ],
            'Size': [0x24, ['unsigned long']],
        },
    ],
    '_TEB': [
        0xFE8,
        {
            'NtTib': [0x0, ['_NT_TIB']],
            'EnvironmentPointer': [0x1C, ['pointer', ['void']]],
            'ClientId': [0x20, ['_CLIENT_ID']],
            'ActiveRpcHandle': [0x28, ['pointer', ['void']]],
            'ThreadLocalStoragePointer': [0x2C, ['pointer', ['void']]],
            'ProcessEnvironmentBlock': [0x30, ['pointer', ['_PEB']]],
            'LastErrorValue': [0x34, ['unsigned long']],
            'CountOfOwnedCriticalSections': [0x38, ['unsigned long']],
            'CsrClientThread': [0x3C, ['pointer', ['void']]],
            'Win32ThreadInfo': [0x40, ['pointer', ['void']]],
            'User32Reserved': [0x44, ['array', 26, ['unsigned long']]],
            'UserReserved': [0xAC, ['array', 5, ['unsigned long']]],
            'WOW32Reserved': [0xC0, ['pointer', ['void']]],
            'CurrentLocale': [0xC4, ['unsigned long']],
            'FpSoftwareStatusRegister': [0xC8, ['unsigned long']],
            'SystemReserved1': [0xCC, ['array', 54, ['pointer', ['void']]]],
            'ExceptionCode': [0x1A4, ['long']],
            'ActivationContextStackPointer': [
                0x1A8,
                ['pointer', ['_ACTIVATION_CONTEXT_STACK']],
            ],
            'SpareBytes': [0x1AC, ['array', 36, ['unsigned char']]],
            'TxFsContext': [0x1D0, ['unsigned long']],
            'GdiTebBatch': [0x1D4, ['_GDI_TEB_BATCH']],
            'RealClientId': [0x6B4, ['_CLIENT_ID']],
            'GdiCachedProcessHandle': [0x6BC, ['pointer', ['void']]],
            'GdiClientPID': [0x6C0, ['unsigned long']],
            'GdiClientTID': [0x6C4, ['unsigned long']],
            'GdiThreadLocalInfo': [0x6C8, ['pointer', ['void']]],
            'Win32ClientInfo': [0x6CC, ['array', 62, ['unsigned long']]],
            'glDispatchTable': [0x7C4, ['array', 233, ['pointer', ['void']]]],
            'glReserved1': [0xB68, ['array', 29, ['unsigned long']]],
            'glReserved2': [0xBDC, ['pointer', ['void']]],
            'glSectionInfo': [0xBE0, ['pointer', ['void']]],
            'glSection': [0xBE4, ['pointer', ['void']]],
            'glTable': [0xBE8, ['pointer', ['void']]],
            'glCurrentRC': [0xBEC, ['pointer', ['void']]],
            'glContext': [0xBF0, ['pointer', ['void']]],
            'LastStatusValue': [0xBF4, ['unsigned long']],
            'StaticUnicodeString': [0xBF8, ['_UNICODE_STRING']],
            'StaticUnicodeBuffer': [0xC00, ['array', 261, ['wchar']]],
            'DeallocationStack': [0xE0C, ['pointer', ['void']]],
            'TlsSlots': [0xE10, ['array', 64, ['pointer', ['void']]]],
            'TlsLinks': [0xF10, ['_LIST_ENTRY']],
            'Vdm': [0xF18, ['pointer', ['void']]],
            'ReservedForNtRpc': [0xF1C, ['pointer', ['void']]],
            'DbgSsReserved': [0xF20, ['array', 2, ['pointer', ['void']]]],
            'HardErrorMode': [0xF28, ['unsigned long']],
            'Instrumentation': [0xF2C, ['array', 9, ['pointer', ['void']]]],
            'ActivityId': [0xF50, ['_GUID']],
            'SubProcessTag': [0xF60, ['pointer', ['void']]],
            'PerflibData': [0xF64, ['pointer', ['void']]],
            'EtwTraceData': [0xF68, ['pointer', ['void']]],
            'WinSockData': [0xF6C, ['pointer', ['void']]],
            'GdiBatchCount': [0xF70, ['unsigned long']],
            'CurrentIdealProcessor': [0xF74, ['_PROCESSOR_NUMBER']],
            'IdealProcessorValue': [0xF74, ['unsigned long']],
            'ReservedPad0': [0xF74, ['unsigned char']],
            'ReservedPad1': [0xF75, ['unsigned char']],
            'ReservedPad2': [0xF76, ['unsigned char']],
            'IdealProcessor': [0xF77, ['unsigned char']],
            'GuaranteedStackBytes': [0xF78, ['unsigned long']],
            'ReservedForPerf': [0xF7C, ['pointer', ['void']]],
            'ReservedForOle': [0xF80, ['pointer', ['void']]],
            'WaitingOnLoaderLock': [0xF84, ['unsigned long']],
            'SavedPriorityState': [0xF88, ['pointer', ['void']]],
            'ReservedForCodeCoverage': [0xF8C, ['unsigned long']],
            'ThreadPoolData': [0xF90, ['pointer', ['void']]],
            'TlsExpansionSlots': [0xF94, ['pointer', ['pointer', ['void']]]],
            'MuiGeneration': [0xF98, ['unsigned long']],
            'IsImpersonating': [0xF9C, ['unsigned long']],
            'NlsCache': [0xFA0, ['pointer', ['void']]],
            'pShimData': [0xFA4, ['pointer', ['void']]],
            'HeapVirtualAffinity': [0xFA8, ['unsigned short']],
            'LowFragHeapDataSlot': [0xFAA, ['unsigned short']],
            'CurrentTransactionHandle': [0xFAC, ['pointer', ['void']]],
            'ActiveFrame': [0xFB0, ['pointer', ['_TEB_ACTIVE_FRAME']]],
            'FlsData': [0xFB4, ['pointer', ['void']]],
            'PreferredLanguages': [0xFB8, ['pointer', ['void']]],
            'UserPrefLanguages': [0xFBC, ['pointer', ['void']]],
            'MergedPrefLanguages': [0xFC0, ['pointer', ['void']]],
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
            'SessionAware': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned short'
                    ),
                ],
            ],
            'SpareSameTebBits': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0xFCC, ['pointer', ['void']]],
            'TxnScopeExitCallback': [0xFD0, ['pointer', ['void']]],
            'TxnScopeContext': [0xFD4, ['pointer', ['void']]],
            'LockCount': [0xFD8, ['unsigned long']],
            'SpareUlong0': [0xFDC, ['unsigned long']],
            'ResourceRetValue': [0xFE0, ['pointer', ['void']]],
            'ReservedForWdf': [0xFE4, ['pointer', ['void']]],
        },
    ],
    '_LIST_ENTRY': [
        0x8,
        {
            'Flink': [0x0, ['pointer', ['_LIST_ENTRY']]],
            'Blink': [0x4, ['pointer', ['_LIST_ENTRY']]],
        },
    ],
    '_SINGLE_LIST_ENTRY': [
        0x4,
        {
            'Next': [0x0, ['pointer', ['_SINGLE_LIST_ENTRY']]],
        },
    ],
    '_RTL_SPLAY_LINKS': [
        0xC,
        {
            'Parent': [0x0, ['pointer', ['_RTL_SPLAY_LINKS']]],
            'LeftChild': [0x4, ['pointer', ['_RTL_SPLAY_LINKS']]],
            'RightChild': [0x8, ['pointer', ['_RTL_SPLAY_LINKS']]],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE_CONTEXT': [
        0xC,
        {
            'ChainHead': [0x0, ['pointer', ['_LIST_ENTRY']]],
            'PrevLinkage': [0x4, ['pointer', ['_LIST_ENTRY']]],
            'Signature': [0x8, ['unsigned long']],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE_ENUMERATOR': [
        0x14,
        {
            'HashEntry': [0x0, ['_RTL_DYNAMIC_HASH_TABLE_ENTRY']],
            'ChainHead': [0xC, ['pointer', ['_LIST_ENTRY']]],
            'BucketIndex': [0x10, ['unsigned long']],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE': [
        0x24,
        {
            'Flags': [0x0, ['unsigned long']],
            'Shift': [0x4, ['unsigned long']],
            'TableSize': [0x8, ['unsigned long']],
            'Pivot': [0xC, ['unsigned long']],
            'DivisorMask': [0x10, ['unsigned long']],
            'NumEntries': [0x14, ['unsigned long']],
            'NonEmptyBuckets': [0x18, ['unsigned long']],
            'NumEnumerators': [0x1C, ['unsigned long']],
            'Directory': [0x20, ['pointer', ['void']]],
        },
    ],
    '_UNICODE_STRING': [
        0x8,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x4, ['pointer', ['unsigned short']]],
        },
    ],
    '_STRING': [
        0x8,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x4, ['pointer', ['unsigned char']]],
        },
    ],
    '_LUID': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['long']],
        },
    ],
    '_IMAGE_NT_HEADERS': [
        0xF8,
        {
            'Signature': [0x0, ['unsigned long']],
            'FileHeader': [0x4, ['_IMAGE_FILE_HEADER']],
            'OptionalHeader': [0x18, ['_IMAGE_OPTIONAL_HEADER']],
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
    '_RTL_BALANCED_NODE': [
        0xC,
        {
            'Children': [
                0x0,
                ['array', 2, ['pointer', ['_RTL_BALANCED_NODE']]],
            ],
            'Left': [0x0, ['pointer', ['_RTL_BALANCED_NODE']]],
            'Right': [0x4, ['pointer', ['_RTL_BALANCED_NODE']]],
            'Red': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Balance': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'ParentValue': [0x8, ['unsigned long']],
        },
    ],
    '_RTL_RB_TREE': [
        0x8,
        {
            'Root': [0x0, ['pointer', ['_RTL_BALANCED_NODE']]],
            'Min': [0x4, ['pointer', ['_RTL_BALANCED_NODE']]],
        },
    ],
    '_RTL_AVL_TREE': [
        0x4,
        {
            'Root': [0x0, ['pointer', ['_RTL_BALANCED_NODE']]],
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
    '_KPCR': [
        0x47D8,
        {
            'NtTib': [0x0, ['_NT_TIB']],
            'Used_ExceptionList': [
                0x0,
                ['pointer', ['_EXCEPTION_REGISTRATION_RECORD']],
            ],
            'Used_StackBase': [0x4, ['pointer', ['void']]],
            'MxCsr': [0x8, ['unsigned long']],
            'TssCopy': [0xC, ['pointer', ['void']]],
            'ContextSwitches': [0x10, ['unsigned long']],
            'SetMemberCopy': [0x14, ['unsigned long']],
            'Used_Self': [0x18, ['pointer', ['void']]],
            'SelfPcr': [0x1C, ['pointer', ['_KPCR']]],
            'Prcb': [0x20, ['pointer', ['_KPRCB']]],
            'Irql': [0x24, ['unsigned char']],
            'IRR': [0x28, ['unsigned long']],
            'IrrActive': [0x2C, ['unsigned long']],
            'IDR': [0x30, ['unsigned long']],
            'KdVersionBlock': [0x34, ['pointer', ['void']]],
            'IDT': [0x38, ['pointer', ['_KIDTENTRY']]],
            'GDT': [0x3C, ['pointer', ['_KGDTENTRY']]],
            'TSS': [0x40, ['pointer', ['_KTSS']]],
            'MajorVersion': [0x44, ['unsigned short']],
            'MinorVersion': [0x46, ['unsigned short']],
            'SetMember': [0x48, ['unsigned long']],
            'StallScaleFactor': [0x4C, ['unsigned long']],
            'SpareUnused': [0x50, ['unsigned char']],
            'Number': [0x51, ['unsigned char']],
            'Spare0': [0x52, ['unsigned char']],
            'SecondLevelCacheAssociativity': [0x53, ['unsigned char']],
            'VdmAlert': [0x54, ['unsigned long']],
            'KernelReserved': [0x58, ['array', 14, ['unsigned long']]],
            'SecondLevelCacheSize': [0x90, ['unsigned long']],
            'HalReserved': [0x94, ['array', 16, ['unsigned long']]],
            'InterruptMode': [0xD4, ['unsigned long']],
            'Spare1': [0xD8, ['unsigned char']],
            'KernelReserved2': [0xDC, ['array', 17, ['unsigned long']]],
            'PrcbData': [0x120, ['_KPRCB']],
        },
    ],
    '_KPRCB': [
        0x46B8,
        {
            'MinorVersion': [0x0, ['unsigned short']],
            'MajorVersion': [0x2, ['unsigned short']],
            'CurrentThread': [0x4, ['pointer', ['_KTHREAD']]],
            'NextThread': [0x8, ['pointer', ['_KTHREAD']]],
            'IdleThread': [0xC, ['pointer', ['_KTHREAD']]],
            'LegacyNumber': [0x10, ['unsigned char']],
            'NestingLevel': [0x11, ['unsigned char']],
            'BuildType': [0x12, ['unsigned short']],
            'CpuType': [0x14, ['unsigned char']],
            'CpuID': [0x15, ['unsigned char']],
            'CpuStep': [0x16, ['unsigned short']],
            'CpuStepping': [0x16, ['unsigned char']],
            'CpuModel': [0x17, ['unsigned char']],
            'ProcessorState': [0x18, ['_KPROCESSOR_STATE']],
            'ParentNode': [0x338, ['pointer', ['_KNODE']]],
            'PriorityState': [0x33C, ['pointer', ['unsigned char']]],
            'KernelReserved': [0x340, ['array', 14, ['unsigned long']]],
            'HalReserved': [0x378, ['array', 16, ['unsigned long']]],
            'CFlushSize': [0x3B8, ['unsigned long']],
            'CoresPerPhysicalProcessor': [0x3BC, ['unsigned char']],
            'LogicalProcessorsPerCore': [0x3BD, ['unsigned char']],
            'CpuVendor': [0x3BE, ['unsigned char']],
            'PrcbPad0': [0x3BF, ['array', 1, ['unsigned char']]],
            'MHz': [0x3C0, ['unsigned long']],
            'GroupIndex': [0x3C4, ['unsigned char']],
            'Group': [0x3C5, ['unsigned char']],
            'PrcbPad05': [0x3C6, ['array', 2, ['unsigned char']]],
            'GroupSetMember': [0x3C8, ['unsigned long']],
            'Number': [0x3CC, ['unsigned long']],
            'ClockOwner': [0x3D0, ['unsigned char']],
            'PendingTickFlags': [0x3D1, ['unsigned char']],
            'PendingTick': [
                0x3D1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'PendingBackupTick': [
                0x3D1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'PrcbPad10': [0x3D2, ['array', 70, ['unsigned char']]],
            'LockQueue': [0x418, ['array', 17, ['_KSPIN_LOCK_QUEUE']]],
            'InterruptCount': [0x4A0, ['unsigned long']],
            'KernelTime': [0x4A4, ['unsigned long']],
            'UserTime': [0x4A8, ['unsigned long']],
            'DpcTime': [0x4AC, ['unsigned long']],
            'DpcTimeCount': [0x4B0, ['unsigned long']],
            'InterruptTime': [0x4B4, ['unsigned long']],
            'AdjustDpcThreshold': [0x4B8, ['unsigned long']],
            'PageColor': [0x4BC, ['unsigned long']],
            'DebuggerSavedIRQL': [0x4C0, ['unsigned char']],
            'NodeColor': [0x4C1, ['unsigned char']],
            'PrcbPad20': [0x4C2, ['array', 6, ['unsigned char']]],
            'NodeShiftedColor': [0x4C8, ['unsigned long']],
            'SecondaryColorMask': [0x4CC, ['unsigned long']],
            'DpcTimeLimit': [0x4D0, ['unsigned long']],
            'PrcbPad21': [0x4D4, ['array', 3, ['unsigned long']]],
            'CcFastReadNoWait': [0x4E0, ['unsigned long']],
            'CcFastReadWait': [0x4E4, ['unsigned long']],
            'CcFastReadNotPossible': [0x4E8, ['unsigned long']],
            'CcCopyReadNoWait': [0x4EC, ['unsigned long']],
            'CcCopyReadWait': [0x4F0, ['unsigned long']],
            'CcCopyReadNoWaitMiss': [0x4F4, ['unsigned long']],
            'MmSpinLockOrdering': [0x4F8, ['long']],
            'IoReadOperationCount': [0x4FC, ['long']],
            'IoWriteOperationCount': [0x500, ['long']],
            'IoOtherOperationCount': [0x504, ['long']],
            'IoReadTransferCount': [0x508, ['_LARGE_INTEGER']],
            'IoWriteTransferCount': [0x510, ['_LARGE_INTEGER']],
            'IoOtherTransferCount': [0x518, ['_LARGE_INTEGER']],
            'CcFastMdlReadNoWait': [0x520, ['unsigned long']],
            'CcFastMdlReadWait': [0x524, ['unsigned long']],
            'CcFastMdlReadNotPossible': [0x528, ['unsigned long']],
            'CcMapDataNoWait': [0x52C, ['unsigned long']],
            'CcMapDataWait': [0x530, ['unsigned long']],
            'CcPinMappedDataCount': [0x534, ['unsigned long']],
            'CcPinReadNoWait': [0x538, ['unsigned long']],
            'CcPinReadWait': [0x53C, ['unsigned long']],
            'CcMdlReadNoWait': [0x540, ['unsigned long']],
            'CcMdlReadWait': [0x544, ['unsigned long']],
            'CcLazyWriteHotSpots': [0x548, ['unsigned long']],
            'CcLazyWriteIos': [0x54C, ['unsigned long']],
            'CcLazyWritePages': [0x550, ['unsigned long']],
            'CcDataFlushes': [0x554, ['unsigned long']],
            'CcDataPages': [0x558, ['unsigned long']],
            'CcLostDelayedWrites': [0x55C, ['unsigned long']],
            'CcFastReadResourceMiss': [0x560, ['unsigned long']],
            'CcCopyReadWaitMiss': [0x564, ['unsigned long']],
            'CcFastMdlReadResourceMiss': [0x568, ['unsigned long']],
            'CcMapDataNoWaitMiss': [0x56C, ['unsigned long']],
            'CcMapDataWaitMiss': [0x570, ['unsigned long']],
            'CcPinReadNoWaitMiss': [0x574, ['unsigned long']],
            'CcPinReadWaitMiss': [0x578, ['unsigned long']],
            'CcMdlReadNoWaitMiss': [0x57C, ['unsigned long']],
            'CcMdlReadWaitMiss': [0x580, ['unsigned long']],
            'CcReadAheadIos': [0x584, ['unsigned long']],
            'KeAlignmentFixupCount': [0x588, ['unsigned long']],
            'KeExceptionDispatchCount': [0x58C, ['unsigned long']],
            'KeSystemCalls': [0x590, ['unsigned long']],
            'AvailableTime': [0x594, ['unsigned long']],
            'PrcbPad22': [0x598, ['array', 2, ['unsigned long']]],
            'PPLookasideList': [0x5A0, ['array', 16, ['_PP_LOOKASIDE_LIST']]],
            'PPNxPagedLookasideList': [
                0x620,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PPNPagedLookasideList': [
                0xF20,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PPPagedLookasideList': [
                0x1820,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PacketBarrier': [0x2120, ['unsigned long']],
            'ReverseStall': [0x2124, ['long']],
            'IpiFrame': [0x2128, ['pointer', ['void']]],
            'PrcbPad3': [0x212C, ['array', 52, ['unsigned char']]],
            'CurrentPacket': [0x2160, ['array', 3, ['pointer', ['void']]]],
            'TargetSet': [0x216C, ['unsigned long']],
            'WorkerRoutine': [0x2170, ['pointer', ['void']]],
            'IpiFrozen': [0x2174, ['unsigned long']],
            'PrcbPad4': [0x2178, ['array', 40, ['unsigned char']]],
            'RequestSummary': [0x21A0, ['unsigned long']],
            'SignalDone': [0x21A4, ['pointer', ['_KPRCB']]],
            'PrcbPad50': [0x21A8, ['array', 40, ['unsigned char']]],
            'InterruptLastCount': [0x21D0, ['unsigned long']],
            'InterruptRate': [0x21D4, ['unsigned long']],
            'DeviceInterrupts': [0x21D8, ['unsigned long']],
            'IsrDpcStats': [0x21DC, ['pointer', ['void']]],
            'DpcData': [0x21E0, ['array', 2, ['_KDPC_DATA']]],
            'DpcStack': [0x2210, ['pointer', ['void']]],
            'MaximumDpcQueueDepth': [0x2214, ['long']],
            'DpcRequestRate': [0x2218, ['unsigned long']],
            'MinimumDpcRate': [0x221C, ['unsigned long']],
            'DpcLastCount': [0x2220, ['unsigned long']],
            'PrcbLock': [0x2224, ['unsigned long']],
            'DpcGate': [0x2228, ['_KGATE']],
            'ThreadDpcEnable': [0x2238, ['unsigned char']],
            'QuantumEnd': [0x2239, ['unsigned char']],
            'DpcRoutineActive': [0x223A, ['unsigned char']],
            'IdleSchedule': [0x223B, ['unsigned char']],
            'DpcRequestSummary': [0x223C, ['long']],
            'DpcRequestSlot': [0x223C, ['array', 2, ['short']]],
            'NormalDpcState': [0x223C, ['short']],
            'ThreadDpcState': [0x223E, ['short']],
            'DpcNormalProcessingActive': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DpcNormalProcessingRequested': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'DpcNormalThreadSignal': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'DpcNormalTimerExpiration': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'DpcNormalDpcPresent': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'DpcNormalLocalInterrupt': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'DpcNormalSpare': [
                0x223C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'DpcThreadActive': [
                0x223C,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'DpcThreadRequested': [
                0x223C,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'DpcThreadSpare': [
                0x223C,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'LastTimerHand': [0x2240, ['unsigned long']],
            'LastTick': [0x2244, ['unsigned long']],
            'PeriodicCount': [0x2248, ['unsigned long']],
            'PeriodicBias': [0x224C, ['unsigned long']],
            'ClockInterrupts': [0x2250, ['unsigned long']],
            'ReadyScanTick': [0x2254, ['unsigned long']],
            'GroupSchedulingOverQuota': [0x2258, ['unsigned char']],
            'PrcbPad41': [0x2259, ['array', 3, ['unsigned char']]],
            'TimerTable': [0x2260, ['_KTIMER_TABLE']],
            'CallDpc': [0x3AA0, ['_KDPC']],
            'ClockKeepAlive': [0x3AC0, ['long']],
            'PrcbPad6': [0x3AC4, ['array', 4, ['unsigned char']]],
            'DpcWatchdogPeriod': [0x3AC8, ['long']],
            'DpcWatchdogCount': [0x3ACC, ['long']],
            'KeSpinLockOrdering': [0x3AD0, ['long']],
            'PrcbPad70': [0x3AD4, ['array', 1, ['unsigned long']]],
            'QueueIndex': [0x3AD8, ['unsigned long']],
            'DeferredReadyListHead': [0x3ADC, ['_SINGLE_LIST_ENTRY']],
            'ReadySummary': [0x3AE0, ['unsigned long']],
            'AffinitizedSelectionMask': [0x3AE4, ['long']],
            'WaitLock': [0x3AE8, ['unsigned long']],
            'WaitListHead': [0x3AEC, ['_LIST_ENTRY']],
            'ScbOffset': [0x3AF4, ['unsigned long']],
            'StartCycles': [0x3AF8, ['unsigned long long']],
            'GenerationTarget': [0x3B00, ['unsigned long long']],
            'CycleTime': [0x3B08, ['unsigned long long']],
            'AffinitizedCycles': [0x3B10, ['unsigned long long']],
            'HighCycleTime': [0x3B18, ['unsigned long']],
            'PrcbPad71': [0x3B1C, ['unsigned long']],
            'DispatcherReadyListHead': [
                0x3B20,
                ['array', 32, ['_LIST_ENTRY']],
            ],
            'ChainedInterruptList': [0x3C20, ['pointer', ['void']]],
            'LookasideIrpFloat': [0x3C24, ['long']],
            'ScbQueue': [0x3C28, ['_RTL_RB_TREE']],
            'ScbList': [0x3C30, ['_LIST_ENTRY']],
            'MmPageFaultCount': [0x3C38, ['long']],
            'MmCopyOnWriteCount': [0x3C3C, ['long']],
            'MmTransitionCount': [0x3C40, ['long']],
            'MmCacheTransitionCount': [0x3C44, ['long']],
            'MmDemandZeroCount': [0x3C48, ['long']],
            'MmPageReadCount': [0x3C4C, ['long']],
            'MmPageReadIoCount': [0x3C50, ['long']],
            'MmCacheReadCount': [0x3C54, ['long']],
            'MmCacheIoCount': [0x3C58, ['long']],
            'MmDirtyPagesWriteCount': [0x3C5C, ['long']],
            'MmDirtyWriteIoCount': [0x3C60, ['long']],
            'MmMappedPagesWriteCount': [0x3C64, ['long']],
            'MmMappedWriteIoCount': [0x3C68, ['long']],
            'CachedCommit': [0x3C6C, ['unsigned long']],
            'CachedResidentAvailable': [0x3C70, ['unsigned long']],
            'HyperPte': [0x3C74, ['pointer', ['void']]],
            'PrcbPad8': [0x3C78, ['array', 4, ['unsigned char']]],
            'VendorString': [0x3C7C, ['array', 13, ['unsigned char']]],
            'InitialApicId': [0x3C89, ['unsigned char']],
            'LogicalProcessorsPerPhysicalProcessor': [
                0x3C8A,
                ['unsigned char'],
            ],
            'PrcbPad9': [0x3C8B, ['array', 5, ['unsigned char']]],
            'FeatureBits': [0x3C90, ['unsigned long']],
            'UpdateSignature': [0x3C98, ['_LARGE_INTEGER']],
            'IsrTime': [0x3CA0, ['unsigned long long']],
            'PrcbPad90': [0x3CA8, ['array', 2, ['unsigned long']]],
            'PowerState': [0x3CB0, ['_PROCESSOR_POWER_STATE']],
            'PrcbPad91': [0x3E40, ['array', 13, ['unsigned long']]],
            'DpcWatchdogDpc': [0x3E74, ['_KDPC']],
            'DpcWatchdogTimer': [0x3E98, ['_KTIMER']],
            'HypercallPageList': [0x3EC0, ['_SLIST_HEADER']],
            'HypercallPageVirtual': [0x3EC8, ['pointer', ['void']]],
            'VirtualApicAssist': [0x3ECC, ['pointer', ['void']]],
            'StatisticsPage': [0x3ED0, ['pointer', ['unsigned long long']]],
            'Cache': [0x3ED4, ['array', 5, ['_CACHE_DESCRIPTOR']]],
            'CacheCount': [0x3F10, ['unsigned long']],
            'PackageProcessorSet': [0x3F14, ['_KAFFINITY_EX']],
            'SharedReadyQueueMask': [0x3F20, ['unsigned long']],
            'SharedReadyQueue': [
                0x3F24,
                ['pointer', ['_KSHARED_READY_QUEUE']],
            ],
            'CoreProcessorSet': [0x3F28, ['unsigned long']],
            'ScanSiblingMask': [0x3F2C, ['unsigned long']],
            'LLCMask': [0x3F30, ['unsigned long']],
            'CacheProcessorMask': [0x3F34, ['array', 5, ['unsigned long']]],
            'ScanSiblingIndex': [0x3F48, ['unsigned long']],
            'WheaInfo': [0x3F4C, ['pointer', ['void']]],
            'EtwSupport': [0x3F50, ['pointer', ['void']]],
            'InterruptObjectPool': [0x3F58, ['_SLIST_HEADER']],
            'SharedReadyQueueOffset': [0x3F60, ['unsigned long']],
            'PrcbPad92': [0x3F64, ['array', 2, ['unsigned long']]],
            'PteBitCache': [0x3F6C, ['unsigned long']],
            'PteBitOffset': [0x3F70, ['unsigned long']],
            'PrcbPad93': [0x3F74, ['unsigned long']],
            'ProcessorProfileControlArea': [
                0x3F78,
                ['pointer', ['_PROCESSOR_PROFILE_CONTROL_AREA']],
            ],
            'ProfileEventIndexAddress': [0x3F7C, ['pointer', ['void']]],
            'TimerExpirationDpc': [0x3F80, ['_KDPC']],
            'SynchCounters': [0x3FA0, ['_SYNCH_COUNTERS']],
            'FsCounters': [0x4058, ['_FILESYSTEM_DISK_COUNTERS']],
            'Context': [0x4068, ['pointer', ['_CONTEXT']]],
            'ContextFlagsInit': [0x406C, ['unsigned long']],
            'ExtendedState': [0x4070, ['pointer', ['_XSAVE_AREA']]],
            'EntropyTimingState': [0x4074, ['_KENTROPY_TIMING_STATE']],
            'IsrStack': [0x419C, ['pointer', ['void']]],
            'VectorToInterruptObject': [
                0x41A0,
                ['array', 208, ['pointer', ['_KINTERRUPT']]],
            ],
            'AbSelfIoBoostsList': [0x44E0, ['_SINGLE_LIST_ENTRY']],
            'AbPropagateBoostsList': [0x44E4, ['_SINGLE_LIST_ENTRY']],
            'AbDpc': [0x44E8, ['_KDPC']],
            'IoIrpStackProfilerCurrent': [0x4508, ['_IOP_IRP_STACK_PROFILER']],
            'IoIrpStackProfilerPrevious': [
                0x455C,
                ['_IOP_IRP_STACK_PROFILER'],
            ],
            'TimerExpirationTrace': [
                0x45B0,
                ['array', 16, ['_KTIMER_EXPIRATION_TRACE']],
            ],
            'TimerExpirationTraceCount': [0x46B0, ['unsigned long']],
        },
    ],
    '_KAPC': [
        0x30,
        {
            'Type': [0x0, ['unsigned char']],
            'SpareByte0': [0x1, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'SpareByte1': [0x3, ['unsigned char']],
            'SpareLong0': [0x4, ['unsigned long']],
            'Thread': [0x8, ['pointer', ['_KTHREAD']]],
            'ApcListEntry': [0xC, ['_LIST_ENTRY']],
            'KernelRoutine': [0x14, ['pointer', ['void']]],
            'RundownRoutine': [0x18, ['pointer', ['void']]],
            'NormalRoutine': [0x1C, ['pointer', ['void']]],
            'Reserved': [0x14, ['array', 3, ['pointer', ['void']]]],
            'NormalContext': [0x20, ['pointer', ['void']]],
            'SystemArgument1': [0x24, ['pointer', ['void']]],
            'SystemArgument2': [0x28, ['pointer', ['void']]],
            'ApcStateIndex': [0x2C, ['unsigned char']],
            'ApcMode': [0x2D, ['unsigned char']],
            'Inserted': [0x2E, ['unsigned char']],
        },
    ],
    '_CPU_INFO': [
        0x10,
        {
            'AsUINT32': [0x0, ['array', 4, ['unsigned long']]],
            'Eax': [0x0, ['unsigned long']],
            'Ebx': [0x4, ['unsigned long']],
            'Ecx': [0x8, ['unsigned long']],
            'Edx': [0xC, ['unsigned long']],
        },
    ],
    '_EXT_SET_PARAMETERS_V0': [
        0x10,
        {
            'Version': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'NoWakeTolerance': [0x8, ['long long']],
        },
    ],
    '_KTHREAD': [
        0x338,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'SListFaultAddress': [0x10, ['pointer', ['void']]],
            'QuantumTarget': [0x18, ['unsigned long long']],
            'InitialStack': [0x20, ['pointer', ['void']]],
            'StackLimit': [0x24, ['pointer', ['void']]],
            'StackBase': [0x28, ['pointer', ['void']]],
            'ThreadLock': [0x2C, ['unsigned long']],
            'CycleTime': [0x30, ['unsigned long long']],
            'HighCycleTime': [0x38, ['unsigned long']],
            'ServiceTable': [0x3C, ['pointer', ['void']]],
            'CurrentRunTime': [0x40, ['unsigned long']],
            'ExpectedRunTime': [0x44, ['unsigned long']],
            'KernelStack': [0x48, ['pointer', ['void']]],
            'StateSaveArea': [0x4C, ['pointer', ['_XSAVE_FORMAT']]],
            'SchedulingGroup': [0x50, ['pointer', ['_KSCHEDULING_GROUP']]],
            'WaitRegister': [0x54, ['_KWAIT_STATUS_REGISTER']],
            'Running': [0x55, ['unsigned char']],
            'Alerted': [0x56, ['array', 2, ['unsigned char']]],
            'SpareMiscFlag0': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReadyTransition': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessReadyQueue': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WaitNext': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SystemAffinityActive': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Alertable': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'UserStackWalkActive': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'ApcInterruptRequest': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'QuantumEndMigrate': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'UmsDirectedSwitchEnable': [
                0x58,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'TimerActive': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'SystemThread': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessDetachActive': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'CalloutActive': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'ScbReadyQueue': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'ApcQueueable': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedStackInUse': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'UmsPerformingSyscall': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'ApcPendingReload': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'TimerSuspended': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'SuspendedWaitMode': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved': [
                0x58,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'MiscFlags': [0x58, ['long']],
            'AutoAlignment': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DisableBoost': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'UserAffinitySet': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'AlertedByThreadId': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'QuantumDonation': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'EnableStackSwap': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'GuiThread': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'DisableQuantum': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ChargeOnlySchedulingGroup': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'DeferPreemption': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'QueueDeferPreemption': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'ForceDeferSchedule': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'SharedReadyQueueAffinity': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'FreezeCount': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'TerminationApcRequest': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'AutoBoostEntriesExhausted': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'KernelStackResident': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'EtwStackTraceApcInserted': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedFlags': [
                0x5C,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ThreadFlags': [0x5C, ['long']],
            'Spare0': [0x60, ['unsigned long']],
            'SystemCallNumber': [0x64, ['unsigned long']],
            'FirstArgument': [0x68, ['pointer', ['void']]],
            'TrapFrame': [0x6C, ['pointer', ['_KTRAP_FRAME']]],
            'ApcState': [0x70, ['_KAPC_STATE']],
            'ApcStateFill': [0x70, ['array', 23, ['unsigned char']]],
            'Priority': [0x87, ['unsigned char']],
            'UserIdealProcessor': [0x88, ['unsigned long']],
            'ContextSwitches': [0x8C, ['unsigned long']],
            'State': [0x90, ['unsigned char']],
            'NpxState': [0x91, ['unsigned char']],
            'WaitIrql': [0x92, ['unsigned char']],
            'WaitMode': [0x93, ['unsigned char']],
            'WaitStatus': [0x94, ['long']],
            'WaitBlockList': [0x98, ['pointer', ['_KWAIT_BLOCK']]],
            'WaitListEntry': [0x9C, ['_LIST_ENTRY']],
            'SwapListEntry': [0x9C, ['_SINGLE_LIST_ENTRY']],
            'Queue': [0xA4, ['pointer', ['_DISPATCHER_HEADER']]],
            'Teb': [0xA8, ['pointer', ['void']]],
            'RelativeTimerBias': [0xB0, ['unsigned long long']],
            'Timer': [0xB8, ['_KTIMER']],
            'WaitBlock': [0xE0, ['array', 4, ['_KWAIT_BLOCK']]],
            'WaitBlockFill8': [0xE0, ['array', 20, ['unsigned char']]],
            'ThreadCounters': [0xF4, ['pointer', ['_KTHREAD_COUNTERS']]],
            'WaitBlockFill9': [0xE0, ['array', 44, ['unsigned char']]],
            'XStateSave': [0x10C, ['pointer', ['_XSTATE_SAVE']]],
            'WaitBlockFill10': [0xE0, ['array', 68, ['unsigned char']]],
            'Win32Thread': [0x124, ['pointer', ['void']]],
            'WaitBlockFill11': [0xE0, ['array', 88, ['unsigned char']]],
            'WaitTime': [0x138, ['unsigned long']],
            'KernelApcDisable': [0x13C, ['short']],
            'SpecialApcDisable': [0x13E, ['short']],
            'CombinedApcDisable': [0x13C, ['unsigned long']],
            'QueueListEntry': [0x140, ['_LIST_ENTRY']],
            'NextProcessor': [0x148, ['unsigned long']],
            'NextProcessorNumber': [
                0x148,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'SharedReadyQueue': [
                0x148,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'QueuePriority': [0x14C, ['long']],
            'Process': [0x150, ['pointer', ['_KPROCESS']]],
            'UserAffinity': [0x154, ['_GROUP_AFFINITY']],
            'UserAffinityFill': [0x154, ['array', 6, ['unsigned char']]],
            'PreviousMode': [0x15A, ['unsigned char']],
            'BasePriority': [0x15B, ['unsigned char']],
            'PriorityDecrement': [0x15C, ['unsigned char']],
            'ForegroundBoost': [
                0x15C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'UnusualBoost': [
                0x15C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Preempted': [0x15D, ['unsigned char']],
            'AdjustReason': [0x15E, ['unsigned char']],
            'AdjustIncrement': [0x15F, ['unsigned char']],
            'Affinity': [0x160, ['_GROUP_AFFINITY']],
            'AffinityFill': [0x160, ['array', 6, ['unsigned char']]],
            'ApcStateIndex': [0x166, ['unsigned char']],
            'WaitBlockCount': [0x167, ['unsigned char']],
            'IdealProcessor': [0x168, ['unsigned long']],
            'ApcStatePointer': [
                0x16C,
                ['array', 2, ['pointer', ['_KAPC_STATE']]],
            ],
            'SavedApcState': [0x174, ['_KAPC_STATE']],
            'SavedApcStateFill': [0x174, ['array', 23, ['unsigned char']]],
            'WaitReason': [0x18B, ['unsigned char']],
            'SuspendCount': [0x18C, ['unsigned char']],
            'Saturation': [0x18D, ['unsigned char']],
            'SListFaultCount': [0x18E, ['unsigned short']],
            'SchedulerApc': [0x190, ['_KAPC']],
            'SchedulerApcFill0': [0x190, ['array', 1, ['unsigned char']]],
            'ResourceIndex': [0x191, ['unsigned char']],
            'SchedulerApcFill1': [0x190, ['array', 3, ['unsigned char']]],
            'QuantumReset': [0x193, ['unsigned char']],
            'SchedulerApcFill2': [0x190, ['array', 4, ['unsigned char']]],
            'KernelTime': [0x194, ['unsigned long']],
            'SchedulerApcFill3': [0x190, ['array', 36, ['unsigned char']]],
            'WaitPrcb': [0x1B4, ['pointer', ['_KPRCB']]],
            'SchedulerApcFill4': [0x190, ['array', 40, ['unsigned char']]],
            'LegoData': [0x1B8, ['pointer', ['void']]],
            'SchedulerApcFill5': [0x190, ['array', 47, ['unsigned char']]],
            'CallbackNestingLevel': [0x1BF, ['unsigned char']],
            'UserTime': [0x1C0, ['unsigned long']],
            'SuspendEvent': [0x1C4, ['_KEVENT']],
            'ThreadListEntry': [0x1D4, ['_LIST_ENTRY']],
            'MutantListHead': [0x1DC, ['_LIST_ENTRY']],
            'LockEntriesFreeList': [0x1E4, ['_SINGLE_LIST_ENTRY']],
            'LockEntries': [0x1E8, ['array', 6, ['_KLOCK_ENTRY']]],
            'PropagateBoostsEntry': [0x308, ['_SINGLE_LIST_ENTRY']],
            'IoSelfBoostsEntry': [0x30C, ['_SINGLE_LIST_ENTRY']],
            'PriorityFloorCounts': [0x310, ['array', 16, ['unsigned char']]],
            'PriorityFloorSummary': [0x320, ['unsigned long']],
            'AbCompletedIoBoostCount': [0x324, ['long']],
            'AbReferenceCount': [0x328, ['short']],
            'AbFreeEntryCount': [0x32A, ['unsigned char']],
            'AbWaitEntryCount': [0x32B, ['unsigned char']],
            'ForegroundLossTime': [0x32C, ['unsigned long']],
            'GlobalForegroundListEntry': [0x330, ['_LIST_ENTRY']],
            'ForegroundDpcStackListEntry': [0x330, ['_SINGLE_LIST_ENTRY']],
            'InGlobalForegroundList': [0x334, ['unsigned long']],
        },
    ],
    '_KSTACK_CONTROL': [
        0x20,
        {
            'StackBase': [0x0, ['unsigned long']],
            'ActualLimit': [0x4, ['unsigned long']],
            'StackExpansion': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'PreviousTrapFrame': [0x8, ['pointer', ['_KTRAP_FRAME']]],
            'PreviousExceptionList': [0xC, ['pointer', ['void']]],
            'Previous': [0x10, ['_KERNEL_STACK_SEGMENT']],
        },
    ],
    '_KSPIN_LOCK_QUEUE': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_KSPIN_LOCK_QUEUE']]],
            'Lock': [0x4, ['pointer', ['unsigned long']]],
        },
    ],
    '_FAST_MUTEX': [
        0x20,
        {
            'Count': [0x0, ['long']],
            'Owner': [0x4, ['pointer', ['void']]],
            'Contention': [0x8, ['unsigned long']],
            'Event': [0xC, ['_KEVENT']],
            'OldIrql': [0x1C, ['unsigned long']],
        },
    ],
    '_KEVENT': [
        0x10,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '_SLIST_HEADER': [
        0x8,
        {
            'Alignment': [0x0, ['unsigned long long']],
            'Next': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Depth': [0x4, ['unsigned short']],
            'CpuId': [0x6, ['unsigned short']],
        },
    ],
    '_LOOKASIDE_LIST_EX': [
        0x48,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE_POOL']],
        },
    ],
    '_NPAGED_LOOKASIDE_LIST': [
        0xC0,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE']],
            'Lock__ObsoleteButDoNotDelete': [0x80, ['unsigned long']],
        },
    ],
    '_PAGED_LOOKASIDE_LIST': [
        0xC0,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE']],
            'Lock__ObsoleteButDoNotDelete': [0x80, ['_FAST_MUTEX']],
        },
    ],
    '_IO_STATUS_BLOCK': [
        0x8,
        {
            'Status': [0x0, ['long']],
            'Pointer': [0x0, ['pointer', ['void']]],
            'Information': [0x4, ['unsigned long']],
        },
    ],
    '_QUAD': [
        0x8,
        {
            'UseThisFieldToCopy': [0x0, ['long long']],
            'DoNotUseThisField': [0x0, ['double']],
        },
    ],
    '_WORK_QUEUE_ITEM': [
        0x10,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'WorkerRoutine': [0x8, ['pointer', ['void']]],
            'Parameter': [0xC, ['pointer', ['void']]],
        },
    ],
    '_EXT_DELETE_PARAMETERS': [
        0x10,
        {
            'Version': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'DeleteCallback': [0x8, ['pointer', ['void']]],
            'DeleteContext': [0xC, ['pointer', ['void']]],
        },
    ],
    '_EX_PUSH_LOCK': [
        0x4,
        {
            'Locked': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Waiting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Waking': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'MultipleShared': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Shared': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'Value': [0x0, ['unsigned long']],
            'Ptr': [0x0, ['pointer', ['void']]],
        },
    ],
    '_PP_LOOKASIDE_LIST': [
        0x8,
        {
            'P': [0x0, ['pointer', ['_GENERAL_LOOKASIDE']]],
            'L': [0x4, ['pointer', ['_GENERAL_LOOKASIDE']]],
        },
    ],
    '_GENERAL_LOOKASIDE': [
        0x80,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
            'SingleListHead': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Depth': [0x8, ['unsigned short']],
            'MaximumDepth': [0xA, ['unsigned short']],
            'TotalAllocates': [0xC, ['unsigned long']],
            'AllocateMisses': [0x10, ['unsigned long']],
            'AllocateHits': [0x10, ['unsigned long']],
            'TotalFrees': [0x14, ['unsigned long']],
            'FreeMisses': [0x18, ['unsigned long']],
            'FreeHits': [0x18, ['unsigned long']],
            'Type': [
                0x1C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPoolBase',
                            1: 'PagedPool',
                            2: 'NonPagedPoolBaseMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolBaseCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolBaseCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            516: 'NonPagedPoolNxCacheAligned',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            512: 'NonPagedPoolNx',
                            544: 'NonPagedPoolSessionNx',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'Tag': [0x20, ['unsigned long']],
            'Size': [0x24, ['unsigned long']],
            'AllocateEx': [0x28, ['pointer', ['void']]],
            'Allocate': [0x28, ['pointer', ['void']]],
            'FreeEx': [0x2C, ['pointer', ['void']]],
            'Free': [0x2C, ['pointer', ['void']]],
            'ListEntry': [0x30, ['_LIST_ENTRY']],
            'LastTotalAllocates': [0x38, ['unsigned long']],
            'LastAllocateMisses': [0x3C, ['unsigned long']],
            'LastAllocateHits': [0x3C, ['unsigned long']],
            'Future': [0x40, ['array', 2, ['unsigned long']]],
        },
    ],
    '_KNODE': [
        0xC0,
        {
            'DeepIdleSet': [0x0, ['unsigned long']],
            'SharedReadyQueueLeaders': [0x4, ['unsigned long']],
            'ProximityId': [0x40, ['unsigned long']],
            'NodeNumber': [0x44, ['unsigned short']],
            'PrimaryNodeNumber': [0x46, ['unsigned short']],
            'MaximumProcessors': [0x48, ['unsigned char']],
            'Flags': [0x49, ['_flags']],
            'Stride': [0x4A, ['unsigned char']],
            'LowIndex': [0x4B, ['unsigned char']],
            'Affinity': [0x4C, ['_GROUP_AFFINITY']],
            'IdleCpuSet': [0x58, ['unsigned long']],
            'IdleSmtSet': [0x5C, ['unsigned long']],
            'NonParkedSet': [0x80, ['unsigned long']],
            'Seed': [0x84, ['unsigned long']],
            'Lowest': [0x88, ['unsigned long']],
            'Highest': [0x8C, ['unsigned long']],
            'ParkLock': [0x90, ['long']],
        },
    ],
    '_ENODE': [
        0x340,
        {
            'Ncb': [0x0, ['_KNODE']],
            'ExWorkQueues': [
                0xC0,
                ['array', 8, ['pointer', ['_EX_WORK_QUEUE']]],
            ],
            'ExWorkQueue': [0xE0, ['_EX_WORK_QUEUE']],
            'ExpThreadSetManagerEvent': [0x298, ['_KEVENT']],
            'ExpDeadlockTimer': [0x2A8, ['_KTIMER']],
            'ExpThreadReaperEvent': [0x2D0, ['_KEVENT']],
            'WaitBlocks': [0x2E0, ['array', 3, ['_KWAIT_BLOCK']]],
            'ExpWorkerThreadBalanceManagerPtr': [
                0x328,
                ['pointer', ['_ETHREAD']],
            ],
            'ExpWorkerSeed': [0x32C, ['unsigned long']],
            'ExWorkerFullInit': [
                0x330,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ExWorkerStructInit': [
                0x330,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ExWorkerFlags': [0x330, ['unsigned long']],
        },
    ],
    '_HANDLE_TABLE': [
        0x5C,
        {
            'NextHandleNeedingPool': [0x0, ['unsigned long']],
            'ExtraInfoPages': [0x4, ['long']],
            'TableCode': [0x8, ['unsigned long']],
            'QuotaProcess': [0xC, ['pointer', ['_EPROCESS']]],
            'HandleTableList': [0x10, ['_LIST_ENTRY']],
            'UniqueProcessId': [0x18, ['unsigned long']],
            'Flags': [0x1C, ['unsigned long']],
            'StrictFIFO': [
                0x1C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'EnableHandleExceptions': [
                0x1C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Rundown': [
                0x1C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Duplicated': [
                0x1C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'HandleContentionEvent': [0x20, ['_EX_PUSH_LOCK']],
            'HandleTableLock': [0x24, ['_EX_PUSH_LOCK']],
            'FreeLists': [0x28, ['array', 1, ['_HANDLE_TABLE_FREE_LIST']]],
            'ActualEntry': [0x28, ['array', 20, ['unsigned char']]],
            'DebugInfo': [0x3C, ['pointer', ['_HANDLE_TRACE_DEBUG_INFO']]],
        },
    ],
    '_HANDLE_TABLE_ENTRY_INFO': [
        0x4,
        {
            'AuditMask': [0x0, ['unsigned long']],
        },
    ],
    '_HANDLE_TABLE_ENTRY': [
        0x8,
        {
            'VolatileLowValue': [0x0, ['long']],
            'LowValue': [0x0, ['long']],
            'InfoTable': [0x0, ['pointer', ['_HANDLE_TABLE_ENTRY_INFO']]],
            'Unlocked': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Attributes': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ObjectPointerBits': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'HighValue': [0x4, ['long']],
            'NextFreeHandleEntry': [0x4, ['pointer', ['_HANDLE_TABLE_ENTRY']]],
            'LeafHandleValue': [0x4, ['_EXHANDLE']],
            'GrantedAccessBits': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=25, native_type='unsigned long'),
                ],
            ],
            'ProtectFromClose': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'NoRightsUpgrade': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'RefCnt': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_EX_FAST_REF': [
        0x4,
        {
            'Object': [0x0, ['pointer', ['void']]],
            'RefCnt': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Value': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1301': [
        0x2C,
        {
            'InitialPrivilegeSet': [0x0, ['_INITIAL_PRIVILEGE_SET']],
            'PrivilegeSet': [0x0, ['_PRIVILEGE_SET']],
        },
    ],
    '_ACCESS_STATE': [
        0x74,
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
            'SubjectSecurityContext': [0x1C, ['_SECURITY_SUBJECT_CONTEXT']],
            'SecurityDescriptor': [0x2C, ['pointer', ['void']]],
            'AuxData': [0x30, ['pointer', ['void']]],
            'Privileges': [0x34, ['__unnamed_1301']],
            'AuditPrivileges': [0x60, ['unsigned char']],
            'ObjectName': [0x64, ['_UNICODE_STRING']],
            'ObjectTypeName': [0x6C, ['_UNICODE_STRING']],
        },
    ],
    '_AUX_ACCESS_DATA': [
        0xC4,
        {
            'PrivilegesUsed': [0x0, ['pointer', ['_PRIVILEGE_SET']]],
            'GenericMapping': [0x4, ['_GENERIC_MAPPING']],
            'AccessesToAudit': [0x14, ['unsigned long']],
            'MaximumAuditMask': [0x18, ['unsigned long']],
            'TransactionId': [0x1C, ['_GUID']],
            'NewSecurityDescriptor': [0x2C, ['pointer', ['void']]],
            'ExistingSecurityDescriptor': [0x30, ['pointer', ['void']]],
            'ParentSecurityDescriptor': [0x34, ['pointer', ['void']]],
            'DeRefSecurityDescriptor': [0x38, ['pointer', ['void']]],
            'SDLock': [0x3C, ['pointer', ['void']]],
            'AccessReasons': [0x40, ['_ACCESS_REASONS']],
            'GenerateStagingEvents': [0xC0, ['unsigned char']],
        },
    ],
    '_ETHREAD': [
        0x418,
        {
            'Tcb': [0x0, ['_KTHREAD']],
            'CreateTime': [0x338, ['_LARGE_INTEGER']],
            'ExitTime': [0x340, ['_LARGE_INTEGER']],
            'KeyedWaitChain': [0x340, ['_LIST_ENTRY']],
            'ChargeOnlySession': [0x348, ['pointer', ['void']]],
            'PostBlockList': [0x34C, ['_LIST_ENTRY']],
            'ForwardLinkShadow': [0x34C, ['pointer', ['void']]],
            'StartAddress': [0x350, ['pointer', ['void']]],
            'TerminationPort': [0x354, ['pointer', ['_TERMINATION_PORT']]],
            'ReaperLink': [0x354, ['pointer', ['_ETHREAD']]],
            'KeyedWaitValue': [0x354, ['pointer', ['void']]],
            'ActiveTimerListLock': [0x358, ['unsigned long']],
            'ActiveTimerListHead': [0x35C, ['_LIST_ENTRY']],
            'Cid': [0x364, ['_CLIENT_ID']],
            'KeyedWaitSemaphore': [0x36C, ['_KSEMAPHORE']],
            'AlpcWaitSemaphore': [0x36C, ['_KSEMAPHORE']],
            'ClientSecurity': [0x380, ['_PS_CLIENT_SECURITY_CONTEXT']],
            'IrpList': [0x384, ['_LIST_ENTRY']],
            'TopLevelIrp': [0x38C, ['unsigned long']],
            'DeviceToVerify': [0x390, ['pointer', ['_DEVICE_OBJECT']]],
            'Win32StartAddress': [0x394, ['pointer', ['void']]],
            'LegacyPowerObject': [0x398, ['pointer', ['void']]],
            'ThreadListEntry': [0x39C, ['_LIST_ENTRY']],
            'RundownProtect': [0x3A4, ['_EX_RUNDOWN_REF']],
            'ThreadLock': [0x3A8, ['_EX_PUSH_LOCK']],
            'ReadClusterSize': [0x3AC, ['unsigned long']],
            'MmLockOrdering': [0x3B0, ['long']],
            'CmLockOrdering': [0x3B4, ['long']],
            'CrossThreadFlags': [0x3B8, ['unsigned long']],
            'Terminated': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ThreadInserted': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HideFromDebugger': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ActiveImpersonationInfo': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'HardErrorsAreDisabled': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'BreakOnTermination': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'SkipCreationMsg': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SkipTerminationMsg': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'CopyTokenOnOpen': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'ThreadIoPriority': [
                0x3B8,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=12, native_type='unsigned long'),
                ],
            ],
            'ThreadPagePriority': [
                0x3B8,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'RundownFail': [
                0x3B8,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'UmsForceQueueTermination': [
                0x3B8,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedCrossThreadFlags': [
                0x3B8,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'SameThreadPassiveFlags': [0x3BC, ['unsigned long']],
            'ActiveExWorker': [
                0x3BC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'MemoryMaker': [
                0x3BC,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ClonedThread': [
                0x3BC,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'KeyedEventInUse': [
                0x3BC,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SelfTerminate': [
                0x3BC,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'SameThreadApcFlags': [0x3C0, ['unsigned long']],
            'HardFaultBehavior': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'StartAddressInvalid': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'EtwCalloutActive': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetExclusive': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetShared': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemCacheWorkingSetExclusive': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemCacheWorkingSetShared': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetExclusive': [
                0x3C0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetShared': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessAddressSpaceExclusive': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessAddressSpaceShared': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'SuppressSymbolLoad': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Prefetching': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsVadExclusive': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsChangeControlAreaExclusive': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsChangeControlAreaShared': [
                0x3C1,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OwnsPagedPoolWorkingSetExclusive': [
                0x3C2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'OwnsPagedPoolWorkingSetShared': [
                0x3C2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemPtesWorkingSetExclusive': [
                0x3C2,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemPtesWorkingSetShared': [
                0x3C2,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'TrimTrigger': [
                0x3C2,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Spare2': [
                0x3C2,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'SystemPagePriorityActive': [
                0x3C3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'SystemPagePriority': [
                0x3C3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Spare3': [
                0x3C3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'CacheManagerActive': [0x3C4, ['unsigned char']],
            'DisablePageFaultClustering': [0x3C5, ['unsigned char']],
            'ActiveFaultCount': [0x3C6, ['unsigned char']],
            'LockOrderState': [0x3C7, ['unsigned char']],
            'AlpcMessageId': [0x3C8, ['unsigned long']],
            'AlpcMessage': [0x3CC, ['pointer', ['void']]],
            'AlpcReceiveAttributeSet': [0x3CC, ['unsigned long']],
            'ExitStatus': [0x3D0, ['long']],
            'AlpcWaitListEntry': [0x3D4, ['_LIST_ENTRY']],
            'CacheManagerCount': [0x3DC, ['unsigned long']],
            'IoBoostCount': [0x3E0, ['unsigned long']],
            'BoostList': [0x3E4, ['_LIST_ENTRY']],
            'DeboostList': [0x3EC, ['_LIST_ENTRY']],
            'BoostListLock': [0x3F4, ['unsigned long']],
            'IrpListLock': [0x3F8, ['unsigned long']],
            'ReservedForSynchTracking': [0x3FC, ['pointer', ['void']]],
            'CmCallbackListHead': [0x400, ['_SINGLE_LIST_ENTRY']],
            'ActivityId': [0x404, ['pointer', ['_GUID']]],
            'SeLearningModeListHead': [0x408, ['_SINGLE_LIST_ENTRY']],
            'VerifierContext': [0x40C, ['pointer', ['void']]],
            'KernelStackReference': [0x410, ['unsigned long']],
            'AdjustedClientToken': [0x414, ['pointer', ['void']]],
        },
    ],
    '_EPROCESS': [
        0x310,
        {
            'Pcb': [0x0, ['_KPROCESS']],
            'ProcessLock': [0xA0, ['_EX_PUSH_LOCK']],
            'CreateTime': [0xA8, ['_LARGE_INTEGER']],
            'RundownProtect': [0xB0, ['_EX_RUNDOWN_REF']],
            'UniqueProcessId': [0xB4, ['pointer', ['void']]],
            'ActiveProcessLinks': [0xB8, ['_LIST_ENTRY']],
            'Flags2': [0xC0, ['unsigned long']],
            'JobNotReallyActive': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AccountingFolded': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'NewProcessReported': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ExitProcessReported': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ReportCommitChanges': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'LastReportMemory': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'ForceWakeCharge': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'CrossSessionCreate': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'NeedsHandleRundown': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'RefTraceEnabled': [
                0xC0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'DisableDynamicCode': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'EmptyJobEvaluated': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultPagePriority': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'PrimaryTokenFrozen': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessVerifierTarget': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'StackRandomizationDisabled': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'AffinityPermanent': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'AffinityUpdateEnable': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'PropagateNode': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'ExplicitAffinity': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessExecutionState': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'DisallowStrippedImages': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'HighEntropyASLREnabled': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'ExtensionPointDisable': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'ForceRelocateImages': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessStateChangeRequest': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessStateChangeInProgress': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'DisallowWin32kSystemCalls': [
                0xC0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'Flags': [0xC4, ['unsigned long']],
            'CreateReported': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoDebugInherit': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessExiting': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessDelete': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ControlFlowGuardEnabled': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'VmDeleted': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'OutswapEnabled': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Outswapped': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ForkFailed': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Wow64VaSpace4Gb': [
                0xC4,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'AddressSpaceInitialized': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolution': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'BreakOnTermination': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'DeprioritizeViews': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteWatch': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInSession': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'OverrideAddressSpace': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'HasAddressSpace': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'LaunchPrefetched': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'Background': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'VmTopDown': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageNotifyDone': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'PdeUpdateNeeded': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'VdmAllowed': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessRundown': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInserted': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultIoPriority': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessSelfDelete': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolutionLink': [
                0xC4,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessQuotaUsage': [0xC8, ['array', 2, ['unsigned long']]],
            'ProcessQuotaPeak': [0xD0, ['array', 2, ['unsigned long']]],
            'PeakVirtualSize': [0xD8, ['unsigned long']],
            'VirtualSize': [0xDC, ['unsigned long']],
            'SessionProcessLinks': [0xE0, ['_LIST_ENTRY']],
            'ExceptionPortData': [0xE8, ['pointer', ['void']]],
            'ExceptionPortValue': [0xE8, ['unsigned long']],
            'ExceptionPortState': [
                0xE8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Token': [0xEC, ['_EX_FAST_REF']],
            'WorkingSetPage': [0xF0, ['unsigned long']],
            'AddressCreationLock': [0xF4, ['_EX_PUSH_LOCK']],
            'PageTableCommitmentLock': [0xF8, ['_EX_PUSH_LOCK']],
            'RotateInProgress': [0xFC, ['pointer', ['_ETHREAD']]],
            'ForkInProgress': [0x100, ['pointer', ['_ETHREAD']]],
            'CommitChargeJob': [0x104, ['pointer', ['_EJOB']]],
            'CloneRoot': [0x108, ['_RTL_AVL_TREE']],
            'NumberOfPrivatePages': [0x10C, ['unsigned long']],
            'NumberOfLockedPages': [0x110, ['unsigned long']],
            'Win32Process': [0x114, ['pointer', ['void']]],
            'Job': [0x118, ['pointer', ['_EJOB']]],
            'SectionObject': [0x11C, ['pointer', ['void']]],
            'SectionBaseAddress': [0x120, ['pointer', ['void']]],
            'Cookie': [0x124, ['unsigned long']],
            'VdmObjects': [0x128, ['pointer', ['void']]],
            'WorkingSetWatch': [0x12C, ['pointer', ['_PAGEFAULT_HISTORY']]],
            'Win32WindowStation': [0x130, ['pointer', ['void']]],
            'InheritedFromUniqueProcessId': [0x134, ['pointer', ['void']]],
            'LdtInformation': [0x138, ['pointer', ['void']]],
            'OwnerProcessId': [0x13C, ['unsigned long']],
            'Peb': [0x140, ['pointer', ['_PEB']]],
            'Session': [0x144, ['pointer', ['void']]],
            'AweInfo': [0x148, ['pointer', ['void']]],
            'QuotaBlock': [0x14C, ['pointer', ['_EPROCESS_QUOTA_BLOCK']]],
            'ObjectTable': [0x150, ['pointer', ['_HANDLE_TABLE']]],
            'DebugPort': [0x154, ['pointer', ['void']]],
            'PaeTop': [0x158, ['pointer', ['void']]],
            'DeviceMap': [0x15C, ['pointer', ['void']]],
            'EtwDataSource': [0x160, ['pointer', ['void']]],
            'PageDirectoryPte': [0x168, ['unsigned long long']],
            'ImageFileName': [0x170, ['array', 15, ['unsigned char']]],
            'PriorityClass': [0x17F, ['unsigned char']],
            'SecurityPort': [0x180, ['pointer', ['void']]],
            'SeAuditProcessCreationInfo': [
                0x184,
                ['_SE_AUDIT_PROCESS_CREATION_INFO'],
            ],
            'JobLinks': [0x188, ['_LIST_ENTRY']],
            'HighestUserAddress': [0x190, ['pointer', ['void']]],
            'ThreadListHead': [0x194, ['_LIST_ENTRY']],
            'ActiveThreads': [0x19C, ['unsigned long']],
            'ImagePathHash': [0x1A0, ['unsigned long']],
            'DefaultHardErrorProcessing': [0x1A4, ['unsigned long']],
            'LastThreadExitStatus': [0x1A8, ['long']],
            'PrefetchTrace': [0x1AC, ['_EX_FAST_REF']],
            'LockedPagesList': [0x1B0, ['pointer', ['void']]],
            'ReadOperationCount': [0x1B8, ['_LARGE_INTEGER']],
            'WriteOperationCount': [0x1C0, ['_LARGE_INTEGER']],
            'OtherOperationCount': [0x1C8, ['_LARGE_INTEGER']],
            'ReadTransferCount': [0x1D0, ['_LARGE_INTEGER']],
            'WriteTransferCount': [0x1D8, ['_LARGE_INTEGER']],
            'OtherTransferCount': [0x1E0, ['_LARGE_INTEGER']],
            'CommitCharge': [0x1E8, ['unsigned long']],
            'Vm': [0x1EC, ['_MMSUPPORT']],
            'MmProcessLinks': [0x264, ['_LIST_ENTRY']],
            'ModifiedPageCount': [0x26C, ['unsigned long']],
            'ExitStatus': [0x270, ['long']],
            'VadRoot': [0x274, ['_RTL_AVL_TREE']],
            'VadHint': [0x278, ['pointer', ['void']]],
            'VadCount': [0x27C, ['unsigned long']],
            'VadPhysicalPages': [0x280, ['unsigned long']],
            'VadPhysicalPagesLimit': [0x284, ['unsigned long']],
            'AlpcContext': [0x288, ['_ALPC_PROCESS_CONTEXT']],
            'TimerResolutionLink': [0x298, ['_LIST_ENTRY']],
            'TimerResolutionStackRecord': [
                0x2A0,
                ['pointer', ['_PO_DIAG_STACK_RECORD']],
            ],
            'RequestedTimerResolution': [0x2A4, ['unsigned long']],
            'SmallestTimerResolution': [0x2A8, ['unsigned long']],
            'ExitTime': [0x2B0, ['_LARGE_INTEGER']],
            'ActiveThreadsHighWatermark': [0x2B8, ['unsigned long']],
            'LargePrivateVadCount': [0x2BC, ['unsigned long']],
            'ThreadListLock': [0x2C0, ['_EX_PUSH_LOCK']],
            'WnfContext': [0x2C4, ['pointer', ['void']]],
            'Spare0': [0x2C8, ['unsigned long']],
            'SignatureLevel': [0x2CC, ['unsigned char']],
            'SectionSignatureLevel': [0x2CD, ['unsigned char']],
            'Protection': [0x2CE, ['_PS_PROTECTION']],
            'SpareByte20': [0x2CF, ['array', 1, ['unsigned char']]],
            'Flags3': [0x2D0, ['unsigned long']],
            'Minimal': [
                0x2D0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'SvmReserved': [0x2D4, ['long']],
            'SvmReserved1': [0x2D8, ['pointer', ['void']]],
            'SvmReserved2': [0x2DC, ['unsigned long']],
            'LastFreezeInterruptTime': [0x2E0, ['unsigned long long']],
            'DiskCounters': [0x2E8, ['pointer', ['_PROCESS_DISK_COUNTERS']]],
            'KeepAliveCounter': [0x2EC, ['unsigned long']],
            'NoWakeKeepAliveCounter': [0x2F0, ['unsigned long']],
            'DeepFreezeStartTime': [0x2F8, ['unsigned long long']],
            'CommitChargeLimit': [0x300, ['unsigned long']],
            'CommitChargePeak': [0x304, ['unsigned long']],
            'HighPriorityFaultsAllowed': [0x308, ['unsigned long']],
        },
    ],
    '_KPROCESS': [
        0xA0,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'ProfileListHead': [0x10, ['_LIST_ENTRY']],
            'DirectoryTableBase': [0x18, ['unsigned long']],
            'LdtDescriptor': [0x1C, ['_KGDTENTRY']],
            'Int21Descriptor': [0x24, ['_KIDTENTRY']],
            'ThreadListHead': [0x2C, ['_LIST_ENTRY']],
            'ProcessLock': [0x34, ['unsigned long']],
            'Affinity': [0x38, ['_KAFFINITY_EX']],
            'ReadyListHead': [0x44, ['_LIST_ENTRY']],
            'SwapListEntry': [0x4C, ['_SINGLE_LIST_ENTRY']],
            'ActiveProcessors': [0x50, ['_KAFFINITY_EX']],
            'AutoAlignment': [
                0x5C,
                ['BitField', dict(start_bit=0, end_bit=1, native_type='long')],
            ],
            'DisableBoost': [
                0x5C,
                ['BitField', dict(start_bit=1, end_bit=2, native_type='long')],
            ],
            'DisableQuantum': [
                0x5C,
                ['BitField', dict(start_bit=2, end_bit=3, native_type='long')],
            ],
            'AffinitySet': [
                0x5C,
                ['BitField', dict(start_bit=3, end_bit=4, native_type='long')],
            ],
            'DeepFreeze': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'TimerVirtualization': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'CheckStackExtents': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'ActiveGroupsMask': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags': [
                0x5C,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=32, native_type='long'),
                ],
            ],
            'ProcessFlags': [0x5C, ['long']],
            'BasePriority': [0x60, ['unsigned char']],
            'QuantumReset': [0x61, ['unsigned char']],
            'Visited': [0x62, ['unsigned char']],
            'Flags': [0x63, ['_KEXECUTE_OPTIONS']],
            'ThreadSeed': [0x64, ['array', 1, ['unsigned long']]],
            'IdealNode': [0x68, ['array', 1, ['unsigned short']]],
            'IdealGlobalNode': [0x6A, ['unsigned short']],
            'Spare1': [0x6C, ['unsigned short']],
            'IopmOffset': [0x6E, ['unsigned short']],
            'SchedulingGroup': [0x70, ['pointer', ['_KSCHEDULING_GROUP']]],
            'StackCount': [0x74, ['_KSTACK_COUNT']],
            'ProcessListEntry': [0x78, ['_LIST_ENTRY']],
            'CycleTime': [0x80, ['unsigned long long']],
            'ContextSwitches': [0x88, ['unsigned long long']],
            'FreezeCount': [0x90, ['unsigned long']],
            'KernelTime': [0x94, ['unsigned long']],
            'UserTime': [0x98, ['unsigned long']],
            'VdmTrapcHandler': [0x9C, ['pointer', ['void']]],
        },
    ],
    '__unnamed_134d': [
        0x4,
        {
            'MasterIrp': [0x0, ['pointer', ['_IRP']]],
            'IrpCount': [0x0, ['long']],
            'SystemBuffer': [0x0, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1353': [
        0x8,
        {
            'UserApcRoutine': [0x0, ['pointer', ['void']]],
            'IssuingProcess': [0x0, ['pointer', ['void']]],
            'UserApcContext': [0x4, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1355': [
        0x8,
        {
            'AsynchronousParameters': [0x0, ['__unnamed_1353']],
            'AllocationSize': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1360': [
        0x2C,
        {
            'DeviceQueueEntry': [0x0, ['_KDEVICE_QUEUE_ENTRY']],
            'DriverContext': [0x0, ['array', 4, ['pointer', ['void']]]],
            'Thread': [0x10, ['pointer', ['_ETHREAD']]],
            'AuxiliaryBuffer': [0x14, ['pointer', ['unsigned char']]],
            'ListEntry': [0x18, ['_LIST_ENTRY']],
            'CurrentStackLocation': [
                0x20,
                ['pointer', ['_IO_STACK_LOCATION']],
            ],
            'PacketType': [0x20, ['unsigned long']],
            'OriginalFileObject': [0x24, ['pointer', ['_FILE_OBJECT']]],
            'IrpExtension': [0x28, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1362': [
        0x30,
        {
            'Overlay': [0x0, ['__unnamed_1360']],
            'Apc': [0x0, ['_KAPC']],
            'CompletionKey': [0x0, ['pointer', ['void']]],
        },
    ],
    '_IRP': [
        0x70,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['unsigned short']],
            'MdlAddress': [0x4, ['pointer', ['_MDL']]],
            'Flags': [0x8, ['unsigned long']],
            'AssociatedIrp': [0xC, ['__unnamed_134d']],
            'ThreadListEntry': [0x10, ['_LIST_ENTRY']],
            'IoStatus': [0x18, ['_IO_STATUS_BLOCK']],
            'RequestorMode': [0x20, ['unsigned char']],
            'PendingReturned': [0x21, ['unsigned char']],
            'StackCount': [0x22, ['unsigned char']],
            'CurrentLocation': [0x23, ['unsigned char']],
            'Cancel': [0x24, ['unsigned char']],
            'CancelIrql': [0x25, ['unsigned char']],
            'ApcEnvironment': [0x26, ['unsigned char']],
            'AllocationFlags': [0x27, ['unsigned char']],
            'UserIosb': [0x28, ['pointer', ['_IO_STATUS_BLOCK']]],
            'UserEvent': [0x2C, ['pointer', ['_KEVENT']]],
            'Overlay': [0x30, ['__unnamed_1355']],
            'CancelRoutine': [0x38, ['pointer', ['void']]],
            'UserBuffer': [0x3C, ['pointer', ['void']]],
            'Tail': [0x40, ['__unnamed_1362']],
        },
    ],
    '__unnamed_1369': [
        0x10,
        {
            'SecurityContext': [0x0, ['pointer', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x4, ['unsigned long']],
            'FileAttributes': [0x8, ['unsigned short']],
            'ShareAccess': [0xA, ['unsigned short']],
            'EaLength': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_136d': [
        0x10,
        {
            'SecurityContext': [0x0, ['pointer', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned short']],
            'ShareAccess': [0xA, ['unsigned short']],
            'Parameters': [
                0xC,
                ['pointer', ['_NAMED_PIPE_CREATE_PARAMETERS']],
            ],
        },
    ],
    '__unnamed_1371': [
        0x10,
        {
            'SecurityContext': [0x0, ['pointer', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned short']],
            'ShareAccess': [0xA, ['unsigned short']],
            'Parameters': [0xC, ['pointer', ['_MAILSLOT_CREATE_PARAMETERS']]],
        },
    ],
    '__unnamed_1373': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'Key': [0x4, ['unsigned long']],
            'ByteOffset': [0x8, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1377': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'FileName': [0x4, ['pointer', ['_UNICODE_STRING']]],
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
                            52: 'FileUnusedInformation',
                            53: 'FileNumaNodeInformation',
                            54: 'FileStandardLinkInformation',
                            55: 'FileRemoteProtocolInformation',
                            56: 'FileRenameInformationBypassAccessCheck',
                            57: 'FileLinkInformationBypassAccessCheck',
                            58: 'FileVolumeNameInformation',
                            59: 'FileIdInformation',
                            60: 'FileIdExtdDirectoryInformation',
                            61: 'FileReplaceCompletionInformation',
                            62: 'FileHardLinkFullIdInformation',
                            63: 'FileIdExtdBothDirectoryInformation',
                            64: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileIndex': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1379': [
        0x8,
        {
            'Length': [0x0, ['unsigned long']],
            'CompletionFilter': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_137b': [
        0x8,
        {
            'Length': [0x0, ['unsigned long']],
            'FileInformationClass': [
                0x4,
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
                            52: 'FileUnusedInformation',
                            53: 'FileNumaNodeInformation',
                            54: 'FileStandardLinkInformation',
                            55: 'FileRemoteProtocolInformation',
                            56: 'FileRenameInformationBypassAccessCheck',
                            57: 'FileLinkInformationBypassAccessCheck',
                            58: 'FileVolumeNameInformation',
                            59: 'FileIdInformation',
                            60: 'FileIdExtdDirectoryInformation',
                            61: 'FileReplaceCompletionInformation',
                            62: 'FileHardLinkFullIdInformation',
                            63: 'FileIdExtdBothDirectoryInformation',
                            64: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_137d': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'FileInformationClass': [
                0x4,
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
                            52: 'FileUnusedInformation',
                            53: 'FileNumaNodeInformation',
                            54: 'FileStandardLinkInformation',
                            55: 'FileRemoteProtocolInformation',
                            56: 'FileRenameInformationBypassAccessCheck',
                            57: 'FileLinkInformationBypassAccessCheck',
                            58: 'FileVolumeNameInformation',
                            59: 'FileIdInformation',
                            60: 'FileIdExtdDirectoryInformation',
                            61: 'FileReplaceCompletionInformation',
                            62: 'FileHardLinkFullIdInformation',
                            63: 'FileIdExtdBothDirectoryInformation',
                            64: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileObject': [0x8, ['pointer', ['_FILE_OBJECT']]],
            'ReplaceIfExists': [0xC, ['unsigned char']],
            'AdvanceOnly': [0xD, ['unsigned char']],
            'ClusterCount': [0xC, ['unsigned long']],
            'DeleteHandle': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_137f': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'EaList': [0x4, ['pointer', ['void']]],
            'EaListLength': [0x8, ['unsigned long']],
            'EaIndex': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1381': [
        0x4,
        {
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1385': [
        0x8,
        {
            'Length': [0x0, ['unsigned long']],
            'FsInformationClass': [
                0x4,
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
                            12: 'FileFsDataCopyInformation',
                            13: 'FileFsMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1387': [
        0x10,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x4, ['unsigned long']],
            'FsControlCode': [0x8, ['unsigned long']],
            'Type3InputBuffer': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_138a': [
        0x10,
        {
            'Length': [0x0, ['pointer', ['_LARGE_INTEGER']]],
            'Key': [0x4, ['unsigned long']],
            'ByteOffset': [0x8, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_138c': [
        0x10,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x4, ['unsigned long']],
            'IoControlCode': [0x8, ['unsigned long']],
            'Type3InputBuffer': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_138e': [
        0x8,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1390': [
        0x8,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'SecurityDescriptor': [0x4, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1394': [
        0x8,
        {
            'Vpb': [0x0, ['pointer', ['_VPB']]],
            'DeviceObject': [0x4, ['pointer', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_1398': [
        0x4,
        {
            'Srb': [0x0, ['pointer', ['_SCSI_REQUEST_BLOCK']]],
        },
    ],
    '__unnamed_139c': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'StartSid': [0x4, ['pointer', ['void']]],
            'SidList': [0x8, ['pointer', ['_FILE_GET_QUOTA_INFORMATION']]],
            'SidListLength': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_13a0': [
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
    '__unnamed_13a4': [
        0x10,
        {
            'InterfaceType': [0x0, ['pointer', ['_GUID']]],
            'Size': [0x4, ['unsigned short']],
            'Version': [0x6, ['unsigned short']],
            'Interface': [0x8, ['pointer', ['_INTERFACE']]],
            'InterfaceSpecificData': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_13a8': [
        0x4,
        {
            'Capabilities': [0x0, ['pointer', ['_DEVICE_CAPABILITIES']]],
        },
    ],
    '__unnamed_13ac': [
        0x4,
        {
            'IoResourceRequirementList': [
                0x0,
                ['pointer', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
        },
    ],
    '__unnamed_13ae': [
        0x10,
        {
            'WhichSpace': [0x0, ['unsigned long']],
            'Buffer': [0x4, ['pointer', ['void']]],
            'Offset': [0x8, ['unsigned long']],
            'Length': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_13b0': [
        0x1,
        {
            'Lock': [0x0, ['unsigned char']],
        },
    ],
    '__unnamed_13b4': [
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
    '__unnamed_13b8': [
        0x8,
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
            'LocaleId': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_13bc': [
        0x8,
        {
            'InPath': [0x0, ['unsigned char']],
            'Reserved': [0x1, ['array', 3, ['unsigned char']]],
            'Type': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DeviceUsageTypeUndefined',
                            1: 'DeviceUsageTypePaging',
                            2: 'DeviceUsageTypeHibernation',
                            3: 'DeviceUsageTypeDumpFile',
                            4: 'DeviceUsageTypeBoot',
                            5: 'DeviceUsageTypePostDisplay',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_13c0': [
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
    '__unnamed_13c4': [
        0x4,
        {
            'PowerSequence': [0x0, ['pointer', ['_POWER_SEQUENCE']]],
        },
    ],
    '__unnamed_13cc': [
        0x10,
        {
            'SystemContext': [0x0, ['unsigned long']],
            'SystemPowerStateContext': [0x0, ['_SYSTEM_POWER_STATE_CONTEXT']],
            'Type': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'SystemPowerState', 1: 'DevicePowerState'},
                    ),
                ],
            ],
            'State': [0x8, ['_POWER_STATE']],
            'ShutdownType': [
                0xC,
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
    '__unnamed_13d0': [
        0x8,
        {
            'AllocatedResources': [0x0, ['pointer', ['_CM_RESOURCE_LIST']]],
            'AllocatedResourcesTranslated': [
                0x4,
                ['pointer', ['_CM_RESOURCE_LIST']],
            ],
        },
    ],
    '__unnamed_13d2': [
        0x10,
        {
            'ProviderId': [0x0, ['unsigned long']],
            'DataPath': [0x4, ['pointer', ['void']]],
            'BufferSize': [0x8, ['unsigned long']],
            'Buffer': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_13d4': [
        0x10,
        {
            'Argument1': [0x0, ['pointer', ['void']]],
            'Argument2': [0x4, ['pointer', ['void']]],
            'Argument3': [0x8, ['pointer', ['void']]],
            'Argument4': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_13d6': [
        0x10,
        {
            'Create': [0x0, ['__unnamed_1369']],
            'CreatePipe': [0x0, ['__unnamed_136d']],
            'CreateMailslot': [0x0, ['__unnamed_1371']],
            'Read': [0x0, ['__unnamed_1373']],
            'Write': [0x0, ['__unnamed_1373']],
            'QueryDirectory': [0x0, ['__unnamed_1377']],
            'NotifyDirectory': [0x0, ['__unnamed_1379']],
            'QueryFile': [0x0, ['__unnamed_137b']],
            'SetFile': [0x0, ['__unnamed_137d']],
            'QueryEa': [0x0, ['__unnamed_137f']],
            'SetEa': [0x0, ['__unnamed_1381']],
            'QueryVolume': [0x0, ['__unnamed_1385']],
            'SetVolume': [0x0, ['__unnamed_1385']],
            'FileSystemControl': [0x0, ['__unnamed_1387']],
            'LockControl': [0x0, ['__unnamed_138a']],
            'DeviceIoControl': [0x0, ['__unnamed_138c']],
            'QuerySecurity': [0x0, ['__unnamed_138e']],
            'SetSecurity': [0x0, ['__unnamed_1390']],
            'MountVolume': [0x0, ['__unnamed_1394']],
            'VerifyVolume': [0x0, ['__unnamed_1394']],
            'Scsi': [0x0, ['__unnamed_1398']],
            'QueryQuota': [0x0, ['__unnamed_139c']],
            'SetQuota': [0x0, ['__unnamed_1381']],
            'QueryDeviceRelations': [0x0, ['__unnamed_13a0']],
            'QueryInterface': [0x0, ['__unnamed_13a4']],
            'DeviceCapabilities': [0x0, ['__unnamed_13a8']],
            'FilterResourceRequirements': [0x0, ['__unnamed_13ac']],
            'ReadWriteConfig': [0x0, ['__unnamed_13ae']],
            'SetLock': [0x0, ['__unnamed_13b0']],
            'QueryId': [0x0, ['__unnamed_13b4']],
            'QueryDeviceText': [0x0, ['__unnamed_13b8']],
            'UsageNotification': [0x0, ['__unnamed_13bc']],
            'WaitWake': [0x0, ['__unnamed_13c0']],
            'PowerSequence': [0x0, ['__unnamed_13c4']],
            'Power': [0x0, ['__unnamed_13cc']],
            'StartDevice': [0x0, ['__unnamed_13d0']],
            'WMI': [0x0, ['__unnamed_13d2']],
            'Others': [0x0, ['__unnamed_13d4']],
        },
    ],
    '_IO_STACK_LOCATION': [
        0x24,
        {
            'MajorFunction': [0x0, ['unsigned char']],
            'MinorFunction': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned char']],
            'Control': [0x3, ['unsigned char']],
            'Parameters': [0x4, ['__unnamed_13d6']],
            'DeviceObject': [0x14, ['pointer', ['_DEVICE_OBJECT']]],
            'FileObject': [0x18, ['pointer', ['_FILE_OBJECT']]],
            'CompletionRoutine': [0x1C, ['pointer', ['void']]],
            'Context': [0x20, ['pointer', ['void']]],
        },
    ],
    '__unnamed_13ec': [
        0x28,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Wcb': [0x0, ['_WAIT_CONTEXT_BLOCK']],
        },
    ],
    '_DEVICE_OBJECT': [
        0xB8,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['unsigned short']],
            'ReferenceCount': [0x4, ['long']],
            'DriverObject': [0x8, ['pointer', ['_DRIVER_OBJECT']]],
            'NextDevice': [0xC, ['pointer', ['_DEVICE_OBJECT']]],
            'AttachedDevice': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'CurrentIrp': [0x14, ['pointer', ['_IRP']]],
            'Timer': [0x18, ['pointer', ['_IO_TIMER']]],
            'Flags': [0x1C, ['unsigned long']],
            'Characteristics': [0x20, ['unsigned long']],
            'Vpb': [0x24, ['pointer', ['_VPB']]],
            'DeviceExtension': [0x28, ['pointer', ['void']]],
            'DeviceType': [0x2C, ['unsigned long']],
            'StackSize': [0x30, ['unsigned char']],
            'Queue': [0x34, ['__unnamed_13ec']],
            'AlignmentRequirement': [0x5C, ['unsigned long']],
            'DeviceQueue': [0x60, ['_KDEVICE_QUEUE']],
            'Dpc': [0x74, ['_KDPC']],
            'ActiveThreadCount': [0x94, ['unsigned long']],
            'SecurityDescriptor': [0x98, ['pointer', ['void']]],
            'DeviceLock': [0x9C, ['_KEVENT']],
            'SectorSize': [0xAC, ['unsigned short']],
            'Spare1': [0xAE, ['unsigned short']],
            'DeviceObjectExtension': [
                0xB0,
                ['pointer', ['_DEVOBJ_EXTENSION']],
            ],
            'Reserved': [0xB4, ['pointer', ['void']]],
        },
    ],
    '_KDPC': [
        0x20,
        {
            'TargetInfoAsUlong': [0x0, ['unsigned long']],
            'Type': [0x0, ['unsigned char']],
            'Importance': [0x1, ['unsigned char']],
            'Number': [0x2, ['unsigned short']],
            'DpcListEntry': [0x4, ['_SINGLE_LIST_ENTRY']],
            'ProcessorHistory': [0x8, ['unsigned long']],
            'DeferredRoutine': [0xC, ['pointer', ['void']]],
            'DeferredContext': [0x10, ['pointer', ['void']]],
            'SystemArgument1': [0x14, ['pointer', ['void']]],
            'SystemArgument2': [0x18, ['pointer', ['void']]],
            'DpcData': [0x1C, ['pointer', ['void']]],
        },
    ],
    '_IO_DRIVER_CREATE_CONTEXT': [
        0x10,
        {
            'Size': [0x0, ['short']],
            'ExtraCreateParameter': [0x4, ['pointer', ['_ECP_LIST']]],
            'DeviceObjectHint': [0x8, ['pointer', ['void']]],
            'TxnParameters': [0xC, ['pointer', ['_TXN_PARAMETER_BLOCK']]],
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
    '_OBJECT_HANDLE_INFORMATION': [
        0x8,
        {
            'HandleAttributes': [0x0, ['unsigned long']],
            'GrantedAccess': [0x4, ['unsigned long']],
        },
    ],
    '_MDL': [
        0x1C,
        {
            'Next': [0x0, ['pointer', ['_MDL']]],
            'Size': [0x4, ['short']],
            'MdlFlags': [0x6, ['short']],
            'Process': [0x8, ['pointer', ['_EPROCESS']]],
            'MappedSystemVa': [0xC, ['pointer', ['void']]],
            'StartVa': [0x10, ['pointer', ['void']]],
            'ByteCount': [0x14, ['unsigned long']],
            'ByteOffset': [0x18, ['unsigned long']],
        },
    ],
    '_EVENT_DATA_DESCRIPTOR': [
        0x10,
        {
            'Ptr': [0x0, ['unsigned long long']],
            'Size': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
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
    '_EVENT_RECORD': [
        0x68,
        {
            'EventHeader': [0x0, ['_EVENT_HEADER']],
            'BufferContext': [0x50, ['_ETW_BUFFER_CONTEXT']],
            'ExtendedDataCount': [0x54, ['unsigned short']],
            'UserDataLength': [0x56, ['unsigned short']],
            'ExtendedData': [
                0x58,
                ['pointer', ['_EVENT_HEADER_EXTENDED_DATA_ITEM']],
            ],
            'UserData': [0x5C, ['pointer', ['void']]],
            'UserContext': [0x60, ['pointer', ['void']]],
        },
    ],
    '_PERFINFO_GROUPMASK': [
        0x20,
        {
            'Masks': [0x0, ['array', 8, ['unsigned long']]],
        },
    ],
    '_FILE_OBJECT': [
        0x80,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'DeviceObject': [0x4, ['pointer', ['_DEVICE_OBJECT']]],
            'Vpb': [0x8, ['pointer', ['_VPB']]],
            'FsContext': [0xC, ['pointer', ['void']]],
            'FsContext2': [0x10, ['pointer', ['void']]],
            'SectionObjectPointer': [
                0x14,
                ['pointer', ['_SECTION_OBJECT_POINTERS']],
            ],
            'PrivateCacheMap': [0x18, ['pointer', ['void']]],
            'FinalStatus': [0x1C, ['long']],
            'RelatedFileObject': [0x20, ['pointer', ['_FILE_OBJECT']]],
            'LockOperation': [0x24, ['unsigned char']],
            'DeletePending': [0x25, ['unsigned char']],
            'ReadAccess': [0x26, ['unsigned char']],
            'WriteAccess': [0x27, ['unsigned char']],
            'DeleteAccess': [0x28, ['unsigned char']],
            'SharedRead': [0x29, ['unsigned char']],
            'SharedWrite': [0x2A, ['unsigned char']],
            'SharedDelete': [0x2B, ['unsigned char']],
            'Flags': [0x2C, ['unsigned long']],
            'FileName': [0x30, ['_UNICODE_STRING']],
            'CurrentByteOffset': [0x38, ['_LARGE_INTEGER']],
            'Waiters': [0x40, ['unsigned long']],
            'Busy': [0x44, ['unsigned long']],
            'LastLock': [0x48, ['pointer', ['void']]],
            'Lock': [0x4C, ['_KEVENT']],
            'Event': [0x5C, ['_KEVENT']],
            'CompletionContext': [
                0x6C,
                ['pointer', ['_IO_COMPLETION_CONTEXT']],
            ],
            'IrpListLock': [0x70, ['unsigned long']],
            'IrpList': [0x74, ['_LIST_ENTRY']],
            'FileObjectExtension': [0x7C, ['pointer', ['void']]],
        },
    ],
    '_EX_RUNDOWN_REF': [
        0x4,
        {
            'Count': [0x0, ['unsigned long']],
            'Ptr': [0x0, ['pointer', ['void']]],
        },
    ],
    '_MM_PAGE_ACCESS_INFO_HEADER': [
        0x38,
        {
            'Link': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Type': [
                0x4,
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
            'EmptySequenceNumber': [0x8, ['unsigned long']],
            'CurrentFileIndex': [0x8, ['unsigned long']],
            'CreateTime': [0x10, ['unsigned long long']],
            'EmptyTime': [0x18, ['unsigned long long']],
            'TempEntry': [0x18, ['pointer', ['_MM_PAGE_ACCESS_INFO']]],
            'PageEntry': [0x20, ['pointer', ['_MM_PAGE_ACCESS_INFO']]],
            'FileEntry': [0x24, ['pointer', ['unsigned long']]],
            'FirstFileEntry': [0x28, ['pointer', ['unsigned long']]],
            'Process': [0x2C, ['pointer', ['_EPROCESS']]],
            'SessionId': [0x30, ['unsigned long']],
            'PageFrameEntry': [0x20, ['pointer', ['unsigned long']]],
            'LastPageFrameEntry': [0x24, ['pointer', ['unsigned long']]],
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
    '_FSRTL_ADVANCED_FCB_HEADER': [
        0x48,
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
            'Resource': [0x8, ['pointer', ['_ERESOURCE']]],
            'PagingIoResource': [0xC, ['pointer', ['_ERESOURCE']]],
            'AllocationSize': [0x10, ['_LARGE_INTEGER']],
            'FileSize': [0x18, ['_LARGE_INTEGER']],
            'ValidDataLength': [0x20, ['_LARGE_INTEGER']],
            'FastMutex': [0x28, ['pointer', ['_FAST_MUTEX']]],
            'FilterContexts': [0x2C, ['_LIST_ENTRY']],
            'PushLock': [0x34, ['_EX_PUSH_LOCK']],
            'FileContextSupportPointer': [
                0x38,
                ['pointer', ['pointer', ['void']]],
            ],
            'Oplock': [0x3C, ['pointer', ['void']]],
            'ReservedForRemote': [0x3C, ['pointer', ['void']]],
            'ReservedContext': [0x40, ['pointer', ['void']]],
        },
    ],
    '_iobuf': [
        0x20,
        {
            '_ptr': [0x0, ['pointer', ['unsigned char']]],
            '_cnt': [0x4, ['long']],
            '_base': [0x8, ['pointer', ['unsigned char']]],
            '_flag': [0xC, ['long']],
            '_file': [0x10, ['long']],
            '_charbuf': [0x14, ['long']],
            '_bufsiz': [0x18, ['long']],
            '_tmpfname': [0x1C, ['pointer', ['unsigned char']]],
        },
    ],
    '__unnamed_1578': [
        0x8,
        {
            'Long': [0x0, ['unsigned long long']],
            'VolatileLong': [0x0, ['unsigned long long']],
            'HighLow': [0x0, ['_MMPTE_HIGHLOW']],
            'Flush': [0x0, ['_HARDWARE_PTE']],
            'Hard': [0x0, ['_MMPTE_HARDWARE']],
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
            'u': [0x0, ['__unnamed_1578']],
        },
    ],
    '_EX_PUSH_LOCK_CACHE_AWARE': [
        0x80,
        {
            'Locks': [0x0, ['array', 32, ['pointer', ['_EX_PUSH_LOCK']]]],
        },
    ],
    '_ERESOURCE': [
        0x38,
        {
            'SystemResourcesList': [0x0, ['_LIST_ENTRY']],
            'OwnerTable': [0x8, ['pointer', ['_OWNER_ENTRY']]],
            'ActiveCount': [0xC, ['short']],
            'Flag': [0xE, ['unsigned short']],
            'ReservedLowFlags': [0xE, ['unsigned char']],
            'WaiterPriority': [0xF, ['unsigned char']],
            'SharedWaiters': [0x10, ['pointer', ['_KSEMAPHORE']]],
            'ExclusiveWaiters': [0x14, ['pointer', ['_KEVENT']]],
            'OwnerEntry': [0x18, ['_OWNER_ENTRY']],
            'ActiveEntries': [0x20, ['unsigned long']],
            'ContentionCount': [0x24, ['unsigned long']],
            'NumberOfSharedWaiters': [0x28, ['unsigned long']],
            'NumberOfExclusiveWaiters': [0x2C, ['unsigned long']],
            'Address': [0x30, ['pointer', ['void']]],
            'CreatorBackTraceIndex': [0x30, ['unsigned long']],
            'SpinLock': [0x34, ['unsigned long']],
        },
    ],
    '_MI_CACHED_PTE': [
        0x8,
        {
            'GlobalTimeStamp': [0x0, ['unsigned long']],
            'PteIndex': [0x4, ['unsigned long']],
            'Long': [0x0, ['long long']],
        },
    ],
    '_KLOCK_QUEUE_HANDLE': [
        0xC,
        {
            'LockQueue': [0x0, ['_KSPIN_LOCK_QUEUE']],
            'OldIrql': [0x8, ['unsigned char']],
        },
    ],
    '_MMPFNLIST': [
        0x14,
        {
            'Total': [0x0, ['unsigned long']],
            'ListName': [
                0x4,
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
            'Flink': [0x8, ['unsigned long']],
            'Blink': [0xC, ['unsigned long']],
            'Lock': [0x10, ['unsigned long']],
        },
    ],
    '__unnamed_15ba': [
        0x4,
        {
            'Flink': [0x0, ['unsigned long']],
            'WsIndex': [0x0, ['unsigned long']],
            'Event': [0x0, ['pointer', ['_KEVENT']]],
            'Next': [0x0, ['pointer', ['void']]],
            'VolatileNext': [0x0, ['pointer', ['void']]],
            'KernelStackOwner': [0x0, ['pointer', ['_KTHREAD']]],
            'NextStackPfn': [0x0, ['_SINGLE_LIST_ENTRY']],
        },
    ],
    '__unnamed_15bf': [
        0x4,
        {
            'Blink': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'TbFlushStamp': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'SpareBlink': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageProtoPte': [0x0, ['pointer', ['_MMPTE']]],
            'ShareCount': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_15c2': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'VolatileReferenceCount': [0x0, ['short']],
            'ShortFlags': [0x2, ['unsigned short']],
            'VolatileShortFlags': [0x2, ['unsigned short']],
        },
    ],
    '__unnamed_15c4': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'e1': [0x2, ['_MMPFNENTRY']],
            'e2': [0x0, ['__unnamed_15c2']],
        },
    ],
    '__unnamed_15c8': [
        0x4,
        {
            'PteFrame': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'PageIdentity': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'PrototypePte': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'PageColor': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'EntireField': [0x0, ['unsigned long']],
        },
    ],
    '_MMPFN': [
        0x1C,
        {
            'u1': [0x0, ['__unnamed_15ba']],
            'u2': [0x4, ['__unnamed_15bf']],
            'PteAddress': [0x8, ['pointer', ['_MMPTE']]],
            'VolatilePteAddress': [0x8, ['pointer', ['void']]],
            'Lock': [0x8, ['long']],
            'PteLong': [0x8, ['unsigned long']],
            'u3': [0xC, ['__unnamed_15c4']],
            'OriginalPte': [0x10, ['_MMPTE']],
            'u4': [0x18, ['__unnamed_15c8']],
        },
    ],
    '_MI_SYSTEM_PTE_TYPE': [
        0x38,
        {
            'Bitmap': [0x0, ['_RTL_BITMAP']],
            'BasePte': [0x8, ['pointer', ['_MMPTE']]],
            'Flags': [0xC, ['unsigned long']],
            'VaType': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'MiVaUnused',
                            1: 'MiVaSessionSpace',
                            2: 'MiVaProcessSpace',
                            3: 'MiVaBootLoaded',
                            4: 'MiVaPfnDatabase',
                            5: 'MiVaNonPagedPool',
                            6: 'MiVaPagedPool',
                            7: 'MiVaSpecialPoolPaged',
                            8: 'MiVaSystemCache',
                            9: 'MiVaSystemPtes',
                            10: 'MiVaHal',
                            11: 'MiVaSessionGlobalSpace',
                            12: 'MiVaDriverImages',
                            13: 'MiVaSpecialPoolNonPaged',
                            14: 'MiVaPagedProtoPool',
                            15: 'MiVaMaximumType',
                            16: 'MiVaSystemPtesLarge',
                        },
                    ),
                ],
            ],
            'FailureCount': [0x14, ['pointer', ['unsigned long']]],
            'PteFailures': [0x18, ['unsigned long']],
            'SpinLock': [0x1C, ['unsigned long']],
            'GlobalMutex': [0x1C, ['pointer', ['_FAST_MUTEX']]],
            'Vm': [0x20, ['pointer', ['_MMSUPPORT']]],
            'TotalSystemPtes': [0x24, ['unsigned long']],
            'Hint': [0x28, ['unsigned long']],
            'CachedPtes': [0x2C, ['pointer', ['_MI_CACHED_PTE']]],
            'TotalFreeSystemPtes': [0x30, ['unsigned long']],
            'CachedPteCount': [0x34, ['long']],
        },
    ],
    '__unnamed_15e8': [
        0x4,
        {
            'VirtualAddress': [0x0, ['pointer', ['void']]],
            'Long': [0x0, ['unsigned long']],
            'e1': [0x0, ['_MMWSLENTRY']],
            'e2': [0x0, ['_MMWSLE_FREE_ENTRY']],
        },
    ],
    '_MMWSLE': [
        0x4,
        {
            'u1': [0x0, ['__unnamed_15e8']],
        },
    ],
    '_MMWSL': [
        0xE1C,
        {
            'FirstFree': [0x0, ['unsigned long']],
            'FirstDynamic': [0x4, ['unsigned long']],
            'LastEntry': [0x8, ['unsigned long']],
            'NextSlot': [0xC, ['unsigned long']],
            'LastInitializedWsle': [0x10, ['unsigned long']],
            'NextAgingSlot': [0x14, ['unsigned long']],
            'NextAccessClearingSlot': [0x18, ['unsigned long']],
            'LastAccessClearingRemainder': [0x1C, ['unsigned long']],
            'LastAgingRemainder': [0x20, ['unsigned long']],
            'WsleSize': [0x24, ['unsigned long']],
            'NonDirectCount': [0x28, ['unsigned long']],
            'LowestPagableAddress': [0x2C, ['pointer', ['void']]],
            'NonDirectHash': [0x30, ['pointer', ['_MMWSLE_NONDIRECT_HASH']]],
            'HashTableStart': [0x34, ['pointer', ['_MMWSLE_HASH']]],
            'HighestPermittedHashAddress': [
                0x38,
                ['pointer', ['_MMWSLE_HASH']],
            ],
            'ActiveWsleCounts': [0x3C, ['array', 16, ['unsigned long']]],
            'ActiveWsles': [0x7C, ['array', 16, ['_MI_ACTIVE_WSLE_LISTHEAD']]],
            'Wsle': [0xFC, ['pointer', ['_MMWSLE']]],
            'UserVaInfo': [0x100, ['_MI_USER_VA_INFO']],
        },
    ],
    '_MMSUPPORT': [
        0x78,
        {
            'ExitGate': [0x0, ['pointer', ['_KGATE']]],
            'AccessLog': [0x4, ['pointer', ['void']]],
            'WorkingSetMutex': [0x8, ['_EX_PUSH_LOCK']],
            'WorkingSetExpansionLinks': [0xC, ['_LIST_ENTRY']],
            'AgeDistribution': [0x14, ['array', 7, ['unsigned long']]],
            'MinimumWorkingSetSize': [0x30, ['unsigned long']],
            'WorkingSetLeafSize': [0x34, ['unsigned long']],
            'WorkingSetLeafPrivateSize': [0x38, ['unsigned long']],
            'WorkingSetSize': [0x3C, ['unsigned long']],
            'WorkingSetPrivateSize': [0x40, ['unsigned long']],
            'MaximumWorkingSetSize': [0x44, ['unsigned long']],
            'ChargedWslePages': [0x48, ['unsigned long']],
            'ActualWslePages': [0x4C, ['unsigned long']],
            'WorkingSetSizeOverhead': [0x50, ['unsigned long']],
            'PeakWorkingSetSize': [0x54, ['unsigned long']],
            'HardFaultCount': [0x58, ['unsigned long']],
            'VmWorkingSetList': [0x5C, ['pointer', ['_MMWSL']]],
            'NextPageColor': [0x60, ['unsigned short']],
            'LastTrimStamp': [0x62, ['unsigned short']],
            'PageFaultCount': [0x64, ['unsigned long']],
            'TrimmedPageCount': [0x68, ['unsigned long']],
            'ForceTrimPages': [0x6C, ['unsigned long']],
            'Flags': [0x70, ['_MMSUPPORT_FLAGS']],
            'WsSwapSupport': [0x74, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1601': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MMSECTION_FLAGS']],
        },
    ],
    '__unnamed_160b': [
        0xC,
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
                        start_bit=16, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'CantMove': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'BitMap': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=31, native_type='unsigned long'
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
            'FlushInProgressCount': [0x8, ['unsigned long']],
            'NumberOfSubsections': [0x8, ['unsigned long']],
            'SeImageStub': [
                0x8,
                ['pointer', ['_MI_IMAGE_SECURITY_REFERENCE']],
            ],
        },
    ],
    '__unnamed_160d': [
        0xC,
        {
            'e2': [0x0, ['__unnamed_160b']],
        },
    ],
    '_CONTROL_AREA': [
        0x50,
        {
            'Segment': [0x0, ['pointer', ['_SEGMENT']]],
            'ListHead': [0x4, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0xC, ['unsigned long']],
            'NumberOfPfnReferences': [0x10, ['unsigned long']],
            'NumberOfMappedViews': [0x14, ['unsigned long']],
            'NumberOfUserReferences': [0x18, ['unsigned long']],
            'u': [0x1C, ['__unnamed_1601']],
            'FilePointer': [0x20, ['_EX_FAST_REF']],
            'ControlAreaLock': [0x24, ['long']],
            'ModifiedWriteCount': [0x28, ['unsigned long']],
            'WaitList': [0x2C, ['pointer', ['_MI_CONTROL_AREA_WAIT_BLOCK']]],
            'u2': [0x30, ['__unnamed_160d']],
            'LockedPages': [0x40, ['unsigned long long']],
            'FileObjectLock': [0x48, ['_EX_PUSH_LOCK']],
        },
    ],
    '_MM_STORE_KEY': [
        0x4,
        {
            'KeyLow': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=28, native_type='unsigned long'),
                ],
            ],
            'KeyHigh': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'EntireKey': [0x0, ['unsigned long']],
        },
    ],
    '_MMPAGING_FILE': [
        0x80,
        {
            'Size': [0x0, ['unsigned long']],
            'MaximumSize': [0x4, ['unsigned long']],
            'MinimumSize': [0x8, ['unsigned long']],
            'FreeSpace': [0xC, ['unsigned long']],
            'PeakUsage': [0x10, ['unsigned long']],
            'HighestPage': [0x14, ['unsigned long']],
            'FreeReservationSpace': [0x18, ['unsigned long']],
            'LargestReserveCluster': [0x1C, ['unsigned long']],
            'File': [0x20, ['pointer', ['_FILE_OBJECT']]],
            'Entry': [
                0x24,
                ['array', 2, ['pointer', ['_MMMOD_WRITER_MDL_ENTRY']]],
            ],
            'PfnsToFree': [0x30, ['_SLIST_HEADER']],
            'PageFileName': [0x38, ['_UNICODE_STRING']],
            'Bitmaps': [0x40, ['pointer', ['_MI_PAGING_FILE_SPACE_BITMAPS']]],
            'AllocationBitmapHint': [0x44, ['unsigned long']],
            'ReservationBitmapHint': [0x48, ['unsigned long']],
            'LargestNonReservedClusterSize': [0x4C, ['unsigned long']],
            'RefreshClusterSize': [0x50, ['unsigned long']],
            'LastRefreshClusterSize': [0x54, ['unsigned long']],
            'ReservedClusterSizeAggregate': [0x58, ['unsigned long']],
            'ToBeEvictedCount': [0x5C, ['unsigned long']],
            'HybridPriority': [0x60, ['unsigned long']],
            'PageFileNumber': [
                0x64,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'BootPartition': [
                0x64,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'WsSwapPagefile': [
                0x64,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'NoReservations': [
                0x64,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'Spare0': [
                0x64,
                [
                    'BitField',
                    dict(
                        start_bit=7, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AdriftMdls': [
                0x66,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Spare1': [
                0x66,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Spare2': [
                0x67,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'PageHashPages': [0x68, ['unsigned long']],
            'PageHashPagesPeak': [0x6C, ['unsigned long']],
            'PageHash': [0x70, ['pointer', ['unsigned long']]],
            'FileHandle': [0x74, ['pointer', ['void']]],
            'Lock': [0x78, ['unsigned long']],
            'LockOwner': [0x7C, ['pointer', ['_ETHREAD']]],
        },
    ],
    '_MI_PAGING_FILE_SPACE_BITMAPS': [
        0x18,
        {
            'RefCount': [0x0, ['unsigned long']],
            'Anchor': [0x0, ['pointer', ['_MI_PAGING_FILE_SPACE_BITMAPS']]],
            'AllocationBitmap': [0x4, ['_RTL_BITMAP']],
            'ReservationBitmap': [0xC, ['_RTL_BITMAP']],
            'EvictStoreBitmap': [0x14, ['pointer', ['_RTL_BITMAP']]],
        },
    ],
    '_RTL_BITMAP': [
        0x8,
        {
            'SizeOfBitMap': [0x0, ['unsigned long']],
            'Buffer': [0x4, ['pointer', ['unsigned long']]],
        },
    ],
    'tagSWITCH_CONTEXT': [
        0x60,
        {
            'Attribute': [0x0, ['tagSWITCH_CONTEXT_ATTRIBUTE']],
            'Data': [0x18, ['tagSWITCH_CONTEXT_DATA']],
        },
    ],
    '__unnamed_1657': [
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
                            4: '_HvpBuildMapForLoaderHive',
                            5: '_HvpInitMap',
                            6: '_HvLoadHive',
                            7: '_HvpMapHiveImage',
                            8: '_HvpRecoverData',
                            9: '_CmpValidateHiveSecurityDescriptors',
                            10: '_HvpEnlistBinInMap',
                            11: '_CmCheckRegistry',
                            12: '_CmRegistryIO',
                            13: '_CmCheckRegistry2',
                            14: '_CmpCheckKey',
                            15: '_CmpCheckValueList',
                            16: '_HvCheckHive',
                            17: '_HvCheckBin',
                            18: '_HvpGetLogEntryDirtyVector',
                            19: '_HvpReadLogEntryHeader',
                            20: '_HvpReadLogEntry',
                        },
                    ),
                ],
            ],
            'Status': [0x4, ['long']],
            'Point': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_165a': [
        0xC,
        {
            'Action': [0x0, ['unsigned long']],
            'Handle': [0x4, ['pointer', ['void']]],
            'Status': [0x8, ['long']],
        },
    ],
    '__unnamed_165c': [
        0x4,
        {
            'CheckStack': [0x0, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1660': [
        0x10,
        {
            'Cell': [0x0, ['unsigned long']],
            'CellPoint': [0x4, ['pointer', ['_CELL_DATA']]],
            'RootPoint': [0x8, ['pointer', ['void']]],
            'Index': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1662': [
        0x10,
        {
            'List': [0x0, ['pointer', ['_CELL_DATA']]],
            'Index': [0x4, ['unsigned long']],
            'Cell': [0x8, ['unsigned long']],
            'CellPoint': [0xC, ['pointer', ['_CELL_DATA']]],
        },
    ],
    '__unnamed_1666': [
        0xC,
        {
            'Space': [0x0, ['unsigned long']],
            'MapPoint': [0x4, ['unsigned long']],
            'BinPoint': [0x8, ['pointer', ['_HBIN']]],
        },
    ],
    '__unnamed_166a': [
        0x8,
        {
            'Bin': [0x0, ['pointer', ['_HBIN']]],
            'CellPoint': [0x4, ['pointer', ['_HCELL']]],
        },
    ],
    '__unnamed_166c': [
        0x4,
        {
            'FileOffset': [0x0, ['unsigned long']],
        },
    ],
    '_HIVE_LOAD_FAILURE': [
        0x120,
        {
            'Hive': [0x0, ['pointer', ['_HHIVE']]],
            'Index': [0x4, ['unsigned long']],
            'RecoverableIndex': [0x8, ['unsigned long']],
            'Locations': [0xC, ['array', 8, ['__unnamed_1657']]],
            'RecoverableLocations': [0x6C, ['array', 8, ['__unnamed_1657']]],
            'RegistryIO': [0xCC, ['__unnamed_165a']],
            'CheckRegistry2': [0xD8, ['__unnamed_165c']],
            'CheckKey': [0xDC, ['__unnamed_1660']],
            'CheckValueList': [0xEC, ['__unnamed_1662']],
            'CheckHive': [0xFC, ['__unnamed_1666']],
            'CheckHive1': [0x108, ['__unnamed_1666']],
            'CheckBin': [0x114, ['__unnamed_166a']],
            'RecoverData': [0x11C, ['__unnamed_166c']],
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
        0x18,
        {
            'Version': [0x0, ['unsigned long']],
            'Name': [0x4, ['pointer', ['_UNICODE_STRING']]],
            'CounterCount': [0x8, ['unsigned long']],
            'Counters': [0xC, ['pointer', ['_PCW_COUNTER_DESCRIPTOR']]],
            'Callback': [0x10, ['pointer', ['void']]],
            'CallbackContext': [0x14, ['pointer', ['void']]],
        },
    ],
    '_PCW_PROCESSOR_INFO': [
        0xB8,
        {
            'IdleTime': [0x0, ['unsigned long long']],
            'AvailableTime': [0x8, ['unsigned long long']],
            'UserTime': [0x10, ['unsigned long long']],
            'KernelTime': [0x18, ['unsigned long long']],
            'Interrupts': [0x20, ['unsigned long']],
            'DpcTime': [0x28, ['unsigned long long']],
            'InterruptTime': [0x30, ['unsigned long long']],
            'ClockInterrupts': [0x38, ['unsigned long']],
            'DpcCount': [0x3C, ['unsigned long']],
            'DpcRate': [0x40, ['unsigned long']],
            'C1Time': [0x48, ['unsigned long long']],
            'C2Time': [0x50, ['unsigned long long']],
            'C3Time': [0x58, ['unsigned long long']],
            'C1Transitions': [0x60, ['unsigned long long']],
            'C2Transitions': [0x68, ['unsigned long long']],
            'C3Transitions': [0x70, ['unsigned long long']],
            'ParkingStatus': [0x78, ['unsigned long']],
            'CurrentFrequency': [0x7C, ['unsigned long']],
            'PercentMaxFrequency': [0x80, ['unsigned long']],
            'StateFlags': [0x84, ['unsigned long']],
            'NominalThroughput': [0x88, ['unsigned long']],
            'ActiveThroughput': [0x8C, ['unsigned long']],
            'ScaledThroughput': [0x90, ['unsigned long long']],
            'ScaledKernelThroughput': [0x98, ['unsigned long long']],
            'AverageIdleTime': [0xA0, ['unsigned long long']],
            'IdleBreakEvents': [0xA8, ['unsigned long long']],
            'PerformanceLimit': [0xB0, ['unsigned long']],
            'PerformanceLimitFlags': [0xB4, ['unsigned long']],
        },
    ],
    '_PCW_DATA': [
        0x8,
        {
            'Data': [0x0, ['pointer', ['void']]],
            'Size': [0x4, ['unsigned long']],
        },
    ],
    '_SYNCH_COUNTERS': [
        0xB8,
        {
            'SpinLockAcquireCount': [0x0, ['unsigned long']],
            'SpinLockContentionCount': [0x4, ['unsigned long']],
            'SpinLockSpinCount': [0x8, ['unsigned long']],
            'IpiSendRequestBroadcastCount': [0xC, ['unsigned long']],
            'IpiSendRequestRoutineCount': [0x10, ['unsigned long']],
            'IpiSendSoftwareInterruptCount': [0x14, ['unsigned long']],
            'ExInitializeResourceCount': [0x18, ['unsigned long']],
            'ExReInitializeResourceCount': [0x1C, ['unsigned long']],
            'ExDeleteResourceCount': [0x20, ['unsigned long']],
            'ExecutiveResourceAcquiresCount': [0x24, ['unsigned long']],
            'ExecutiveResourceContentionsCount': [0x28, ['unsigned long']],
            'ExecutiveResourceReleaseExclusiveCount': [
                0x2C,
                ['unsigned long'],
            ],
            'ExecutiveResourceReleaseSharedCount': [0x30, ['unsigned long']],
            'ExecutiveResourceConvertsCount': [0x34, ['unsigned long']],
            'ExAcqResExclusiveAttempts': [0x38, ['unsigned long']],
            'ExAcqResExclusiveAcquiresExclusive': [0x3C, ['unsigned long']],
            'ExAcqResExclusiveAcquiresExclusiveRecursive': [
                0x40,
                ['unsigned long'],
            ],
            'ExAcqResExclusiveWaits': [0x44, ['unsigned long']],
            'ExAcqResExclusiveNotAcquires': [0x48, ['unsigned long']],
            'ExAcqResSharedAttempts': [0x4C, ['unsigned long']],
            'ExAcqResSharedAcquiresExclusive': [0x50, ['unsigned long']],
            'ExAcqResSharedAcquiresShared': [0x54, ['unsigned long']],
            'ExAcqResSharedAcquiresSharedRecursive': [0x58, ['unsigned long']],
            'ExAcqResSharedWaits': [0x5C, ['unsigned long']],
            'ExAcqResSharedNotAcquires': [0x60, ['unsigned long']],
            'ExAcqResSharedStarveExclusiveAttempts': [0x64, ['unsigned long']],
            'ExAcqResSharedStarveExclusiveAcquiresExclusive': [
                0x68,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveAcquiresShared': [
                0x6C,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveAcquiresSharedRecursive': [
                0x70,
                ['unsigned long'],
            ],
            'ExAcqResSharedStarveExclusiveWaits': [0x74, ['unsigned long']],
            'ExAcqResSharedStarveExclusiveNotAcquires': [
                0x78,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAttempts': [
                0x7C,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAcquiresExclusive': [
                0x80,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAcquiresShared': [
                0x84,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive': [
                0x88,
                ['unsigned long'],
            ],
            'ExAcqResSharedWaitForExclusiveWaits': [0x8C, ['unsigned long']],
            'ExAcqResSharedWaitForExclusiveNotAcquires': [
                0x90,
                ['unsigned long'],
            ],
            'ExSetResOwnerPointerExclusive': [0x94, ['unsigned long']],
            'ExSetResOwnerPointerSharedNew': [0x98, ['unsigned long']],
            'ExSetResOwnerPointerSharedOld': [0x9C, ['unsigned long']],
            'ExTryToAcqExclusiveAttempts': [0xA0, ['unsigned long']],
            'ExTryToAcqExclusiveAcquires': [0xA4, ['unsigned long']],
            'ExBoostExclusiveOwner': [0xA8, ['unsigned long']],
            'ExBoostSharedOwners': [0xAC, ['unsigned long']],
            'ExEtwSynchTrackingNotificationsCount': [0xB0, ['unsigned long']],
            'ExEtwSynchTrackingNotificationsAccountedCount': [
                0xB4,
                ['unsigned long'],
            ],
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
    '_FILESYSTEM_DISK_COUNTERS': [
        0x10,
        {
            'FsBytesRead': [0x0, ['unsigned long long']],
            'FsBytesWritten': [0x8, ['unsigned long long']],
        },
    ],
    '_THERMAL_ZONE_COUNTERS': [
        0xC,
        {
            'Temperature': [0x0, ['unsigned long']],
            'ThrottleLimit': [0x4, ['unsigned long']],
            'ThrottleReasons': [0x8, ['unsigned long']],
        },
    ],
    '_TEB32': [
        0xFE8,
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
            'PerflibData': [0xF64, ['unsigned long']],
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
            'ReservedForCodeCoverage': [0xF8C, ['unsigned long']],
            'ThreadPoolData': [0xF90, ['unsigned long']],
            'TlsExpansionSlots': [0xF94, ['unsigned long']],
            'MuiGeneration': [0xF98, ['unsigned long']],
            'IsImpersonating': [0xF9C, ['unsigned long']],
            'NlsCache': [0xFA0, ['unsigned long']],
            'pShimData': [0xFA4, ['unsigned long']],
            'HeapVirtualAffinity': [0xFA8, ['unsigned short']],
            'LowFragHeapDataSlot': [0xFAA, ['unsigned short']],
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
            'SessionAware': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned short'
                    ),
                ],
            ],
            'SpareSameTebBits': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0xFCC, ['unsigned long']],
            'TxnScopeExitCallback': [0xFD0, ['unsigned long']],
            'TxnScopeContext': [0xFD4, ['unsigned long']],
            'LockCount': [0xFD8, ['unsigned long']],
            'SpareUlong0': [0xFDC, ['unsigned long']],
            'ResourceRetValue': [0xFE0, ['unsigned long']],
            'ReservedForWdf': [0xFE4, ['unsigned long']],
        },
    ],
    '_TEB64': [
        0x1820,
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
            'Padding0': [0x2C4, ['array', 4, ['unsigned char']]],
            'ActivationContextStackPointer': [0x2C8, ['unsigned long long']],
            'SpareBytes': [0x2D0, ['array', 24, ['unsigned char']]],
            'TxFsContext': [0x2E8, ['unsigned long']],
            'Padding1': [0x2EC, ['array', 4, ['unsigned char']]],
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
            'Padding2': [0x1254, ['array', 4, ['unsigned char']]],
            'StaticUnicodeString': [0x1258, ['_STRING64']],
            'StaticUnicodeBuffer': [0x1268, ['array', 261, ['wchar']]],
            'Padding3': [0x1472, ['array', 6, ['unsigned char']]],
            'DeallocationStack': [0x1478, ['unsigned long long']],
            'TlsSlots': [0x1480, ['array', 64, ['unsigned long long']]],
            'TlsLinks': [0x1680, ['LIST_ENTRY64']],
            'Vdm': [0x1690, ['unsigned long long']],
            'ReservedForNtRpc': [0x1698, ['unsigned long long']],
            'DbgSsReserved': [0x16A0, ['array', 2, ['unsigned long long']]],
            'HardErrorMode': [0x16B0, ['unsigned long']],
            'Padding4': [0x16B4, ['array', 4, ['unsigned char']]],
            'Instrumentation': [0x16B8, ['array', 11, ['unsigned long long']]],
            'ActivityId': [0x1710, ['_GUID']],
            'SubProcessTag': [0x1720, ['unsigned long long']],
            'PerflibData': [0x1728, ['unsigned long long']],
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
            'Padding5': [0x174C, ['array', 4, ['unsigned char']]],
            'ReservedForPerf': [0x1750, ['unsigned long long']],
            'ReservedForOle': [0x1758, ['unsigned long long']],
            'WaitingOnLoaderLock': [0x1760, ['unsigned long']],
            'Padding6': [0x1764, ['array', 4, ['unsigned char']]],
            'SavedPriorityState': [0x1768, ['unsigned long long']],
            'ReservedForCodeCoverage': [0x1770, ['unsigned long long']],
            'ThreadPoolData': [0x1778, ['unsigned long long']],
            'TlsExpansionSlots': [0x1780, ['unsigned long long']],
            'DeallocationBStore': [0x1788, ['unsigned long long']],
            'BStoreLimit': [0x1790, ['unsigned long long']],
            'MuiGeneration': [0x1798, ['unsigned long']],
            'IsImpersonating': [0x179C, ['unsigned long']],
            'NlsCache': [0x17A0, ['unsigned long long']],
            'pShimData': [0x17A8, ['unsigned long long']],
            'HeapVirtualAffinity': [0x17B0, ['unsigned short']],
            'LowFragHeapDataSlot': [0x17B2, ['unsigned short']],
            'Padding7': [0x17B4, ['array', 4, ['unsigned char']]],
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
            'SessionAware': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned short'
                    ),
                ],
            ],
            'SpareSameTebBits': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0x17F0, ['unsigned long long']],
            'TxnScopeExitCallback': [0x17F8, ['unsigned long long']],
            'TxnScopeContext': [0x1800, ['unsigned long long']],
            'LockCount': [0x1808, ['unsigned long']],
            'SpareUlong0': [0x180C, ['unsigned long']],
            'ResourceRetValue': [0x1810, ['unsigned long long']],
            'ReservedForWdf': [0x1818, ['unsigned long long']],
        },
    ],
    '__unnamed_16ef': [
        0x10,
        {
            'ReservedEax': [0x0, ['unsigned long']],
            'ReservedEbx': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'InitialApicId': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedEcx': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'HypervisorPresent': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedEdx': [0xC, ['unsigned long']],
        },
    ],
    '_HV_CPUID_RESULT': [
        0x10,
        {
            'Eax': [0x0, ['unsigned long']],
            'Ebx': [0x4, ['unsigned long']],
            'Ecx': [0x8, ['unsigned long']],
            'Edx': [0xC, ['unsigned long']],
            'AsUINT32': [0x0, ['array', 4, ['unsigned long']]],
            'VersionAndFeatures': [0x0, ['__unnamed_16ef']],
            'HvVendorAndMaxFunction': [0x0, ['_HV_VENDOR_AND_MAX_FUNCTION']],
            'HvInterface': [0x0, ['_HV_HYPERVISOR_INTERFACE_INFO']],
            'MsHvVersion': [0x0, ['_HV_HYPERVISOR_VERSION_INFO']],
            'MsHvFeatures': [0x0, ['_HV_HYPERVISOR_FEATURES']],
            'MsHvEnlightenmentInformation': [
                0x0,
                ['_HV_ENLIGHTENMENT_INFORMATION'],
            ],
            'MsHvImplementationLimits': [0x0, ['_HV_IMPLEMENTATION_LIMITS']],
            'MsHvHardwareFeatures': [
                0x0,
                ['_HV_HYPERVISOR_HARDWARE_FEATURES'],
            ],
        },
    ],
    '_HV_VENDOR_AND_MAX_FUNCTION': [
        0x10,
        {
            'MaxFunction': [0x0, ['unsigned long']],
            'VendorName': [0x4, ['array', 12, ['unsigned char']]],
        },
    ],
    '_HV_HYPERVISOR_INTERFACE_INFO': [
        0x10,
        {
            'Interface': [0x0, ['unsigned long']],
            'ReservedEbx': [0x4, ['unsigned long']],
            'ReservedEcx': [0x8, ['unsigned long']],
            'ReservedEdx': [0xC, ['unsigned long']],
        },
    ],
    '_HV_HYPERVISOR_VERSION_INFO': [
        0x10,
        {
            'BuildNumber': [0x0, ['unsigned long']],
            'MinorVersion': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'MajorVersion': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ServicePack': [0x8, ['unsigned long']],
            'ServiceNumber': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'ServiceBranch': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_HV_HYPERVISOR_FEATURES': [
        0x10,
        {
            'PartitionPrivileges': [0x0, ['_HV_PARTITION_PRIVILEGE_MASK']],
            'MaxSupportedCState': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'HpetNeededForC3PowerState': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'MwaitAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'GuestDebuggingAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'PerformanceMonitorsAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'CpuDynamicPartitioningAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'XmmRegistersForFastHypercallAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'GuestIdleAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'HypervisorSleepStateSupportAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'NumaDistanceQueryAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'FrequencyMsrsAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'SyntheticMachineCheckAvailable': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'GuestCrashMsrsAvailable': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'DebugMsrsAvailable': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'Npiep1Available': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'DisableHypervisorAvailable': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved1': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_HV_HYPERVISOR_HARDWARE_FEATURES': [
        0x10,
        {
            'ApicOverlayAssistInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'MsrBitmapsInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ArchitecturalPerformanceCountersInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'SecondLevelAddressTranslationInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'DmaRemappingInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'InterruptRemappingInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'MemoryPatrolScrubberPresent': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'ReservedEbx': [0x4, ['unsigned long']],
            'ReservedEcx': [0x8, ['unsigned long']],
            'ReservedEdx': [0xC, ['unsigned long']],
        },
    ],
    '_HV_ENLIGHTENMENT_INFORMATION': [
        0x10,
        {
            'UseHypercallForAddressSpaceSwitch': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'UseHypercallForLocalFlush': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'UseHypercallForRemoteFlush': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'UseApicMsrs': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'UseMsrForReset': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'UseRelaxedTiming': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'UseDmaRemapping': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'UseInterruptRemapping': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'UseX2ApicMsrs': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'DeprecateAutoEoi': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'LongSpinWaitCount': [0x4, ['unsigned long']],
            'ReservedEcx': [0x8, ['unsigned long']],
            'ReservedEdx': [0xC, ['unsigned long']],
        },
    ],
    '_HV_IMPLEMENTATION_LIMITS': [
        0x10,
        {
            'MaxVirtualProcessorCount': [0x0, ['unsigned long']],
            'MaxLogicalProcessorCount': [0x4, ['unsigned long']],
            'MaxInterruptMappingCount': [0x8, ['unsigned long']],
            'ReservedEdx': [0xC, ['unsigned long']],
        },
    ],
    '_HV_PARTITION_PRIVILEGE_MASK': [
        0x8,
        {
            'AsUINT64': [0x0, ['unsigned long long']],
            'AccessVpRunTimeMsr': [
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
            'AccessPartitionReferenceCounter': [
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
            'AccessSynicMsrs': [
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
            'AccessSyntheticTimerMsrs': [
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
            'AccessApicMsrs': [
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
            'AccessHypercallMsrs': [
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
            'AccessVpIndex': [
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
            'AccessResetMsr': [
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
            'AccessStatsMsr': [
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
            'AccessPartitionReferenceTsc': [
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
            'AccessGuestIdleMsr': [
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
            'AccessFrequencyMsrs': [
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
            'AccessDebugMsrs': [
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
            'Reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CreatePartitions': [
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
            'AccessPartitionId': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=33,
                        end_bit=34,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'AccessMemoryPool': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=34,
                        end_bit=35,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'AdjustMessageBuffers': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=35,
                        end_bit=36,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PostMessages': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=36,
                        end_bit=37,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SignalEvents': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=37,
                        end_bit=38,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CreatePort': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=38,
                        end_bit=39,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ConnectPort': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=39,
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'AccessStats': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
                        end_bit=41,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved2': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=41,
                        end_bit=43,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Debugging': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=43,
                        end_bit=44,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'CpuManagement': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=44,
                        end_bit=45,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ConfigureProfiler': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=45,
                        end_bit=46,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'EnableExpandedStackwalking': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=46,
                        end_bit=47,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Reserved3': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=47,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_KTIMER_TABLE': [
        0x1840,
        {
            'TimerExpiry': [0x0, ['array', 16, ['pointer', ['_KTIMER']]]],
            'TimerEntries': [0x40, ['array', 256, ['_KTIMER_TABLE_ENTRY']]],
        },
    ],
    '_KTIMER_TABLE_ENTRY': [
        0x18,
        {
            'Lock': [0x0, ['unsigned long']],
            'Entry': [0x4, ['_LIST_ENTRY']],
            'Time': [0x10, ['_ULARGE_INTEGER']],
        },
    ],
    '_KAFFINITY_EX': [
        0xC,
        {
            'Count': [0x0, ['unsigned short']],
            'Size': [0x2, ['unsigned short']],
            'Reserved': [0x4, ['unsigned long']],
            'Bitmap': [0x8, ['array', 1, ['unsigned long']]],
        },
    ],
    '_XSTATE_SAVE': [
        0x20,
        {
            'Reserved1': [0x0, ['long long']],
            'Reserved2': [0x8, ['unsigned long']],
            'Prev': [0xC, ['pointer', ['_XSTATE_SAVE']]],
            'Reserved3': [0x10, ['pointer', ['_XSAVE_AREA']]],
            'Thread': [0x14, ['pointer', ['_KTHREAD']]],
            'Reserved4': [0x18, ['pointer', ['void']]],
            'Level': [0x1C, ['unsigned char']],
            'XStateContext': [0x0, ['_XSTATE_CONTEXT']],
        },
    ],
    '_XSAVE_AREA': [
        0x240,
        {
            'LegacyState': [0x0, ['_XSAVE_FORMAT']],
            'Header': [0x200, ['_XSAVE_AREA_HEADER']],
        },
    ],
    '_KSHARED_READY_QUEUE': [
        0x13C,
        {
            'Lock': [0x0, ['unsigned long']],
            'ReadySummary': [0x4, ['unsigned long']],
            'ReadyListHead': [0x8, ['array', 32, ['_LIST_ENTRY']]],
            'RunningSummary': [0x108, ['array', 32, ['unsigned char']]],
            'Span': [0x128, ['unsigned long']],
            'LowProcIndex': [0x12C, ['unsigned long']],
            'QueueIndex': [0x130, ['unsigned long']],
            'ProcCount': [0x134, ['unsigned long']],
            'Affinity': [0x138, ['unsigned long']],
        },
    ],
    '_MCGEN_TRACE_CONTEXT': [
        0x38,
        {
            'RegistrationHandle': [0x0, ['unsigned long long']],
            'Logger': [0x8, ['unsigned long long']],
            'MatchAnyKeyword': [0x10, ['unsigned long long']],
            'MatchAllKeyword': [0x18, ['unsigned long long']],
            'Flags': [0x20, ['unsigned long']],
            'IsEnabled': [0x24, ['unsigned long']],
            'Level': [0x28, ['unsigned char']],
            'Reserve': [0x29, ['unsigned char']],
            'EnableBitsCount': [0x2A, ['unsigned short']],
            'EnableBitMask': [0x2C, ['pointer', ['unsigned long']]],
            'EnableKeyWords': [0x30, ['pointer', ['unsigned long long']]],
            'EnableLevel': [0x34, ['pointer', ['unsigned char']]],
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
    '_SID': [
        0xC,
        {
            'Revision': [0x0, ['unsigned char']],
            'SubAuthorityCount': [0x1, ['unsigned char']],
            'IdentifierAuthority': [0x2, ['_SID_IDENTIFIER_AUTHORITY']],
            'SubAuthority': [0x8, ['array', 1, ['unsigned long']]],
        },
    ],
    '_PNP_DEVICE_COMPLETION_QUEUE': [
        0x2C,
        {
            'DispatchedList': [0x0, ['_LIST_ENTRY']],
            'DispatchedCount': [0x8, ['unsigned long']],
            'CompletedList': [0xC, ['_LIST_ENTRY']],
            'CompletedSemaphore': [0x14, ['_KSEMAPHORE']],
            'SpinLock': [0x28, ['unsigned long']],
        },
    ],
    '_KSEMAPHORE': [
        0x14,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'Limit': [0x10, ['long']],
        },
    ],
    '_DEVOBJ_EXTENSION': [
        0x34,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['unsigned short']],
            'DeviceObject': [0x4, ['pointer', ['_DEVICE_OBJECT']]],
            'PowerFlags': [0x8, ['unsigned long']],
            'Dope': [0xC, ['pointer', ['_DEVICE_OBJECT_POWER_EXTENSION']]],
            'ExtensionFlags': [0x10, ['unsigned long']],
            'DeviceNode': [0x14, ['pointer', ['void']]],
            'AttachedTo': [0x18, ['pointer', ['_DEVICE_OBJECT']]],
            'StartIoCount': [0x1C, ['long']],
            'StartIoKey': [0x20, ['long']],
            'StartIoFlags': [0x24, ['unsigned long']],
            'Vpb': [0x28, ['pointer', ['_VPB']]],
            'DependencyNode': [0x2C, ['pointer', ['void']]],
            'VerifierContext': [0x30, ['pointer', ['void']]],
        },
    ],
    '__unnamed_17f2': [
        0x4,
        {
            'LegacyDeviceNode': [0x0, ['pointer', ['_DEVICE_NODE']]],
            'PendingDeviceRelations': [
                0x0,
                ['pointer', ['_DEVICE_RELATIONS']],
            ],
            'Information': [0x0, ['pointer', ['void']]],
        },
    ],
    '__unnamed_17f4': [
        0x4,
        {
            'NextResourceDeviceNode': [0x0, ['pointer', ['_DEVICE_NODE']]],
        },
    ],
    '__unnamed_17f8': [
        0x10,
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
            'ListEntry': [0x4, ['_LIST_ENTRY']],
            'SerialNumber': [0xC, ['pointer', ['unsigned short']]],
        },
    ],
    '_DEVICE_NODE': [
        0x1CC,
        {
            'Sibling': [0x0, ['pointer', ['_DEVICE_NODE']]],
            'Child': [0x4, ['pointer', ['_DEVICE_NODE']]],
            'Parent': [0x8, ['pointer', ['_DEVICE_NODE']]],
            'LastChild': [0xC, ['pointer', ['_DEVICE_NODE']]],
            'PhysicalDeviceObject': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'InstancePath': [0x14, ['_UNICODE_STRING']],
            'ServiceName': [0x1C, ['_UNICODE_STRING']],
            'PendingIrp': [0x24, ['pointer', ['_IRP']]],
            'FxDevice': [0x28, ['pointer', ['_POP_FX_DEVICE']]],
            'FxDeviceLock': [0x2C, ['long']],
            'FxRemoveEvent': [0x30, ['_KEVENT']],
            'FxActivationCount': [0x40, ['long']],
            'FxSleepCount': [0x44, ['long']],
            'Plugin': [0x48, ['pointer', ['_POP_FX_PLUGIN']]],
            'Level': [0x4C, ['unsigned long']],
            'CurrentPowerState': [0x50, ['_POWER_STATE']],
            'Notify': [0x54, ['_PO_DEVICE_NOTIFY']],
            'PoIrpManager': [0x90, ['_PO_IRP_MANAGER']],
            'UniqueId': [0xA0, ['_UNICODE_STRING']],
            'PowerFlags': [0xA8, ['unsigned long']],
            'State': [
                0xAC,
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
                0xB0,
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
                0xB4,
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
            'StateHistoryEntry': [0x104, ['unsigned long']],
            'CompletionStatus': [0x108, ['long']],
            'Flags': [0x10C, ['unsigned long']],
            'UserFlags': [0x110, ['unsigned long']],
            'Problem': [0x114, ['unsigned long']],
            'ProblemStatus': [0x118, ['long']],
            'ResourceList': [0x11C, ['pointer', ['_CM_RESOURCE_LIST']]],
            'ResourceListTranslated': [
                0x120,
                ['pointer', ['_CM_RESOURCE_LIST']],
            ],
            'DuplicatePDO': [0x124, ['pointer', ['_DEVICE_OBJECT']]],
            'ResourceRequirements': [
                0x128,
                ['pointer', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'InterfaceType': [
                0x12C,
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
                            17: 'ACPIBus',
                            18: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0x130, ['unsigned long']],
            'ChildInterfaceType': [
                0x134,
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
                            17: 'ACPIBus',
                            18: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'ChildBusNumber': [0x138, ['unsigned long']],
            'ChildBusTypeIndex': [0x13C, ['unsigned short']],
            'RemovalPolicy': [0x13E, ['unsigned char']],
            'HardwareRemovalPolicy': [0x13F, ['unsigned char']],
            'TargetDeviceNotify': [0x140, ['_LIST_ENTRY']],
            'DeviceArbiterList': [0x148, ['_LIST_ENTRY']],
            'DeviceTranslatorList': [0x150, ['_LIST_ENTRY']],
            'NoTranslatorMask': [0x158, ['unsigned short']],
            'QueryTranslatorMask': [0x15A, ['unsigned short']],
            'NoArbiterMask': [0x15C, ['unsigned short']],
            'QueryArbiterMask': [0x15E, ['unsigned short']],
            'OverUsed1': [0x160, ['__unnamed_17f2']],
            'OverUsed2': [0x164, ['__unnamed_17f4']],
            'BootResources': [0x168, ['pointer', ['_CM_RESOURCE_LIST']]],
            'BootResourcesTranslated': [
                0x16C,
                ['pointer', ['_CM_RESOURCE_LIST']],
            ],
            'CapabilityFlags': [0x170, ['unsigned long']],
            'DockInfo': [0x174, ['__unnamed_17f8']],
            'DisableableDepends': [0x184, ['unsigned long']],
            'PendedSetInterfaceState': [0x188, ['_LIST_ENTRY']],
            'LegacyBusListEntry': [0x190, ['_LIST_ENTRY']],
            'DriverUnloadRetryCount': [0x198, ['unsigned long']],
            'PreviousParent': [0x19C, ['pointer', ['_DEVICE_NODE']]],
            'DeletedChildren': [0x1A0, ['unsigned long']],
            'NumaNodeIndex': [0x1A4, ['unsigned long']],
            'ContainerID': [0x1A8, ['_GUID']],
            'OverrideFlags': [0x1B8, ['unsigned char']],
            'DeviceIdsHash': [0x1BC, ['unsigned long']],
            'RequiresUnloadedDriver': [0x1C0, ['unsigned char']],
            'PendingEjectRelations': [
                0x1C4,
                ['pointer', ['_PENDING_RELATIONS_LIST_ENTRY']],
            ],
            'StateFlags': [0x1C8, ['unsigned long']],
        },
    ],
    '_GROUP_AFFINITY': [
        0xC,
        {
            'Mask': [0x0, ['unsigned long']],
            'Group': [0x4, ['unsigned short']],
            'Reserved': [0x6, ['array', 3, ['unsigned short']]],
        },
    ],
    '_PNP_ASSIGN_RESOURCES_CONTEXT': [
        0xC,
        {
            'IncludeFailedDevices': [0x0, ['unsigned long']],
            'DeviceCount': [0x4, ['unsigned long']],
            'DeviceList': [0x8, ['array', 1, ['pointer', ['_DEVICE_OBJECT']]]],
        },
    ],
    '_PNP_RESOURCE_REQUEST': [
        0x28,
        {
            'PhysicalDevice': [0x0, ['pointer', ['_DEVICE_OBJECT']]],
            'Flags': [0x4, ['unsigned long']],
            'AllocationType': [
                0x8,
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
            'Priority': [0xC, ['unsigned long']],
            'Position': [0x10, ['unsigned long']],
            'ResourceRequirements': [
                0x14,
                ['pointer', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'ReqList': [0x18, ['pointer', ['void']]],
            'ResourceAssignment': [0x1C, ['pointer', ['_CM_RESOURCE_LIST']]],
            'TranslatedResourceAssignment': [
                0x20,
                ['pointer', ['_CM_RESOURCE_LIST']],
            ],
            'Status': [0x24, ['long']],
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
                            17: 'ACPIBus',
                            18: 'MaximumInterfaceType',
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
    '_X86_KTRAP_FRAME': [
        0x8C,
        {
            'DbgEbp': [0x0, ['unsigned long']],
            'DbgEip': [0x4, ['unsigned long']],
            'DbgArgMark': [0x8, ['unsigned long']],
            'DbgArgPointer': [0xC, ['unsigned long']],
            'TempSegCs': [0x10, ['unsigned long']],
            'TempEsp': [0x14, ['unsigned long']],
            'Dr0': [0x18, ['unsigned long']],
            'Dr1': [0x1C, ['unsigned long']],
            'Dr2': [0x20, ['unsigned long']],
            'Dr3': [0x24, ['unsigned long']],
            'Dr6': [0x28, ['unsigned long']],
            'Dr7': [0x2C, ['unsigned long']],
            'SegGs': [0x30, ['unsigned long']],
            'SegEs': [0x34, ['unsigned long']],
            'SegDs': [0x38, ['unsigned long']],
            'Edx': [0x3C, ['unsigned long']],
            'Ecx': [0x40, ['unsigned long']],
            'Eax': [0x44, ['unsigned long']],
            'PreviousPreviousMode': [0x48, ['unsigned char']],
            'EntropyQueueDpc': [0x49, ['unsigned char']],
            'Reserved': [0x4A, ['array', 2, ['unsigned char']]],
            'ExceptionList': [0x4C, ['unsigned long']],
            'SegFs': [0x50, ['unsigned long']],
            'Edi': [0x54, ['unsigned long']],
            'Esi': [0x58, ['unsigned long']],
            'Ebx': [0x5C, ['unsigned long']],
            'Ebp': [0x60, ['unsigned long']],
            'ErrCode': [0x64, ['unsigned long']],
            'Eip': [0x68, ['unsigned long']],
            'SegCs': [0x6C, ['unsigned long']],
            'EFlags': [0x70, ['unsigned long']],
            'HardwareEsp': [0x74, ['unsigned long']],
            'HardwareSegSs': [0x78, ['unsigned long']],
            'V86Es': [0x7C, ['unsigned long']],
            'V86Ds': [0x80, ['unsigned long']],
            'V86Fs': [0x84, ['unsigned long']],
            'V86Gs': [0x88, ['unsigned long']],
        },
    ],
    '_X86_KTRAP_FRAME_BLUE': [
        0x8C,
        {
            'DbgEbp': [0x0, ['unsigned long']],
            'DbgEip': [0x4, ['unsigned long']],
            'DbgArgMark': [0x8, ['unsigned long']],
            'TempSegCs': [0xC, ['unsigned short']],
            'Logging': [0xE, ['unsigned char']],
            'FrameType': [0xF, ['unsigned char']],
            'TempEsp': [0x10, ['unsigned long']],
            'Dr0': [0x14, ['unsigned long']],
            'Dr1': [0x18, ['unsigned long']],
            'Dr2': [0x1C, ['unsigned long']],
            'Dr3': [0x20, ['unsigned long']],
            'Dr6': [0x24, ['unsigned long']],
            'Dr7': [0x28, ['unsigned long']],
            'SegGs': [0x2C, ['unsigned long']],
            'SegEs': [0x30, ['unsigned long']],
            'SegDs': [0x34, ['unsigned long']],
            'Edx': [0x38, ['unsigned long']],
            'Ecx': [0x3C, ['unsigned long']],
            'Eax': [0x40, ['unsigned long']],
            'PreviousPreviousMode': [0x44, ['unsigned char']],
            'EntropyQueueDpc': [0x45, ['unsigned char']],
            'Reserved': [0x46, ['array', 2, ['unsigned char']]],
            'MxCsr': [0x48, ['unsigned long']],
            'ExceptionList': [0x4C, ['unsigned long']],
            'SegFs': [0x50, ['unsigned long']],
            'Edi': [0x54, ['unsigned long']],
            'Esi': [0x58, ['unsigned long']],
            'Ebx': [0x5C, ['unsigned long']],
            'Ebp': [0x60, ['unsigned long']],
            'ErrCode': [0x64, ['unsigned long']],
            'Eip': [0x68, ['unsigned long']],
            'SegCs': [0x6C, ['unsigned long']],
            'EFlags': [0x70, ['unsigned long']],
            'HardwareEsp': [0x74, ['unsigned long']],
            'HardwareSegSs': [0x78, ['unsigned long']],
            'V86Es': [0x7C, ['unsigned long']],
            'V86Ds': [0x80, ['unsigned long']],
            'V86Fs': [0x84, ['unsigned long']],
            'V86Gs': [0x88, ['unsigned long']],
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
    '__unnamed_18ac': [
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
            'GetContextEx': [0x0, ['_DBGKD_CONTEXT_EX']],
            'SetContextEx': [0x0, ['_DBGKD_CONTEXT_EX']],
        },
    ],
    '_DBGKD_MANIPULATE_STATE64': [
        0x38,
        {
            'ApiNumber': [0x0, ['unsigned long']],
            'ProcessorLevel': [0x4, ['unsigned short']],
            'Processor': [0x6, ['unsigned short']],
            'ReturnStatus': [0x8, ['long']],
            'u': [0x10, ['__unnamed_18ac']],
        },
    ],
    '__unnamed_18b3': [
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
            'GetContextEx': [0x0, ['_DBGKD_CONTEXT_EX']],
            'SetContextEx': [0x0, ['_DBGKD_CONTEXT_EX']],
        },
    ],
    '_DBGKD_MANIPULATE_STATE32': [
        0x34,
        {
            'ApiNumber': [0x0, ['unsigned long']],
            'ProcessorLevel': [0x4, ['unsigned short']],
            'Processor': [0x6, ['unsigned short']],
            'ReturnStatus': [0x8, ['long']],
            'u': [0xC, ['__unnamed_18b3']],
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
            'ControlSet': [0x4, ['_X86_DBGKD_CONTROL_SET']],
            'AnyControlSet': [0x4, ['_DBGKD_ANY_CONTROL_SET']],
        },
    ],
    '_PROCESSOR_POWER_STATE': [
        0x190,
        {
            'IdleStates': [0x0, ['pointer', ['_PPM_IDLE_STATES']]],
            'IdleAccounting': [0x4, ['pointer', ['_PROC_IDLE_ACCOUNTING']]],
            'IdleTimeLast': [0x8, ['unsigned long long']],
            'IdleTimeTotal': [0x10, ['unsigned long long']],
            'IdleTimeEntry': [0x18, ['unsigned long long']],
            'Reserved': [0x20, ['unsigned long long']],
            'IdlePolicy': [0x28, ['_PROC_IDLE_POLICY']],
            'Synchronization': [0x30, ['_PPM_IDLE_SYNCHRONIZATION_STATE']],
            'PerfFeedback': [0x38, ['_PROC_FEEDBACK']],
            'Hypervisor': [
                0xA0,
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
            'LastSysTime': [0xA4, ['unsigned long']],
            'WmiDispatchPtr': [0xA8, ['unsigned long']],
            'WmiInterfaceEnabled': [0xAC, ['long']],
            'FFHThrottleStateInfo': [0xB0, ['_PPM_FFH_THROTTLE_STATE_INFO']],
            'PerfActionDpc': [0xD0, ['_KDPC']],
            'PerfActionMask': [0xF0, ['long']],
            'HvIdleCheck': [0xF8, ['_PROC_IDLE_SNAP']],
            'PerfCheck': [0x108, ['_PROC_PERF_SNAP']],
            'Domain': [0x148, ['pointer', ['_PROC_PERF_DOMAIN']]],
            'PerfConstraint': [0x14C, ['pointer', ['_PROC_PERF_CONSTRAINT']]],
            'Concurrency': [
                0x150,
                ['pointer', ['_PPM_CONCURRENCY_ACCOUNTING']],
            ],
            'Load': [0x154, ['pointer', ['_PROC_PERF_LOAD']]],
            'PerfHistory': [0x158, ['pointer', ['_PROC_PERF_HISTORY']]],
            'GuaranteedPerformancePercent': [0x15C, ['unsigned char']],
            'HvTargetState': [0x15D, ['unsigned char']],
            'Parked': [0x15E, ['unsigned char']],
            'OverUtilized': [0x15F, ['unsigned char']],
            'LatestPerformancePercent': [0x160, ['unsigned long']],
            'LatestAffinitizedPercent': [0x164, ['unsigned long']],
            'ExpectedUtility': [0x168, ['unsigned long']],
            'Utility': [0x16C, ['array', 3, ['_PROC_PERF_UTILITY']]],
        },
    ],
    '_PROC_PERF_UTILITY': [
        0xC,
        {
            'Affinitized': [0x0, ['unsigned long']],
            'Performance': [0x4, ['unsigned long']],
            'Total': [0x8, ['unsigned long']],
        },
    ],
    '_POP_CPU_INFO': [
        0x10,
        {
            'Eax': [0x0, ['unsigned long']],
            'Ebx': [0x4, ['unsigned long']],
            'Ecx': [0x8, ['unsigned long']],
            'Edx': [0xC, ['unsigned long']],
        },
    ],
    '_POP_FX_COMPONENT_FLAGS': [
        0x8,
        {
            'Value': [0x0, ['long']],
            'Value2': [0x4, ['long']],
            'RefCount': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=30, native_type='unsigned long'),
                ],
            ],
            'Idling': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'Active': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'CriticalIdleOverride': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ResidentOverride': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'CompleteIdleStatePending': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_POP_FX_DEVICE_STATUS': [
        0x4,
        {
            'Value': [0x0, ['long']],
            'SystemTransition': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'PepD0Notify': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'IdleTimerOn': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'IgnoreIdleTimeout': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'IrpInUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'IrpPending': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'DPNRDeviceNotified': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'DPNRReceivedFromPep': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_POP_RW_LOCK': [
        0x8,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'Thread': [0x4, ['pointer', ['_KTHREAD']]],
        },
    ],
    '_VOLUME_CACHE_MAP': [
        0x90,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteCode': [0x2, ['short']],
            'UseCount': [0x4, ['unsigned long']],
            'DeviceObject': [0x8, ['pointer', ['_DEVICE_OBJECT']]],
            'VolumeCacheMapLinks': [0xC, ['_LIST_ENTRY']],
            'DirtyPages': [0x14, ['unsigned long']],
            'LogHandleContext': [0x18, ['_LOG_HANDLE_CONTEXT']],
            'Flags': [0x80, ['unsigned long']],
            'PagesQueuedToDisk': [0x84, ['unsigned long']],
            'LoggedPagesQueuedToDisk': [0x88, ['unsigned long']],
        },
    ],
    '_SHARED_CACHE_MAP': [
        0x170,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteSize': [0x2, ['short']],
            'OpenCount': [0x4, ['unsigned long']],
            'FileSize': [0x8, ['_LARGE_INTEGER']],
            'BcbList': [0x10, ['_LIST_ENTRY']],
            'SectionSize': [0x18, ['_LARGE_INTEGER']],
            'ValidDataLength': [0x20, ['_LARGE_INTEGER']],
            'ValidDataGoal': [0x28, ['_LARGE_INTEGER']],
            'InitialVacbs': [0x30, ['array', 4, ['pointer', ['_VACB']]]],
            'Vacbs': [0x40, ['pointer', ['pointer', ['_VACB']]]],
            'FileObjectFastRef': [0x44, ['_EX_FAST_REF']],
            'VacbLock': [0x48, ['_EX_PUSH_LOCK']],
            'DirtyPages': [0x4C, ['unsigned long']],
            'LoggedStreamLinks': [0x50, ['_LIST_ENTRY']],
            'SharedCacheMapLinks': [0x58, ['_LIST_ENTRY']],
            'Flags': [0x60, ['unsigned long']],
            'Status': [0x64, ['long']],
            'Mbcb': [0x68, ['pointer', ['_MBCB']]],
            'Section': [0x6C, ['pointer', ['void']]],
            'CreateEvent': [0x70, ['pointer', ['_KEVENT']]],
            'WaitOnActiveCount': [0x74, ['pointer', ['_KEVENT']]],
            'PagesToWrite': [0x78, ['unsigned long']],
            'BeyondLastFlush': [0x80, ['long long']],
            'Callbacks': [0x88, ['pointer', ['_CACHE_MANAGER_CALLBACKS']]],
            'LazyWriteContext': [0x8C, ['pointer', ['void']]],
            'PrivateList': [0x90, ['_LIST_ENTRY']],
            'V1': [0x98, ['_LOGGED_STREAM_CALLBACK_V1']],
            'V2': [0x98, ['_LOGGED_STREAM_CALLBACK_V2']],
            'LargestLSN': [0xA0, ['_LARGE_INTEGER']],
            'DirtyPageThreshold': [0xA8, ['unsigned long']],
            'LazyWritePassCount': [0xAC, ['unsigned long']],
            'UninitializeEvent': [
                0xB0,
                ['pointer', ['_CACHE_UNINITIALIZE_EVENT']],
            ],
            'BcbLock': [0xB4, ['_FAST_MUTEX']],
            'LastUnmapBehindOffset': [0xD8, ['_LARGE_INTEGER']],
            'Event': [0xE0, ['_KEVENT']],
            'HighWaterMappingOffset': [0xF0, ['_LARGE_INTEGER']],
            'PrivateCacheMap': [0xF8, ['_PRIVATE_CACHE_MAP']],
            'WriteBehindWorkQueueEntry': [0x160, ['pointer', ['void']]],
            'VolumeCacheMap': [0x164, ['pointer', ['_VOLUME_CACHE_MAP']]],
            'ProcImagePathHash': [0x168, ['unsigned long']],
            'WritesInProgress': [0x16C, ['unsigned long']],
        },
    ],
    '__unnamed_1960': [
        0x8,
        {
            'FileOffset': [0x0, ['_LARGE_INTEGER']],
            'ActiveCount': [0x0, ['unsigned short']],
            'Links': [0x0, ['_LIST_ENTRY']],
        },
    ],
    '_VACB': [
        0x18,
        {
            'BaseAddress': [0x0, ['pointer', ['void']]],
            'SharedCacheMap': [0x4, ['pointer', ['_SHARED_CACHE_MAP']]],
            'Overlay': [0x8, ['__unnamed_1960']],
            'ArrayHead': [0x10, ['pointer', ['_VACB_ARRAY_HEADER']]],
        },
    ],
    '__unnamed_1981': [
        0x4,
        {
            'FileObject': [0x0, ['pointer', ['_FILE_OBJECT']]],
        },
    ],
    '__unnamed_1983': [
        0x4,
        {
            'SharedCacheMap': [0x0, ['pointer', ['_SHARED_CACHE_MAP']]],
        },
    ],
    '__unnamed_1985': [
        0x4,
        {
            'Event': [0x0, ['pointer', ['_KEVENT']]],
        },
    ],
    '__unnamed_1987': [
        0x4,
        {
            'Reason': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1989': [
        0x1C,
        {
            'SharedCacheMap': [0x0, ['pointer', ['_SHARED_CACHE_MAP']]],
            'IoStatus': [0x4, ['pointer', ['_IO_STATUS_BLOCK']]],
            'CallerWaitEvent': [0x8, ['_KEVENT']],
            'IsLowPriWriteBehind': [0x18, ['unsigned char']],
        },
    ],
    '__unnamed_198b': [
        0x1C,
        {
            'Read': [0x0, ['__unnamed_1981']],
            'Write': [0x0, ['__unnamed_1983']],
            'Event': [0x0, ['__unnamed_1985']],
            'Notification': [0x0, ['__unnamed_1987']],
            'LowPriWrite': [0x0, ['__unnamed_1989']],
        },
    ],
    '_WORK_QUEUE_ENTRY': [
        0x28,
        {
            'WorkQueueLinks': [0x0, ['_LIST_ENTRY']],
            'Parameters': [0x8, ['__unnamed_198b']],
            'Function': [0x24, ['unsigned char']],
        },
    ],
    '_CC_EXTERNAL_CACHE_INFO': [
        0x18,
        {
            'Callback': [0x0, ['pointer', ['void']]],
            'DirtyPageStatistics': [0x4, ['_DIRTY_PAGE_STATISTICS']],
            'Links': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_LOG_HANDLE_CONTEXT': [
        0x68,
        {
            'LogHandle': [0x0, ['pointer', ['void']]],
            'FlushToLsnRoutine': [0x4, ['pointer', ['void']]],
            'QueryLogHandleInfoRoutine': [0x8, ['pointer', ['void']]],
            'DirtyPageStatistics': [0xC, ['_DIRTY_PAGE_STATISTICS']],
            'DirtyPageThresholds': [0x18, ['_DIRTY_PAGE_THRESHOLDS']],
            'AdditionalPagesToWrite': [0x40, ['unsigned long']],
            'CcLWScanDPThreshold': [0x44, ['unsigned long']],
            'LargestLsnForCurrentLWScan': [0x48, ['_LARGE_INTEGER']],
            'RelatedFileObject': [0x50, ['pointer', ['_FILE_OBJECT']]],
            'LargestLsnFileObjectKey': [0x54, ['unsigned long']],
            'LastLWTimeStamp': [0x58, ['_LARGE_INTEGER']],
            'Flags': [0x60, ['unsigned long']],
        },
    ],
    '_MBCB': [
        0x88,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeIsInZone': [0x2, ['short']],
            'PagesToWrite': [0x4, ['unsigned long']],
            'DirtyPages': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
            'BitmapRanges': [0x10, ['_LIST_ENTRY']],
            'ResumeWritePage': [0x18, ['long long']],
            'MostRecentlyDirtiedPage': [0x20, ['long long']],
            'BitmapRange1': [0x28, ['_BITMAP_RANGE']],
            'BitmapRange2': [0x48, ['_BITMAP_RANGE']],
            'BitmapRange3': [0x68, ['_BITMAP_RANGE']],
        },
    ],
    '_BITMAP_RANGE': [
        0x20,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'BasePage': [0x8, ['long long']],
            'FirstDirtyPage': [0x10, ['unsigned long']],
            'LastDirtyPage': [0x14, ['unsigned long']],
            'DirtyPages': [0x18, ['unsigned long']],
            'Bitmap': [0x1C, ['pointer', ['unsigned long']]],
        },
    ],
    'VACB_LEVEL_ALLOCATION_LIST': [
        0x10,
        {
            'VacbLevelList': [0x0, ['_LIST_ENTRY']],
            'VacbLevelWithBcbListHeads': [0x8, ['pointer', ['void']]],
            'VacbLevelsAllocated': [0xC, ['unsigned long']],
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
        0x14,
        {
            'Next': [0x0, ['pointer', ['_CACHE_UNINITIALIZE_EVENT']]],
            'Event': [0x4, ['_KEVENT']],
        },
    ],
    '_HEAP_LIST_LOOKUP': [
        0x24,
        {
            'ExtendedLookup': [0x0, ['pointer', ['_HEAP_LIST_LOOKUP']]],
            'ArraySize': [0x4, ['unsigned long']],
            'ExtraItem': [0x8, ['unsigned long']],
            'ItemCount': [0xC, ['unsigned long']],
            'OutOfRangeItems': [0x10, ['unsigned long']],
            'BaseIndex': [0x14, ['unsigned long']],
            'ListHead': [0x18, ['pointer', ['_LIST_ENTRY']]],
            'ListsInUseUlong': [0x1C, ['pointer', ['unsigned long']]],
            'ListHints': [0x20, ['pointer', ['pointer', ['_LIST_ENTRY']]]],
        },
    ],
    '_HEAP': [
        0x248,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'SegmentSignature': [0x8, ['unsigned long']],
            'SegmentFlags': [0xC, ['unsigned long']],
            'SegmentListEntry': [0x10, ['_LIST_ENTRY']],
            'Heap': [0x18, ['pointer', ['_HEAP']]],
            'BaseAddress': [0x1C, ['pointer', ['void']]],
            'NumberOfPages': [0x20, ['unsigned long']],
            'FirstEntry': [0x24, ['pointer', ['_HEAP_ENTRY']]],
            'LastValidEntry': [0x28, ['pointer', ['_HEAP_ENTRY']]],
            'NumberOfUnCommittedPages': [0x2C, ['unsigned long']],
            'NumberOfUnCommittedRanges': [0x30, ['unsigned long']],
            'SegmentAllocatorBackTraceIndex': [0x34, ['unsigned short']],
            'Reserved': [0x36, ['unsigned short']],
            'UCRSegmentList': [0x38, ['_LIST_ENTRY']],
            'Flags': [0x40, ['unsigned long']],
            'ForceFlags': [0x44, ['unsigned long']],
            'CompatibilityFlags': [0x48, ['unsigned long']],
            'EncodeFlagMask': [0x4C, ['unsigned long']],
            'Encoding': [0x50, ['_HEAP_ENTRY']],
            'Interceptor': [0x58, ['unsigned long']],
            'VirtualMemoryThreshold': [0x5C, ['unsigned long']],
            'Signature': [0x60, ['unsigned long']],
            'SegmentReserve': [0x64, ['unsigned long']],
            'SegmentCommit': [0x68, ['unsigned long']],
            'DeCommitFreeBlockThreshold': [0x6C, ['unsigned long']],
            'DeCommitTotalFreeThreshold': [0x70, ['unsigned long']],
            'TotalFreeSize': [0x74, ['unsigned long']],
            'MaximumAllocationSize': [0x78, ['unsigned long']],
            'ProcessHeapsListIndex': [0x7C, ['unsigned short']],
            'HeaderValidateLength': [0x7E, ['unsigned short']],
            'HeaderValidateCopy': [0x80, ['pointer', ['void']]],
            'NextAvailableTagIndex': [0x84, ['unsigned short']],
            'MaximumTagIndex': [0x86, ['unsigned short']],
            'TagEntries': [0x88, ['pointer', ['_HEAP_TAG_ENTRY']]],
            'UCRList': [0x8C, ['_LIST_ENTRY']],
            'AlignRound': [0x94, ['unsigned long']],
            'AlignMask': [0x98, ['unsigned long']],
            'VirtualAllocdBlocks': [0x9C, ['_LIST_ENTRY']],
            'SegmentList': [0xA4, ['_LIST_ENTRY']],
            'AllocatorBackTraceIndex': [0xAC, ['unsigned short']],
            'NonDedicatedListLength': [0xB0, ['unsigned long']],
            'BlocksIndex': [0xB4, ['pointer', ['void']]],
            'UCRIndex': [0xB8, ['pointer', ['void']]],
            'PseudoTagEntries': [
                0xBC,
                ['pointer', ['_HEAP_PSEUDO_TAG_ENTRY']],
            ],
            'FreeLists': [0xC0, ['_LIST_ENTRY']],
            'LockVariable': [0xC8, ['pointer', ['_HEAP_LOCK']]],
            'CommitRoutine': [0xCC, ['pointer', ['void']]],
            'FrontEndHeap': [0xD0, ['pointer', ['void']]],
            'FrontHeapLockCount': [0xD4, ['unsigned short']],
            'FrontEndHeapType': [0xD6, ['unsigned char']],
            'RequestedFrontEndHeapType': [0xD7, ['unsigned char']],
            'FrontEndHeapUsageData': [0xD8, ['pointer', ['unsigned short']]],
            'FrontEndHeapMaximumIndex': [0xDC, ['unsigned short']],
            'FrontEndHeapStatusBitmap': [
                0xDE,
                ['array', 257, ['unsigned char']],
            ],
            'Counters': [0x1E0, ['_HEAP_COUNTERS']],
            'TuningParameters': [0x23C, ['_HEAP_TUNING_PARAMETERS']],
        },
    ],
    '__unnamed_19f6': [
        0x38,
        {
            'CriticalSection': [0x0, ['_RTL_CRITICAL_SECTION']],
            'Resource': [0x0, ['_ERESOURCE']],
        },
    ],
    '_HEAP_LOCK': [
        0x38,
        {
            'Lock': [0x0, ['__unnamed_19f6']],
        },
    ],
    '_HEAP_ENTRY': [
        0x8,
        {
            'Size': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned char']],
            'SmallTagIndex': [0x3, ['unsigned char']],
            'SubSegmentCode': [0x0, ['unsigned long']],
            'PreviousSize': [0x4, ['unsigned short']],
            'SegmentOffset': [0x6, ['unsigned char']],
            'LFHFlags': [0x6, ['unsigned char']],
            'UnusedBytes': [0x7, ['unsigned char']],
            'FunctionIndex': [0x0, ['unsigned short']],
            'ContextValue': [0x2, ['unsigned short']],
            'InterceptorValue': [0x0, ['unsigned long']],
            'UnusedBytesLength': [0x4, ['unsigned short']],
            'EntryOffset': [0x6, ['unsigned char']],
            'ExtendedBlockSignature': [0x7, ['unsigned char']],
            'Code1': [0x0, ['unsigned long']],
            'Code2': [0x4, ['unsigned short']],
            'Code3': [0x6, ['unsigned char']],
            'Code4': [0x7, ['unsigned char']],
            'Code234': [0x4, ['unsigned long']],
            'AgregateCode': [0x0, ['unsigned long long']],
        },
    ],
    '_HEAP_SEGMENT': [
        0x40,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'SegmentSignature': [0x8, ['unsigned long']],
            'SegmentFlags': [0xC, ['unsigned long']],
            'SegmentListEntry': [0x10, ['_LIST_ENTRY']],
            'Heap': [0x18, ['pointer', ['_HEAP']]],
            'BaseAddress': [0x1C, ['pointer', ['void']]],
            'NumberOfPages': [0x20, ['unsigned long']],
            'FirstEntry': [0x24, ['pointer', ['_HEAP_ENTRY']]],
            'LastValidEntry': [0x28, ['pointer', ['_HEAP_ENTRY']]],
            'NumberOfUnCommittedPages': [0x2C, ['unsigned long']],
            'NumberOfUnCommittedRanges': [0x30, ['unsigned long']],
            'SegmentAllocatorBackTraceIndex': [0x34, ['unsigned short']],
            'Reserved': [0x36, ['unsigned short']],
            'UCRSegmentList': [0x38, ['_LIST_ENTRY']],
        },
    ],
    '_HEAP_VIRTUAL_ALLOC_ENTRY': [
        0x20,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'ExtraStuff': [0x8, ['_HEAP_ENTRY_EXTRA']],
            'CommitSize': [0x10, ['unsigned long']],
            'ReserveSize': [0x14, ['unsigned long']],
            'BusyBlock': [0x18, ['_HEAP_ENTRY']],
        },
    ],
    '_HEAP_FREE_ENTRY': [
        0x10,
        {
            'Size': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned char']],
            'SmallTagIndex': [0x3, ['unsigned char']],
            'SubSegmentCode': [0x0, ['unsigned long']],
            'PreviousSize': [0x4, ['unsigned short']],
            'SegmentOffset': [0x6, ['unsigned char']],
            'LFHFlags': [0x6, ['unsigned char']],
            'UnusedBytes': [0x7, ['unsigned char']],
            'FunctionIndex': [0x0, ['unsigned short']],
            'ContextValue': [0x2, ['unsigned short']],
            'InterceptorValue': [0x0, ['unsigned long']],
            'UnusedBytesLength': [0x4, ['unsigned short']],
            'EntryOffset': [0x6, ['unsigned char']],
            'ExtendedBlockSignature': [0x7, ['unsigned char']],
            'Code1': [0x0, ['unsigned long']],
            'Code2': [0x4, ['unsigned short']],
            'Code3': [0x6, ['unsigned char']],
            'Code4': [0x7, ['unsigned char']],
            'Code234': [0x4, ['unsigned long']],
            'AgregateCode': [0x0, ['unsigned long long']],
            'FreeList': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1a48': [
        0x4,
        {
            'DataLength': [0x0, ['short']],
            'TotalLength': [0x2, ['short']],
        },
    ],
    '__unnamed_1a4a': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1a48']],
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1a4c': [
        0x4,
        {
            'Type': [0x0, ['short']],
            'DataInfoOffset': [0x2, ['short']],
        },
    ],
    '__unnamed_1a4e': [
        0x4,
        {
            's2': [0x0, ['__unnamed_1a4c']],
            'ZeroInit': [0x0, ['unsigned long']],
        },
    ],
    '_PORT_MESSAGE': [
        0x18,
        {
            'u1': [0x0, ['__unnamed_1a4a']],
            'u2': [0x4, ['__unnamed_1a4e']],
            'ClientId': [0x8, ['_CLIENT_ID']],
            'DoNotUseThisField': [0x8, ['double']],
            'MessageId': [0x10, ['unsigned long']],
            'ClientViewSize': [0x14, ['unsigned long']],
            'CallbackId': [0x14, ['unsigned long']],
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
        0x4,
        {
            'Object': [0x0, ['pointer', ['void']]],
        },
    ],
    '_BLOB_TYPE': [
        0x20,
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
            'LookasideIndex': [0x8, ['unsigned long']],
            'Flags': [0xC, ['unsigned long']],
            'Counters': [0x10, ['pointer', ['_BLOB_COUNTERS']]],
            'DeleteProcedure': [0x14, ['pointer', ['void']]],
            'DestroyProcedure': [0x18, ['pointer', ['void']]],
            'UsualSize': [0x1C, ['unsigned long']],
        },
    ],
    '__unnamed_1a6b': [
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
    '__unnamed_1a6d': [
        0x1,
        {
            's1': [0x0, ['__unnamed_1a6b']],
            'Flags': [0x0, ['unsigned char']],
        },
    ],
    '_BLOB': [
        0x18,
        {
            'ResourceList': [0x0, ['_LIST_ENTRY']],
            'FreeListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'u1': [0x8, ['__unnamed_1a6d']],
            'ResourceId': [0x9, ['unsigned char']],
            'CachedReferences': [0xA, ['short']],
            'ReferenceCount': [0xC, ['long']],
            'Pad': [0x10, ['unsigned long']],
            'Lock': [0x14, ['_EX_PUSH_LOCK']],
        },
    ],
    '__unnamed_1a81': [
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
    '__unnamed_1a83': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1a81']],
        },
    ],
    '_KALPC_SECTION': [
        0x28,
        {
            'SectionObject': [0x0, ['pointer', ['void']]],
            'Size': [0x4, ['unsigned long']],
            'HandleTable': [0x8, ['pointer', ['_ALPC_HANDLE_TABLE']]],
            'SectionHandle': [0xC, ['pointer', ['void']]],
            'OwnerProcess': [0x10, ['pointer', ['_EPROCESS']]],
            'OwnerPort': [0x14, ['pointer', ['_ALPC_PORT']]],
            'u1': [0x18, ['__unnamed_1a83']],
            'NumberOfRegions': [0x1C, ['unsigned long']],
            'RegionListHead': [0x20, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1a8c': [
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
    '__unnamed_1a8e': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1a8c']],
        },
    ],
    '_KALPC_REGION': [
        0x30,
        {
            'RegionListEntry': [0x0, ['_LIST_ENTRY']],
            'Section': [0x8, ['pointer', ['_KALPC_SECTION']]],
            'Offset': [0xC, ['unsigned long']],
            'Size': [0x10, ['unsigned long']],
            'ViewSize': [0x14, ['unsigned long']],
            'u1': [0x18, ['__unnamed_1a8e']],
            'NumberOfViews': [0x1C, ['unsigned long']],
            'ViewListHead': [0x20, ['_LIST_ENTRY']],
            'ReadOnlyView': [0x28, ['pointer', ['_KALPC_VIEW']]],
            'ReadWriteView': [0x2C, ['pointer', ['_KALPC_VIEW']]],
        },
    ],
    '__unnamed_1a94': [
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
    '__unnamed_1a96': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1a94']],
        },
    ],
    '_KALPC_VIEW': [
        0x34,
        {
            'ViewListEntry': [0x0, ['_LIST_ENTRY']],
            'Region': [0x8, ['pointer', ['_KALPC_REGION']]],
            'OwnerPort': [0xC, ['pointer', ['_ALPC_PORT']]],
            'OwnerProcess': [0x10, ['pointer', ['_EPROCESS']]],
            'Address': [0x14, ['pointer', ['void']]],
            'Size': [0x18, ['unsigned long']],
            'SecureViewHandle': [0x1C, ['pointer', ['void']]],
            'WriteAccessHandle': [0x20, ['pointer', ['void']]],
            'u1': [0x24, ['__unnamed_1a96']],
            'NumberOfOwnerMessages': [0x28, ['unsigned long']],
            'ProcessViewListEntry': [0x2C, ['_LIST_ENTRY']],
        },
    ],
    '_ALPC_COMMUNICATION_INFO': [
        0x28,
        {
            'ConnectionPort': [0x0, ['pointer', ['_ALPC_PORT']]],
            'ServerCommunicationPort': [0x4, ['pointer', ['_ALPC_PORT']]],
            'ClientCommunicationPort': [0x8, ['pointer', ['_ALPC_PORT']]],
            'CommunicationList': [0xC, ['_LIST_ENTRY']],
            'HandleTable': [0x14, ['_ALPC_HANDLE_TABLE']],
            'CloseMessage': [0x24, ['pointer', ['_KALPC_MESSAGE']]],
        },
    ],
    '__unnamed_1ab3': [
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
    '__unnamed_1ab5': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1ab3']],
            'State': [0x0, ['unsigned long']],
        },
    ],
    '_ALPC_PORT': [
        0x10C,
        {
            'PortListEntry': [0x0, ['_LIST_ENTRY']],
            'CommunicationInfo': [
                0x8,
                ['pointer', ['_ALPC_COMMUNICATION_INFO']],
            ],
            'OwnerProcess': [0xC, ['pointer', ['_EPROCESS']]],
            'CompletionPort': [0x10, ['pointer', ['void']]],
            'CompletionKey': [0x14, ['pointer', ['void']]],
            'CompletionPacketLookaside': [
                0x18,
                ['pointer', ['_ALPC_COMPLETION_PACKET_LOOKASIDE']],
            ],
            'PortContext': [0x1C, ['pointer', ['void']]],
            'StaticSecurity': [0x20, ['_SECURITY_CLIENT_CONTEXT']],
            'IncomingQueueLock': [0x5C, ['_EX_PUSH_LOCK']],
            'MainQueue': [0x60, ['_LIST_ENTRY']],
            'LargeMessageQueue': [0x68, ['_LIST_ENTRY']],
            'PendingQueueLock': [0x70, ['_EX_PUSH_LOCK']],
            'PendingQueue': [0x74, ['_LIST_ENTRY']],
            'WaitQueueLock': [0x7C, ['_EX_PUSH_LOCK']],
            'WaitQueue': [0x80, ['_LIST_ENTRY']],
            'Semaphore': [0x88, ['pointer', ['_KSEMAPHORE']]],
            'DummyEvent': [0x88, ['pointer', ['_KEVENT']]],
            'PortAttributes': [0x8C, ['_ALPC_PORT_ATTRIBUTES']],
            'ResourceListLock': [0xB8, ['_EX_PUSH_LOCK']],
            'ResourceListHead': [0xBC, ['_LIST_ENTRY']],
            'PortObjectLock': [0xC4, ['_EX_PUSH_LOCK']],
            'CompletionList': [0xC8, ['pointer', ['_ALPC_COMPLETION_LIST']]],
            'CallbackObject': [0xCC, ['pointer', ['_CALLBACK_OBJECT']]],
            'CallbackContext': [0xD0, ['pointer', ['void']]],
            'CanceledQueue': [0xD4, ['_LIST_ENTRY']],
            'SequenceNo': [0xDC, ['long']],
            'ReferenceNo': [0xE0, ['long']],
            'ReferenceNoWait': [
                0xE4,
                ['pointer', ['_PALPC_PORT_REFERENCE_WAIT_BLOCK']],
            ],
            'u1': [0xE8, ['__unnamed_1ab5']],
            'TargetQueuePort': [0xEC, ['pointer', ['_ALPC_PORT']]],
            'TargetSequencePort': [0xF0, ['pointer', ['_ALPC_PORT']]],
            'CachedMessage': [0xF4, ['pointer', ['_KALPC_MESSAGE']]],
            'MainQueueLength': [0xF8, ['unsigned long']],
            'LargeMessageQueueLength': [0xFC, ['unsigned long']],
            'PendingQueueLength': [0x100, ['unsigned long']],
            'CanceledQueueLength': [0x104, ['unsigned long']],
            'WaitQueueLength': [0x108, ['unsigned long']],
        },
    ],
    '_ALPC_COMPLETION_LIST': [
        0x58,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'OwnerProcess': [0x8, ['pointer', ['_EPROCESS']]],
            'CompletionListLock': [0xC, ['_EX_PUSH_LOCK']],
            'Mdl': [0x10, ['pointer', ['_MDL']]],
            'UserVa': [0x14, ['pointer', ['void']]],
            'UserLimit': [0x18, ['pointer', ['void']]],
            'DataUserVa': [0x1C, ['pointer', ['void']]],
            'SystemVa': [0x20, ['pointer', ['void']]],
            'TotalSize': [0x24, ['unsigned long']],
            'Header': [0x28, ['pointer', ['_ALPC_COMPLETION_LIST_HEADER']]],
            'List': [0x2C, ['pointer', ['void']]],
            'ListSize': [0x30, ['unsigned long']],
            'Bitmap': [0x34, ['pointer', ['void']]],
            'BitmapSize': [0x38, ['unsigned long']],
            'Data': [0x3C, ['pointer', ['void']]],
            'DataSize': [0x40, ['unsigned long']],
            'BitmapLimit': [0x44, ['unsigned long']],
            'BitmapNextHint': [0x48, ['unsigned long']],
            'ConcurrencyCount': [0x4C, ['unsigned long']],
            'AttributeFlags': [0x50, ['unsigned long']],
            'AttributeSize': [0x54, ['unsigned long']],
        },
    ],
    '_OBJECT_ATTRIBUTES': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'RootDirectory': [0x4, ['pointer', ['void']]],
            'ObjectName': [0x8, ['pointer', ['_UNICODE_STRING']]],
            'Attributes': [0xC, ['unsigned long']],
            'SecurityDescriptor': [0x10, ['pointer', ['void']]],
            'SecurityQualityOfService': [0x14, ['pointer', ['void']]],
        },
    ],
    '_OBJECT_TYPE': [
        0x90,
        {
            'TypeList': [0x0, ['_LIST_ENTRY']],
            'Name': [0x8, ['_UNICODE_STRING']],
            'DefaultObject': [0x10, ['pointer', ['void']]],
            'Index': [0x14, ['unsigned char']],
            'TotalNumberOfObjects': [0x18, ['unsigned long']],
            'TotalNumberOfHandles': [0x1C, ['unsigned long']],
            'HighWaterNumberOfObjects': [0x20, ['unsigned long']],
            'HighWaterNumberOfHandles': [0x24, ['unsigned long']],
            'TypeInfo': [0x28, ['_OBJECT_TYPE_INITIALIZER']],
            'TypeLock': [0x80, ['_EX_PUSH_LOCK']],
            'Key': [0x84, ['unsigned long']],
            'CallbackList': [0x88, ['_LIST_ENTRY']],
        },
    ],
    '_PALPC_PORT_REFERENCE_WAIT_BLOCK': [
        0x14,
        {
            'DesiredReferenceNoEvent': [0x0, ['_KEVENT']],
            'DesiredReferenceNo': [0x10, ['long']],
        },
    ],
    '__unnamed_1ad9': [
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
    '__unnamed_1adb': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1ad9']],
            'State': [0x0, ['unsigned long']],
        },
    ],
    '_KALPC_MESSAGE': [
        0x88,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'PortQueue': [0x8, ['pointer', ['_ALPC_PORT']]],
            'OwnerPort': [0xC, ['pointer', ['_ALPC_PORT']]],
            'WaitingThread': [0x10, ['pointer', ['_ETHREAD']]],
            'u1': [0x14, ['__unnamed_1adb']],
            'SequenceNo': [0x18, ['long']],
            'QuotaProcess': [0x1C, ['pointer', ['_EPROCESS']]],
            'QuotaBlock': [0x1C, ['pointer', ['void']]],
            'CancelSequencePort': [0x20, ['pointer', ['_ALPC_PORT']]],
            'CancelQueuePort': [0x24, ['pointer', ['_ALPC_PORT']]],
            'CancelSequenceNo': [0x28, ['long']],
            'CancelListEntry': [0x2C, ['_LIST_ENTRY']],
            'Reserve': [0x34, ['pointer', ['_KALPC_RESERVE']]],
            'MessageAttributes': [0x38, ['_KALPC_MESSAGE_ATTRIBUTES']],
            'DataUserVa': [0x54, ['pointer', ['void']]],
            'CommunicationInfo': [
                0x58,
                ['pointer', ['_ALPC_COMMUNICATION_INFO']],
            ],
            'ConnectionPort': [0x5C, ['pointer', ['_ALPC_PORT']]],
            'ServerThread': [0x60, ['pointer', ['_ETHREAD']]],
            'WakeReference': [0x64, ['pointer', ['void']]],
            'ExtensionBuffer': [0x68, ['pointer', ['void']]],
            'ExtensionBufferSize': [0x6C, ['unsigned long']],
            'PortMessage': [0x70, ['_PORT_MESSAGE']],
        },
    ],
    '_ALPC_DISPATCH_CONTEXT': [
        0x20,
        {
            'PortObject': [0x0, ['pointer', ['_ALPC_PORT']]],
            'Message': [0x4, ['pointer', ['_KALPC_MESSAGE']]],
            'CommunicationInfo': [
                0x8,
                ['pointer', ['_ALPC_COMMUNICATION_INFO']],
            ],
            'TargetThread': [0xC, ['pointer', ['_ETHREAD']]],
            'TargetPort': [0x10, ['pointer', ['_ALPC_PORT']]],
            'Flags': [0x14, ['unsigned long']],
            'TotalLength': [0x18, ['unsigned short']],
            'Type': [0x1A, ['unsigned short']],
            'DataInfoOffset': [0x1C, ['unsigned short']],
            'SignalCompletion': [0x1E, ['unsigned char']],
            'PostedToCompletionList': [0x1F, ['unsigned char']],
        },
    ],
    '_REMOTE_PORT_VIEW': [
        0xC,
        {
            'Length': [0x0, ['unsigned long']],
            'ViewSize': [0x4, ['unsigned long']],
            'ViewBase': [0x8, ['pointer', ['void']]],
        },
    ],
    '_KALPC_RESERVE': [
        0x14,
        {
            'OwnerPort': [0x0, ['pointer', ['_ALPC_PORT']]],
            'HandleTable': [0x4, ['pointer', ['_ALPC_HANDLE_TABLE']]],
            'Handle': [0x8, ['pointer', ['void']]],
            'Message': [0xC, ['pointer', ['_KALPC_MESSAGE']]],
            'Active': [0x10, ['long']],
        },
    ],
    '_KALPC_HANDLE_DATA': [
        0x20,
        {
            'Flags': [0x0, ['unsigned long']],
            'ObjectType': [0x4, ['unsigned long']],
            'DuplicateContext': [0x8, ['_OB_DUPLICATE_OBJECT_STATE']],
        },
    ],
    '_KALPC_MESSAGE_ATTRIBUTES': [
        0x1C,
        {
            'ClientContext': [0x0, ['pointer', ['void']]],
            'ServerContext': [0x4, ['pointer', ['void']]],
            'PortContext': [0x8, ['pointer', ['void']]],
            'CancelPortContext': [0xC, ['pointer', ['void']]],
            'SecurityData': [0x10, ['pointer', ['_KALPC_SECURITY_DATA']]],
            'View': [0x14, ['pointer', ['_KALPC_VIEW']]],
            'HandleData': [0x18, ['pointer', ['_KALPC_HANDLE_DATA']]],
        },
    ],
    '__unnamed_1b1c': [
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
    '__unnamed_1b1e': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1b1c']],
        },
    ],
    '_KALPC_SECURITY_DATA': [
        0x50,
        {
            'HandleTable': [0x0, ['pointer', ['_ALPC_HANDLE_TABLE']]],
            'ContextHandle': [0x4, ['pointer', ['void']]],
            'OwningProcess': [0x8, ['pointer', ['_EPROCESS']]],
            'OwnerPort': [0xC, ['pointer', ['_ALPC_PORT']]],
            'DynamicSecurity': [0x10, ['_SECURITY_CLIENT_CONTEXT']],
            'u1': [0x4C, ['__unnamed_1b1e']],
        },
    ],
    '_IO_MINI_COMPLETION_PACKET_USER': [
        0x28,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'PacketType': [0x8, ['unsigned long']],
            'KeyContext': [0xC, ['pointer', ['void']]],
            'ApcContext': [0x10, ['pointer', ['void']]],
            'IoStatus': [0x14, ['long']],
            'IoStatusInformation': [0x18, ['unsigned long']],
            'MiniPacketCallback': [0x1C, ['pointer', ['void']]],
            'Context': [0x20, ['pointer', ['void']]],
            'Allocated': [0x24, ['unsigned char']],
        },
    ],
    '_IOP_IRP_EXTENSION': [
        0x24,
        {
            'ExtensionFlags': [0x0, ['unsigned short']],
            'Allocated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'PropagateId': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'TimeStamped': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'SpareBits': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TypesAllocated': [0x2, ['unsigned short']],
            'GenericExtension': [0x4, ['array', 4, ['unsigned char']]],
            'VerifierContext': [0x8, ['pointer', ['void']]],
            'ActivityId': [0xC, ['_GUID']],
            'Timestamp': [0x1C, ['_LARGE_INTEGER']],
        },
    ],
    '_DRIVER_OBJECT': [
        0xA8,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'DeviceObject': [0x4, ['pointer', ['_DEVICE_OBJECT']]],
            'Flags': [0x8, ['unsigned long']],
            'DriverStart': [0xC, ['pointer', ['void']]],
            'DriverSize': [0x10, ['unsigned long']],
            'DriverSection': [0x14, ['pointer', ['void']]],
            'DriverExtension': [0x18, ['pointer', ['_DRIVER_EXTENSION']]],
            'DriverName': [0x1C, ['_UNICODE_STRING']],
            'HardwareDatabase': [0x24, ['pointer', ['_UNICODE_STRING']]],
            'FastIoDispatch': [0x28, ['pointer', ['_FAST_IO_DISPATCH']]],
            'DriverInit': [0x2C, ['pointer', ['void']]],
            'DriverStartIo': [0x30, ['pointer', ['void']]],
            'DriverUnload': [0x34, ['pointer', ['void']]],
            'MajorFunction': [0x38, ['array', 28, ['pointer', ['void']]]],
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
        0x14,
        {
            'ExposedNamespaceLength': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned short']],
            'DeviceNameLength': [0x4, ['unsigned short']],
            'Reserved': [0x6, ['unsigned short']],
            'InteriorMountPoint': [
                0x8,
                ['pointer', ['_RELATIVE_SYMLINK_INFO']],
            ],
            'OpenedName': [0xC, ['_UNICODE_STRING']],
        },
    ],
    '_ECP_LIST': [
        0x10,
        {
            'Signature': [0x0, ['unsigned long']],
            'Flags': [0x4, ['unsigned long']],
            'EcpList': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_IOP_FILE_OBJECT_EXTENSION': [
        0x24,
        {
            'FoExtFlags': [0x0, ['unsigned long']],
            'FoExtPerTypeExtension': [
                0x4,
                ['array', 7, ['pointer', ['void']]],
            ],
            'FoIoPriorityHint': [
                0x20,
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
        0x70,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'FileObject': [0x4, ['pointer', ['_FILE_OBJECT']]],
            'FinalStatus': [0x8, ['long']],
            'Information': [0xC, ['unsigned long']],
            'ParseCheck': [0x10, ['unsigned long']],
            'RelatedFileObject': [0x14, ['pointer', ['_FILE_OBJECT']]],
            'ReferencedDeviceObject': [0x14, ['pointer', ['_DEVICE_OBJECT']]],
            'OriginalAttributes': [0x18, ['pointer', ['_OBJECT_ATTRIBUTES']]],
            'AllocationSize': [0x20, ['_LARGE_INTEGER']],
            'CreateOptions': [0x28, ['unsigned long']],
            'FileAttributes': [0x2C, ['unsigned short']],
            'ShareAccess': [0x2E, ['unsigned short']],
            'EaBuffer': [0x30, ['pointer', ['void']]],
            'EaLength': [0x34, ['unsigned long']],
            'Options': [0x38, ['unsigned long']],
            'Disposition': [0x3C, ['unsigned long']],
            'BasicInformation': [
                0x40,
                ['pointer', ['_FILE_BASIC_INFORMATION']],
            ],
            'NetworkInformation': [
                0x44,
                ['pointer', ['_FILE_NETWORK_OPEN_INFORMATION']],
            ],
            'CreateFileType': [
                0x48,
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
            'MailslotOrPipeParameters': [0x4C, ['pointer', ['void']]],
            'Override': [0x50, ['unsigned char']],
            'QueryOnly': [0x51, ['unsigned char']],
            'DeleteOnly': [0x52, ['unsigned char']],
            'FullAttributes': [0x53, ['unsigned char']],
            'LocalFileObject': [0x54, ['pointer', ['_DUMMY_FILE_OBJECT']]],
            'InternalFlags': [0x58, ['unsigned long']],
            'AccessMode': [0x5C, ['unsigned char']],
            'DriverCreateContext': [0x60, ['_IO_DRIVER_CREATE_CONTEXT']],
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
    '__unnamed_1be3': [
        0x4,
        {
            'MajorVersion': [0x0, ['unsigned char']],
            'MinorVersion': [0x1, ['unsigned char']],
            'SubVersion': [0x2, ['unsigned char']],
            'SubMinorVersion': [0x3, ['unsigned char']],
        },
    ],
    '_TRACE_LOGFILE_HEADER': [
        0x110,
        {
            'BufferSize': [0x0, ['unsigned long']],
            'Version': [0x4, ['unsigned long']],
            'VersionDetail': [0x4, ['__unnamed_1be3']],
            'ProviderVersion': [0x8, ['unsigned long']],
            'NumberOfProcessors': [0xC, ['unsigned long']],
            'EndTime': [0x10, ['_LARGE_INTEGER']],
            'TimerResolution': [0x18, ['unsigned long']],
            'MaximumFileSize': [0x1C, ['unsigned long']],
            'LogFileMode': [0x20, ['unsigned long']],
            'BuffersWritten': [0x24, ['unsigned long']],
            'LogInstanceGuid': [0x28, ['_GUID']],
            'StartBuffers': [0x28, ['unsigned long']],
            'PointerSize': [0x2C, ['unsigned long']],
            'EventsLost': [0x30, ['unsigned long']],
            'CpuSpeedInMHz': [0x34, ['unsigned long']],
            'LoggerName': [0x38, ['pointer', ['unsigned short']]],
            'LogFileName': [0x3C, ['pointer', ['unsigned short']]],
            'TimeZone': [0x40, ['_RTL_TIME_ZONE_INFORMATION']],
            'BootTime': [0xF0, ['_LARGE_INTEGER']],
            'PerfFreq': [0xF8, ['_LARGE_INTEGER']],
            'StartTime': [0x100, ['_LARGE_INTEGER']],
            'ReservedFlags': [0x108, ['unsigned long']],
            'BuffersLost': [0x10C, ['unsigned long']],
        },
    ],
    '_WMI_LOGGER_CONTEXT': [
        0x278,
        {
            'LoggerId': [0x0, ['unsigned long']],
            'BufferSize': [0x4, ['unsigned long']],
            'MaximumEventSize': [0x8, ['unsigned long']],
            'LoggerMode': [0xC, ['unsigned long']],
            'AcceptNewEvents': [0x10, ['long']],
            'EventMarker': [0x14, ['array', 1, ['unsigned long']]],
            'ErrorMarker': [0x18, ['unsigned long']],
            'SizeMask': [0x1C, ['unsigned long']],
            'GetCpuClock': [0x20, ['pointer', ['void']]],
            'LoggerThread': [0x24, ['pointer', ['_ETHREAD']]],
            'LoggerStatus': [0x28, ['long']],
            'FailureReason': [0x2C, ['unsigned long']],
            'BufferQueue': [0x30, ['_ETW_BUFFER_QUEUE']],
            'OverflowQueue': [0x3C, ['_ETW_BUFFER_QUEUE']],
            'GlobalList': [0x48, ['_LIST_ENTRY']],
            'ProviderBinaryList': [0x50, ['_LIST_ENTRY']],
            'BatchedBufferList': [0x58, ['pointer', ['_WMI_BUFFER_HEADER']]],
            'CurrentBuffer': [0x58, ['_EX_FAST_REF']],
            'LoggerName': [0x5C, ['_UNICODE_STRING']],
            'LogFileName': [0x64, ['_UNICODE_STRING']],
            'LogFilePattern': [0x6C, ['_UNICODE_STRING']],
            'NewLogFileName': [0x74, ['_UNICODE_STRING']],
            'ClockType': [0x7C, ['unsigned long']],
            'LastFlushedBuffer': [0x80, ['unsigned long']],
            'FlushTimer': [0x84, ['unsigned long']],
            'FlushThreshold': [0x88, ['unsigned long']],
            'ByteOffset': [0x90, ['_LARGE_INTEGER']],
            'MinimumBuffers': [0x98, ['unsigned long']],
            'BuffersAvailable': [0x9C, ['long']],
            'NumberOfBuffers': [0xA0, ['long']],
            'MaximumBuffers': [0xA4, ['unsigned long']],
            'EventsLost': [0xA8, ['unsigned long']],
            'PeakBuffersCount': [0xAC, ['long']],
            'BuffersWritten': [0xB0, ['unsigned long']],
            'LogBuffersLost': [0xB4, ['unsigned long']],
            'RealTimeBuffersDelivered': [0xB8, ['unsigned long']],
            'RealTimeBuffersLost': [0xBC, ['unsigned long']],
            'SequencePtr': [0xC0, ['pointer', ['long']]],
            'LocalSequence': [0xC4, ['unsigned long']],
            'InstanceGuid': [0xC8, ['_GUID']],
            'MaximumFileSize': [0xD8, ['unsigned long']],
            'FileCounter': [0xDC, ['long']],
            'PoolType': [
                0xE0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPoolBase',
                            1: 'PagedPool',
                            2: 'NonPagedPoolBaseMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolBaseCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolBaseCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            516: 'NonPagedPoolNxCacheAligned',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            512: 'NonPagedPoolNx',
                            544: 'NonPagedPoolSessionNx',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'ReferenceTime': [0xE8, ['_ETW_REF_CLOCK']],
            'CollectionOn': [0xF8, ['long']],
            'ProviderInfoSize': [0xFC, ['unsigned long']],
            'Consumers': [0x100, ['_LIST_ENTRY']],
            'NumConsumers': [0x108, ['unsigned long']],
            'TransitionConsumer': [
                0x10C,
                ['pointer', ['_ETW_REALTIME_CONSUMER']],
            ],
            'RealtimeLogfileHandle': [0x110, ['pointer', ['void']]],
            'RealtimeLogfileName': [0x114, ['_UNICODE_STRING']],
            'RealtimeWriteOffset': [0x120, ['_LARGE_INTEGER']],
            'RealtimeReadOffset': [0x128, ['_LARGE_INTEGER']],
            'RealtimeLogfileSize': [0x130, ['_LARGE_INTEGER']],
            'RealtimeLogfileUsage': [0x138, ['unsigned long long']],
            'RealtimeMaximumFileSize': [0x140, ['unsigned long long']],
            'RealtimeBuffersSaved': [0x148, ['unsigned long']],
            'RealtimeReferenceTime': [0x150, ['_ETW_REF_CLOCK']],
            'NewRTEventsLost': [
                0x160,
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
            'LoggerEvent': [0x164, ['_KEVENT']],
            'FlushEvent': [0x174, ['_KEVENT']],
            'FlushTimeOutTimer': [0x188, ['_KTIMER']],
            'LoggerDpc': [0x1B0, ['_KDPC']],
            'LoggerMutex': [0x1D0, ['_KMUTANT']],
            'LoggerLock': [0x1F0, ['_EX_PUSH_LOCK']],
            'BufferListSpinLock': [0x1F4, ['unsigned long']],
            'BufferListPushLock': [0x1F4, ['_EX_PUSH_LOCK']],
            'ClientSecurityContext': [0x1F8, ['_SECURITY_CLIENT_CONTEXT']],
            'SecurityDescriptor': [0x234, ['_EX_FAST_REF']],
            'StartTime': [0x238, ['_LARGE_INTEGER']],
            'LogFileHandle': [0x240, ['pointer', ['void']]],
            'BufferSequenceNumber': [0x248, ['long long']],
            'Flags': [0x250, ['unsigned long']],
            'Persistent': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AutoLogger': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'FsReady': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'RealTime': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'KernelTrace': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'NoMoreEnable': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'StackTracing': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ErrorLogged': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'RealtimeLoggerContextFreed': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'PebsTracing': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'PmcCounters': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'PageAlignBuffers': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'SpareFlags1': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'SystemLoggerIndex': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'StackCaching': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'SpareFlags2': [
                0x250,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'RequestFlag': [0x254, ['unsigned long']],
            'DbgRequestNewFie': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DbgRequestUpdateFile': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'DbgRequestFlush': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'DbgRequestDisableRealtime': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'DbgRequestDisconnectConsumer': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'DbgRequestConnectConsumer': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'DbgRequestNotifyConsumer': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'DbgRequestUpdateHeader': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'DbgRequestDefferdFlush': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'DbgRequestDefferdFlushTimer': [
                0x254,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'DbgRequestFlushTimer': [
                0x254,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'DbgRequestUpdateDebugger': [
                0x254,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'DbgSpareRequestFlags': [
                0x254,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'HookIdMap': [0x258, ['_RTL_BITMAP']],
            'StackCache': [0x260, ['pointer', ['_ETW_STACK_CACHE']]],
            'PmcData': [0x264, ['pointer', ['_ETW_PMC_SUPPORT']]],
            'WinRtProviderBinaryList': [0x268, ['_LIST_ENTRY']],
            'ScratchArray': [
                0x270,
                ['pointer', ['pointer', ['_WMI_BUFFER_HEADER']]],
            ],
        },
    ],
    '_ETW_PMC_SUPPORT': [
        0x24,
        {
            'Source': [
                0x0,
                [
                    'array',
                    -16,
                    [
                        'Enumeration',
                        dict(
                            target='long',
                            choices={
                                0: 'ProfileTime',
                                1: 'ProfileAlignmentFixup',
                                2: 'ProfileTotalIssues',
                                3: 'ProfilePipelineDry',
                                4: 'ProfileLoadInstructions',
                                5: 'ProfilePipelineFrozen',
                                6: 'ProfileBranchInstructions',
                                7: 'ProfileTotalNonissues',
                                8: 'ProfileDcacheMisses',
                                9: 'ProfileIcacheMisses',
                                10: 'ProfileCacheMisses',
                                11: 'ProfileBranchMispredictions',
                                12: 'ProfileStoreInstructions',
                                13: 'ProfileFpInstructions',
                                14: 'ProfileIntegerInstructions',
                                15: 'Profile2Issue',
                                16: 'Profile3Issue',
                                17: 'Profile4Issue',
                                18: 'ProfileSpecialInstructions',
                                19: 'ProfileTotalCycles',
                                20: 'ProfileIcacheIssues',
                                21: 'ProfileDcacheAccesses',
                                22: 'ProfileMemoryBarrierCycles',
                                23: 'ProfileLoadLinkedIssues',
                                24: 'ProfileMaximum',
                            },
                        ),
                    ],
                ],
            ],
            'HookIdCount': [0x10, ['unsigned long']],
            'HookId': [0x14, ['array', 4, ['unsigned short']]],
            'CountersCount': [0x1C, ['unsigned long']],
            'ProcessorCtrs': [
                0x20,
                ['array', 1, ['pointer', ['_HAL_PMC_COUNTERS']]],
            ],
        },
    ],
    '_ETW_LOGGER_HANDLE': [
        0x1,
        {
            'DereferenceAndLeave': [0x0, ['unsigned char']],
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
        0x298,
        {
            'TokenSource': [0x0, ['_TOKEN_SOURCE']],
            'TokenId': [0x10, ['_LUID']],
            'AuthenticationId': [0x18, ['_LUID']],
            'ParentTokenId': [0x20, ['_LUID']],
            'ExpirationTime': [0x28, ['_LARGE_INTEGER']],
            'TokenLock': [0x30, ['pointer', ['_ERESOURCE']]],
            'ModifiedId': [0x34, ['_LUID']],
            'Privileges': [0x40, ['_SEP_TOKEN_PRIVILEGES']],
            'AuditPolicy': [0x58, ['_SEP_AUDIT_POLICY']],
            'SessionId': [0x78, ['unsigned long']],
            'UserAndGroupCount': [0x7C, ['unsigned long']],
            'RestrictedSidCount': [0x80, ['unsigned long']],
            'VariableLength': [0x84, ['unsigned long']],
            'DynamicCharged': [0x88, ['unsigned long']],
            'DynamicAvailable': [0x8C, ['unsigned long']],
            'DefaultOwnerIndex': [0x90, ['unsigned long']],
            'UserAndGroups': [0x94, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'RestrictedSids': [0x98, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'PrimaryGroup': [0x9C, ['pointer', ['void']]],
            'DynamicPart': [0xA0, ['pointer', ['unsigned long']]],
            'DefaultDacl': [0xA4, ['pointer', ['_ACL']]],
            'TokenType': [
                0xA8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={1: 'TokenPrimary', 2: 'TokenImpersonation'},
                    ),
                ],
            ],
            'ImpersonationLevel': [
                0xAC,
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
            'TokenFlags': [0xB0, ['unsigned long']],
            'TokenInUse': [0xB4, ['unsigned char']],
            'IntegrityLevelIndex': [0xB8, ['unsigned long']],
            'MandatoryPolicy': [0xBC, ['unsigned long']],
            'LogonSession': [
                0xC0,
                ['pointer', ['_SEP_LOGON_SESSION_REFERENCES']],
            ],
            'OriginatingLogonSession': [0xC4, ['_LUID']],
            'SidHash': [0xCC, ['_SID_AND_ATTRIBUTES_HASH']],
            'RestrictedSidHash': [0x154, ['_SID_AND_ATTRIBUTES_HASH']],
            'pSecurityAttributes': [
                0x1DC,
                ['pointer', ['_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION']],
            ],
            'Package': [0x1E0, ['pointer', ['void']]],
            'Capabilities': [0x1E4, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'CapabilityCount': [0x1E8, ['unsigned long']],
            'CapabilitiesHash': [0x1EC, ['_SID_AND_ATTRIBUTES_HASH']],
            'LowboxNumberEntry': [
                0x274,
                ['pointer', ['_SEP_LOWBOX_NUMBER_ENTRY']],
            ],
            'LowboxHandlesEntry': [
                0x278,
                ['pointer', ['_SEP_LOWBOX_HANDLES_ENTRY']],
            ],
            'pClaimAttributes': [
                0x27C,
                ['pointer', ['_AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION']],
            ],
            'TrustLevelSid': [0x280, ['pointer', ['void']]],
            'TrustLinkedToken': [0x284, ['pointer', ['_TOKEN']]],
            'IntegrityLevelSidValue': [0x288, ['pointer', ['void']]],
            'TokenSidValues': [0x28C, ['pointer', ['_SEP_SID_VALUES_BLOCK']]],
            'VariablePart': [0x290, ['unsigned long']],
        },
    ],
    '_SEP_LOGON_SESSION_REFERENCES': [
        0x48,
        {
            'Next': [0x0, ['pointer', ['_SEP_LOGON_SESSION_REFERENCES']]],
            'LogonId': [0x4, ['_LUID']],
            'BuddyLogonId': [0xC, ['_LUID']],
            'ReferenceCount': [0x14, ['long']],
            'Flags': [0x18, ['unsigned long']],
            'pDeviceMap': [0x1C, ['pointer', ['_DEVICE_MAP']]],
            'Token': [0x20, ['pointer', ['void']]],
            'AccountName': [0x24, ['_UNICODE_STRING']],
            'AuthorityName': [0x2C, ['_UNICODE_STRING']],
            'LowBoxHandlesTable': [0x34, ['_SEP_LOWBOX_HANDLES_TABLE']],
            'SharedDataLock': [0x3C, ['_EX_PUSH_LOCK']],
            'SharedClaimAttributes': [
                0x40,
                ['pointer', ['_AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION']],
            ],
            'SharedSidValues': [0x44, ['pointer', ['_SEP_SID_VALUES_BLOCK']]],
        },
    ],
    '_PS_PROTECTION': [
        0x1,
        {
            'Level': [0x0, ['unsigned char']],
            'Type': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Audit': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Signer': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_OBJECT_HEADER': [
        0x20,
        {
            'PointerCount': [0x0, ['long']],
            'HandleCount': [0x4, ['long']],
            'NextToFree': [0x4, ['pointer', ['void']]],
            'Lock': [0x8, ['_EX_PUSH_LOCK']],
            'TypeIndex': [0xC, ['unsigned char']],
            'TraceFlags': [0xD, ['unsigned char']],
            'DbgRefTrace': [
                0xD,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'DbgTracePermanent': [
                0xD,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'InfoMask': [0xE, ['unsigned char']],
            'Flags': [0xF, ['unsigned char']],
            'NewObject': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'KernelObject': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'KernelOnlyAccess': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'ExclusiveObject': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'PermanentObject': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'DefaultSecurityQuota': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'SingleHandleEntry': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'DeletedInline': [
                0xF,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'ObjectCreateInfo': [
                0x10,
                ['pointer', ['_OBJECT_CREATE_INFORMATION']],
            ],
            'QuotaBlockCharged': [0x10, ['pointer', ['void']]],
            'SecurityDescriptor': [0x14, ['pointer', ['void']]],
            'Body': [0x18, ['_QUAD']],
        },
    ],
    '_OBJECT_HEADER_QUOTA_INFO': [
        0x10,
        {
            'PagedPoolCharge': [0x0, ['unsigned long']],
            'NonPagedPoolCharge': [0x4, ['unsigned long']],
            'SecurityDescriptorCharge': [0x8, ['unsigned long']],
            'SecurityDescriptorQuotaBlock': [0xC, ['pointer', ['void']]],
        },
    ],
    '_OBJECT_HEADER_PROCESS_INFO': [
        0x8,
        {
            'ExclusiveProcess': [0x0, ['pointer', ['_EPROCESS']]],
            'Reserved': [0x4, ['unsigned long']],
        },
    ],
    '_OBJECT_HEADER_HANDLE_INFO': [
        0x8,
        {
            'HandleCountDataBase': [
                0x0,
                ['pointer', ['_OBJECT_HANDLE_COUNT_DATABASE']],
            ],
            'SingleEntry': [0x0, ['_OBJECT_HANDLE_COUNT_ENTRY']],
        },
    ],
    '_OBJECT_HEADER_NAME_INFO': [
        0x10,
        {
            'Directory': [0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
            'Name': [0x4, ['_UNICODE_STRING']],
            'ReferenceCount': [0xC, ['long']],
        },
    ],
    '_OBJECT_HEADER_CREATOR_INFO': [
        0x10,
        {
            'TypeList': [0x0, ['_LIST_ENTRY']],
            'CreatorUniqueProcess': [0x8, ['pointer', ['void']]],
            'CreatorBackTraceIndex': [0xC, ['unsigned short']],
            'Reserved': [0xE, ['unsigned short']],
        },
    ],
    '_OBJECT_HEADER_AUDIT_INFO': [
        0x8,
        {
            'SecurityDescriptor': [0x0, ['pointer', ['void']]],
            'Reserved': [0x4, ['unsigned long']],
        },
    ],
    '_OBP_LOOKUP_CONTEXT': [
        0x18,
        {
            'Directory': [0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
            'Object': [0x4, ['pointer', ['void']]],
            'EntryLink': [
                0x8,
                ['pointer', ['pointer', ['_OBJECT_DIRECTORY_ENTRY']]],
            ],
            'HashValue': [0xC, ['unsigned long']],
            'HashIndex': [0x10, ['unsigned short']],
            'DirectoryLocked': [0x12, ['unsigned char']],
            'LockedExclusive': [0x13, ['unsigned char']],
            'LockStateSignature': [0x14, ['unsigned long']],
        },
    ],
    '_OBJECT_DIRECTORY': [
        0xA8,
        {
            'HashBuckets': [
                0x0,
                ['array', 37, ['pointer', ['_OBJECT_DIRECTORY_ENTRY']]],
            ],
            'Lock': [0x94, ['_EX_PUSH_LOCK']],
            'DeviceMap': [0x98, ['pointer', ['_DEVICE_MAP']]],
            'ShadowDirectory': [0x98, ['pointer', ['_OBJECT_DIRECTORY']]],
            'SessionId': [0x9C, ['unsigned long']],
            'NamespaceEntry': [0xA0, ['pointer', ['void']]],
            'Flags': [0xA4, ['unsigned long']],
        },
    ],
    '_WHEAP_INFO_BLOCK': [
        0xC,
        {
            'ErrorSourceCount': [0x0, ['unsigned long']],
            'ErrorSourceTable': [
                0x4,
                ['pointer', ['_WHEAP_ERROR_SOURCE_TABLE']],
            ],
            'WorkQueue': [0x8, ['pointer', ['_WHEAP_WORK_QUEUE']]],
        },
    ],
    '_WHEAP_ERROR_SOURCE': [
        0x418,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'FailedAllocations': [0x8, ['unsigned long']],
            'PlatformErrorSourceId': [0xC, ['unsigned long']],
            'ErrorCount': [0x10, ['long']],
            'RecordCount': [0x14, ['unsigned long']],
            'RecordLength': [0x18, ['unsigned long']],
            'PoolTag': [0x1C, ['unsigned long']],
            'Type': [
                0x20,
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
            'Records': [0x24, ['pointer', ['_WHEAP_ERROR_RECORD_WRAPPER']]],
            'Context': [0x28, ['pointer', ['void']]],
            'SectionCount': [0x2C, ['unsigned long']],
            'SectionLength': [0x30, ['unsigned long']],
            'TickCountAtLastError': [0x38, ['_LARGE_INTEGER']],
            'AccumulatedErrors': [0x40, ['unsigned long']],
            'TotalErrors': [0x44, ['unsigned long']],
            'Deferred': [0x48, ['unsigned char']],
            'Descriptor': [0x49, ['_WHEA_ERROR_SOURCE_DESCRIPTOR']],
        },
    ],
    '_WHEAP_ERROR_RECORD_WRAPPER': [
        0xE4,
        {
            'WorkEntry': [0x0, ['_LIST_ENTRY']],
            'Length': [0x8, ['unsigned long']],
            'ProcessorNumber': [0xC, ['unsigned long']],
            'Flags': [0x10, ['_WHEAP_ERROR_RECORD_WRAPPER_FLAGS']],
            'InUse': [0x14, ['long']],
            'ErrorSource': [0x18, ['pointer', ['_WHEAP_ERROR_SOURCE']]],
            'ErrorRecord': [0x1C, ['_WHEA_ERROR_RECORD']],
        },
    ],
    '_KSECONDARY_IDT_ENTRY': [
        0x1C,
        {
            'SpinLock': [0x0, ['unsigned long']],
            'ConnectLock': [0x4, ['_KEVENT']],
            'LineMasked': [0x14, ['unsigned char']],
            'InterruptList': [0x18, ['pointer', ['_KINTERRUPT']]],
        },
    ],
    '_WNF_STATE_NAME': [
        0x8,
        {
            'Data': [0x0, ['array', 2, ['unsigned long']]],
        },
    ],
    '_PS_CLIENT_SECURITY_CONTEXT': [
        0x4,
        {
            'ImpersonationData': [0x0, ['unsigned long']],
            'ImpersonationToken': [0x0, ['pointer', ['void']]],
            'ImpersonationLevel': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'EffectiveOnly': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
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
            'ArmCeControlSet': [0x0, ['_ARMCE_DBGKD_CONTROL_SET']],
            'PpcControlSet': [0x0, ['_PPC_DBGKD_CONTROL_SET']],
        },
    ],
    '_MI_VERIFIER_POOL_HEADER': [
        0x4,
        {
            'VerifierPoolEntry': [0x0, ['pointer', ['_VI_POOL_ENTRY']]],
        },
    ],
    '_POP_FX_PLUGIN': [
        0x68,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'Version': [0x8, ['unsigned long']],
            'Flags': [0x10, ['unsigned long long']],
            'WorkQueue': [0x18, ['_KQUEUE']],
            'AcceptDeviceNotification': [0x40, ['pointer', ['void']]],
            'AcceptProcessorNotification': [0x44, ['pointer', ['void']]],
            'WorkOrderCount': [0x48, ['unsigned long']],
            'WorkOrders': [0x4C, ['array', 1, ['_POP_FX_WORK_ORDER']]],
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
        0x30,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'FreeEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Reserved0': [0x4, ['unsigned long']],
            'SenderPort': [0x8, ['pointer', ['void']]],
            'RepliedToThread': [0xC, ['pointer', ['_ETHREAD']]],
            'PortContext': [0x10, ['pointer', ['void']]],
            'Request': [0x18, ['_PORT_MESSAGE']],
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
                        end_bit=38,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=38,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['unsigned long']],
        },
    ],
    '_ALPC_PORT_ATTRIBUTES': [
        0x2C,
        {
            'Flags': [0x0, ['unsigned long']],
            'SecurityQos': [0x4, ['_SECURITY_QUALITY_OF_SERVICE']],
            'MaxMessageLength': [0x10, ['unsigned long']],
            'MemoryBandwidth': [0x14, ['unsigned long']],
            'MaxPoolUsage': [0x18, ['unsigned long']],
            'MaxSectionSize': [0x1C, ['unsigned long']],
            'MaxViewSize': [0x20, ['unsigned long']],
            'MaxTotalSectionSize': [0x24, ['unsigned long']],
            'DupObjectTypes': [0x28, ['unsigned long']],
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
    '_KENTROPY_TIMING_STATE': [
        0x128,
        {
            'EntropyCount': [0x0, ['unsigned long']],
            'Buffer': [0x4, ['array', 64, ['unsigned long']]],
            'Dpc': [0x104, ['_KDPC']],
            'LastDeliveredBuffer': [0x124, ['unsigned long']],
        },
    ],
    '_DISPATCHER_HEADER': [
        0x10,
        {
            'Lock': [0x0, ['long']],
            'LockNV': [0x0, ['long']],
            'Type': [0x0, ['unsigned char']],
            'Signalling': [0x1, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'Reserved1': [0x3, ['unsigned char']],
            'TimerType': [0x0, ['unsigned char']],
            'TimerControlFlags': [0x1, ['unsigned char']],
            'Absolute': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Wake': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'EncodedTolerableDelay': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Hand': [0x2, ['unsigned char']],
            'TimerMiscFlags': [0x3, ['unsigned char']],
            'Index': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Processor': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=6, native_type='unsigned char'),
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
            'Timer2Type': [0x0, ['unsigned char']],
            'Timer2Flags': [0x1, ['unsigned char']],
            'Timer2Inserted': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Timer2Expiring': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Timer2CancelPending': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Timer2SetPending': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Timer2Running': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'Timer2Disabled': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Timer2ReservedFlags': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Timer2Reserved1': [0x2, ['unsigned char']],
            'Timer2Reserved2': [0x3, ['unsigned char']],
            'QueueType': [0x0, ['unsigned char']],
            'QueueControlFlags': [0x1, ['unsigned char']],
            'Abandoned': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'DisableIncrement': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'QueueReservedControlFlags': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'QueueSize': [0x2, ['unsigned char']],
            'QueueReserved': [0x3, ['unsigned char']],
            'ThreadType': [0x0, ['unsigned char']],
            'ThreadReserved': [0x1, ['unsigned char']],
            'ThreadControlFlags': [0x2, ['unsigned char']],
            'CycleProfiling': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'CounterProfiling': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'GroupScheduling': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'AffinitySet': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ThreadReservedControlFlags': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'DebugActive': [0x3, ['unsigned char']],
            'MutantType': [0x0, ['unsigned char']],
            'MutantSize': [0x1, ['unsigned char']],
            'DpcActive': [0x2, ['unsigned char']],
            'MutantReserved': [0x3, ['unsigned char']],
            'SignalState': [0x4, ['long']],
            'WaitListHead': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_VI_POOL_ENTRY': [
        0x10,
        {
            'PageHeader': [0x0, ['_VI_POOL_PAGE_HEADER']],
            'InUse': [0x0, ['_VI_POOL_ENTRY_INUSE']],
            'NextFree': [0x0, ['pointer', ['_SINGLE_LIST_ENTRY']]],
        },
    ],
    '_MM_PAGE_ACCESS_INFO': [
        0x8,
        {
            'Flags': [0x0, ['_MM_PAGE_ACCESS_INFO_FLAGS']],
            'FileOffset': [0x0, ['unsigned long long']],
            'VirtualAddress': [0x0, ['pointer', ['void']]],
            'DontUse0': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Spare0': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'PointerProtoPte': [0x4, ['pointer', ['void']]],
        },
    ],
    '_MI_CONTROL_AREA_WAIT_BLOCK': [
        0x1C,
        {
            'Next': [0x0, ['pointer', ['_MI_CONTROL_AREA_WAIT_BLOCK']]],
            'WaitReason': [0x4, ['unsigned long']],
            'WaitResponse': [0x8, ['unsigned long']],
            'Gate': [0xC, ['_KGATE']],
        },
    ],
    '_HEAP_COUNTERS': [
        0x5C,
        {
            'TotalMemoryReserved': [0x0, ['unsigned long']],
            'TotalMemoryCommitted': [0x4, ['unsigned long']],
            'TotalMemoryLargeUCR': [0x8, ['unsigned long']],
            'TotalSizeInVirtualBlocks': [0xC, ['unsigned long']],
            'TotalSegments': [0x10, ['unsigned long']],
            'TotalUCRs': [0x14, ['unsigned long']],
            'CommittOps': [0x18, ['unsigned long']],
            'DeCommitOps': [0x1C, ['unsigned long']],
            'LockAcquires': [0x20, ['unsigned long']],
            'LockCollisions': [0x24, ['unsigned long']],
            'CommitRate': [0x28, ['unsigned long']],
            'DecommittRate': [0x2C, ['unsigned long']],
            'CommitFailures': [0x30, ['unsigned long']],
            'InBlockCommitFailures': [0x34, ['unsigned long']],
            'PollIntervalCounter': [0x38, ['unsigned long']],
            'DecommitsSinceLastCheck': [0x3C, ['unsigned long']],
            'HeapPollInterval': [0x40, ['unsigned long']],
            'AllocAndFreeOps': [0x44, ['unsigned long']],
            'AllocationIndicesActive': [0x48, ['unsigned long']],
            'InBlockDeccommits': [0x4C, ['unsigned long']],
            'InBlockDeccomitSize': [0x50, ['unsigned long']],
            'HighWatermarkSize': [0x54, ['unsigned long']],
            'LastPolledSize': [0x58, ['unsigned long']],
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
    '_SYSPTES_HEADER': [
        0x14,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Count': [0x8, ['unsigned long']],
            'NumberOfEntries': [0xC, ['unsigned long']],
            'NumberOfEntriesPeak': [0x10, ['unsigned long']],
        },
    ],
    '_EXCEPTION_RECORD': [
        0x50,
        {
            'ExceptionCode': [0x0, ['long']],
            'ExceptionFlags': [0x4, ['unsigned long']],
            'ExceptionRecord': [0x8, ['pointer', ['_EXCEPTION_RECORD']]],
            'ExceptionAddress': [0xC, ['pointer', ['void']]],
            'NumberParameters': [0x10, ['unsigned long']],
            'ExceptionInformation': [0x14, ['array', 15, ['unsigned long']]],
        },
    ],
    '_MI_ACTIVE_WSLE_LISTHEAD': [
        0x8,
        {
            'Flink': [0x0, ['unsigned long']],
            'Blink': [0x4, ['unsigned long']],
        },
    ],
    '_PPM_IDLE_SYNCHRONIZATION_STATE': [
        0x4,
        {
            'AsLong': [0x0, ['long']],
            'RefCount': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='long'),
                ],
            ],
            'State': [
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
    '_PENDING_RELATIONS_LIST_ENTRY': [
        0x44,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'WorkItem': [0x8, ['_WORK_QUEUE_ITEM']],
            'DeviceEvent': [0x18, ['pointer', ['_PNP_DEVICE_EVENT_ENTRY']]],
            'DeviceObject': [0x1C, ['pointer', ['_DEVICE_OBJECT']]],
            'RelationsList': [0x20, ['pointer', ['_RELATION_LIST']]],
            'EjectIrp': [0x24, ['pointer', ['_IRP']]],
            'Lock': [
                0x28,
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
            'Problem': [0x2C, ['unsigned long']],
            'ProfileChangingEject': [0x30, ['unsigned char']],
            'DisplaySafeRemovalDialog': [0x31, ['unsigned char']],
            'LightestSleepState': [
                0x34,
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
            'DockInterface': [0x38, ['pointer', ['DOCK_INTERFACE']]],
            'DequeuePending': [0x3C, ['unsigned char']],
            'DeleteType': [
                0x40,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'QueryRemoveDevice',
                            1: 'CancelRemoveDevice',
                            2: 'RemoveDevice',
                            3: 'SurpriseRemoveDevice',
                            4: 'EjectDevice',
                            5: 'RemoveFailedDevice',
                            6: 'RemoveUnstartedFailedDevice',
                            7: 'MaxDeviceDeleteType',
                        },
                    ),
                ],
            ],
        },
    ],
    '_CELL_DATA': [
        0x50,
        {
            'u': [0x0, ['_u']],
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
        0x8,
        {
            'CommittThresholdShift': [0x0, ['unsigned long']],
            'MaxPreCommittThreshold': [0x4, ['unsigned long']],
        },
    ],
    '_MMWSLE_NONDIRECT_HASH': [
        0x8,
        {
            'Key': [0x0, ['pointer', ['void']]],
            'Index': [0x4, ['unsigned long']],
        },
    ],
    '_POP_FX_WORK_ORDER': [
        0x1C,
        {
            'WorkItem': [0x0, ['_WORK_QUEUE_ITEM']],
            'WorkCount': [0x10, ['long']],
            'Context': [0x14, ['pointer', ['void']]],
            'WatchdogTimerInfo': [
                0x18,
                ['pointer', ['_POP_FX_WORK_ORDER_WATCHDOG_INFO']],
            ],
        },
    ],
    '_KTIMER_EXPIRATION_TRACE': [
        0x10,
        {
            'InterruptTime': [0x0, ['unsigned long long']],
            'PerformanceCounter': [0x8, ['_LARGE_INTEGER']],
        },
    ],
    '_POOL_TRACKER_BIG_PAGES': [
        0x10,
        {
            'Va': [0x0, ['unsigned long']],
            'Key': [0x4, ['unsigned long']],
            'PoolType': [0x8, ['unsigned long']],
            'NumberOfBytes': [0xC, ['unsigned long']],
        },
    ],
    'tagSWITCH_CONTEXT_DATA': [
        0x48,
        {
            'ullOsMaxVersionTested': [0x0, ['unsigned long long']],
            'ullContextMinimum': [0x8, ['unsigned long long']],
            'guPlatform': [0x10, ['_GUID']],
            'guMinPlatform': [0x20, ['_GUID']],
            'ulContextSource': [0x30, ['unsigned long']],
            'ulElementCount': [0x34, ['unsigned long']],
            'guElements': [0x38, ['array', 1, ['_GUID']]],
        },
    ],
    '_WHEAP_ERROR_SOURCE_TABLE': [
        0x20,
        {
            'Signature': [0x0, ['unsigned long']],
            'Count': [0x4, ['long']],
            'Items': [0x8, ['_LIST_ENTRY']],
            'InsertLock': [0x10, ['_KEVENT']],
        },
    ],
    '_TEB_ACTIVE_FRAME': [
        0xC,
        {
            'Flags': [0x0, ['unsigned long']],
            'Previous': [0x4, ['pointer', ['_TEB_ACTIVE_FRAME']]],
            'Context': [0x8, ['pointer', ['_TEB_ACTIVE_FRAME_CONTEXT']]],
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
        0x2C,
        {
            'Type': [0x0, ['unsigned long']],
            'KeyControlBlock': [0x4, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'NotifyBlock': [0x8, ['pointer', ['_CM_NOTIFY_BLOCK']]],
            'ProcessID': [0xC, ['pointer', ['void']]],
            'KeyBodyList': [0x10, ['_LIST_ENTRY']],
            'Flags': [
                0x18,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'HandleTags': [
                0x18,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'KtmTrans': [0x1C, ['pointer', ['void']]],
            'KtmUow': [0x20, ['pointer', ['_GUID']]],
            'ContextListHead': [0x24, ['_LIST_ENTRY']],
        },
    ],
    '_KWAIT_BLOCK': [
        0x18,
        {
            'WaitListEntry': [0x0, ['_LIST_ENTRY']],
            'WaitType': [0x8, ['unsigned char']],
            'BlockState': [0x9, ['unsigned char']],
            'WaitKey': [0xA, ['unsigned short']],
            'Thread': [0xC, ['pointer', ['_KTHREAD']]],
            'NotificationQueue': [0xC, ['pointer', ['_KQUEUE']]],
            'Object': [0x10, ['pointer', ['void']]],
            'SparePtr': [0x14, ['pointer', ['void']]],
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
            'DemandFillProto': [
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
            'HiberVerifyConverted': [
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
            'Unused1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=3,
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
            'Combined': [
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
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16,
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ProtoAddress': [
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
        0x50,
        {
            'ThermalStamp': [0x0, ['unsigned long']],
            'ThermalConstant1': [0x4, ['unsigned long']],
            'ThermalConstant2': [0x8, ['unsigned long']],
            'SamplingPeriod': [0xC, ['unsigned long']],
            'CurrentTemperature': [0x10, ['unsigned long']],
            'PassiveTripPoint': [0x14, ['unsigned long']],
            'CriticalTripPoint': [0x18, ['unsigned long']],
            'ActiveTripPointCount': [0x1C, ['unsigned char']],
            'ActiveTripPoint': [0x20, ['array', 10, ['unsigned long']]],
            'S4TransitionTripPoint': [0x48, ['unsigned long']],
            'MinimumThrottle': [0x4C, ['unsigned long']],
        },
    ],
    '__unnamed_1d6c': [
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
    '__unnamed_1d6e': [
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
            'File': [0x0, ['__unnamed_1d6c']],
            'Private': [0x0, ['__unnamed_1d6e']],
        },
    ],
    '_PPM_CONCURRENCY_ACCOUNTING': [
        0x28,
        {
            'Lock': [0x0, ['unsigned long']],
            'Processors': [0x4, ['unsigned long']],
            'ActiveProcessors': [0x8, ['unsigned long']],
            'LastUpdateTime': [0x10, ['unsigned long long']],
            'TotalTime': [0x18, ['unsigned long long']],
            'AccumulatedTime': [0x20, ['array', 1, ['unsigned long long']]],
        },
    ],
    '_VI_VERIFIER_ISSUE': [
        0x10,
        {
            'IssueType': [0x0, ['unsigned long']],
            'Address': [0x4, ['pointer', ['void']]],
            'Parameters': [0x8, ['array', 2, ['unsigned long']]],
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
            'OnDereferenceList': [
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
        0x8,
        {
            'ExceptionRecord': [0x0, ['pointer', ['_EXCEPTION_RECORD']]],
            'ContextRecord': [0x4, ['pointer', ['_CONTEXT']]],
        },
    ],
    '_KMUTANT': [
        0x20,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'MutantListEntry': [0x10, ['_LIST_ENTRY']],
            'OwnerThread': [0x18, ['pointer', ['_KTHREAD']]],
            'Abandoned': [0x1C, ['unsigned char']],
            'ApcDisable': [0x1D, ['unsigned char']],
        },
    ],
    '_OBJECT_REF_INFO': [
        0x1C,
        {
            'ObjectHeader': [0x0, ['pointer', ['_OBJECT_HEADER']]],
            'NextRef': [0x4, ['pointer', ['void']]],
            'ImageFileName': [0x8, ['array', 16, ['unsigned char']]],
            'NextPos': [0x18, ['unsigned short']],
            'MaxStacks': [0x1A, ['unsigned short']],
            'StackInfo': [0x1C, ['array', 0, ['_OBJECT_REF_STACK_INFO']]],
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
        0x8,
        {
            'SecurityContext': [0x0, ['_IMAGE_SECURITY_CONTEXT']],
            'DynamicRelocations': [0x4, ['pointer', ['void']]],
        },
    ],
    '_AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION': [
        0x130,
        {
            'DeviceGroupsCount': [0x0, ['unsigned long']],
            'pDeviceGroups': [0x4, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'RestrictedDeviceGroupsCount': [0x8, ['unsigned long']],
            'pRestrictedDeviceGroups': [
                0xC,
                ['pointer', ['_SID_AND_ATTRIBUTES']],
            ],
            'DeviceGroupsHash': [0x10, ['_SID_AND_ATTRIBUTES_HASH']],
            'RestrictedDeviceGroupsHash': [0x98, ['_SID_AND_ATTRIBUTES_HASH']],
            'pUserSecurityAttributes': [
                0x120,
                ['pointer', ['_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION']],
            ],
            'pDeviceSecurityAttributes': [
                0x124,
                ['pointer', ['_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION']],
            ],
            'pRestrictedUserSecurityAttributes': [
                0x128,
                ['pointer', ['_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION']],
            ],
            'pRestrictedDeviceSecurityAttributes': [
                0x12C,
                ['pointer', ['_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION']],
            ],
        },
    ],
    '_HEAP_TAG_ENTRY': [
        0x40,
        {
            'Allocs': [0x0, ['unsigned long']],
            'Frees': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long']],
            'TagIndex': [0xC, ['unsigned short']],
            'CreatorBackTraceIndex': [0xE, ['unsigned short']],
            'TagName': [0x10, ['array', 24, ['wchar']]],
        },
    ],
    '_MMPTE_HIGHLOW': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['unsigned long']],
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
    '_MMWSLE_FREE_ENTRY': [
        0x4,
        {
            'MustBeZero': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'PreviousFree': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=12, native_type='unsigned long'),
                ],
            ],
            'NextFree': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_NT_TIB': [
        0x1C,
        {
            'ExceptionList': [
                0x0,
                ['pointer', ['_EXCEPTION_REGISTRATION_RECORD']],
            ],
            'StackBase': [0x4, ['pointer', ['void']]],
            'StackLimit': [0x8, ['pointer', ['void']]],
            'SubSystemTib': [0xC, ['pointer', ['void']]],
            'FiberData': [0x10, ['pointer', ['void']]],
            'Version': [0x10, ['unsigned long']],
            'ArbitraryUserPointer': [0x14, ['pointer', ['void']]],
            'Self': [0x18, ['pointer', ['_NT_TIB']]],
        },
    ],
    '_LEARNING_MODE_DATA': [
        0x8,
        {
            'Settings': [0x0, ['unsigned long']],
            'Enabled': [0x4, ['unsigned char']],
            'PermissiveModeEnabled': [0x5, ['unsigned char']],
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
        0x2C0,
        {
            'Event': [0x0, ['_KEVENT']],
            'JobLinks': [0x10, ['_LIST_ENTRY']],
            'ProcessListHead': [0x18, ['_LIST_ENTRY']],
            'JobLock': [0x20, ['_ERESOURCE']],
            'TotalUserTime': [0x58, ['_LARGE_INTEGER']],
            'TotalKernelTime': [0x60, ['_LARGE_INTEGER']],
            'TotalCycleTime': [0x68, ['_LARGE_INTEGER']],
            'ThisPeriodTotalUserTime': [0x70, ['_LARGE_INTEGER']],
            'ThisPeriodTotalKernelTime': [0x78, ['_LARGE_INTEGER']],
            'TotalContextSwitches': [0x80, ['unsigned long long']],
            'TotalPageFaultCount': [0x88, ['unsigned long']],
            'TotalProcesses': [0x8C, ['unsigned long']],
            'ActiveProcesses': [0x90, ['unsigned long']],
            'TotalTerminatedProcesses': [0x94, ['unsigned long']],
            'PerProcessUserTimeLimit': [0x98, ['_LARGE_INTEGER']],
            'PerJobUserTimeLimit': [0xA0, ['_LARGE_INTEGER']],
            'MinimumWorkingSetSize': [0xA8, ['unsigned long']],
            'MaximumWorkingSetSize': [0xAC, ['unsigned long']],
            'LimitFlags': [0xB0, ['unsigned long']],
            'ActiveProcessLimit': [0xB4, ['unsigned long']],
            'Affinity': [0xB8, ['_KAFFINITY_EX']],
            'AccessState': [0xC4, ['pointer', ['_JOB_ACCESS_STATE']]],
            'AccessStateQuotaReference': [0xC8, ['pointer', ['void']]],
            'UIRestrictionsClass': [0xCC, ['unsigned long']],
            'EndOfJobTimeAction': [0xD0, ['unsigned long']],
            'CompletionPort': [0xD4, ['pointer', ['void']]],
            'CompletionKey': [0xD8, ['pointer', ['void']]],
            'CompletionCount': [0xE0, ['unsigned long long']],
            'SessionId': [0xE8, ['unsigned long']],
            'SchedulingClass': [0xEC, ['unsigned long']],
            'ReadOperationCount': [0xF0, ['unsigned long long']],
            'WriteOperationCount': [0xF8, ['unsigned long long']],
            'OtherOperationCount': [0x100, ['unsigned long long']],
            'ReadTransferCount': [0x108, ['unsigned long long']],
            'WriteTransferCount': [0x110, ['unsigned long long']],
            'OtherTransferCount': [0x118, ['unsigned long long']],
            'DiskIoInfo': [0x120, ['_PROCESS_DISK_COUNTERS']],
            'ProcessMemoryLimit': [0x148, ['unsigned long']],
            'JobMemoryLimit': [0x14C, ['unsigned long']],
            'PeakProcessMemoryUsed': [0x150, ['unsigned long']],
            'PeakJobMemoryUsed': [0x154, ['unsigned long']],
            'EffectiveAffinity': [0x158, ['_KAFFINITY_EX']],
            'EffectivePerProcessUserTimeLimit': [0x168, ['_LARGE_INTEGER']],
            'EffectiveMinimumWorkingSetSize': [0x170, ['unsigned long']],
            'EffectiveMaximumWorkingSetSize': [0x174, ['unsigned long']],
            'EffectiveProcessMemoryLimit': [0x178, ['unsigned long']],
            'EffectiveProcessMemoryLimitJob': [0x17C, ['pointer', ['_EJOB']]],
            'EffectivePerProcessUserTimeLimitJob': [
                0x180,
                ['pointer', ['_EJOB']],
            ],
            'EffectiveLimitFlags': [0x184, ['unsigned long']],
            'EffectiveSchedulingClass': [0x188, ['unsigned long']],
            'EffectiveFreezeCount': [0x18C, ['unsigned long']],
            'EffectiveBackgroundCount': [0x190, ['unsigned long']],
            'EffectiveSwapCount': [0x194, ['unsigned long']],
            'EffectiveNotificationLimitCount': [0x198, ['unsigned long']],
            'EffectivePriorityClass': [0x19C, ['unsigned char']],
            'PriorityClass': [0x19D, ['unsigned char']],
            'Reserved1': [0x19E, ['array', 2, ['unsigned char']]],
            'CompletionFilter': [0x1A0, ['unsigned long']],
            'WakeChannel': [0x1A8, ['_WNF_STATE_NAME']],
            'WakeInfo': [0x1A8, ['_PS_WAKE_INFORMATION']],
            'WakeFilter': [0x1E0, ['_JOBOBJECT_WAKE_FILTER']],
            'LowEdgeLatchFilter': [0x1E8, ['unsigned long']],
            'OwnedHighEdgeFilters': [0x1EC, ['unsigned long']],
            'NotificationLink': [0x1F0, ['pointer', ['_EJOB']]],
            'CurrentJobMemoryUsed': [0x1F8, ['unsigned long long']],
            'NotificationInfo': [
                0x200,
                ['pointer', ['_JOB_NOTIFICATION_INFORMATION']],
            ],
            'NotificationInfoQuotaReference': [0x204, ['pointer', ['void']]],
            'NotificationPacket': [
                0x208,
                ['pointer', ['_IO_MINI_COMPLETION_PACKET_USER']],
            ],
            'CpuRateControl': [0x20C, ['pointer', ['_JOB_CPU_RATE_CONTROL']]],
            'EffectiveSchedulingGroup': [0x210, ['pointer', ['void']]],
            'ReadyTime': [0x218, ['unsigned long long']],
            'MemoryLimitsLock': [0x220, ['_EX_PUSH_LOCK']],
            'SiblingJobLinks': [0x224, ['_LIST_ENTRY']],
            'ChildJobListHead': [0x22C, ['_LIST_ENTRY']],
            'ParentJob': [0x234, ['pointer', ['_EJOB']]],
            'RootJob': [0x238, ['pointer', ['_EJOB']]],
            'IteratorListHead': [0x23C, ['_LIST_ENTRY']],
            'AncestorCount': [0x244, ['unsigned long']],
            'Ancestors': [0x248, ['pointer', ['pointer', ['_EJOB']]]],
            'Accounting': [0x250, ['_EPROCESS_VALUES']],
            'ShadowActiveProcessCount': [0x2A0, ['unsigned long']],
            'SequenceNumber': [0x2A4, ['unsigned long']],
            'TimerListLock': [0x2A8, ['unsigned long']],
            'TimerListHead': [0x2AC, ['_LIST_ENTRY']],
            'JobFlags': [0x2B4, ['unsigned long']],
            'CloseDone': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'MultiGroup': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'OutstandingNotification': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'NotificationInProgress': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'UILimits': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'CpuRateControlActive': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'OwnCpuRateControl': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Terminating': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'WorkingSetLock': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'JobFrozen': [
                0x2B4,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Background': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'WakeNotificationAllocated': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'WakeNotificationEnabled': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'WakeNotificationPending': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'LimitNotificationRequired': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'ZeroCountNotificationRequired': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'CycleTimeNotificationRequired': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'CycleTimeNotificationPending': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'TimersVirtualized': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'JobSwapped': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'ViolationDetected': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'EmptyJobNotified': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'NoSystemCharge': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'DropNoWakeCharges': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'NoWakeChargePolicyDecided': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'SpareJobFlags': [
                0x2B4,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'EffectiveHighEdgeFilters': [0x2B8, ['unsigned long']],
        },
    ],
    '_PPM_IDLE_STATES': [
        0x110,
        {
            'InterfaceVersion': [0x0, ['unsigned char']],
            'ForceIdle': [0x1, ['unsigned char']],
            'EstimateIdleDuration': [0x2, ['unsigned char']],
            'ExitLatencyTraceEnabled': [0x3, ['unsigned char']],
            'NonInterruptibleTransition': [0x4, ['unsigned char']],
            'ExitLatencyCountdown': [0x8, ['unsigned long']],
            'TargetState': [0xC, ['unsigned long']],
            'ActualState': [0x10, ['unsigned long']],
            'OldState': [0x14, ['unsigned long']],
            'OverrideIndex': [0x18, ['unsigned long']],
            'ProcessorIdleCount': [0x1C, ['unsigned long']],
            'Type': [0x20, ['unsigned long']],
            'ReasonFlags': [0x24, ['unsigned short']],
            'InitiateWakeStamp': [0x28, ['unsigned long long']],
            'PreviousStatus': [0x30, ['long']],
            'PreviousCancelReason': [0x34, ['unsigned long']],
            'PrimaryProcessorMask': [0x38, ['_KAFFINITY_EX']],
            'SecondaryProcessorMask': [0x44, ['_KAFFINITY_EX']],
            'IdlePrepare': [0x50, ['pointer', ['void']]],
            'IdleExecute': [0x54, ['pointer', ['void']]],
            'IdlePreselect': [0x58, ['pointer', ['void']]],
            'IdleTest': [0x5C, ['pointer', ['void']]],
            'IdleComplete': [0x60, ['pointer', ['void']]],
            'IdleCancel': [0x64, ['pointer', ['void']]],
            'IdleIsHalted': [0x68, ['pointer', ['void']]],
            'IdleInitiateWake': [0x6C, ['pointer', ['void']]],
            'QueryPlatformStateResidency': [0x70, ['pointer', ['void']]],
            'PrepareInfo': [0x78, ['_PROCESSOR_IDLE_PREPARE_INFO']],
            'Tracing': [0xD8, ['pointer', ['_PERFINFO_PPM_STATE_SELECTION']]],
            'State': [0xDC, ['array', 1, ['_PPM_IDLE_STATE']]],
        },
    ],
    '_PEB': [
        0x250,
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
            'IsImageDynamicallyRelocated': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'SkipPatchingUser32Forwarders': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'IsPackagedProcess': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'IsAppContainer': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'IsProtectedProcessLight': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Mutant': [0x4, ['pointer', ['void']]],
            'ImageBaseAddress': [0x8, ['pointer', ['void']]],
            'Ldr': [0xC, ['pointer', ['_PEB_LDR_DATA']]],
            'ProcessParameters': [
                0x10,
                ['pointer', ['_RTL_USER_PROCESS_PARAMETERS']],
            ],
            'SubSystemData': [0x14, ['pointer', ['void']]],
            'ProcessHeap': [0x18, ['pointer', ['void']]],
            'FastPebLock': [0x1C, ['pointer', ['_RTL_CRITICAL_SECTION']]],
            'AtlThunkSListPtr': [0x20, ['pointer', ['void']]],
            'IFEOKey': [0x24, ['pointer', ['void']]],
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
            'KernelCallbackTable': [0x2C, ['pointer', ['void']]],
            'UserSharedInfoPtr': [0x2C, ['pointer', ['void']]],
            'SystemReserved': [0x30, ['array', 1, ['unsigned long']]],
            'AtlThunkSListPtr32': [0x34, ['unsigned long']],
            'ApiSetMap': [0x38, ['pointer', ['void']]],
            'TlsExpansionCounter': [0x3C, ['unsigned long']],
            'TlsBitmap': [0x40, ['pointer', ['void']]],
            'TlsBitmapBits': [0x44, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x4C, ['pointer', ['void']]],
            'SparePvoid0': [0x50, ['pointer', ['void']]],
            'ReadOnlyStaticServerData': [
                0x54,
                ['pointer', ['pointer', ['void']]],
            ],
            'AnsiCodePageData': [0x58, ['pointer', ['void']]],
            'OemCodePageData': [0x5C, ['pointer', ['void']]],
            'UnicodeCaseTableData': [0x60, ['pointer', ['void']]],
            'NumberOfProcessors': [0x64, ['unsigned long']],
            'NtGlobalFlag': [0x68, ['unsigned long']],
            'CriticalSectionTimeout': [0x70, ['_LARGE_INTEGER']],
            'HeapSegmentReserve': [0x78, ['unsigned long']],
            'HeapSegmentCommit': [0x7C, ['unsigned long']],
            'HeapDeCommitTotalFreeThreshold': [0x80, ['unsigned long']],
            'HeapDeCommitFreeBlockThreshold': [0x84, ['unsigned long']],
            'NumberOfHeaps': [0x88, ['unsigned long']],
            'MaximumNumberOfHeaps': [0x8C, ['unsigned long']],
            'ProcessHeaps': [0x90, ['pointer', ['pointer', ['void']]]],
            'GdiSharedHandleTable': [0x94, ['pointer', ['void']]],
            'ProcessStarterHelper': [0x98, ['pointer', ['void']]],
            'GdiDCAttributeList': [0x9C, ['unsigned long']],
            'LoaderLock': [0xA0, ['pointer', ['_RTL_CRITICAL_SECTION']]],
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
            'PostProcessInitRoutine': [0x14C, ['pointer', ['void']]],
            'TlsExpansionBitmap': [0x150, ['pointer', ['void']]],
            'TlsExpansionBitmapBits': [
                0x154,
                ['array', 32, ['unsigned long']],
            ],
            'SessionId': [0x1D4, ['unsigned long']],
            'AppCompatFlags': [0x1D8, ['_ULARGE_INTEGER']],
            'AppCompatFlagsUser': [0x1E0, ['_ULARGE_INTEGER']],
            'pShimData': [0x1E8, ['pointer', ['void']]],
            'AppCompatInfo': [0x1EC, ['pointer', ['void']]],
            'CSDVersion': [0x1F0, ['_UNICODE_STRING']],
            'ActivationContextData': [
                0x1F8,
                ['pointer', ['_ACTIVATION_CONTEXT_DATA']],
            ],
            'ProcessAssemblyStorageMap': [
                0x1FC,
                ['pointer', ['_ASSEMBLY_STORAGE_MAP']],
            ],
            'SystemDefaultActivationContextData': [
                0x200,
                ['pointer', ['_ACTIVATION_CONTEXT_DATA']],
            ],
            'SystemAssemblyStorageMap': [
                0x204,
                ['pointer', ['_ASSEMBLY_STORAGE_MAP']],
            ],
            'MinimumStackCommit': [0x208, ['unsigned long']],
            'FlsCallback': [0x20C, ['pointer', ['_FLS_CALLBACK_INFO']]],
            'FlsListHead': [0x210, ['_LIST_ENTRY']],
            'FlsBitmap': [0x218, ['pointer', ['void']]],
            'FlsBitmapBits': [0x21C, ['array', 4, ['unsigned long']]],
            'FlsHighIndex': [0x22C, ['unsigned long']],
            'WerRegistrationData': [0x230, ['pointer', ['void']]],
            'WerShipAssertPtr': [0x234, ['pointer', ['void']]],
            'pUnused': [0x238, ['pointer', ['void']]],
            'pImageHeaderHash': [0x23C, ['pointer', ['void']]],
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
            'LibLoaderTracingEnabled': [
                0x240,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'SpareTracingBits': [
                0x240,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'CsrServerReadOnlySharedMemoryBase': [
                0x248,
                ['unsigned long long'],
            ],
        },
    ],
    '_HEAP_UCR_DESCRIPTOR': [
        0x18,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'SegmentEntry': [0x8, ['_LIST_ENTRY']],
            'Address': [0x10, ['pointer', ['void']]],
            'Size': [0x14, ['unsigned long']],
        },
    ],
    '_ETW_REALTIME_CONSUMER': [
        0x54,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'ProcessHandle': [0x8, ['pointer', ['void']]],
            'ProcessObject': [0xC, ['pointer', ['_EPROCESS']]],
            'NextNotDelivered': [0x10, ['pointer', ['void']]],
            'RealtimeConnectContext': [0x14, ['pointer', ['void']]],
            'DisconnectEvent': [0x18, ['pointer', ['_KEVENT']]],
            'DataAvailableEvent': [0x1C, ['pointer', ['_KEVENT']]],
            'UserBufferCount': [0x20, ['pointer', ['unsigned long']]],
            'UserBufferListHead': [0x24, ['pointer', ['_SINGLE_LIST_ENTRY']]],
            'BuffersLost': [0x28, ['unsigned long']],
            'EmptyBuffersCount': [0x2C, ['unsigned long']],
            'LoggerId': [0x30, ['unsigned short']],
            'Flags': [0x32, ['unsigned char']],
            'ShutDownRequested': [
                0x32,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'NewBuffersLost': [
                0x32,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Disconnected': [
                0x32,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Notified': [
                0x32,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ReservedBufferSpaceBitMap': [0x34, ['_RTL_BITMAP']],
            'ReservedBufferSpace': [0x3C, ['pointer', ['unsigned char']]],
            'ReservedBufferSpaceSize': [0x40, ['unsigned long']],
            'UserPagesAllocated': [0x44, ['unsigned long']],
            'UserPagesReused': [0x48, ['unsigned long']],
            'EventsLostCount': [0x4C, ['pointer', ['unsigned long']]],
            'BuffersLostCount': [0x50, ['pointer', ['unsigned long']]],
        },
    ],
    '__unnamed_1dde': [
        0x4,
        {
            'BaseMid': [0x0, ['unsigned char']],
            'Flags1': [0x1, ['unsigned char']],
            'Flags2': [0x2, ['unsigned char']],
            'BaseHi': [0x3, ['unsigned char']],
        },
    ],
    '__unnamed_1de4': [
        0x4,
        {
            'BaseMid': [
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
            'Pres': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'LimitHi': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'Sys': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved_0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'Default_Big': [
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
            'BaseHi': [
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
    '__unnamed_1de6': [
        0x4,
        {
            'Bytes': [0x0, ['__unnamed_1dde']],
            'Bits': [0x0, ['__unnamed_1de4']],
        },
    ],
    '_KGDTENTRY': [
        0x8,
        {
            'LimitLow': [0x0, ['unsigned short']],
            'BaseLow': [0x2, ['unsigned short']],
            'HighWord': [0x4, ['__unnamed_1de6']],
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
                            0: 'NonPagedPoolBase',
                            1: 'PagedPool',
                            2: 'NonPagedPoolBaseMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolBaseCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolBaseCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            516: 'NonPagedPoolNxCacheAligned',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            512: 'NonPagedPoolNx',
                            544: 'NonPagedPoolSessionNx',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'PagedLock': [0x4, ['_FAST_MUTEX']],
            'NonPagedLock': [0x4, ['unsigned long']],
            'RunningAllocs': [0x40, ['long']],
            'RunningDeAllocs': [0x44, ['long']],
            'TotalBigPages': [0x48, ['long']],
            'ThreadsProcessingDeferrals': [0x4C, ['long']],
            'TotalBytes': [0x50, ['unsigned long']],
            'PoolIndex': [0x80, ['unsigned long']],
            'TotalPages': [0xC0, ['long']],
            'PendingFrees': [0x100, ['_SINGLE_LIST_ENTRY']],
            'PendingFreeDepth': [0x104, ['long']],
            'ListHeads': [0x140, ['array', 512, ['_LIST_ENTRY']]],
        },
    ],
    '_BLOB_COUNTERS': [
        0x8,
        {
            'CreatedObjects': [0x0, ['unsigned long']],
            'DeletedObjects': [0x4, ['unsigned long']],
        },
    ],
    '_KGATE': [
        0x10,
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
        0x10,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'ViewListHead': [0x4, ['_LIST_ENTRY']],
            'PagedPoolQuotaCache': [0xC, ['unsigned long']],
        },
    ],
    '_DRIVER_EXTENSION': [
        0x28,
        {
            'DriverObject': [0x0, ['pointer', ['_DRIVER_OBJECT']]],
            'AddDevice': [0x4, ['pointer', ['void']]],
            'Count': [0x8, ['unsigned long']],
            'ServiceKeyName': [0xC, ['_UNICODE_STRING']],
            'ClientDriverExtension': [
                0x14,
                ['pointer', ['_IO_CLIENT_EXTENSION']],
            ],
            'FsFilterCallbacks': [0x18, ['pointer', ['_FS_FILTER_CALLBACKS']]],
            'KseCallbacks': [0x1C, ['pointer', ['void']]],
            'DvCallbacks': [0x20, ['pointer', ['void']]],
            'VerifierContext': [0x24, ['pointer', ['void']]],
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
    '_WHEAP_WORK_QUEUE': [
        0x44,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'ListLock': [0x8, ['unsigned long']],
            'ItemCount': [0xC, ['long']],
            'Dpc': [0x10, ['_KDPC']],
            'WorkItem': [0x30, ['_WORK_QUEUE_ITEM']],
            'WorkRoutine': [0x40, ['pointer', ['void']]],
        },
    ],
    '_CM_NOTIFY_BLOCK': [
        0x2C,
        {
            'HiveList': [0x0, ['_LIST_ENTRY']],
            'PostList': [0x8, ['_LIST_ENTRY']],
            'KeyControlBlock': [0x10, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'KeyBody': [0x14, ['pointer', ['_CM_KEY_BODY']]],
            'Filter': [
                0x18,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=30, native_type='unsigned long'),
                ],
            ],
            'WatchTree': [
                0x18,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'NotifyPending': [
                0x18,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'SubjectContext': [0x1C, ['_SECURITY_SUBJECT_CONTEXT']],
        },
    ],
    '_KINTERRUPT': [
        0xA8,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'InterruptListEntry': [0x4, ['_LIST_ENTRY']],
            'ServiceRoutine': [0xC, ['pointer', ['void']]],
            'MessageServiceRoutine': [0x10, ['pointer', ['void']]],
            'MessageIndex': [0x14, ['unsigned long']],
            'ServiceContext': [0x18, ['pointer', ['void']]],
            'SpinLock': [0x1C, ['unsigned long']],
            'TickCount': [0x20, ['unsigned long']],
            'ActualLock': [0x24, ['pointer', ['unsigned long']]],
            'DispatchAddress': [0x28, ['pointer', ['void']]],
            'Vector': [0x2C, ['unsigned long']],
            'Irql': [0x30, ['unsigned char']],
            'SynchronizeIrql': [0x31, ['unsigned char']],
            'FloatingSave': [0x32, ['unsigned char']],
            'Connected': [0x33, ['unsigned char']],
            'Number': [0x34, ['unsigned long']],
            'ShareVector': [0x38, ['unsigned char']],
            'EmulateActiveBoth': [0x39, ['unsigned char']],
            'ActiveCount': [0x3A, ['unsigned short']],
            'InternalState': [0x3C, ['long']],
            'Mode': [
                0x40,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'LevelSensitive', 1: 'Latched'},
                    ),
                ],
            ],
            'Polarity': [
                0x44,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'InterruptPolarityUnknown',
                            1: 'InterruptRisingEdge',
                            2: 'InterruptFallingEdge',
                            3: 'InterruptActiveBothTriggerLow',
                            4: 'InterruptActiveBothTriggerHigh',
                        },
                    ),
                ],
            ],
            'ServiceCount': [0x48, ['unsigned long']],
            'DispatchCount': [0x4C, ['unsigned long']],
            'PassiveEvent': [0x50, ['pointer', ['_KEVENT']]],
            'DisconnectData': [0x54, ['pointer', ['void']]],
            'ServiceThread': [0x58, ['pointer', ['_KTHREAD']]],
            'IsrDpcStats': [0x60, ['_ISRDPCSTATS']],
            'ConnectionData': [
                0xA0,
                ['pointer', ['_INTERRUPT_CONNECTION_DATA']],
            ],
        },
    ],
    '_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION': [
        0x18,
        {
            'SecurityAttributeCount': [0x0, ['unsigned long']],
            'SecurityAttributesList': [0x4, ['_LIST_ENTRY']],
            'WorkingSecurityAttributeCount': [0xC, ['unsigned long']],
            'WorkingSecurityAttributesList': [0x10, ['_LIST_ENTRY']],
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
    '_STRING64': [
        0x10,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x8, ['unsigned long long']],
        },
    ],
    '_HIVE_LIST_ENTRY': [
        0x58,
        {
            'FileName': [0x0, ['pointer', ['unsigned short']]],
            'BaseName': [0x4, ['pointer', ['unsigned short']]],
            'RegRootName': [0x8, ['pointer', ['unsigned short']]],
            'CmHive': [0xC, ['pointer', ['_CMHIVE']]],
            'HHiveFlags': [0x10, ['unsigned long']],
            'CmHiveFlags': [0x14, ['unsigned long']],
            'CmKcbCacheSize': [0x18, ['unsigned long']],
            'CmHive2': [0x1C, ['pointer', ['_CMHIVE']]],
            'HiveMounted': [0x20, ['unsigned char']],
            'ThreadFinished': [0x21, ['unsigned char']],
            'ThreadStarted': [0x22, ['unsigned char']],
            'Allocate': [0x23, ['unsigned char']],
            'WinPERequired': [0x24, ['unsigned char']],
            'StartEvent': [0x28, ['_KEVENT']],
            'FinishedEvent': [0x38, ['_KEVENT']],
            'MountLock': [0x48, ['_KEVENT']],
        },
    ],
    '_HMAP_DIRECTORY': [
        0x1000,
        {
            'Directory': [0x0, ['array', 1024, ['pointer', ['_HMAP_TABLE']]]],
        },
    ],
    '_CONTEXT': [
        0x2CC,
        {
            'ContextFlags': [0x0, ['unsigned long']],
            'Dr0': [0x4, ['unsigned long']],
            'Dr1': [0x8, ['unsigned long']],
            'Dr2': [0xC, ['unsigned long']],
            'Dr3': [0x10, ['unsigned long']],
            'Dr6': [0x14, ['unsigned long']],
            'Dr7': [0x18, ['unsigned long']],
            'FloatSave': [0x1C, ['_FLOATING_SAVE_AREA']],
            'SegGs': [0x8C, ['unsigned long']],
            'SegFs': [0x90, ['unsigned long']],
            'SegEs': [0x94, ['unsigned long']],
            'SegDs': [0x98, ['unsigned long']],
            'Edi': [0x9C, ['unsigned long']],
            'Esi': [0xA0, ['unsigned long']],
            'Ebx': [0xA4, ['unsigned long']],
            'Edx': [0xA8, ['unsigned long']],
            'Ecx': [0xAC, ['unsigned long']],
            'Eax': [0xB0, ['unsigned long']],
            'Ebp': [0xB4, ['unsigned long']],
            'Eip': [0xB8, ['unsigned long']],
            'SegCs': [0xBC, ['unsigned long']],
            'EFlags': [0xC0, ['unsigned long']],
            'Esp': [0xC4, ['unsigned long']],
            'SegSs': [0xC8, ['unsigned long']],
            'ExtendedRegisters': [0xCC, ['array', 512, ['unsigned char']]],
        },
    ],
    '_ALPC_HANDLE_TABLE': [
        0x10,
        {
            'Handles': [0x0, ['pointer', ['_ALPC_HANDLE_ENTRY']]],
            'TotalHandles': [0x4, ['unsigned long']],
            'Flags': [0x8, ['unsigned long']],
            'Lock': [0xC, ['_EX_PUSH_LOCK']],
        },
    ],
    '__unnamed_1e46': [
        0x3A4,
        {
            'XpfMceDescriptor': [0x0, ['_WHEA_XPF_MCE_DESCRIPTOR']],
            'XpfCmcDescriptor': [0x0, ['_WHEA_XPF_CMC_DESCRIPTOR']],
            'XpfNmiDescriptor': [0x0, ['_WHEA_XPF_NMI_DESCRIPTOR']],
            'IpfMcaDescriptor': [0x0, ['_WHEA_IPF_MCA_DESCRIPTOR']],
            'IpfCmcDescriptor': [0x0, ['_WHEA_IPF_CMC_DESCRIPTOR']],
            'IpfCpeDescriptor': [0x0, ['_WHEA_IPF_CPE_DESCRIPTOR']],
            'AerRootportDescriptor': [0x0, ['_WHEA_AER_ROOTPORT_DESCRIPTOR']],
            'AerEndpointDescriptor': [0x0, ['_WHEA_AER_ENDPOINT_DESCRIPTOR']],
            'AerBridgeDescriptor': [0x0, ['_WHEA_AER_BRIDGE_DESCRIPTOR']],
            'GenErrDescriptor': [0x0, ['_WHEA_GENERIC_ERROR_DESCRIPTOR']],
        },
    ],
    '_WHEA_ERROR_SOURCE_DESCRIPTOR': [
        0x3CC,
        {
            'Length': [0x0, ['unsigned long']],
            'Version': [0x4, ['unsigned long']],
            'Type': [
                0x8,
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
            'State': [
                0xC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'WheaErrSrcStateStopped',
                            2: 'WheaErrSrcStateStarted',
                        },
                    ),
                ],
            ],
            'MaxRawDataLength': [0x10, ['unsigned long']],
            'NumRecordsToPreallocate': [0x14, ['unsigned long']],
            'MaxSectionsPerRecord': [0x18, ['unsigned long']],
            'ErrorSourceId': [0x1C, ['unsigned long']],
            'PlatformErrorSourceId': [0x20, ['unsigned long']],
            'Flags': [0x24, ['unsigned long']],
            'Info': [0x28, ['__unnamed_1e46']],
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
                        end_bit=38,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=38,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_IO_COMPLETION_CONTEXT': [
        0x8,
        {
            'Port': [0x0, ['pointer', ['void']]],
            'Key': [0x4, ['pointer', ['void']]],
        },
    ],
    '_EX_WORK_QUEUE': [
        0x1B8,
        {
            'WorkPriQueue': [0x0, ['_KPRIQUEUE']],
            'Node': [0x19C, ['pointer', ['_ENODE']]],
            'WorkItemsProcessed': [0x1A0, ['unsigned long']],
            'WorkItemsProcessedLastPass': [0x1A4, ['unsigned long']],
            'ThreadCount': [0x1A8, ['long']],
            'MinThreads': [
                0x1AC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='long'),
                ],
            ],
            'TryFailed': [
                0x1AC,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'MaxThreads': [0x1B0, ['long']],
            'QueueIndex': [
                0x1B4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ExPoolUntrusted',
                            1: 'ExPoolTrusted',
                            8: 'ExPoolMax',
                        },
                    ),
                ],
            ],
        },
    ],
    '_IOV_FORCED_PENDING_TRACE': [
        0x100,
        {
            'Irp': [0x0, ['pointer', ['_IRP']]],
            'Thread': [0x4, ['pointer', ['_ETHREAD']]],
            'StackTrace': [0x8, ['array', 62, ['pointer', ['void']]]],
        },
    ],
    '_IOP_IRP_EXTENSION_STATUS': [
        0xC,
        {
            'Flags': [0x0, ['unsigned long']],
            'ActivityId': [0x4, ['unsigned long']],
            'IoTracking': [0x8, ['unsigned long']],
        },
    ],
    '_DBGKD_SET_CONTEXT': [
        0x4,
        {
            'ContextFlags': [0x0, ['unsigned long']],
        },
    ],
    '_VI_POOL_ENTRY_INUSE': [
        0x10,
        {
            'VirtualAddress': [0x0, ['pointer', ['void']]],
            'CallingAddress': [0x4, ['pointer', ['void']]],
            'NumberOfBytes': [0x8, ['unsigned long']],
            'Tag': [0xC, ['unsigned long']],
        },
    ],
    '_INTERFACE': [
        0x10,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x4, ['pointer', ['void']]],
            'InterfaceReference': [0x8, ['pointer', ['void']]],
            'InterfaceDereference': [0xC, ['pointer', ['void']]],
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
        0x50,
        {
            'ScanDpc': [0x0, ['_KDPC']],
            'ScanTimer': [0x20, ['_KTIMER']],
            'ScanActive': [0x48, ['unsigned char']],
            'OtherWork': [0x49, ['unsigned char']],
            'PendingTeardownScan': [0x4A, ['unsigned char']],
            'PendingPeriodicScan': [0x4B, ['unsigned char']],
            'PendingLowMemoryScan': [0x4C, ['unsigned char']],
            'PendingPowerScan': [0x4D, ['unsigned char']],
            'PendingCoalescingFlushScan': [0x4E, ['unsigned char']],
        },
    ],
    '_PI_BUS_EXTENSION': [
        0x44,
        {
            'Flags': [0x0, ['unsigned long']],
            'NumberCSNs': [0x4, ['unsigned char']],
            'ReadDataPort': [0x8, ['pointer', ['unsigned char']]],
            'DataPortMapped': [0xC, ['unsigned char']],
            'AddressPort': [0x10, ['pointer', ['unsigned char']]],
            'AddrPortMapped': [0x14, ['unsigned char']],
            'CommandPort': [0x18, ['pointer', ['unsigned char']]],
            'CmdPortMapped': [0x1C, ['unsigned char']],
            'NextSlotNumber': [0x20, ['unsigned long']],
            'DeviceList': [0x24, ['_SINGLE_LIST_ENTRY']],
            'CardList': [0x28, ['_SINGLE_LIST_ENTRY']],
            'PhysicalBusDevice': [0x2C, ['pointer', ['_DEVICE_OBJECT']]],
            'FunctionalBusDevice': [0x30, ['pointer', ['_DEVICE_OBJECT']]],
            'AttachedDevice': [0x34, ['pointer', ['_DEVICE_OBJECT']]],
            'BusNumber': [0x38, ['unsigned long']],
            'SystemPowerState': [
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
            'DevicePowerState': [
                0x40,
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
    '_DEVICE_DESCRIPTION': [
        0x40,
        {
            'Version': [0x0, ['unsigned long']],
            'Master': [0x4, ['unsigned char']],
            'ScatterGather': [0x5, ['unsigned char']],
            'DemandMode': [0x6, ['unsigned char']],
            'AutoInitialize': [0x7, ['unsigned char']],
            'Dma32BitAddresses': [0x8, ['unsigned char']],
            'IgnoreCount': [0x9, ['unsigned char']],
            'Reserved1': [0xA, ['unsigned char']],
            'Dma64BitAddresses': [0xB, ['unsigned char']],
            'BusNumber': [0xC, ['unsigned long']],
            'DmaChannel': [0x10, ['unsigned long']],
            'InterfaceType': [
                0x14,
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
                            17: 'ACPIBus',
                            18: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'DmaWidth': [
                0x18,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Width8Bits',
                            1: 'Width16Bits',
                            2: 'Width32Bits',
                            3: 'Width64Bits',
                            4: 'WidthNoWrap',
                            5: 'MaximumDmaWidth',
                        },
                    ),
                ],
            ],
            'DmaSpeed': [
                0x1C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Compatible',
                            1: 'TypeA',
                            2: 'TypeB',
                            3: 'TypeC',
                            4: 'TypeF',
                            5: 'MaximumDmaSpeed',
                        },
                    ),
                ],
            ],
            'MaximumLength': [0x20, ['unsigned long']],
            'DmaPort': [0x24, ['unsigned long']],
            'DmaAddressWidth': [0x28, ['unsigned long']],
            'DmaControllerInstance': [0x2C, ['unsigned long']],
            'DmaRequestLine': [0x30, ['unsigned long']],
            'DeviceAddress': [0x38, ['_LARGE_INTEGER']],
        },
    ],
    '_SID_AND_ATTRIBUTES': [
        0x8,
        {
            'Sid': [0x0, ['pointer', ['void']]],
            'Attributes': [0x4, ['unsigned long']],
        },
    ],
    '_SID_IDENTIFIER_AUTHORITY': [
        0x6,
        {
            'Value': [0x0, ['array', 6, ['unsigned char']]],
        },
    ],
    '_PROCESS_DISK_COUNTERS': [
        0x28,
        {
            'BytesRead': [0x0, ['unsigned long long']],
            'BytesWritten': [0x8, ['unsigned long long']],
            'ReadOperationCount': [0x10, ['unsigned long long']],
            'WriteOperationCount': [0x18, ['unsigned long long']],
            'FlushOperationCount': [0x20, ['unsigned long long']],
        },
    ],
    '_IO_WORKITEM': [
        0x30,
        {
            'WorkItem': [0x0, ['_WORK_QUEUE_ITEM']],
            'Routine': [0x10, ['pointer', ['void']]],
            'IoObject': [0x14, ['pointer', ['void']]],
            'Context': [0x18, ['pointer', ['void']]],
            'Type': [0x1C, ['unsigned long']],
            'ActivityId': [0x20, ['_GUID']],
        },
    ],
    '_MMWSLE_HASH': [
        0x4,
        {
            'Index': [0x0, ['unsigned long']],
        },
    ],
    '_JOBOBJECT_WAKE_FILTER': [
        0x8,
        {
            'HighEdgeFilter': [0x0, ['unsigned long']],
            'LowEdgeFilter': [0x4, ['unsigned long']],
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
    '_POP_FX_WORK_ORDER_WATCHDOG_INFO': [
        0x50,
        {
            'Timer': [0x0, ['_KTIMER']],
            'Dpc': [0x28, ['_KDPC']],
            'WorkOrder': [0x48, ['pointer', ['_POP_FX_WORK_ORDER']]],
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
        0x18,
        {
            'AllocAddress': [0x0, ['unsigned long']],
            'AllocTag': [0x4, ['_HEAP_STOP_ON_TAG']],
            'ReAllocAddress': [0x8, ['unsigned long']],
            'ReAllocTag': [0xC, ['_HEAP_STOP_ON_TAG']],
            'FreeAddress': [0x10, ['unsigned long']],
            'FreeTag': [0x14, ['_HEAP_STOP_ON_TAG']],
        },
    ],
    '_HEAP_PSEUDO_TAG_ENTRY': [
        0xC,
        {
            'Allocs': [0x0, ['unsigned long']],
            'Frees': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long']],
        },
    ],
    '_CALL_HASH_ENTRY': [
        0x14,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'CallersAddress': [0x8, ['pointer', ['void']]],
            'CallersCaller': [0xC, ['pointer', ['void']]],
            'CallCount': [0x10, ['unsigned long']],
        },
    ],
    '_VF_TRACKER_STAMP': [
        0x8,
        {
            'Thread': [0x0, ['pointer', ['void']]],
            'Flags': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OldIrql': [
                0x5,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'NewIrql': [
                0x6,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Processor': [
                0x7,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_VI_TRACK_IRQL': [
        0x20,
        {
            'Thread': [0x0, ['pointer', ['void']]],
            'OldIrql': [0x4, ['unsigned char']],
            'NewIrql': [0x5, ['unsigned char']],
            'Processor': [0x6, ['unsigned short']],
            'TickCount': [0x8, ['unsigned long']],
            'StackTrace': [0xC, ['array', 5, ['pointer', ['void']]]],
        },
    ],
    '_SESSION_LOWBOX_MAP': [
        0x20,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'SessionId': [0x8, ['unsigned long']],
            'LowboxMap': [0xC, ['_SEP_LOWBOX_NUMBER_MAPPING']],
        },
    ],
    '_PROCESSOR_PROFILE_CONTROL_AREA': [
        0x60,
        {
            'PebsDsSaveArea': [0x0, ['_PEBS_DS_SAVE_AREA']],
        },
    ],
    '_PEB_LDR_DATA': [
        0x30,
        {
            'Length': [0x0, ['unsigned long']],
            'Initialized': [0x4, ['unsigned char']],
            'SsHandle': [0x8, ['pointer', ['void']]],
            'InLoadOrderModuleList': [0xC, ['_LIST_ENTRY']],
            'InMemoryOrderModuleList': [0x14, ['_LIST_ENTRY']],
            'InInitializationOrderModuleList': [0x1C, ['_LIST_ENTRY']],
            'EntryInProgress': [0x24, ['pointer', ['void']]],
            'ShutdownInProgress': [0x28, ['unsigned char']],
            'ShutdownThreadId': [0x2C, ['pointer', ['void']]],
        },
    ],
    '_PNP_DEVICE_EVENT_ENTRY': [
        0x74,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Argument': [0x8, ['unsigned long']],
            'CallerEvent': [0xC, ['pointer', ['_KEVENT']]],
            'Callback': [0x10, ['pointer', ['void']]],
            'Context': [0x14, ['pointer', ['void']]],
            'VetoType': [
                0x18,
                [
                    'pointer',
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
            'VetoName': [0x1C, ['pointer', ['_UNICODE_STRING']]],
            'RefCount': [0x20, ['unsigned long']],
            'Lock': [0x24, ['unsigned long']],
            'Cancel': [0x28, ['unsigned char']],
            'Parent': [0x2C, ['pointer', ['_PNP_DEVICE_EVENT_ENTRY']]],
            'Data': [0x30, ['_PLUGPLAY_EVENT_BLOCK']],
        },
    ],
    '_PROC_IDLE_POLICY': [
        0x5,
        {
            'PromotePercent': [0x0, ['unsigned char']],
            'DemotePercent': [0x1, ['unsigned char']],
            'PromotePercentBase': [0x2, ['unsigned char']],
            'DemotePercentBase': [0x3, ['unsigned char']],
            'AllowScaling': [0x4, ['unsigned char']],
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
    '_PS_WAKE_INFORMATION': [
        0x38,
        {
            'NotificationChannel': [0x0, ['unsigned long long']],
            'WakeCounters': [0x8, ['array', 5, ['unsigned long long']]],
            'NoWakeCounter': [0x30, ['unsigned long long']],
        },
    ],
    '_RH_OP_CONTEXT': [
        0x24,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'OplockRequestIrp': [0x8, ['pointer', ['_IRP']]],
            'OplockRequestFileObject': [0xC, ['pointer', ['_FILE_OBJECT']]],
            'OplockRequestProcess': [0x10, ['pointer', ['_EPROCESS']]],
            'OplockOwnerThread': [0x14, ['pointer', ['_ETHREAD']]],
            'Flags': [0x18, ['unsigned long']],
            'AtomicLinks': [0x1C, ['_LIST_ENTRY']],
        },
    ],
    '_DBGKD_GET_CONTEXT': [
        0x4,
        {
            'Unused': [0x0, ['unsigned long']],
        },
    ],
    '_TEB_ACTIVE_FRAME_CONTEXT': [
        0x8,
        {
            'Flags': [0x0, ['unsigned long']],
            'FrameName': [0x4, ['pointer', ['unsigned char']]],
        },
    ],
    '_ISRDPCSTATS': [
        0x40,
        {
            'IsrTime': [0x0, ['unsigned long long']],
            'IsrTimeStart': [0x8, ['unsigned long long']],
            'IsrCount': [0x10, ['unsigned long long']],
            'DpcTime': [0x18, ['unsigned long long']],
            'DpcTimeStart': [0x20, ['unsigned long long']],
            'DpcCount': [0x28, ['unsigned long long']],
            'IsrActive': [0x30, ['unsigned char']],
            'Reserved': [0x31, ['array', 15, ['unsigned char']]],
        },
    ],
    '_XSTATE_CONFIGURATION': [
        0x218,
        {
            'EnabledFeatures': [0x0, ['unsigned long long']],
            'EnabledVolatileFeatures': [0x8, ['unsigned long long']],
            'Size': [0x10, ['unsigned long']],
            'OptimizedSave': [
                0x14,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Features': [0x18, ['array', 64, ['_XSTATE_FEATURE']]],
        },
    ],
    '_CM_KEY_CONTROL_BLOCK': [
        0xA0,
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
            'KeyHash': [0xC, ['_CM_KEY_HASH']],
            'ConvKey': [0xC, ['unsigned long']],
            'NextHash': [0x10, ['pointer', ['_CM_KEY_HASH']]],
            'KeyHive': [0x14, ['pointer', ['_HHIVE']]],
            'KeyCell': [0x18, ['unsigned long']],
            'KcbPushlock': [0x1C, ['_EX_PUSH_LOCK']],
            'Owner': [0x20, ['pointer', ['_KTHREAD']]],
            'SharedCount': [0x20, ['long']],
            'SlotHint': [0x24, ['unsigned long']],
            'ParentKcb': [0x28, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'NameBlock': [0x2C, ['pointer', ['_CM_NAME_CONTROL_BLOCK']]],
            'CachedSecurity': [0x30, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
            'ValueCache': [0x34, ['_CACHED_CHILD_LIST']],
            'IndexHint': [0x3C, ['pointer', ['_CM_INDEX_HINT_BLOCK']]],
            'HashKey': [0x3C, ['unsigned long']],
            'SubKeyCount': [0x3C, ['unsigned long']],
            'KeyBodyListHead': [0x40, ['_LIST_ENTRY']],
            'FreeListEntry': [0x40, ['_LIST_ENTRY']],
            'KeyBodyArray': [
                0x48,
                ['array', 4, ['pointer', ['_CM_KEY_BODY']]],
            ],
            'KcbLastWriteTime': [0x58, ['_LARGE_INTEGER']],
            'KcbMaxNameLen': [0x60, ['unsigned short']],
            'KcbMaxValueNameLen': [0x62, ['unsigned short']],
            'KcbMaxValueDataLen': [0x64, ['unsigned long']],
            'KcbUserFlags': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'KcbVirtControlFlags': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'KcbDebug': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'Flags': [
                0x68,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'KCBUoWListHead': [0x6C, ['_LIST_ENTRY']],
            'DelayQueueEntry': [0x74, ['_LIST_ENTRY']],
            'Stolen': [0x74, ['pointer', ['unsigned char']]],
            'TransKCBOwner': [0x7C, ['pointer', ['_CM_TRANS']]],
            'KCBLock': [0x80, ['_CM_INTENT_LOCK']],
            'KeyLock': [0x88, ['_CM_INTENT_LOCK']],
            'TransValueCache': [0x90, ['_CHILD_LIST']],
            'TransValueListOwner': [0x98, ['pointer', ['_CM_TRANS']]],
            'FullKCBName': [0x9C, ['pointer', ['_UNICODE_STRING']]],
        },
    ],
    '_KLOCK_ENTRY': [
        0x30,
        {
            'TreeNode': [0x0, ['_RTL_BALANCED_NODE']],
            'FreeListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'ThreadUnsafe': [0xC, ['pointer', ['void']]],
            'HeadNodeByte': [0xC, ['unsigned char']],
            'Reserved1': [0xD, ['array', 2, ['unsigned char']]],
            'AcquiredByte': [0xF, ['unsigned char']],
            'LockState': [0x10, ['_KLOCK_ENTRY_LOCK_STATE']],
            'LockUnsafe': [0x10, ['pointer', ['void']]],
            'WaitingAndBusyByte': [0x10, ['unsigned char']],
            'Reserved': [0x11, ['array', 2, ['unsigned char']]],
            'InTreeByte': [0x13, ['unsigned char']],
            'SessionState': [0x14, ['pointer', ['void']]],
            'SessionId': [0x14, ['unsigned long']],
            'OwnerTree': [0x18, ['_RTL_RB_TREE']],
            'WaiterTree': [0x20, ['_RTL_RB_TREE']],
            'CpuPriorityKey': [0x18, ['unsigned char']],
            'EntryLock': [0x28, ['unsigned long']],
            'AllBoosts': [0x2C, ['unsigned short']],
            'IoBoost': [
                0x2C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'CpuBoostsBitmap': [
                0x2C,
                [
                    'BitField',
                    dict(
                        start_bit=1, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'IoNormalPriorityWaiterCount': [
                0x2E,
                [
                    'BitField',
                    dict(
                        start_bit=0, end_bit=15, native_type='unsigned short'
                    ),
                ],
            ],
            'IoPriorityBit': [
                0x2E,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
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
            'InStore': [
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
            'PageFileReserved': [
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
            'PageFileAllocated': [
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
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15,
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
    '__unnamed_1ee8': [
        0x8,
        {
            'IoStatus': [0x0, ['_IO_STATUS_BLOCK']],
        },
    ],
    '_MMMOD_WRITER_MDL_ENTRY': [
        0x98,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'u': [0x8, ['__unnamed_1ee8']],
            'Irp': [0x10, ['pointer', ['_IRP']]],
            'u1': [0x14, ['_MODWRITER_FLAGS']],
            'StoreWriteRefCount': [0x18, ['unsigned long']],
            'StoreWriteCompletionApc': [0x1C, ['_KAPC']],
            'ByteCount': [0x4C, ['unsigned long']],
            'PagingFile': [0x50, ['pointer', ['_MMPAGING_FILE']]],
            'File': [0x54, ['pointer', ['_FILE_OBJECT']]],
            'ControlArea': [0x58, ['pointer', ['_CONTROL_AREA']]],
            'FileResource': [0x5C, ['pointer', ['_ERESOURCE']]],
            'WriteOffset': [0x60, ['_LARGE_INTEGER']],
            'IssueTime': [0x68, ['_LARGE_INTEGER']],
            'PointerMdl': [0x70, ['pointer', ['_MDL']]],
            'Mdl': [0x74, ['_MDL']],
            'Page': [0x90, ['array', 1, ['unsigned long']]],
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
    '_CM_RESOURCE_LIST': [
        0x24,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['array', 1, ['_CM_FULL_RESOURCE_DESCRIPTOR']]],
        },
    ],
    '_POOL_TRACKER_TABLE': [
        0x1C,
        {
            'Key': [0x0, ['long']],
            'NonPagedAllocs': [0x4, ['unsigned long']],
            'NonPagedFrees': [0x8, ['unsigned long']],
            'NonPagedBytes': [0xC, ['unsigned long']],
            'PagedAllocs': [0x10, ['unsigned long']],
            'PagedFrees': [0x14, ['unsigned long']],
            'PagedBytes': [0x18, ['unsigned long']],
        },
    ],
    '_CM_FULL_RESOURCE_DESCRIPTOR': [
        0x20,
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
                            17: 'ACPIBus',
                            18: 'MaximumInterfaceType',
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
            'ClockType': [
                0x20,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Frequency': [
                0x20,
                [
                    'BitField',
                    dict(
                        start_bit=3,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SlistEntry': [0x20, ['_SINGLE_LIST_ENTRY']],
            'NextBuffer': [0x20, ['pointer', ['_WMI_BUFFER_HEADER']]],
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
            'Pointer0': [0x38, ['pointer', ['void']]],
            'Pointer1': [0x3C, ['pointer', ['void']]],
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
    '_POWER_SEQUENCE': [
        0xC,
        {
            'SequenceD1': [0x0, ['unsigned long']],
            'SequenceD2': [0x4, ['unsigned long']],
            'SequenceD3': [0x8, ['unsigned long']],
        },
    ],
    '_EPROCESS_VALUES': [
        0x50,
        {
            'KernelTime': [0x0, ['unsigned long long']],
            'UserTime': [0x8, ['unsigned long long']],
            'CycleTime': [0x10, ['unsigned long long']],
            'ContextSwitches': [0x18, ['unsigned long long']],
            'ReadOperationCount': [0x20, ['long long']],
            'WriteOperationCount': [0x28, ['long long']],
            'OtherOperationCount': [0x30, ['long long']],
            'ReadTransferCount': [0x38, ['long long']],
            'WriteTransferCount': [0x40, ['long long']],
            'OtherTransferCount': [0x48, ['long long']],
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
            'OnProtectedStandby': [
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
            'Spare': [
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
        0x28,
        {
            'BaseAddress': [0x0, ['pointer', ['void']]],
            'TotalNumberOfPtes': [0x4, ['unsigned long']],
            'SizeOfSegment': [0x8, ['_LARGE_INTEGER']],
            'NonExtendedPtes': [0x10, ['unsigned long']],
            'ImageCommitment': [0x14, ['unsigned long']],
            'ControlArea': [0x18, ['pointer', ['_CONTROL_AREA']]],
            'Subsection': [0x1C, ['pointer', ['_SUBSECTION']]],
            'MmSectionFlags': [0x20, ['pointer', ['_MMSECTION_FLAGS']]],
            'MmSubSectionFlags': [0x24, ['pointer', ['_MMSUBSECTION_FLAGS']]],
        },
    ],
    '_PCW_CALLBACK_INFORMATION': [
        0x20,
        {
            'AddCounter': [0x0, ['_PCW_COUNTER_INFORMATION']],
            'RemoveCounter': [0x0, ['_PCW_COUNTER_INFORMATION']],
            'EnumerateInstances': [0x0, ['_PCW_MASK_INFORMATION']],
            'CollectData': [0x0, ['_PCW_MASK_INFORMATION']],
        },
    ],
    '_KTSS': [
        0x20AC,
        {
            'Backlink': [0x0, ['unsigned short']],
            'Reserved0': [0x2, ['unsigned short']],
            'Esp0': [0x4, ['unsigned long']],
            'Ss0': [0x8, ['unsigned short']],
            'Reserved1': [0xA, ['unsigned short']],
            'NotUsed1': [0xC, ['array', 4, ['unsigned long']]],
            'CR3': [0x1C, ['unsigned long']],
            'Eip': [0x20, ['unsigned long']],
            'EFlags': [0x24, ['unsigned long']],
            'Eax': [0x28, ['unsigned long']],
            'Ecx': [0x2C, ['unsigned long']],
            'Edx': [0x30, ['unsigned long']],
            'Ebx': [0x34, ['unsigned long']],
            'Esp': [0x38, ['unsigned long']],
            'Ebp': [0x3C, ['unsigned long']],
            'Esi': [0x40, ['unsigned long']],
            'Edi': [0x44, ['unsigned long']],
            'Es': [0x48, ['unsigned short']],
            'Reserved2': [0x4A, ['unsigned short']],
            'Cs': [0x4C, ['unsigned short']],
            'Reserved3': [0x4E, ['unsigned short']],
            'Ss': [0x50, ['unsigned short']],
            'Reserved4': [0x52, ['unsigned short']],
            'Ds': [0x54, ['unsigned short']],
            'Reserved5': [0x56, ['unsigned short']],
            'Fs': [0x58, ['unsigned short']],
            'Reserved6': [0x5A, ['unsigned short']],
            'Gs': [0x5C, ['unsigned short']],
            'Reserved7': [0x5E, ['unsigned short']],
            'LDT': [0x60, ['unsigned short']],
            'Reserved8': [0x62, ['unsigned short']],
            'Flags': [0x64, ['unsigned short']],
            'IoMapBase': [0x66, ['unsigned short']],
            'IoMaps': [0x68, ['array', 1, ['_KiIoAccessMap']]],
            'IntDirectionMap': [0x208C, ['array', 32, ['unsigned char']]],
        },
    ],
    '_TOKEN_SOURCE': [
        0x10,
        {
            'SourceName': [0x0, ['array', 8, ['unsigned char']]],
            'SourceIdentifier': [0x8, ['_LUID']],
        },
    ],
    '_CMHIVE': [
        0xC20,
        {
            'Hive': [0x0, ['_HHIVE']],
            'FileHandles': [0x3BC, ['array', 6, ['pointer', ['void']]]],
            'NotifyList': [0x3D4, ['_LIST_ENTRY']],
            'HiveList': [0x3DC, ['_LIST_ENTRY']],
            'PreloadedHiveList': [0x3E4, ['_LIST_ENTRY']],
            'HiveRundown': [0x3EC, ['_EX_RUNDOWN_REF']],
            'ParseCacheEntries': [0x3F0, ['_LIST_ENTRY']],
            'KcbCacheTable': [
                0x3F8,
                ['pointer', ['_CM_KEY_HASH_TABLE_ENTRY']],
            ],
            'KcbCacheTableSize': [0x3FC, ['unsigned long']],
            'DeletedKcbTable': [
                0x400,
                ['pointer', ['_CM_KEY_HASH_TABLE_ENTRY']],
            ],
            'DeletedKcbTableSize': [0x404, ['unsigned long']],
            'Identity': [0x408, ['unsigned long']],
            'HiveLock': [0x40C, ['pointer', ['_FAST_MUTEX']]],
            'WriterLock': [0x410, ['pointer', ['_FAST_MUTEX']]],
            'FlusherLock': [0x414, ['pointer', ['_ERESOURCE']]],
            'FlushDirtyVector': [0x418, ['_RTL_BITMAP']],
            'FlushDirtyVectorSize': [0x420, ['unsigned long']],
            'FlushLogEntry': [0x424, ['pointer', ['unsigned char']]],
            'FlushLogEntrySize': [0x428, ['unsigned long']],
            'FlushHiveTruncated': [0x42C, ['unsigned long']],
            'FlushBaseBlockDirty': [0x430, ['unsigned char']],
            'CapturedUnreconciledVector': [0x434, ['_RTL_BITMAP']],
            'CapturedUnreconciledVectorSize': [0x43C, ['unsigned long']],
            'UnreconciledOffsetArray': [
                0x440,
                ['pointer', ['CMP_OFFSET_ARRAY']],
            ],
            'UnreconciledOffsetArrayCount': [0x444, ['unsigned long']],
            'UnreconciledBaseBlock': [0x448, ['pointer', ['_HBASE_BLOCK']]],
            'SecurityLock': [0x44C, ['_EX_PUSH_LOCK']],
            'UseCount': [0x450, ['unsigned long']],
            'LastShrinkHiveSize': [0x454, ['unsigned long']],
            'ActualFileSize': [0x458, ['_LARGE_INTEGER']],
            'LogFileSizes': [0x460, ['array', 2, ['_LARGE_INTEGER']]],
            'FileFullPath': [0x470, ['_UNICODE_STRING']],
            'FileUserName': [0x478, ['_UNICODE_STRING']],
            'HiveRootPath': [0x480, ['_UNICODE_STRING']],
            'SecurityCount': [0x488, ['unsigned long']],
            'SecurityCacheSize': [0x48C, ['unsigned long']],
            'SecurityHitHint': [0x490, ['long']],
            'SecurityCache': [
                0x494,
                ['pointer', ['_CM_KEY_SECURITY_CACHE_ENTRY']],
            ],
            'SecurityHash': [0x498, ['array', 64, ['_LIST_ENTRY']]],
            'UnloadEventCount': [0x698, ['unsigned long']],
            'UnloadEventArray': [0x69C, ['pointer', ['pointer', ['_KEVENT']]]],
            'RootKcb': [0x6A0, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'Frozen': [0x6A4, ['unsigned char']],
            'UnloadWorkItem': [0x6A8, ['pointer', ['_CM_WORKITEM']]],
            'UnloadWorkItemHolder': [0x6AC, ['_CM_WORKITEM']],
            'GrowOnlyMode': [0x6C0, ['unsigned char']],
            'GrowOffset': [0x6C4, ['unsigned long']],
            'KcbConvertListHead': [0x6C8, ['_LIST_ENTRY']],
            'KnodeConvertListHead': [0x6D0, ['_LIST_ENTRY']],
            'CellRemapArray': [0x6D8, ['pointer', ['_CM_CELL_REMAP_BLOCK']]],
            'DirtyVectorLog': [0x6DC, ['_CM_DIRTY_VECTOR_LOG']],
            'Flags': [0x9A4, ['unsigned long']],
            'TrustClassEntry': [0x9A8, ['_LIST_ENTRY']],
            'DirtyTime': [0x9B0, ['unsigned long long']],
            'UnreconciledTime': [0x9B8, ['unsigned long long']],
            'CmRm': [0x9C0, ['pointer', ['_CM_RM']]],
            'CmRmInitFailPoint': [0x9C4, ['unsigned long']],
            'CmRmInitFailStatus': [0x9C8, ['long']],
            'CreatorOwner': [0x9CC, ['pointer', ['_KTHREAD']]],
            'RundownThread': [0x9D0, ['pointer', ['_KTHREAD']]],
            'LastWriteTime': [0x9D8, ['_LARGE_INTEGER']],
            'FlushQueue': [0x9E0, ['_HIVE_WRITE_WAIT_QUEUE']],
            'ReconcileQueue': [0x9EC, ['_HIVE_WRITE_WAIT_QUEUE']],
            'FlushFlags': [0x9F8, ['unsigned long']],
            'FlushActive': [
                0x9F8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReconcileActive': [
                0x9F8,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'PrimaryFilePurged': [
                0x9F8,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'DiskFileBad': [
                0x9F8,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'PrimaryFileSizeBeforeLastFlush': [0x9FC, ['unsigned long']],
            'ReferenceCount': [0xA00, ['long']],
            'UnloadHistoryIndex': [0xA04, ['long']],
            'UnloadHistory': [0xA08, ['array', 128, ['unsigned long']]],
            'BootStart': [0xC08, ['unsigned long']],
            'UnaccessedStart': [0xC0C, ['unsigned long']],
            'UnaccessedEnd': [0xC10, ['unsigned long']],
            'LoadedKeyCount': [0xC14, ['unsigned long']],
            'HandleClosePending': [0xC18, ['unsigned long']],
            'HandleClosePendingEvent': [0xC1C, ['_EX_PUSH_LOCK']],
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
    '_KIDTENTRY': [
        0x8,
        {
            'Offset': [0x0, ['unsigned short']],
            'Selector': [0x2, ['unsigned short']],
            'Access': [0x4, ['unsigned short']],
            'ExtendedOffset': [0x6, ['unsigned short']],
        },
    ],
    '_DIRTY_PAGE_THRESHOLDS': [
        0x28,
        {
            'DirtyPageThreshold': [0x0, ['unsigned long']],
            'DirtyPageThresholdTop': [0x4, ['unsigned long']],
            'DirtyPageThresholdBottom': [0x8, ['unsigned long']],
            'DirtyPageTarget': [0xC, ['unsigned long']],
            'AggregateAvailablePages': [0x10, ['unsigned long long']],
            'AggregateDirtyPages': [0x18, ['unsigned long long']],
            'AvailableHistory': [0x20, ['unsigned long']],
        },
    ],
    'DOCK_INTERFACE': [
        0x18,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x4, ['pointer', ['void']]],
            'InterfaceReference': [0x8, ['pointer', ['void']]],
            'InterfaceDereference': [0xC, ['pointer', ['void']]],
            'ProfileDepartureSetMode': [0x10, ['pointer', ['void']]],
            'ProfileDepartureUpdate': [0x14, ['pointer', ['void']]],
        },
    ],
    'CMP_OFFSET_ARRAY': [
        0xC,
        {
            'FileOffset': [0x0, ['unsigned long']],
            'DataBuffer': [0x4, ['pointer', ['void']]],
            'DataLength': [0x8, ['unsigned long']],
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
            'ForceCredits': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'MaximumWorkingSetHard': [
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
            'MemoryPriority': [0x2, ['unsigned char']],
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
            'SvmEnabled': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Available': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_IMAGE_OPTIONAL_HEADER': [
        0xE0,
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
            'ImageBase': [0x1C, ['unsigned long']],
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
            'SizeOfStackReserve': [0x48, ['unsigned long']],
            'SizeOfStackCommit': [0x4C, ['unsigned long']],
            'SizeOfHeapReserve': [0x50, ['unsigned long']],
            'SizeOfHeapCommit': [0x54, ['unsigned long']],
            'LoaderFlags': [0x58, ['unsigned long']],
            'NumberOfRvaAndSizes': [0x5C, ['unsigned long']],
            'DataDirectory': [0x60, ['array', 16, ['_IMAGE_DATA_DIRECTORY']]],
        },
    ],
    '_ALPC_COMPLETION_PACKET_LOOKASIDE': [
        0x30,
        {
            'Lock': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned long']],
            'ActiveCount': [0x8, ['unsigned long']],
            'PendingNullCount': [0xC, ['unsigned long']],
            'PendingCheckCompletionListCount': [0x10, ['unsigned long']],
            'PendingDelete': [0x14, ['unsigned long']],
            'FreeListHead': [0x18, ['_SINGLE_LIST_ENTRY']],
            'CompletionPort': [0x1C, ['pointer', ['void']]],
            'CompletionKey': [0x20, ['pointer', ['void']]],
            'Entry': [
                0x24,
                ['array', 1, ['_ALPC_COMPLETION_PACKET_LOOKASIDE_ENTRY']],
            ],
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
    '_TERMINATION_PORT': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_TERMINATION_PORT']]],
            'Port': [0x4, ['pointer', ['void']]],
        },
    ],
    '_MEMORY_ALLOCATION_DESCRIPTOR': [
        0x14,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'MemoryType': [
                0x8,
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
            'BasePage': [0xC, ['unsigned long']],
            'PageCount': [0x10, ['unsigned long']],
        },
    ],
    '_CM_INTENT_LOCK': [
        0x8,
        {
            'OwnerCount': [0x0, ['unsigned long']],
            'OwnerTable': [0x4, ['pointer', ['pointer', ['_CM_KCB_UOW']]]],
        },
    ],
    '_PROC_IDLE_ACCOUNTING': [
        0x3F8,
        {
            'StateCount': [0x0, ['unsigned long']],
            'TotalTransitions': [0x4, ['unsigned long']],
            'ResetCount': [0x8, ['unsigned long']],
            'AbortCount': [0xC, ['unsigned long']],
            'StartTime': [0x10, ['unsigned long long']],
            'PriorIdleTime': [0x18, ['unsigned long long']],
            'TimeUnit': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PpmIdleBucketTimeInQpc',
                            1: 'PpmIdleBucketTimeIn100ns',
                            2: 'PpmIdleBucketTimeMaximum',
                        },
                    ),
                ],
            ],
            'State': [0x28, ['array', 1, ['_PROC_IDLE_STATE_ACCOUNTING']]],
        },
    ],
    '_THERMAL_INFORMATION': [
        0x4C,
        {
            'ThermalStamp': [0x0, ['unsigned long']],
            'ThermalConstant1': [0x4, ['unsigned long']],
            'ThermalConstant2': [0x8, ['unsigned long']],
            'Processors': [0xC, ['unsigned long']],
            'SamplingPeriod': [0x10, ['unsigned long']],
            'CurrentTemperature': [0x14, ['unsigned long']],
            'PassiveTripPoint': [0x18, ['unsigned long']],
            'CriticalTripPoint': [0x1C, ['unsigned long']],
            'ActiveTripPointCount': [0x20, ['unsigned char']],
            'ActiveTripPoint': [0x24, ['array', 10, ['unsigned long']]],
        },
    ],
    '_SEP_LOWBOX_NUMBER_MAPPING': [
        0x14,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'Bitmap': [0x4, ['_RTL_BITMAP']],
            'HashTable': [0xC, ['pointer', ['_RTL_DYNAMIC_HASH_TABLE']]],
            'Active': [0x10, ['unsigned char']],
        },
    ],
    '_MAPPED_FILE_SEGMENT': [
        0x20,
        {
            'ControlArea': [0x0, ['pointer', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x4, ['unsigned long']],
            'SegmentFlags': [0x8, ['_SEGMENT_FLAGS']],
            'NumberOfCommittedPages': [0xC, ['unsigned long']],
            'SizeOfSegment': [0x10, ['unsigned long long']],
            'ExtendInfo': [0x18, ['pointer', ['_MMEXTEND_INFO']]],
            'BasedAddress': [0x18, ['pointer', ['void']]],
            'SegmentLock': [0x1C, ['_EX_PUSH_LOCK']],
        },
    ],
    '_GDI_TEB_BATCH': [
        0x4E0,
        {
            'Offset': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'HasRenderingCommand': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'HDC': [0x4, ['unsigned long']],
            'Buffer': [0x8, ['array', 310, ['unsigned long']]],
        },
    ],
    '_MM_DRIVER_VERIFIER_DATA': [
        0x84,
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
            'PagedBytes': [0x50, ['unsigned long']],
            'NonPagedBytes': [0x54, ['unsigned long']],
            'PeakPagedBytes': [0x58, ['unsigned long']],
            'PeakNonPagedBytes': [0x5C, ['unsigned long']],
            'BurstAllocationsFailedDeliberately': [0x60, ['unsigned long']],
            'SessionTrims': [0x64, ['unsigned long']],
            'OptionChanges': [0x68, ['unsigned long']],
            'VerifyMode': [0x6C, ['unsigned long']],
            'PreviousBucketName': [0x70, ['_UNICODE_STRING']],
            'ActivityCounter': [0x78, ['unsigned long']],
            'PreviousActivityCounter': [0x7C, ['unsigned long']],
            'WorkerTrimRequests': [0x80, ['unsigned long']],
        },
    ],
    '_HIVE_WRITE_WAIT_QUEUE': [
        0xC,
        {
            'ActiveThread': [0x0, ['pointer', ['_ETHREAD']]],
            'WaitList': [0x4, ['pointer', ['_HIVE_WAIT_PACKET']]],
            'OwnerBoosted': [0x8, ['unsigned long']],
        },
    ],
    '_VI_FAULT_TRACE': [
        0x24,
        {
            'Thread': [0x0, ['pointer', ['_ETHREAD']]],
            'StackTrace': [0x4, ['array', 8, ['pointer', ['void']]]],
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
        0xC,
        {
            'CountEntries': [0x0, ['unsigned long']],
            'HandleCountEntries': [
                0x4,
                ['array', 1, ['_OBJECT_HANDLE_COUNT_ENTRY']],
            ],
        },
    ],
    '_OWNER_ENTRY': [
        0x8,
        {
            'OwnerThread': [0x0, ['unsigned long']],
            'IoPriorityBoosted': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'OwnerReferenced': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'OwnerCount': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'TableSize': [0x4, ['unsigned long']],
        },
    ],
    '_ETIMER': [
        0xB8,
        {
            'KeTimer': [0x0, ['_KTIMER']],
            'Lock': [0x28, ['unsigned long']],
            'TimerApc': [0x2C, ['_KAPC']],
            'TimerDpc': [0x5C, ['_KDPC']],
            'ActiveTimerListEntry': [0x7C, ['_LIST_ENTRY']],
            'Period': [0x84, ['unsigned long']],
            'TimerFlags': [0x88, ['unsigned char']],
            'ApcAssociated': [
                0x88,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'FlushDpcs': [
                0x88,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Paused': [
                0x88,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Spare1': [
                0x88,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'DueTimeType': [0x89, ['unsigned char']],
            'Spare2': [0x8A, ['unsigned short']],
            'WakeReason': [0x8C, ['pointer', ['_DIAGNOSTIC_CONTEXT']]],
            'WakeTimerListEntry': [0x90, ['_LIST_ENTRY']],
            'VirtualizedTimerCookie': [0x98, ['pointer', ['void']]],
            'VirtualizedTimerLinks': [0x9C, ['_LIST_ENTRY']],
            'DueTime': [0xA8, ['unsigned long long']],
            'CoalescingWindow': [0xB0, ['unsigned long']],
        },
    ],
    '_PROC_PERF_SNAP': [
        0x40,
        {
            'Time': [0x0, ['unsigned long long']],
            'LastTime': [0x8, ['unsigned long long']],
            'Active': [0x10, ['unsigned long long']],
            'LastActive': [0x18, ['unsigned long long']],
            'FrequencyScaledActive': [0x20, ['unsigned long long']],
            'PerformanceScaledActive': [0x28, ['unsigned long long']],
            'CyclesActive': [0x30, ['unsigned long long']],
            'CyclesAffinitized': [0x38, ['unsigned long long']],
        },
    ],
    '_OBJECT_DIRECTORY_ENTRY': [
        0xC,
        {
            'ChainLink': [0x0, ['pointer', ['_OBJECT_DIRECTORY_ENTRY']]],
            'Object': [0x4, ['pointer', ['void']]],
            'HashValue': [0x8, ['unsigned long']],
        },
    ],
    '_LOCK_TRACKER': [
        0x4C,
        {
            'LockTrackerNode': [0x0, ['_RTL_BALANCED_NODE']],
            'Mdl': [0xC, ['pointer', ['_MDL']]],
            'StartVa': [0x10, ['pointer', ['void']]],
            'Count': [0x14, ['unsigned long']],
            'Offset': [0x18, ['unsigned long']],
            'Length': [0x1C, ['unsigned long']],
            'Page': [0x20, ['unsigned long']],
            'StackTrace': [0x24, ['array', 8, ['pointer', ['void']]]],
            'Who': [0x44, ['unsigned long']],
            'Process': [0x48, ['pointer', ['_EPROCESS']]],
        },
    ],
    '_POOL_BLOCK_HEAD': [
        0x10,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'List': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_EXHANDLE': [
        0x4,
        {
            'TagBits': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Index': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'GenericHandleOverlay': [0x0, ['pointer', ['void']]],
            'Value': [0x0, ['unsigned long']],
        },
    ],
    '_XSTATE_FEATURE': [
        0x8,
        {
            'Offset': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned long']],
        },
    ],
    '_DBGKD_CONTEXT_EX': [
        0xC,
        {
            'Offset': [0x0, ['unsigned long']],
            'ByteCount': [0x4, ['unsigned long']],
            'BytesCopied': [0x8, ['unsigned long']],
        },
    ],
    '_CM_DIRTY_VECTOR_LOG': [
        0x2C8,
        {
            'Next': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned long']],
            'Log': [0x8, ['array', 16, ['_CM_DIRTY_VECTOR_LOG_ENTRY']]],
        },
    ],
    '_ARBITER_INSTANCE': [
        0xA8,
        {
            'Signature': [0x0, ['unsigned long']],
            'MutexEvent': [0x4, ['pointer', ['_KEVENT']]],
            'Name': [0x8, ['pointer', ['unsigned short']]],
            'OrderingName': [0xC, ['pointer', ['unsigned short']]],
            'ResourceType': [0x10, ['long']],
            'Allocation': [0x14, ['pointer', ['_RTL_RANGE_LIST']]],
            'PossibleAllocation': [0x18, ['pointer', ['_RTL_RANGE_LIST']]],
            'OrderingList': [0x1C, ['_ARBITER_ORDERING_LIST']],
            'ReservedList': [0x24, ['_ARBITER_ORDERING_LIST']],
            'ReferenceCount': [0x2C, ['long']],
            'Interface': [0x30, ['pointer', ['_ARBITER_INTERFACE']]],
            'AllocationStackMaxSize': [0x34, ['unsigned long']],
            'AllocationStack': [
                0x38,
                ['pointer', ['_ARBITER_ALLOCATION_STATE']],
            ],
            'UnpackRequirement': [0x3C, ['pointer', ['void']]],
            'PackResource': [0x40, ['pointer', ['void']]],
            'UnpackResource': [0x44, ['pointer', ['void']]],
            'ScoreRequirement': [0x48, ['pointer', ['void']]],
            'TestAllocation': [0x4C, ['pointer', ['void']]],
            'RetestAllocation': [0x50, ['pointer', ['void']]],
            'CommitAllocation': [0x54, ['pointer', ['void']]],
            'RollbackAllocation': [0x58, ['pointer', ['void']]],
            'BootAllocation': [0x5C, ['pointer', ['void']]],
            'QueryArbitrate': [0x60, ['pointer', ['void']]],
            'QueryConflict': [0x64, ['pointer', ['void']]],
            'AddReserved': [0x68, ['pointer', ['void']]],
            'StartArbiter': [0x6C, ['pointer', ['void']]],
            'PreprocessEntry': [0x70, ['pointer', ['void']]],
            'AllocateEntry': [0x74, ['pointer', ['void']]],
            'GetNextAllocationRange': [0x78, ['pointer', ['void']]],
            'FindSuitableRange': [0x7C, ['pointer', ['void']]],
            'AddAllocation': [0x80, ['pointer', ['void']]],
            'BacktrackAllocation': [0x84, ['pointer', ['void']]],
            'OverrideConflict': [0x88, ['pointer', ['void']]],
            'InitializeRangeList': [0x8C, ['pointer', ['void']]],
            'TransactionInProgress': [0x90, ['unsigned char']],
            'TransactionEvent': [0x94, ['pointer', ['_KEVENT']]],
            'Extension': [0x98, ['pointer', ['void']]],
            'BusDeviceObject': [0x9C, ['pointer', ['_DEVICE_OBJECT']]],
            'ConflictCallbackContext': [0xA0, ['pointer', ['void']]],
            'ConflictCallback': [0xA4, ['pointer', ['void']]],
        },
    ],
    '_KDEVICE_QUEUE_ENTRY': [
        0x10,
        {
            'DeviceListEntry': [0x0, ['_LIST_ENTRY']],
            'SortKey': [0x8, ['unsigned long']],
            'Inserted': [0xC, ['unsigned char']],
        },
    ],
    '__unnamed_1ff7': [
        0x4,
        {
            'UserData': [0x0, ['unsigned long']],
            'Next': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1ff9': [
        0x4,
        {
            'u': [0x0, ['__unnamed_1ff7']],
        },
    ],
    '__unnamed_1ffb': [
        0x4,
        {
            'NewCell': [0x0, ['__unnamed_1ff9']],
        },
    ],
    '_HCELL': [
        0x8,
        {
            'Size': [0x0, ['long']],
            'u': [0x4, ['__unnamed_1ffb']],
        },
    ],
    '_WHEA_GENERIC_ERROR_DESCRIPTOR': [
        0x34,
        {
            'Type': [0x0, ['unsigned short']],
            'Reserved': [0x2, ['unsigned char']],
            'Enabled': [0x3, ['unsigned char']],
            'ErrStatusBlockLength': [0x4, ['unsigned long']],
            'RelatedErrorSourceId': [0x8, ['unsigned long']],
            'ErrStatusAddressSpaceID': [0xC, ['unsigned char']],
            'ErrStatusAddressBitWidth': [0xD, ['unsigned char']],
            'ErrStatusAddressBitOffset': [0xE, ['unsigned char']],
            'ErrStatusAddressAccessSize': [0xF, ['unsigned char']],
            'ErrStatusAddress': [0x10, ['_LARGE_INTEGER']],
            'Notify': [0x18, ['_WHEA_NOTIFICATION_DESCRIPTOR']],
        },
    ],
    '_HMAP_TABLE': [
        0x1800,
        {
            'Table': [0x0, ['array', 512, ['_HMAP_ENTRY']]],
        },
    ],
    '_SEP_LOWBOX_HANDLES_ENTRY': [
        0x1C,
        {
            'HashEntry': [0x0, ['_RTL_DYNAMIC_HASH_TABLE_ENTRY']],
            'ReferenceCount': [0xC, ['long']],
            'PackageSid': [0x10, ['pointer', ['void']]],
            'HandleCount': [0x14, ['unsigned long']],
            'Handles': [0x18, ['pointer', ['pointer', ['void']]]],
        },
    ],
    '_PROC_PERF_CONSTRAINT': [
        0x50,
        {
            'Prcb': [0x0, ['pointer', ['_KPRCB']]],
            'PerfContext': [0x4, ['unsigned long']],
            'PlatformCap': [0x8, ['unsigned long']],
            'ThermalCap': [0xC, ['unsigned long']],
            'LimitReasons': [0x10, ['unsigned long']],
            'PlatformCapStartTime': [0x18, ['unsigned long long']],
            'TargetPercent': [0x20, ['unsigned long']],
            'DesiredPercent': [0x24, ['unsigned long']],
            'SelectedPercent': [0x28, ['unsigned long']],
            'SelectedFrequency': [0x2C, ['unsigned long']],
            'PreviousFrequency': [0x30, ['unsigned long']],
            'PreviousPercent': [0x34, ['unsigned long']],
            'LatestFrequencyPercent': [0x38, ['unsigned long']],
            'SelectedState': [0x40, ['unsigned long long']],
            'Force': [0x48, ['unsigned char']],
        },
    ],
    '__unnamed_200e': [
        0x10,
        {
            'CallerCompletion': [0x0, ['pointer', ['void']]],
            'CallerContext': [0x4, ['pointer', ['void']]],
            'CallerDevice': [0x8, ['pointer', ['_DEVICE_OBJECT']]],
            'SystemWake': [0xC, ['unsigned char']],
        },
    ],
    '__unnamed_2011': [
        0x8,
        {
            'NotifyDevice': [0x0, ['pointer', ['_PO_DEVICE_NOTIFY']]],
            'FxDeviceActivated': [0x4, ['unsigned char']],
        },
    ],
    '_POP_IRP_DATA': [
        0x90,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'Irp': [0x8, ['pointer', ['_IRP']]],
            'Pdo': [0xC, ['pointer', ['_DEVICE_OBJECT']]],
            'TargetDevice': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'CurrentDevice': [0x14, ['pointer', ['_DEVICE_OBJECT']]],
            'WatchdogStart': [0x18, ['unsigned long long']],
            'WatchdogTimer': [0x20, ['_KTIMER']],
            'WatchdogDpc': [0x48, ['_KDPC']],
            'MinorFunction': [0x68, ['unsigned char']],
            'PowerStateType': [
                0x6C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'SystemPowerState', 1: 'DevicePowerState'},
                    ),
                ],
            ],
            'PowerState': [0x70, ['_POWER_STATE']],
            'WatchdogEnabled': [0x74, ['unsigned char']],
            'FxDevice': [0x78, ['pointer', ['_POP_FX_DEVICE']]],
            'SystemTransition': [0x7C, ['unsigned char']],
            'NotifyPEP': [0x7D, ['unsigned char']],
            'Device': [0x80, ['__unnamed_200e']],
            'System': [0x80, ['__unnamed_2011']],
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
            'WakeFromInterrupt': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=32, native_type='unsigned long'
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
    '_MI_USER_VA_INFO': [
        0xD1C,
        {
            'NumberOfCommittedPageTables': [0x0, ['unsigned long']],
            'PhysicalMappingCount': [0x4, ['unsigned long']],
            'VadBitMapHint': [0x8, ['unsigned long']],
            'LastAllocationSizeHint': [0xC, ['unsigned long']],
            'LastAllocationSize': [0x10, ['unsigned long']],
            'LowestBottomUpVadBit': [0x14, ['unsigned long']],
            'VadBitMapSize': [0x18, ['unsigned long']],
            'VadBitMapCommitment': [0x1C, ['unsigned long']],
            'MaximumLastVadBit': [0x20, ['unsigned long']],
            'VadsBeingDeleted': [0x24, ['long']],
            'LastVadDeletionEvent': [0x28, ['pointer', ['_KEVENT']]],
            'VadBitBuffer': [0x2C, ['pointer', ['unsigned long']]],
            'LowestBottomUpAllocationAddress': [0x30, ['pointer', ['void']]],
            'HighestTopDownAllocationAddress': [0x34, ['pointer', ['void']]],
            'FreeTebHint': [0x38, ['pointer', ['void']]],
            'NumaAware': [0x3C, ['unsigned char']],
            'PrivateFixupVadCount': [0x40, ['unsigned long']],
            'CfgBitMap': [0x44, ['array', 1, ['_MI_CFG_BITMAP_INFO']]],
            'CommittedPageTableBufferForTopLevel': [
                0x54,
                ['array', 48, ['unsigned long']],
            ],
            'CommittedPageTableBitmaps': [
                0x114,
                ['array', 1, ['_RTL_BITMAP']],
            ],
            'UsedPageTableEntries': [
                0x11C,
                ['array', 1536, ['unsigned short']],
            ],
        },
    ],
    '_PROC_FEEDBACK': [
        0x68,
        {
            'Lock': [0x0, ['unsigned long']],
            'CyclesLast': [0x8, ['unsigned long long']],
            'CyclesActive': [0x10, ['unsigned long long']],
            'Counters': [
                0x18,
                ['array', 2, ['pointer', ['_PROC_FEEDBACK_COUNTER']]],
            ],
            'LastUpdateTime': [0x20, ['unsigned long long']],
            'UnscaledTime': [0x28, ['unsigned long long']],
            'UnaccountedTime': [0x30, ['long long']],
            'ScaledTime': [0x38, ['array', 2, ['unsigned long long']]],
            'UnaccountedKernelTime': [0x48, ['unsigned long long']],
            'PerformanceScaledKernelTime': [0x50, ['unsigned long long']],
            'UserTimeLast': [0x58, ['unsigned long']],
            'KernelTimeLast': [0x5C, ['unsigned long']],
            'KernelTimesIndex': [0x60, ['unsigned char']],
        },
    ],
    '__unnamed_2028': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Alignment': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_202c': [
        0x14,
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
            'TargetedProcessors': [0x10, ['unsigned long']],
        },
    ],
    '__unnamed_202e': [
        0x8,
        {
            'MinimumChannel': [0x0, ['unsigned long']],
            'MaximumChannel': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2030': [
        0x10,
        {
            'RequestLine': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'Channel': [0x8, ['unsigned long']],
            'TransferWidth': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_2032': [
        0xC,
        {
            'Data': [0x0, ['array', 3, ['unsigned long']]],
        },
    ],
    '__unnamed_2034': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'MinBusNumber': [0x4, ['unsigned long']],
            'MaxBusNumber': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_2036': [
        0xC,
        {
            'Priority': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2038': [
        0x18,
        {
            'Length40': [0x0, ['unsigned long']],
            'Alignment40': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_203a': [
        0x18,
        {
            'Length48': [0x0, ['unsigned long']],
            'Alignment48': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_203c': [
        0x18,
        {
            'Length64': [0x0, ['unsigned long']],
            'Alignment64': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_203e': [
        0xC,
        {
            'Class': [0x0, ['unsigned char']],
            'Type': [0x1, ['unsigned char']],
            'Reserved1': [0x2, ['unsigned char']],
            'Reserved2': [0x3, ['unsigned char']],
            'IdLowPart': [0x4, ['unsigned long']],
            'IdHighPart': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2040': [
        0x18,
        {
            'Port': [0x0, ['__unnamed_2028']],
            'Memory': [0x0, ['__unnamed_2028']],
            'Interrupt': [0x0, ['__unnamed_202c']],
            'Dma': [0x0, ['__unnamed_202e']],
            'DmaV3': [0x0, ['__unnamed_2030']],
            'Generic': [0x0, ['__unnamed_2028']],
            'DevicePrivate': [0x0, ['__unnamed_2032']],
            'BusNumber': [0x0, ['__unnamed_2034']],
            'ConfigData': [0x0, ['__unnamed_2036']],
            'Memory40': [0x0, ['__unnamed_2038']],
            'Memory48': [0x0, ['__unnamed_203a']],
            'Memory64': [0x0, ['__unnamed_203c']],
            'Connection': [0x0, ['__unnamed_203e']],
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
            'u': [0x8, ['__unnamed_2040']],
        },
    ],
    '_POP_THERMAL_ZONE': [
        0x170,
        {
            'PolicyDevice': [0x0, ['_POP_POLICY_DEVICE']],
            'Link': [0x0, ['_LIST_ENTRY']],
            'DeviceType': [
                0x8,
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
                            8: 'PolicyDeviceWakeAlarm',
                            9: 'PolicyDeviceFan',
                            10: 'PolicyCsBatterySaver',
                            11: 'PolicyDeviceMax',
                        },
                    ),
                ],
            ],
            'Notification': [0xC, ['pointer', ['void']]],
            'Name': [0x10, ['_UNICODE_STRING']],
            'Device': [0x18, ['pointer', ['_DEVICE_OBJECT']]],
            'Irp': [0x1C, ['pointer', ['_IRP']]],
            'State': [0x20, ['unsigned char']],
            'Flags': [0x21, ['unsigned char']],
            'Removing': [0x22, ['unsigned char']],
            'Mode': [0x23, ['unsigned char']],
            'PendingMode': [0x24, ['unsigned char']],
            'ActivePoint': [0x25, ['unsigned char']],
            'PendingActivePoint': [0x26, ['unsigned char']],
            'Critical': [0x27, ['unsigned char']],
            'HighPrecisionThrottle': [0x28, ['long']],
            'Throttle': [0x2C, ['long']],
            'PendingThrottle': [0x30, ['long']],
            'ThrottleReasons': [0x34, ['unsigned long']],
            'LastTime': [0x38, ['unsigned long long']],
            'SampleRate': [0x40, ['unsigned long']],
            'LastTemp': [0x44, ['unsigned long']],
            'PassiveTimer': [0x48, ['_KTIMER']],
            'PassiveDpc': [0x70, ['_KDPC']],
            'Info': [0x90, ['_THERMAL_INFORMATION_EX']],
            'InfoLastUpdateTime': [0xE0, ['_LARGE_INTEGER']],
            'Policy': [0xE8, ['_THERMAL_POLICY']],
            'PolicyDriver': [0xFC, ['unsigned char']],
            'Metrics': [0x100, ['_POP_THERMAL_ZONE_METRICS']],
            'WorkItem': [0x130, ['_WORK_QUEUE_ITEM']],
            'Lock': [0x140, ['_POP_RW_LOCK']],
            'ZoneStopped': [0x148, ['_KEVENT']],
            'TemperatureUpdated': [0x158, ['_KEVENT']],
            'InstanceId': [0x168, ['unsigned long']],
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
            'filler1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11,
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
        0xC,
        {
            'NextPage': [0x0, ['pointer', ['_SINGLE_LIST_ENTRY']]],
            'VerifierEntry': [0x4, ['pointer', ['void']]],
            'Signature': [0x8, ['unsigned long']],
        },
    ],
    '_HANDLE_TRACE_DEBUG_INFO': [
        0x80,
        {
            'RefCount': [0x0, ['long']],
            'TableSize': [0x4, ['unsigned long']],
            'BitMaskFlags': [0x8, ['unsigned long']],
            'CloseCompactionLock': [0xC, ['_FAST_MUTEX']],
            'CurrentStackIndex': [0x2C, ['unsigned long']],
            'TraceDb': [0x30, ['array', 1, ['_HANDLE_TRACE_DB_ENTRY']]],
        },
    ],
    '_HHIVE': [
        0x3BC,
        {
            'Signature': [0x0, ['unsigned long']],
            'GetCellRoutine': [0x4, ['pointer', ['void']]],
            'Allocate': [0x8, ['pointer', ['void']]],
            'Free': [0xC, ['pointer', ['void']]],
            'FileWrite': [0x10, ['pointer', ['void']]],
            'FileRead': [0x14, ['pointer', ['void']]],
            'HiveLoadFailure': [0x18, ['pointer', ['void']]],
            'BaseBlock': [0x1C, ['pointer', ['_HBASE_BLOCK']]],
            'DirtyVector': [0x20, ['_RTL_BITMAP']],
            'DirtyCount': [0x28, ['unsigned long']],
            'DirtyAlloc': [0x2C, ['unsigned long']],
            'UnreconciledVector': [0x30, ['_RTL_BITMAP']],
            'UnreconciledCount': [0x38, ['unsigned long']],
            'BaseBlockAlloc': [0x3C, ['unsigned long']],
            'Cluster': [0x40, ['unsigned long']],
            'Flat': [
                0x44,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ReadOnly': [
                0x44,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x44,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'DirtyFlag': [0x45, ['unsigned char']],
            'HvBinHeadersUse': [0x48, ['unsigned long']],
            'HvFreeCellsUse': [0x4C, ['unsigned long']],
            'HvUsedCellsUse': [0x50, ['unsigned long']],
            'CmUsedCellsUse': [0x54, ['unsigned long']],
            'HiveFlags': [0x58, ['unsigned long']],
            'CurrentLog': [0x5C, ['unsigned long']],
            'CurrentLogSequence': [0x60, ['unsigned long']],
            'CurrentLogOffset': [0x64, ['unsigned long']],
            'MinimumLogSequence': [0x68, ['unsigned long']],
            'LogFileSizeCap': [0x6C, ['unsigned long']],
            'LogDataPresent': [0x70, ['array', 2, ['unsigned char']]],
            'PrimaryFileValid': [0x72, ['unsigned char']],
            'BaseBlockDirty': [0x73, ['unsigned char']],
            'FirstLogFile': [
                0x74,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'SecondLogFile': [
                0x74,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'HeaderRecovered': [
                0x74,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'LegacyRecoveryIndicated': [
                0x74,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'RecoveryInformationReserved': [
                0x74,
                [
                    'BitField',
                    dict(
                        start_bit=8, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'RecoveryInformation': [0x74, ['unsigned short']],
            'LogEntriesRecovered': [0x76, ['array', 2, ['unsigned char']]],
            'RefreshCount': [0x78, ['unsigned long']],
            'StorageTypeCount': [0x7C, ['unsigned long']],
            'Version': [0x80, ['unsigned long']],
            'Storage': [0x84, ['array', 2, ['_DUAL']]],
        },
    ],
    '_WHEA_XPF_NMI_DESCRIPTOR': [
        0x3,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
        },
    ],
    '_CM_WORKITEM': [
        0x14,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Private': [0x8, ['unsigned long']],
            'WorkerRoutine': [0xC, ['pointer', ['void']]],
            'Parameter': [0x10, ['pointer', ['void']]],
        },
    ],
    '_POP_THERMAL_ZONE_METRICS': [
        0x30,
        {
            'ActiveCount': [0x0, ['unsigned long']],
            'PassiveCount': [0x4, ['unsigned long']],
            'LastActiveStartTime': [0x8, ['unsigned long long']],
            'AverageActiveTime': [0x10, ['unsigned long long']],
            'LastPassiveStartTime': [0x18, ['unsigned long long']],
            'AveragePassiveTime': [0x20, ['unsigned long long']],
            'StartTickSinceLastReset': [0x28, ['_LARGE_INTEGER']],
        },
    ],
    '_CM_TRANS': [
        0x68,
        {
            'TransactionListEntry': [0x0, ['_LIST_ENTRY']],
            'KCBUoWListHead': [0x8, ['_LIST_ENTRY']],
            'LazyCommitListEntry': [0x10, ['_LIST_ENTRY']],
            'KtmTrans': [0x18, ['pointer', ['void']]],
            'CmRm': [0x1C, ['pointer', ['_CM_RM']]],
            'KtmEnlistmentObject': [0x20, ['pointer', ['_KENLISTMENT']]],
            'KtmEnlistmentHandle': [0x24, ['pointer', ['void']]],
            'KtmUow': [0x28, ['_GUID']],
            'StartLsn': [0x38, ['unsigned long long']],
            'TransState': [0x40, ['unsigned long']],
            'HiveCount': [0x44, ['unsigned long']],
            'HiveArray': [0x48, ['array', 7, ['pointer', ['_CMHIVE']]]],
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
        0x18,
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
        0x14,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Flags': [0x8, ['unsigned long']],
            'Count': [0xC, ['unsigned long']],
            'Stamp': [0x10, ['unsigned long']],
        },
    ],
    '_RTL_TIME_ZONE_INFORMATION': [
        0xAC,
        {
            'Bias': [0x0, ['long']],
            'StandardName': [0x4, ['array', 32, ['wchar']]],
            'StandardStart': [0x44, ['_TIME_FIELDS']],
            'StandardBias': [0x54, ['long']],
            'DaylightName': [0x58, ['array', 32, ['wchar']]],
            'DaylightStart': [0x98, ['_TIME_FIELDS']],
            'DaylightBias': [0xA8, ['long']],
        },
    ],
    '_OBJECT_CREATE_INFORMATION': [
        0x2C,
        {
            'Attributes': [0x0, ['unsigned long']],
            'RootDirectory': [0x4, ['pointer', ['void']]],
            'ProbeMode': [0x8, ['unsigned char']],
            'PagedPoolCharge': [0xC, ['unsigned long']],
            'NonPagedPoolCharge': [0x10, ['unsigned long']],
            'SecurityDescriptorCharge': [0x14, ['unsigned long']],
            'SecurityDescriptor': [0x18, ['pointer', ['void']]],
            'SecurityQos': [
                0x1C,
                ['pointer', ['_SECURITY_QUALITY_OF_SERVICE']],
            ],
            'SecurityQualityOfService': [
                0x20,
                ['_SECURITY_QUALITY_OF_SERVICE'],
            ],
        },
    ],
    '_POOL_HACKER': [
        0x28,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'Contents': [0x8, ['array', 8, ['unsigned long']]],
        },
    ],
    '_PO_DIAG_STACK_RECORD': [
        0x8,
        {
            'StackDepth': [0x0, ['unsigned long']],
            'Stack': [0x4, ['array', 1, ['pointer', ['void']]]],
        },
    ],
    '_SECTION_OBJECT_POINTERS': [
        0xC,
        {
            'DataSectionObject': [0x0, ['pointer', ['void']]],
            'SharedCacheMap': [0x4, ['pointer', ['void']]],
            'ImageSectionObject': [0x8, ['pointer', ['void']]],
        },
    ],
    '_VF_BTS_DATA_MANAGEMENT_AREA': [
        0x34,
        {
            'BTSBufferBase': [0x0, ['pointer', ['void']]],
            'BTSIndex': [0x4, ['pointer', ['void']]],
            'BTSMax': [0x8, ['pointer', ['void']]],
            'BTSInterruptThreshold': [0xC, ['pointer', ['void']]],
            'PEBSBufferBase': [0x10, ['pointer', ['void']]],
            'PEBSIndex': [0x14, ['pointer', ['void']]],
            'PEBSMax': [0x18, ['pointer', ['void']]],
            'PEBSInterruptThreshold': [0x1C, ['pointer', ['void']]],
            'PEBSCounterReset': [0x20, ['array', 2, ['pointer', ['void']]]],
            'Reserved': [0x28, ['array', 12, ['unsigned char']]],
        },
    ],
    '_FLOATING_SAVE_AREA': [
        0x70,
        {
            'ControlWord': [0x0, ['unsigned long']],
            'StatusWord': [0x4, ['unsigned long']],
            'TagWord': [0x8, ['unsigned long']],
            'ErrorOffset': [0xC, ['unsigned long']],
            'ErrorSelector': [0x10, ['unsigned long']],
            'DataOffset': [0x14, ['unsigned long']],
            'DataSelector': [0x18, ['unsigned long']],
            'RegisterArea': [0x1C, ['array', 80, ['unsigned char']]],
            'Spare0': [0x6C, ['unsigned long']],
        },
    ],
    '_SEP_AUDIT_POLICY': [
        0x1E,
        {
            'AdtTokenPolicy': [0x0, ['_TOKEN_AUDIT_POLICY']],
            'PolicySetStatus': [0x1D, ['unsigned char']],
        },
    ],
    '__unnamed_2098': [
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
    '__unnamed_209a': [
        0x10,
        {
            'AllSharedExportThunks': [
                0x0,
                ['_VF_TARGET_ALL_SHARED_EXPORT_THUNKS'],
            ],
            'Flags': [0x0, ['__unnamed_2098']],
        },
    ],
    '_VF_TARGET_DRIVER': [
        0x1C,
        {
            'TreeNode': [0x0, ['_VF_AVL_TREE_NODE']],
            'u1': [0x8, ['__unnamed_209a']],
            'VerifiedData': [
                0x18,
                ['pointer', ['_VF_TARGET_VERIFIED_DRIVER_DATA']],
            ],
        },
    ],
    '__unnamed_20a3': [
        0x14,
        {
            'ClassGuid': [0x0, ['_GUID']],
            'SymbolicLinkName': [0x10, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_20a5': [
        0x2,
        {
            'DeviceId': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_20a7': [
        0x8,
        {
            'NotificationStructure': [0x0, ['pointer', ['void']]],
            'DeviceId': [0x4, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_20a9': [
        0x4,
        {
            'Notification': [0x0, ['pointer', ['void']]],
        },
    ],
    '__unnamed_20ab': [
        0x8,
        {
            'NotificationCode': [0x0, ['unsigned long']],
            'NotificationData': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_20ad': [
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
    '__unnamed_20af': [
        0x10,
        {
            'BlockedDriverGuid': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_20b1': [
        0x2,
        {
            'ParentId': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_20b3': [
        0x20,
        {
            'PowerSettingGuid': [0x0, ['_GUID']],
            'Flags': [0x10, ['unsigned long']],
            'SessionId': [0x14, ['unsigned long']],
            'DataLength': [0x18, ['unsigned long']],
            'Data': [0x1C, ['array', 1, ['unsigned char']]],
        },
    ],
    '__unnamed_20b5': [
        0x20,
        {
            'DeviceClass': [0x0, ['__unnamed_20a3']],
            'TargetDevice': [0x0, ['__unnamed_20a5']],
            'InstallDevice': [0x0, ['__unnamed_20a5']],
            'CustomNotification': [0x0, ['__unnamed_20a7']],
            'ProfileNotification': [0x0, ['__unnamed_20a9']],
            'PowerNotification': [0x0, ['__unnamed_20ab']],
            'VetoNotification': [0x0, ['__unnamed_20ad']],
            'BlockedDriverNotification': [0x0, ['__unnamed_20af']],
            'InvalidIDNotification': [0x0, ['__unnamed_20b1']],
            'PowerSettingNotification': [0x0, ['__unnamed_20b3']],
            'PropertyChangeNotification': [0x0, ['__unnamed_20a5']],
            'DeviceInstanceNotification': [0x0, ['__unnamed_20a5']],
        },
    ],
    '_PLUGPLAY_EVENT_BLOCK': [
        0x44,
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
                            11: 'DeviceInstanceStartedEvent',
                            12: 'MaxPlugEventCategory',
                        },
                    ),
                ],
            ],
            'Result': [0x14, ['pointer', ['unsigned long']]],
            'Flags': [0x18, ['unsigned long']],
            'TotalSize': [0x1C, ['unsigned long']],
            'DeviceObject': [0x20, ['pointer', ['void']]],
            'u': [0x24, ['__unnamed_20b5']],
        },
    ],
    '_VF_SUSPECT_DRIVER_ENTRY': [
        0x18,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'Loads': [0x8, ['unsigned long']],
            'Unloads': [0xC, ['unsigned long']],
            'BaseName': [0x10, ['_UNICODE_STRING']],
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
            'Unused': [
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
        0x88,
        {
            'SidCount': [0x0, ['unsigned long']],
            'SidAttr': [0x4, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'Hash': [0x8, ['array', 32, ['unsigned long']]],
        },
    ],
    '_XSTATE_CONTEXT': [
        0x20,
        {
            'Mask': [0x0, ['unsigned long long']],
            'Length': [0x8, ['unsigned long']],
            'Reserved1': [0xC, ['unsigned long']],
            'Area': [0x10, ['pointer', ['_XSAVE_AREA']]],
            'Reserved2': [0x14, ['unsigned long']],
            'Buffer': [0x18, ['pointer', ['void']]],
            'Reserved3': [0x1C, ['unsigned long']],
        },
    ],
    '_PROCESSOR_IDLE_PREPARE_INFO': [
        0x60,
        {
            'Context': [0x0, ['pointer', ['void']]],
            'Constraints': [0x8, ['_PROCESSOR_IDLE_CONSTRAINTS']],
            'DependencyCount': [0x48, ['unsigned long']],
            'DependencyUsed': [0x4C, ['unsigned long']],
            'DependencyArray': [
                0x50,
                ['pointer', ['_PROCESSOR_IDLE_DEPENDENCY']],
            ],
            'PlatformIdleStateIndex': [0x54, ['unsigned long']],
            'ProcessorIdleStateIndex': [0x58, ['unsigned long']],
            'IdleSelectFailureMask': [0x5C, ['unsigned long']],
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
            'XmmRegisters': [0xA0, ['array', 8, ['_M128A']]],
            'Reserved4': [0x120, ['array', 224, ['unsigned char']]],
        },
    ],
    '__unnamed_20d1': [
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
            'Flags': [0x7, ['__unnamed_20d1']],
            'TimeCheck': [0x8, ['unsigned long']],
            'IncreaseTime': [0xC, ['unsigned long']],
            'DecreaseTime': [0x10, ['unsigned long']],
            'IncreasePercent': [0x14, ['unsigned long']],
            'DecreasePercent': [0x18, ['unsigned long']],
        },
    ],
    '_BUS_EXTENSION_LIST': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['void']]],
            'BusExtension': [0x4, ['pointer', ['_PI_BUS_EXTENSION']]],
        },
    ],
    '_CACHED_CHILD_LIST': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'ValueList': [0x4, ['unsigned long']],
            'RealKcb': [0x4, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
        },
    ],
    '_KDEVICE_QUEUE': [
        0x14,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'DeviceListHead': [0x4, ['_LIST_ENTRY']],
            'Lock': [0xC, ['unsigned long']],
            'Busy': [0x10, ['unsigned char']],
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
    '_PEBS_DS_SAVE_AREA': [
        0x60,
        {
            'BtsBufferBase': [0x0, ['unsigned long long']],
            'BtsIndex': [0x8, ['unsigned long long']],
            'BtsAbsoluteMaximum': [0x10, ['unsigned long long']],
            'BtsInterruptThreshold': [0x18, ['unsigned long long']],
            'PebsBufferBase': [0x20, ['unsigned long long']],
            'PebsIndex': [0x28, ['unsigned long long']],
            'PebsAbsoluteMaximum': [0x30, ['unsigned long long']],
            'PebsInterruptThreshold': [0x38, ['unsigned long long']],
            'PebsCounterReset0': [0x40, ['unsigned long long']],
            'PebsCounterReset1': [0x48, ['unsigned long long']],
            'PebsCounterReset2': [0x50, ['unsigned long long']],
            'PebsCounterReset3': [0x58, ['unsigned long long']],
        },
    ],
    '_OBJECT_TYPE_INITIALIZER': [
        0x58,
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
                            0: 'NonPagedPoolBase',
                            1: 'PagedPool',
                            2: 'NonPagedPoolBaseMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolBaseCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolBaseCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            516: 'NonPagedPoolNxCacheAligned',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            512: 'NonPagedPoolNx',
                            544: 'NonPagedPoolSessionNx',
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
            'DumpProcedure': [0x30, ['pointer', ['void']]],
            'OpenProcedure': [0x34, ['pointer', ['void']]],
            'CloseProcedure': [0x38, ['pointer', ['void']]],
            'DeleteProcedure': [0x3C, ['pointer', ['void']]],
            'ParseProcedure': [0x40, ['pointer', ['void']]],
            'SecurityProcedure': [0x44, ['pointer', ['void']]],
            'QueryNameProcedure': [0x48, ['pointer', ['void']]],
            'OkayToCloseProcedure': [0x4C, ['pointer', ['void']]],
            'WaitObjectFlagMask': [0x50, ['unsigned long']],
            'WaitObjectFlagOffset': [0x54, ['unsigned short']],
            'WaitObjectPointerOffset': [0x56, ['unsigned short']],
        },
    ],
    '__unnamed_2106': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'SubsectionFlags': [0x0, ['_MMSUBSECTION_FLAGS']],
        },
    ],
    '_SUBSECTION': [
        0x20,
        {
            'ControlArea': [0x0, ['pointer', ['_CONTROL_AREA']]],
            'SubsectionBase': [0x4, ['pointer', ['_MMPTE']]],
            'NextSubsection': [0x8, ['pointer', ['_SUBSECTION']]],
            'PtesInSubsection': [0xC, ['unsigned long']],
            'UnusedPtes': [0x10, ['unsigned long']],
            'GlobalPerSessionHead': [0x10, ['_RTL_AVL_TREE']],
            'u': [0x14, ['__unnamed_2106']],
            'StartingSector': [0x18, ['unsigned long']],
            'NumberOfFullSectors': [0x1C, ['unsigned long']],
        },
    ],
    'tagSWITCH_CONTEXT_ATTRIBUTE': [
        0x18,
        {
            'ulContextUpdateCounter': [0x0, ['unsigned long long']],
            'fAllowContextUpdate': [0x8, ['long']],
            'fEnableTrace': [0xC, ['long']],
            'EtwHandle': [0x10, ['unsigned long long']],
        },
    ],
    '_IO_CLIENT_EXTENSION': [
        0x8,
        {
            'NextExtension': [0x0, ['pointer', ['_IO_CLIENT_EXTENSION']]],
            'ClientIdentificationAddress': [0x4, ['pointer', ['void']]],
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
    '_DIRTY_PAGE_STATISTICS': [
        0xC,
        {
            'DirtyPages': [0x0, ['unsigned long']],
            'DirtyPagesLastScan': [0x4, ['unsigned long']],
            'DirtyPagesScheduledLastScan': [0x8, ['unsigned long']],
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
        0x10,
        {
            'StackBase': [0x0, ['unsigned long']],
            'StackLimit': [0x4, ['unsigned long']],
            'KernelStack': [0x8, ['unsigned long']],
            'InitialStack': [0xC, ['unsigned long']],
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
            'ExecuteOptionsNV': [0x0, ['unsigned char']],
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
    '_WHEA_XPF_MCE_DESCRIPTOR': [
        0x398,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'NumberOfBanks': [0x3, ['unsigned char']],
            'Flags': [0x4, ['_XPF_MCE_FLAGS']],
            'MCG_Capability': [0x8, ['unsigned long long']],
            'MCG_GlobalControl': [0x10, ['unsigned long long']],
            'Banks': [0x18, ['array', 32, ['_WHEA_XPF_MC_BANK_DESCRIPTOR']]],
        },
    ],
    '_ARBITER_ALLOCATION_STATE': [
        0x38,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
            'CurrentMinimum': [0x10, ['unsigned long long']],
            'CurrentMaximum': [0x18, ['unsigned long long']],
            'Entry': [0x20, ['pointer', ['_ARBITER_LIST_ENTRY']]],
            'CurrentAlternative': [
                0x24,
                ['pointer', ['_ARBITER_ALTERNATIVE']],
            ],
            'AlternativeCount': [0x28, ['unsigned long']],
            'Alternatives': [0x2C, ['pointer', ['_ARBITER_ALTERNATIVE']]],
            'Flags': [0x30, ['unsigned short']],
            'RangeAttributes': [0x32, ['unsigned char']],
            'RangeAvailableAttributes': [0x33, ['unsigned char']],
            'WorkSpace': [0x34, ['unsigned long']],
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
        0x4,
        {
            'Valid': [
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
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Hashed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Direct': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Age': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=12, native_type='unsigned long'),
                ],
            ],
            'VirtualPageNumber': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=32, native_type='unsigned long'
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
    '_WHEA_XPF_CMC_DESCRIPTOR': [
        0x3A4,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'NumberOfBanks': [0x3, ['unsigned char']],
            'Reserved': [0x4, ['unsigned long']],
            'Notify': [0x8, ['_WHEA_NOTIFICATION_DESCRIPTOR']],
            'Banks': [0x24, ['array', 32, ['_WHEA_XPF_MC_BANK_DESCRIPTOR']]],
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
    '_VPB': [
        0x58,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'Flags': [0x4, ['unsigned short']],
            'VolumeLabelLength': [0x6, ['unsigned short']],
            'DeviceObject': [0x8, ['pointer', ['_DEVICE_OBJECT']]],
            'RealDevice': [0xC, ['pointer', ['_DEVICE_OBJECT']]],
            'SerialNumber': [0x10, ['unsigned long']],
            'ReferenceCount': [0x14, ['unsigned long']],
            'VolumeLabel': [0x18, ['array', 32, ['wchar']]],
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
    '_IOP_IRP_STACK_PROFILER': [
        0x54,
        {
            'Profile': [0x0, ['array', 20, ['unsigned long']]],
            'TotalIrps': [0x50, ['unsigned long']],
        },
    ],
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
        0x10,
        {
            'ClientToken': [0x0, ['pointer', ['void']]],
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
            'PrimaryToken': [0x8, ['pointer', ['void']]],
            'ProcessAuditId': [0xC, ['pointer', ['void']]],
        },
    ],
    '_EVENT_HEADER': [
        0x50,
        {
            'Size': [0x0, ['unsigned short']],
            'HeaderType': [0x2, ['unsigned short']],
            'Flags': [0x4, ['unsigned short']],
            'EventProperty': [0x6, ['unsigned short']],
            'ThreadId': [0x8, ['unsigned long']],
            'ProcessId': [0xC, ['unsigned long']],
            'TimeStamp': [0x10, ['_LARGE_INTEGER']],
            'ProviderId': [0x18, ['_GUID']],
            'EventDescriptor': [0x28, ['_EVENT_DESCRIPTOR']],
            'KernelTime': [0x38, ['unsigned long']],
            'UserTime': [0x3C, ['unsigned long']],
            'ProcessorTime': [0x38, ['unsigned long long']],
            'ActivityId': [0x40, ['_GUID']],
        },
    ],
    '_KiIoAccessMap': [
        0x2024,
        {
            'DirectionMap': [0x0, ['array', 32, ['unsigned char']]],
            'IoMap': [0x20, ['array', 8196, ['unsigned char']]],
        },
    ],
    '_PF_KERNEL_GLOBALS': [
        0x40,
        {
            'AccessBufferAgeThreshold': [0x0, ['unsigned long long']],
            'AccessBufferRef': [0x8, ['_EX_RUNDOWN_REF']],
            'AccessBufferExistsEvent': [0xC, ['_KEVENT']],
            'AccessBufferMax': [0x1C, ['unsigned long']],
            'AccessBufferList': [0x20, ['_SLIST_HEADER']],
            'StreamSequenceNumber': [0x28, ['long']],
            'Flags': [0x2C, ['unsigned long']],
            'ScenarioPrefetchCount': [0x30, ['long']],
        },
    ],
    '_CM_KEY_HASH_TABLE_ENTRY': [
        0xC,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'Owner': [0x4, ['pointer', ['_KTHREAD']]],
            'Entry': [0x8, ['pointer', ['_CM_KEY_HASH']]],
        },
    ],
    '_ARBITER_QUERY_ARBITRATE_PARAMETERS': [
        0x4,
        {
            'ArbitrationList': [0x0, ['pointer', ['_LIST_ENTRY']]],
        },
    ],
    '_ARBITER_BOOT_ALLOCATION_PARAMETERS': [
        0x4,
        {
            'ArbitrationList': [0x0, ['pointer', ['_LIST_ENTRY']]],
        },
    ],
    '_KPRIQUEUE': [
        0x19C,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'EntryListHead': [0x10, ['array', 32, ['_LIST_ENTRY']]],
            'CurrentCount': [0x110, ['array', 32, ['long']]],
            'MaximumCount': [0x190, ['unsigned long']],
            'ThreadListHead': [0x194, ['_LIST_ENTRY']],
        },
    ],
    '_EXCEPTION_REGISTRATION_RECORD': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_EXCEPTION_REGISTRATION_RECORD']]],
            'Handler': [0x4, ['pointer', ['void']]],
        },
    ],
    '_WAITING_IRP': [
        0x20,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'Irp': [0x8, ['pointer', ['_IRP']]],
            'CompletionRoutine': [0xC, ['pointer', ['void']]],
            'Context': [0x10, ['pointer', ['void']]],
            'Event': [0x14, ['pointer', ['_KEVENT']]],
            'Information': [0x18, ['unsigned long']],
            'BreakAllRH': [0x1C, ['unsigned char']],
        },
    ],
    '_POP_SYSTEM_IDLE': [
        0x40,
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
            'SystemRequired': [0x24, ['unsigned long']],
            'IdleWorker': [0x28, ['unsigned char']],
            'Sampling': [0x29, ['unsigned char']],
            'LastTick': [0x30, ['unsigned long long']],
            'LastSystemRequiredTime': [0x38, ['unsigned long']],
        },
    ],
    '_VF_TARGET_ALL_SHARED_EXPORT_THUNKS': [
        0x10,
        {
            'SharedExportThunks': [
                0x0,
                ['pointer', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
            'PoolSharedExportThunks': [
                0x4,
                ['pointer', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
            'OrderDependentSharedExportThunks': [
                0x8,
                ['pointer', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
            'XdvSharedExportThunks': [
                0xC,
                ['pointer', ['_VERIFIER_SHARED_EXPORT_THUNK']],
            ],
        },
    ],
    '_KSCHEDULING_GROUP': [
        0x140,
        {
            'Value': [0x0, ['unsigned short']],
            'Type': [0x2, ['unsigned char']],
            'HardCap': [0x3, ['unsigned char']],
            'RelativeWeight': [0x4, ['unsigned long']],
            'QueryHistoryTimeStamp': [0x8, ['unsigned long long']],
            'NotificationCycles': [0x10, ['long long']],
            'SchedulingGroupList': [0x18, ['_LIST_ENTRY']],
            'NotificationDpc': [0x20, ['pointer', ['_KDPC']]],
            'PerProcessor': [0x40, ['array', 1, ['_KSCB']]],
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
        0x18,
        {
            'SourceProcess': [0x0, ['pointer', ['_EPROCESS']]],
            'SourceHandle': [0x4, ['pointer', ['void']]],
            'Object': [0x8, ['pointer', ['void']]],
            'TargetAccess': [0xC, ['unsigned long']],
            'ObjectInfo': [0x10, ['_HANDLE_TABLE_ENTRY_INFO']],
            'HandleAttributes': [0x14, ['unsigned long']],
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
                        end_bit=32,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SubsectionAddress': [
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
    '_POP_IRP_WORKER_ENTRY': [
        0x18,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'Thread': [0x8, ['pointer', ['_ETHREAD']]],
            'Irp': [0xC, ['pointer', ['_IRP']]],
            'Device': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'Static': [0x14, ['unsigned char']],
        },
    ],
    '_POP_POLICY_DEVICE': [
        0x20,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'DeviceType': [
                0x8,
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
                            8: 'PolicyDeviceWakeAlarm',
                            9: 'PolicyDeviceFan',
                            10: 'PolicyCsBatterySaver',
                            11: 'PolicyDeviceMax',
                        },
                    ),
                ],
            ],
            'Notification': [0xC, ['pointer', ['void']]],
            'Name': [0x10, ['_UNICODE_STRING']],
            'Device': [0x18, ['pointer', ['_DEVICE_OBJECT']]],
            'Irp': [0x1C, ['pointer', ['_IRP']]],
        },
    ],
    '__unnamed_2186': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2188': [
        0xC,
        {
            'Level': [0x0, ['unsigned short']],
            'Group': [0x2, ['unsigned short']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_218a': [
        0xC,
        {
            'Group': [0x0, ['unsigned short']],
            'MessageCount': [0x2, ['unsigned short']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_218c': [
        0xC,
        {
            'Raw': [0x0, ['__unnamed_218a']],
            'Translated': [0x0, ['__unnamed_2188']],
        },
    ],
    '__unnamed_218e': [
        0xC,
        {
            'Channel': [0x0, ['unsigned long']],
            'Port': [0x4, ['unsigned long']],
            'Reserved1': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2190': [
        0xC,
        {
            'Channel': [0x0, ['unsigned long']],
            'RequestLine': [0x4, ['unsigned long']],
            'TransferWidth': [0x8, ['unsigned char']],
            'Reserved1': [0x9, ['unsigned char']],
            'Reserved2': [0xA, ['unsigned char']],
            'Reserved3': [0xB, ['unsigned char']],
        },
    ],
    '__unnamed_2192': [
        0xC,
        {
            'Start': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2194': [
        0xC,
        {
            'DataSize': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2196': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length40': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2198': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length48': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_219a': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length64': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_219c': [
        0xC,
        {
            'Generic': [0x0, ['__unnamed_2186']],
            'Port': [0x0, ['__unnamed_2186']],
            'Interrupt': [0x0, ['__unnamed_2188']],
            'MessageInterrupt': [0x0, ['__unnamed_218c']],
            'Memory': [0x0, ['__unnamed_2186']],
            'Dma': [0x0, ['__unnamed_218e']],
            'DmaV3': [0x0, ['__unnamed_2190']],
            'DevicePrivate': [0x0, ['__unnamed_2032']],
            'BusNumber': [0x0, ['__unnamed_2192']],
            'DeviceSpecificData': [0x0, ['__unnamed_2194']],
            'Memory40': [0x0, ['__unnamed_2196']],
            'Memory48': [0x0, ['__unnamed_2198']],
            'Memory64': [0x0, ['__unnamed_219a']],
            'Connection': [0x0, ['__unnamed_203e']],
        },
    ],
    '_CM_PARTIAL_RESOURCE_DESCRIPTOR': [
        0x10,
        {
            'Type': [0x0, ['unsigned char']],
            'ShareDisposition': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned short']],
            'u': [0x4, ['__unnamed_219c']],
        },
    ],
    '_OBJECT_HEADER_PADDING_INFO': [
        0x4,
        {
            'PaddingAmount': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_21a4': [
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
            'Misc': [0x8, ['__unnamed_21a4']],
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
        0x4,
        {
            'ReserveDevice': [0x0, ['pointer', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_21ae': [
        0x50,
        {
            'CellData': [0x0, ['_CELL_DATA']],
            'List': [0x0, ['array', 1, ['unsigned long']]],
        },
    ],
    '_CM_CACHED_VALUE_INDEX': [
        0x54,
        {
            'CellIndex': [0x0, ['unsigned long']],
            'Data': [0x4, ['__unnamed_21ae']],
        },
    ],
    '_DBGKD_QUERY_SPECIAL_CALLS': [
        0x4,
        {
            'NumberOfSpecialCalls': [0x0, ['unsigned long']],
        },
    ],
    '_VF_AVL_TREE_NODE': [
        0x8,
        {
            'p': [0x0, ['pointer', ['void']]],
            'RangeSize': [0x4, ['unsigned long']],
        },
    ],
    '_POP_FX_DEVICE': [
        0x140,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'Irp': [0x8, ['pointer', ['_IRP']]],
            'IrpData': [0xC, ['pointer', ['_POP_IRP_DATA']]],
            'Status': [0x10, ['_POP_FX_DEVICE_STATUS']],
            'PowerReqCall': [0x14, ['long']],
            'PowerNotReqCall': [0x18, ['long']],
            'Plugin': [0x1C, ['pointer', ['_POP_FX_PLUGIN']]],
            'PluginHandle': [0x20, ['pointer', ['PEPHANDLE__']]],
            'MiniPlugin': [0x24, ['pointer', ['_POP_FX_PLUGIN']]],
            'MiniPluginHandle': [0x28, ['pointer', ['PEPHANDLE__']]],
            'DevNode': [0x2C, ['pointer', ['_DEVICE_NODE']]],
            'DeviceObject': [0x30, ['pointer', ['_DEVICE_OBJECT']]],
            'TargetDevice': [0x34, ['pointer', ['_DEVICE_OBJECT']]],
            'Callbacks': [0x38, ['_POP_FX_DRIVER_CALLBACKS']],
            'DriverContext': [0x54, ['pointer', ['void']]],
            'RemoveLock': [0x58, ['_IO_REMOVE_LOCK']],
            'WorkOrder': [0x70, ['_POP_FX_WORK_ORDER']],
            'IdleLock': [0x8C, ['unsigned long']],
            'IdleTimer': [0x90, ['_KTIMER']],
            'IdleDpc': [0xB8, ['_KDPC']],
            'IdleTimeout': [0xD8, ['unsigned long long']],
            'IdleStamp': [0xE0, ['unsigned long long']],
            'NextIrpDeviceObject': [0xE8, ['pointer', ['_DEVICE_OBJECT']]],
            'NextIrpPowerState': [0xEC, ['_POWER_STATE']],
            'NextIrpCallerCompletion': [0xF0, ['pointer', ['void']]],
            'NextIrpCallerContext': [0xF4, ['pointer', ['void']]],
            'IrpCompleteEvent': [0xF8, ['_KEVENT']],
            'PowerOnDumpDeviceCallback': [0x108, ['pointer', ['void']]],
            'Accounting': [0x110, ['_POP_FX_ACCOUNTING']],
            'ComponentCount': [0x138, ['unsigned long']],
            'Components': [
                0x13C,
                ['array', 1, ['pointer', ['_POP_FX_COMPONENT']]],
            ],
        },
    ],
    '__unnamed_21c7': [
        0x8,
        {
            'IdleTime': [0x0, ['unsigned long']],
            'NonIdleTime': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_21c9': [
        0x8,
        {
            'Disk': [0x0, ['__unnamed_21c7']],
        },
    ],
    '_DEVICE_OBJECT_POWER_EXTENSION': [
        0x40,
        {
            'IdleCount': [0x0, ['unsigned long']],
            'BusyCount': [0x4, ['unsigned long']],
            'BusyReference': [0x8, ['unsigned long']],
            'TotalBusyCount': [0xC, ['unsigned long']],
            'ConservationIdleTime': [0x10, ['unsigned long']],
            'PerformanceIdleTime': [0x14, ['unsigned long']],
            'DeviceObject': [0x18, ['pointer', ['_DEVICE_OBJECT']]],
            'IdleList': [0x1C, ['_LIST_ENTRY']],
            'IdleType': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'DeviceIdleNormal', 1: 'DeviceIdleDisk'},
                    ),
                ],
            ],
            'IdleState': [
                0x28,
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
                0x2C,
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
            'Volume': [0x30, ['_LIST_ENTRY']],
            'Specific': [0x38, ['__unnamed_21c9']],
        },
    ],
    '_ARBITER_RETEST_ALLOCATION_PARAMETERS': [
        0xC,
        {
            'ArbitrationList': [0x0, ['pointer', ['_LIST_ENTRY']]],
            'AllocateFromCount': [0x4, ['unsigned long']],
            'AllocateFrom': [
                0x8,
                ['pointer', ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
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
    '_MI_TRIAGE_DUMP_DATA': [
        0x30,
        {
            'BadPageCount': [0x0, ['unsigned long']],
            'BadPagesDetected': [0x4, ['long']],
            'ZeroedPageSingleBitErrorsDetected': [0x8, ['long']],
            'ScrubPasses': [0xC, ['long']],
            'ScrubBadPagesFound': [0x10, ['long']],
            'FeatureBits': [0x18, ['unsigned long long']],
            'TimeZoneId': [0x20, ['unsigned long']],
            'ExceptionChainTerminator': [
                0x24,
                ['pointer', ['_EXCEPTION_REGISTRATION_RECORD']],
            ],
            'ExceptionChainTerminatorRecord': [
                0x28,
                ['_EXCEPTION_REGISTRATION_RECORD'],
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
        0x38,
        {
            'SizeOfFsFilterCallbacks': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'PreAcquireForSectionSynchronization': [
                0x8,
                ['pointer', ['void']],
            ],
            'PostAcquireForSectionSynchronization': [
                0xC,
                ['pointer', ['void']],
            ],
            'PreReleaseForSectionSynchronization': [
                0x10,
                ['pointer', ['void']],
            ],
            'PostReleaseForSectionSynchronization': [
                0x14,
                ['pointer', ['void']],
            ],
            'PreAcquireForCcFlush': [0x18, ['pointer', ['void']]],
            'PostAcquireForCcFlush': [0x1C, ['pointer', ['void']]],
            'PreReleaseForCcFlush': [0x20, ['pointer', ['void']]],
            'PostReleaseForCcFlush': [0x24, ['pointer', ['void']]],
            'PreAcquireForModifiedPageWriter': [0x28, ['pointer', ['void']]],
            'PostAcquireForModifiedPageWriter': [0x2C, ['pointer', ['void']]],
            'PreReleaseForModifiedPageWriter': [0x30, ['pointer', ['void']]],
            'PostReleaseForModifiedPageWriter': [0x34, ['pointer', ['void']]],
        },
    ],
    '_KENLISTMENT': [
        0x168,
        {
            'cookie': [0x0, ['unsigned long']],
            'NamespaceLink': [0x4, ['_KTMOBJECT_NAMESPACE_LINK']],
            'EnlistmentId': [0x18, ['_GUID']],
            'Mutex': [0x28, ['_KMUTANT']],
            'NextSameTx': [0x48, ['_LIST_ENTRY']],
            'NextSameRm': [0x50, ['_LIST_ENTRY']],
            'ResourceManager': [0x58, ['pointer', ['_KRESOURCEMANAGER']]],
            'Transaction': [0x5C, ['pointer', ['_KTRANSACTION']]],
            'State': [
                0x60,
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
            'Flags': [0x64, ['unsigned long']],
            'NotificationMask': [0x68, ['unsigned long']],
            'Key': [0x6C, ['pointer', ['void']]],
            'KeyRefCount': [0x70, ['unsigned long']],
            'RecoveryInformation': [0x74, ['pointer', ['void']]],
            'RecoveryInformationLength': [0x78, ['unsigned long']],
            'DynamicNameInformation': [0x7C, ['pointer', ['void']]],
            'DynamicNameInformationLength': [0x80, ['unsigned long']],
            'FinalNotification': [
                0x84,
                ['pointer', ['_KTMNOTIFICATION_PACKET']],
            ],
            'SupSubEnlistment': [0x88, ['pointer', ['_KENLISTMENT']]],
            'SupSubEnlHandle': [0x8C, ['pointer', ['void']]],
            'SubordinateTxHandle': [0x90, ['pointer', ['void']]],
            'CrmEnlistmentEnId': [0x94, ['_GUID']],
            'CrmEnlistmentTmId': [0xA4, ['_GUID']],
            'CrmEnlistmentRmId': [0xB4, ['_GUID']],
            'NextHistory': [0xC4, ['unsigned long']],
            'History': [0xC8, ['array', 20, ['_KENLISTMENT_HISTORY']]],
        },
    ],
    '_ARBITER_INTERFACE': [
        0x18,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x4, ['pointer', ['void']]],
            'InterfaceReference': [0x8, ['pointer', ['void']]],
            'InterfaceDereference': [0xC, ['pointer', ['void']]],
            'ArbiterHandler': [0x10, ['pointer', ['void']]],
            'Flags': [0x14, ['unsigned long']],
        },
    ],
    '_KAPC_STATE': [
        0x18,
        {
            'ApcListHead': [0x0, ['array', 2, ['_LIST_ENTRY']]],
            'Process': [0x10, ['pointer', ['_KPROCESS']]],
            'InProgressFlags': [0x14, ['unsigned char']],
            'KernelApcInProgress': [
                0x14,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'SpecialApcInProgress': [
                0x14,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'KernelApcPending': [0x15, ['unsigned char']],
            'UserApcPending': [0x16, ['unsigned char']],
        },
    ],
    '_DELAY_ACK_FO': [
        0xC,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'OriginalFileObject': [0x8, ['pointer', ['_FILE_OBJECT']]],
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
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'Objects': [0x4, ['array', 1, ['pointer', ['_DEVICE_OBJECT']]]],
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
        0x180,
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
            'State': [0x40, ['_ALPC_COMPLETION_LIST_STATE']],
            'LastMessageId': [0x48, ['unsigned long']],
            'LastCallbackId': [0x4C, ['unsigned long']],
            'PostCount': [0x80, ['unsigned long']],
            'ReturnCount': [0xC0, ['unsigned long']],
            'LogSequenceNumber': [0x100, ['unsigned long']],
            'UserLock': [0x140, ['_RTL_SRWLOCK']],
            'EndMagic': [0x148, ['unsigned long long']],
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
    '_WHEA_AER_ENDPOINT_DESCRIPTOR': [
        0x20,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
            'BusNumber': [0x4, ['unsigned long']],
            'Slot': [0x8, ['_WHEA_PCI_SLOT_NUMBER']],
            'DeviceControl': [0xC, ['unsigned short']],
            'Flags': [0xE, ['_AER_ENDPOINT_DESCRIPTOR_FLAGS']],
            'UncorrectableErrorMask': [0x10, ['unsigned long']],
            'UncorrectableErrorSeverity': [0x14, ['unsigned long']],
            'CorrectableErrorMask': [0x18, ['unsigned long']],
            'AdvancedCapsAndControl': [0x1C, ['unsigned long']],
        },
    ],
    '_ETW_WMITRACE_WORK': [
        0xF0,
        {
            'LoggerId': [0x0, ['unsigned long']],
            'SpareUlong': [0x4, ['unsigned long']],
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
        0x34,
        {
            'DosDevicesDirectory': [0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
            'GlobalDosDevicesDirectory': [
                0x4,
                ['pointer', ['_OBJECT_DIRECTORY']],
            ],
            'DosDevicesDirectoryHandle': [0x8, ['pointer', ['void']]],
            'ReferenceCount': [0xC, ['long']],
            'DriveMap': [0x10, ['unsigned long']],
            'DriveType': [0x14, ['array', 32, ['unsigned char']]],
        },
    ],
    '_CHILD_LIST': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['unsigned long']],
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
    '_ARMCE_DBGKD_CONTROL_SET': [
        0xC,
        {
            'Continue': [0x0, ['unsigned long']],
            'CurrentSymbolStart': [0x4, ['unsigned long']],
            'CurrentSymbolEnd': [0x8, ['unsigned long']],
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
    '_RTL_CRITICAL_SECTION': [
        0x18,
        {
            'DebugInfo': [0x0, ['pointer', ['_RTL_CRITICAL_SECTION_DEBUG']]],
            'LockCount': [0x4, ['long']],
            'RecursionCount': [0x8, ['long']],
            'OwningThread': [0xC, ['pointer', ['void']]],
            'LockSemaphore': [0x10, ['pointer', ['void']]],
            'SpinCount': [0x14, ['unsigned long']],
        },
    ],
    '_PNP_DEVICE_COMPLETION_REQUEST': [
        0x24,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'DeviceNode': [0x8, ['pointer', ['_DEVICE_NODE']]],
            'Context': [0xC, ['pointer', ['void']]],
            'CompletionState': [
                0x10,
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
            'IrpPended': [0x14, ['unsigned long']],
            'Status': [0x18, ['long']],
            'Information': [0x1C, ['pointer', ['void']]],
            'ReferenceCount': [0x20, ['long']],
        },
    ],
    '__unnamed_2230': [
        0x8,
        {
            'Start': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2232': [
        0x8,
        {
            'RangeCount': [0x0, ['unsigned long']],
            'SetBitCount': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2234': [
        0x8,
        {
            'Context1': [0x0, ['unsigned long']],
            'Context2': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_2236': [
        0x8,
        {
            'DirtyVectorModifiedContext': [0x0, ['__unnamed_2230']],
            'DirtyDataCaptureContext': [0x0, ['__unnamed_2232']],
            'Raw': [0x0, ['__unnamed_2234']],
        },
    ],
    '_CM_DIRTY_VECTOR_LOG_ENTRY': [
        0x2C,
        {
            'Thread': [0x0, ['pointer', ['_ETHREAD']]],
            'Operation': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DirtyVectorModified',
                            1: 'DirtyDataCaptureStart',
                            2: 'DirtyDataCaptureEnd',
                        },
                    ),
                ],
            ],
            'Data': [0x8, ['__unnamed_2236']],
            'Stack': [0x10, ['array', 7, ['pointer', ['void']]]],
        },
    ],
    '_KTRAP_FRAME': [
        0x8C,
        {
            'DbgEbp': [0x0, ['unsigned long']],
            'DbgEip': [0x4, ['unsigned long']],
            'DbgArgMark': [0x8, ['unsigned long']],
            'TempSegCs': [0xC, ['unsigned short']],
            'Logging': [0xE, ['unsigned char']],
            'FrameType': [0xF, ['unsigned char']],
            'TempEsp': [0x10, ['unsigned long']],
            'Dr0': [0x14, ['unsigned long']],
            'Dr1': [0x18, ['unsigned long']],
            'Dr2': [0x1C, ['unsigned long']],
            'Dr3': [0x20, ['unsigned long']],
            'Dr6': [0x24, ['unsigned long']],
            'Dr7': [0x28, ['unsigned long']],
            'SegGs': [0x2C, ['unsigned long']],
            'SegEs': [0x30, ['unsigned long']],
            'SegDs': [0x34, ['unsigned long']],
            'Edx': [0x38, ['unsigned long']],
            'Ecx': [0x3C, ['unsigned long']],
            'Eax': [0x40, ['unsigned long']],
            'PreviousPreviousMode': [0x44, ['unsigned char']],
            'EntropyQueueDpc': [0x45, ['unsigned char']],
            'Reserved': [0x46, ['array', 2, ['unsigned char']]],
            'MxCsr': [0x48, ['unsigned long']],
            'ExceptionList': [
                0x4C,
                ['pointer', ['_EXCEPTION_REGISTRATION_RECORD']],
            ],
            'SegFs': [0x50, ['unsigned long']],
            'Edi': [0x54, ['unsigned long']],
            'Esi': [0x58, ['unsigned long']],
            'Ebx': [0x5C, ['unsigned long']],
            'Ebp': [0x60, ['unsigned long']],
            'ErrCode': [0x64, ['unsigned long']],
            'Eip': [0x68, ['unsigned long']],
            'SegCs': [0x6C, ['unsigned long']],
            'EFlags': [0x70, ['unsigned long']],
            'HardwareEsp': [0x74, ['unsigned long']],
            'HardwareSegSs': [0x78, ['unsigned long']],
            'V86Es': [0x7C, ['unsigned long']],
            'V86Ds': [0x80, ['unsigned long']],
            'V86Fs': [0x84, ['unsigned long']],
            'V86Gs': [0x88, ['unsigned long']],
        },
    ],
    '__unnamed_223f': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'VadFlags': [0x0, ['_MMVAD_FLAGS']],
        },
    ],
    '__unnamed_2242': [
        0x4,
        {
            'LongFlags1': [0x0, ['unsigned long']],
            'VadFlags1': [0x0, ['_MMVAD_FLAGS1']],
        },
    ],
    '_MMVAD_SHORT': [
        0x28,
        {
            'VadNode': [0x0, ['_RTL_BALANCED_NODE']],
            'NextVad': [0x0, ['pointer', ['_MMVAD_SHORT']]],
            'StartingVpn': [0xC, ['unsigned long']],
            'EndingVpn': [0x10, ['unsigned long']],
            'ReferenceCount': [0x14, ['long']],
            'PushLock': [0x18, ['_EX_PUSH_LOCK']],
            'u': [0x1C, ['__unnamed_223f']],
            'u1': [0x20, ['__unnamed_2242']],
            'EventList': [0x24, ['pointer', ['_MI_VAD_EVENT_BLOCK']]],
        },
    ],
    '_KLOCK_ENTRY_LOCK_STATE': [
        0x8,
        {
            'Waiting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Busy': [
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
                    dict(start_bit=2, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'InTree': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'LockState': [0x0, ['pointer', ['void']]],
            'SessionState': [0x4, ['pointer', ['void']]],
            'SessionId': [0x4, ['unsigned long']],
        },
    ],
    '_WAIT_CONTEXT_BLOCK': [
        0x28,
        {
            'WaitQueueEntry': [0x0, ['_KDEVICE_QUEUE_ENTRY']],
            'DmaWaitEntry': [0x0, ['_LIST_ENTRY']],
            'NumberOfChannels': [0x8, ['unsigned long']],
            'SyncCallback': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DmaContext': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'DeviceRoutine': [0x10, ['pointer', ['void']]],
            'DeviceContext': [0x14, ['pointer', ['void']]],
            'NumberOfMapRegisters': [0x18, ['unsigned long']],
            'DeviceObject': [0x1C, ['pointer', ['void']]],
            'CurrentIrp': [0x20, ['pointer', ['void']]],
            'BufferChainingDpc': [0x24, ['pointer', ['_KDPC']]],
        },
    ],
    '_SECTION_OBJECT': [
        0x18,
        {
            'StartingVa': [0x0, ['pointer', ['void']]],
            'EndingVa': [0x4, ['pointer', ['void']]],
            'Parent': [0x8, ['pointer', ['void']]],
            'LeftChild': [0xC, ['pointer', ['void']]],
            'RightChild': [0x10, ['pointer', ['void']]],
            'Segment': [0x14, ['pointer', ['_SEGMENT_OBJECT']]],
        },
    ],
    '_CM_NAME_CONTROL_BLOCK': [
        0x10,
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
            'NameHash': [0x4, ['_CM_NAME_HASH']],
            'ConvKey': [0x4, ['unsigned long']],
            'NextHash': [0x8, ['pointer', ['_CM_KEY_HASH']]],
            'NameLength': [0xC, ['unsigned short']],
            'Name': [0xE, ['array', 1, ['wchar']]],
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
            'LastReorganizeTime': [0xA8, ['unsigned long long']],
            'Reserved1': [0xB0, ['array', 83, ['unsigned long']]],
            'CheckSum': [0x1FC, ['unsigned long']],
            'Reserved2': [0x200, ['array', 882, ['unsigned long']]],
            'ThawTmId': [0xFC8, ['_GUID']],
            'ThawRmId': [0xFD8, ['_GUID']],
            'ThawLogId': [0xFE8, ['_GUID']],
            'BootType': [0xFF8, ['unsigned long']],
            'BootRecover': [0xFFC, ['unsigned long']],
        },
    ],
    '_GENERAL_LOOKASIDE_POOL': [
        0x48,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
            'SingleListHead': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Depth': [0x8, ['unsigned short']],
            'MaximumDepth': [0xA, ['unsigned short']],
            'TotalAllocates': [0xC, ['unsigned long']],
            'AllocateMisses': [0x10, ['unsigned long']],
            'AllocateHits': [0x10, ['unsigned long']],
            'TotalFrees': [0x14, ['unsigned long']],
            'FreeMisses': [0x18, ['unsigned long']],
            'FreeHits': [0x18, ['unsigned long']],
            'Type': [
                0x1C,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'NonPagedPoolBase',
                            1: 'PagedPool',
                            2: 'NonPagedPoolBaseMustSucceed',
                            3: 'DontUseThisType',
                            4: 'NonPagedPoolBaseCacheAligned',
                            5: 'PagedPoolCacheAligned',
                            6: 'NonPagedPoolBaseCacheAlignedMustS',
                            7: 'MaxPoolType',
                            34: 'NonPagedPoolMustSucceedSession',
                            516: 'NonPagedPoolNxCacheAligned',
                            35: 'DontUseThisTypeSession',
                            32: 'NonPagedPoolSession',
                            512: 'NonPagedPoolNx',
                            544: 'NonPagedPoolSessionNx',
                            36: 'NonPagedPoolCacheAlignedSession',
                            33: 'PagedPoolSession',
                            38: 'NonPagedPoolCacheAlignedMustSSession',
                            37: 'PagedPoolCacheAlignedSession',
                        },
                    ),
                ],
            ],
            'Tag': [0x20, ['unsigned long']],
            'Size': [0x24, ['unsigned long']],
            'AllocateEx': [0x28, ['pointer', ['void']]],
            'Allocate': [0x28, ['pointer', ['void']]],
            'FreeEx': [0x2C, ['pointer', ['void']]],
            'Free': [0x2C, ['pointer', ['void']]],
            'ListEntry': [0x30, ['_LIST_ENTRY']],
            'LastTotalAllocates': [0x38, ['unsigned long']],
            'LastAllocateMisses': [0x3C, ['unsigned long']],
            'LastAllocateHits': [0x3C, ['unsigned long']],
            'Future': [0x40, ['array', 2, ['unsigned long']]],
        },
    ],
    '_RTL_DYNAMIC_HASH_TABLE_ENTRY': [
        0xC,
        {
            'Linkage': [0x0, ['_LIST_ENTRY']],
            'Signature': [0x8, ['unsigned long']],
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
        0x30,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
            'Depth': [0x8, ['unsigned short']],
            'MaximumDepth': [0xA, ['unsigned short']],
            'TotalAllocates': [0xC, ['unsigned long']],
            'AllocateMisses': [0x10, ['unsigned long']],
            'TotalFrees': [0x14, ['unsigned long']],
            'FreeMisses': [0x18, ['unsigned long']],
            'LastTotalAllocates': [0x1C, ['unsigned long']],
            'LastAllocateMisses': [0x20, ['unsigned long']],
            'Counters': [0x24, ['array', 2, ['unsigned long']]],
        },
    ],
    '_KTIMER': [
        0x28,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'DueTime': [0x10, ['_ULARGE_INTEGER']],
            'TimerListEntry': [0x18, ['_LIST_ENTRY']],
            'Dpc': [0x20, ['pointer', ['_KDPC']]],
            'Period': [0x24, ['unsigned long']],
        },
    ],
    '_RTL_ATOM_TABLE': [
        0x1C,
        {
            'Signature': [0x0, ['unsigned long']],
            'ReferenceCount': [0x4, ['long']],
            'PushLock': [0x8, ['_EX_PUSH_LOCK']],
            'ExHandleTable': [0xC, ['pointer', ['_HANDLE_TABLE']]],
            'Flags': [0x10, ['unsigned long']],
            'NumberOfBuckets': [0x14, ['unsigned long']],
            'Buckets': [
                0x18,
                ['array', 1, ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]],
            ],
        },
    ],
    '__unnamed_2283': [
        0x10,
        {
            'ProgrammedTime': [0x0, ['unsigned long long']],
            'TimerInfo': [0x8, ['pointer', ['_DIAGNOSTIC_BUFFER']]],
        },
    ],
    '_POP_POWER_ACTION': [
        0xD8,
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
                            8: 'PolicyDeviceWakeAlarm',
                            9: 'PolicyDeviceFan',
                            10: 'PolicyCsBatterySaver',
                            11: 'PolicyDeviceMax',
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
                ['pointer', ['_POP_SHUTDOWN_BUG_CHECK']],
            ],
            'DevState': [0x34, ['pointer', ['_POP_DEVICE_SYS_STATE']]],
            'HiberContext': [0x38, ['pointer', ['_POP_HIBER_CONTEXT']]],
            'WakeTime': [0x40, ['unsigned long long']],
            'SleepTime': [0x48, ['unsigned long long']],
            'WakeAlarmSignaled': [
                0x50,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PoAc',
                            1: 'PoDc',
                            2: 'PoHot',
                            3: 'PoConditionMaximum',
                        },
                    ),
                ],
            ],
            'WakeAlarm': [0x58, ['array', 3, ['__unnamed_2283']]],
            'FilteredCapabilities': [0x88, ['SYSTEM_POWER_CAPABILITIES']],
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
    '_CM_KEY_HASH': [
        0x10,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x4, ['pointer', ['_CM_KEY_HASH']]],
            'KeyHive': [0x8, ['pointer', ['_HHIVE']]],
            'KeyCell': [0xC, ['unsigned long']],
        },
    ],
    '_WHEA_IPF_CMC_DESCRIPTOR': [
        0x4,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
        },
    ],
    '_PROCESSOR_IDLE_DEPENDENCY': [
        0x8,
        {
            'ProcessorIndex': [0x0, ['unsigned long']],
            'ExpectedState': [0x4, ['unsigned char']],
            'AllowDeeperStates': [0x5, ['unsigned char']],
            'LooseDependency': [0x6, ['unsigned char']],
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
        0x3C,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'PowerChildren': [0x8, ['_LIST_ENTRY']],
            'PowerParents': [0x10, ['_LIST_ENTRY']],
            'TargetDevice': [0x18, ['pointer', ['_DEVICE_OBJECT']]],
            'OrderLevel': [0x1C, ['unsigned char']],
            'DeviceObject': [0x20, ['pointer', ['_DEVICE_OBJECT']]],
            'DeviceName': [0x24, ['pointer', ['unsigned short']]],
            'DriverName': [0x28, ['pointer', ['unsigned short']]],
            'ChildCount': [0x2C, ['unsigned long']],
            'ActiveChild': [0x30, ['unsigned long']],
            'ParentCount': [0x34, ['unsigned long']],
            'ActiveParent': [0x38, ['unsigned long']],
        },
    ],
    '_CM_KEY_SECURITY_CACHE_ENTRY': [
        0x8,
        {
            'Cell': [0x0, ['unsigned long']],
            'CachedSecurity': [0x4, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
        },
    ],
    '_FS_FILTER_CALLBACK_DATA': [
        0x24,
        {
            'SizeOfFsFilterCallbackData': [0x0, ['unsigned long']],
            'Operation': [0x4, ['unsigned char']],
            'Reserved': [0x5, ['unsigned char']],
            'DeviceObject': [0x8, ['pointer', ['_DEVICE_OBJECT']]],
            'FileObject': [0xC, ['pointer', ['_FILE_OBJECT']]],
            'Parameters': [0x10, ['_FS_FILTER_PARAMETERS']],
        },
    ],
    '_GDI_TEB_BATCH32': [
        0x4E0,
        {
            'Offset': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'HasRenderingCommand': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'HDC': [0x4, ['unsigned long']],
            'Buffer': [0x8, ['array', 310, ['unsigned long']]],
        },
    ],
    '_WHEA_AER_ROOTPORT_DESCRIPTOR': [
        0x24,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
            'BusNumber': [0x4, ['unsigned long']],
            'Slot': [0x8, ['_WHEA_PCI_SLOT_NUMBER']],
            'DeviceControl': [0xC, ['unsigned short']],
            'Flags': [0xE, ['_AER_ROOTPORT_DESCRIPTOR_FLAGS']],
            'UncorrectableErrorMask': [0x10, ['unsigned long']],
            'UncorrectableErrorSeverity': [0x14, ['unsigned long']],
            'CorrectableErrorMask': [0x18, ['unsigned long']],
            'AdvancedCapsAndControl': [0x1C, ['unsigned long']],
            'RootErrorCommand': [0x20, ['unsigned long']],
        },
    ],
    '_PROC_IDLE_STATE_ACCOUNTING': [
        0x3D0,
        {
            'TotalTime': [0x0, ['unsigned long long']],
            'CancelCount': [0x8, ['unsigned long']],
            'FailureCount': [0xC, ['unsigned long']],
            'SuccessCount': [0x10, ['unsigned long']],
            'InvalidBucketIndex': [0x14, ['unsigned long']],
            'MinTime': [0x18, ['unsigned long long']],
            'MaxTime': [0x20, ['unsigned long long']],
            'SelectionStatistics': [0x28, ['_PPM_SELECTION_STATISTICS']],
            'IdleTimeBuckets': [
                0x90,
                ['array', 26, ['_PROC_IDLE_STATE_BUCKET']],
            ],
        },
    ],
    '_IMAGE_SECURITY_CONTEXT': [
        0x4,
        {
            'PageHashes': [0x0, ['pointer', ['void']]],
            'Value': [0x0, ['unsigned long']],
            'SecurityBeingCreated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SecurityMandatory': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'PageHashPointer': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
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
        0x70,
        {
            'SizeOfFastIoDispatch': [0x0, ['unsigned long']],
            'FastIoCheckIfPossible': [0x4, ['pointer', ['void']]],
            'FastIoRead': [0x8, ['pointer', ['void']]],
            'FastIoWrite': [0xC, ['pointer', ['void']]],
            'FastIoQueryBasicInfo': [0x10, ['pointer', ['void']]],
            'FastIoQueryStandardInfo': [0x14, ['pointer', ['void']]],
            'FastIoLock': [0x18, ['pointer', ['void']]],
            'FastIoUnlockSingle': [0x1C, ['pointer', ['void']]],
            'FastIoUnlockAll': [0x20, ['pointer', ['void']]],
            'FastIoUnlockAllByKey': [0x24, ['pointer', ['void']]],
            'FastIoDeviceControl': [0x28, ['pointer', ['void']]],
            'AcquireFileForNtCreateSection': [0x2C, ['pointer', ['void']]],
            'ReleaseFileForNtCreateSection': [0x30, ['pointer', ['void']]],
            'FastIoDetachDevice': [0x34, ['pointer', ['void']]],
            'FastIoQueryNetworkOpenInfo': [0x38, ['pointer', ['void']]],
            'AcquireForModWrite': [0x3C, ['pointer', ['void']]],
            'MdlRead': [0x40, ['pointer', ['void']]],
            'MdlReadComplete': [0x44, ['pointer', ['void']]],
            'PrepareMdlWrite': [0x48, ['pointer', ['void']]],
            'MdlWriteComplete': [0x4C, ['pointer', ['void']]],
            'FastIoReadCompressed': [0x50, ['pointer', ['void']]],
            'FastIoWriteCompressed': [0x54, ['pointer', ['void']]],
            'MdlReadCompleteCompressed': [0x58, ['pointer', ['void']]],
            'MdlWriteCompleteCompressed': [0x5C, ['pointer', ['void']]],
            'FastIoQueryOpen': [0x60, ['pointer', ['void']]],
            'ReleaseForModWrite': [0x64, ['pointer', ['void']]],
            'AcquireForCcFlush': [0x68, ['pointer', ['void']]],
            'ReleaseForCcFlush': [0x6C, ['pointer', ['void']]],
        },
    ],
    '_PERFINFO_PPM_STATE_SELECTION': [
        0xC,
        {
            'SelectedState': [0x0, ['unsigned long']],
            'VetoedStates': [0x4, ['unsigned long']],
            'VetoReason': [0x8, ['array', 1, ['unsigned long']]],
        },
    ],
    '_CM_CELL_REMAP_BLOCK': [
        0x8,
        {
            'OldCell': [0x0, ['unsigned long']],
            'NewCell': [0x4, ['unsigned long']],
        },
    ],
    '_PI_RESOURCE_ARBITER_ENTRY': [
        0x38,
        {
            'DeviceArbiterList': [0x0, ['_LIST_ENTRY']],
            'ResourceType': [0x8, ['unsigned char']],
            'ArbiterInterface': [0xC, ['pointer', ['_ARBITER_INTERFACE']]],
            'DeviceNode': [0x10, ['pointer', ['_DEVICE_NODE']]],
            'ResourceList': [0x14, ['_LIST_ENTRY']],
            'BestResourceList': [0x1C, ['_LIST_ENTRY']],
            'BestConfig': [0x24, ['_LIST_ENTRY']],
            'ActiveArbiterList': [0x2C, ['_LIST_ENTRY']],
            'State': [0x34, ['unsigned char']],
            'ResourcesChanged': [0x35, ['unsigned char']],
        },
    ],
    '_SECURITY_DESCRIPTOR': [
        0x14,
        {
            'Revision': [0x0, ['unsigned char']],
            'Sbz1': [0x1, ['unsigned char']],
            'Control': [0x2, ['unsigned short']],
            'Owner': [0x4, ['pointer', ['void']]],
            'Group': [0x8, ['pointer', ['void']]],
            'Sacl': [0xC, ['pointer', ['_ACL']]],
            'Dacl': [0x10, ['pointer', ['_ACL']]],
        },
    ],
    '_MODWRITER_FLAGS': [
        0x4,
        {
            'KeepForever': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Networked': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'IoPriority': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ModifiedStoreWrite': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_KQUEUE': [
        0x28,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'EntryListHead': [0x10, ['_LIST_ENTRY']],
            'CurrentCount': [0x18, ['unsigned long']],
            'MaximumCount': [0x1C, ['unsigned long']],
            'ThreadListHead': [0x20, ['_LIST_ENTRY']],
        },
    ],
    '_RTL_USER_PROCESS_PARAMETERS': [
        0x2A0,
        {
            'MaximumLength': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Flags': [0x8, ['unsigned long']],
            'DebugFlags': [0xC, ['unsigned long']],
            'ConsoleHandle': [0x10, ['pointer', ['void']]],
            'ConsoleFlags': [0x14, ['unsigned long']],
            'StandardInput': [0x18, ['pointer', ['void']]],
            'StandardOutput': [0x1C, ['pointer', ['void']]],
            'StandardError': [0x20, ['pointer', ['void']]],
            'CurrentDirectory': [0x24, ['_CURDIR']],
            'DllPath': [0x30, ['_UNICODE_STRING']],
            'ImagePathName': [0x38, ['_UNICODE_STRING']],
            'CommandLine': [0x40, ['_UNICODE_STRING']],
            'Environment': [0x48, ['pointer', ['void']]],
            'StartingX': [0x4C, ['unsigned long']],
            'StartingY': [0x50, ['unsigned long']],
            'CountX': [0x54, ['unsigned long']],
            'CountY': [0x58, ['unsigned long']],
            'CountCharsX': [0x5C, ['unsigned long']],
            'CountCharsY': [0x60, ['unsigned long']],
            'FillAttribute': [0x64, ['unsigned long']],
            'WindowFlags': [0x68, ['unsigned long']],
            'ShowWindowFlags': [0x6C, ['unsigned long']],
            'WindowTitle': [0x70, ['_UNICODE_STRING']],
            'DesktopInfo': [0x78, ['_UNICODE_STRING']],
            'ShellInfo': [0x80, ['_UNICODE_STRING']],
            'RuntimeData': [0x88, ['_UNICODE_STRING']],
            'CurrentDirectores': [
                0x90,
                ['array', 32, ['_RTL_DRIVE_LETTER_CURDIR']],
            ],
            'EnvironmentSize': [0x290, ['unsigned long']],
            'EnvironmentVersion': [0x294, ['unsigned long']],
            'PackageDependencyData': [0x298, ['pointer', ['void']]],
            'ProcessGroupId': [0x29C, ['unsigned long']],
        },
    ],
    '_PHYSICAL_MEMORY_RUN': [
        0x8,
        {
            'BasePage': [0x0, ['unsigned long']],
            'PageCount': [0x4, ['unsigned long']],
        },
    ],
    '_RTL_SRWLOCK': [
        0x4,
        {
            'Locked': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Waiting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Waking': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'MultipleShared': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Shared': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'Value': [0x0, ['unsigned long']],
            'Ptr': [0x0, ['pointer', ['void']]],
        },
    ],
    '_KTMOBJECT_NAMESPACE_LINK': [
        0x14,
        {
            'Links': [0x0, ['_RTL_BALANCED_LINKS']],
            'Expired': [0x10, ['unsigned char']],
        },
    ],
    '_CACHE_MANAGER_CALLBACKS': [
        0x10,
        {
            'AcquireForLazyWrite': [0x0, ['pointer', ['void']]],
            'ReleaseFromLazyWrite': [0x4, ['pointer', ['void']]],
            'AcquireForReadAhead': [0x8, ['pointer', ['void']]],
            'ReleaseFromReadAhead': [0xC, ['pointer', ['void']]],
        },
    ],
    '_PROC_PERF_LOAD': [
        0x2,
        {
            'BusyPercentage': [0x0, ['unsigned char']],
            'FrequencyPercentage': [0x1, ['unsigned char']],
        },
    ],
    '_RTL_RANGE': [
        0x20,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
            'UserData': [0x10, ['pointer', ['void']]],
            'Owner': [0x14, ['pointer', ['void']]],
            'Attributes': [0x18, ['unsigned char']],
            'Flags': [0x19, ['unsigned char']],
        },
    ],
    '_LOCK_HEADER': [
        0x10,
        {
            'LockTree': [0x0, ['_RTL_AVL_TREE']],
            'Count': [0x4, ['unsigned long']],
            'Lock': [0x8, ['unsigned long']],
            'Valid': [0xC, ['unsigned long']],
        },
    ],
    '_WHEA_IPF_MCA_DESCRIPTOR': [
        0x4,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
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
        0x8,
        {
            'PreviousSize': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=9, native_type='unsigned short'),
                ],
            ],
            'PoolIndex': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'BlockSize': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=9, native_type='unsigned short'),
                ],
            ],
            'PoolType': [
                0x2,
                [
                    'BitField',
                    dict(
                        start_bit=9, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'Ulong1': [0x0, ['unsigned long']],
            'PoolTag': [0x4, ['unsigned long']],
            'AllocatorBackTraceIndex': [0x4, ['unsigned short']],
            'PoolTagHash': [0x6, ['unsigned short']],
        },
    ],
    '_SE_AUDIT_PROCESS_CREATION_INFO': [
        0x4,
        {
            'ImageFileName': [0x0, ['pointer', ['_OBJECT_NAME_INFORMATION']]],
        },
    ],
    '_HEAP_ENTRY_EXTRA': [
        0x8,
        {
            'AllocatorBackTraceIndex': [0x0, ['unsigned short']],
            'TagIndex': [0x2, ['unsigned short']],
            'Settable': [0x4, ['unsigned long']],
            'ZeroInit': [0x0, ['unsigned long long']],
        },
    ],
    '_VF_POOL_TRACE': [
        0x40,
        {
            'Address': [0x0, ['pointer', ['void']]],
            'Size': [0x4, ['unsigned long']],
            'Thread': [0x8, ['pointer', ['_ETHREAD']]],
            'StackTrace': [0xC, ['array', 13, ['pointer', ['void']]]],
        },
    ],
    '__unnamed_232f': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MM_SESSION_SPACE_FLAGS']],
        },
    ],
    '_MM_SESSION_SPACE': [
        0x2040,
        {
            'ReferenceCount': [0x0, ['long']],
            'u': [0x4, ['__unnamed_232f']],
            'SessionId': [0x8, ['unsigned long']],
            'ProcessReferenceToSession': [0xC, ['long']],
            'ProcessList': [0x10, ['_LIST_ENTRY']],
            'SessionPageDirectoryIndex': [0x18, ['unsigned long']],
            'NonPagablePages': [0x1C, ['unsigned long']],
            'CommittedPages': [0x20, ['unsigned long']],
            'PagedPoolStart': [0x24, ['pointer', ['void']]],
            'PagedPoolEnd': [0x28, ['pointer', ['void']]],
            'SessionObject': [0x2C, ['pointer', ['void']]],
            'SessionObjectHandle': [0x30, ['pointer', ['void']]],
            'SessionPoolAllocationFailures': [
                0x34,
                ['array', 4, ['unsigned long']],
            ],
            'ImageList': [0x44, ['_LIST_ENTRY']],
            'LocaleId': [0x4C, ['unsigned long']],
            'AttachCount': [0x50, ['unsigned long']],
            'AttachGate': [0x54, ['_KGATE']],
            'WsListEntry': [0x64, ['_LIST_ENTRY']],
            'Lookaside': [0x80, ['array', 24, ['_GENERAL_LOOKASIDE']]],
            'Session': [0xC80, ['_MMSESSION']],
            'PagedPoolInfo': [0xCB8, ['_MM_PAGED_POOL_INFO']],
            'Vm': [0xCF0, ['_MMSUPPORT']],
            'Wsle': [0xD68, ['pointer', ['_MMWSLE']]],
            'DriverUnload': [0xD6C, ['_MI_SESSION_DRIVER_UNLOAD']],
            'PagedPool': [0xD80, ['_POOL_DESCRIPTOR']],
            'PageTables': [0x1EC0, ['pointer', ['_MMPTE']]],
            'PagedPoolBitBuffer': [0x1EC4, ['array', 32, ['unsigned long']]],
            'SpecialPool': [0x1F48, ['_MI_SPECIAL_POOL']],
            'SessionPteLock': [0x1F90, ['_FAST_MUTEX']],
            'PoolBigEntriesInUse': [0x1FB0, ['long']],
            'PagedPoolPdeCount': [0x1FB4, ['unsigned long']],
            'SpecialPoolPdeCount': [0x1FB8, ['unsigned long']],
            'DynamicSessionPdeCount': [0x1FBC, ['unsigned long']],
            'SystemPteInfo': [0x1FC0, ['_MI_SYSTEM_PTE_TYPE']],
            'PoolTrackTableExpansion': [0x1FF8, ['pointer', ['void']]],
            'PoolTrackTableExpansionSize': [0x1FFC, ['unsigned long']],
            'PoolTrackBigPages': [0x2000, ['pointer', ['void']]],
            'PoolTrackBigPagesSize': [0x2004, ['unsigned long']],
            'IoState': [
                0x2008,
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
            'IoStateSequence': [0x200C, ['unsigned long']],
            'IoNotificationEvent': [0x2010, ['_KEVENT']],
        },
    ],
    '_WHEA_XPF_MC_BANK_DESCRIPTOR': [
        0x1C,
        {
            'BankNumber': [0x0, ['unsigned char']],
            'ClearOnInitialization': [0x1, ['unsigned char']],
            'StatusDataFormat': [0x2, ['unsigned char']],
            'Flags': [0x3, ['_XPF_MC_BANK_FLAGS']],
            'ControlMsr': [0x4, ['unsigned long']],
            'StatusMsr': [0x8, ['unsigned long']],
            'AddressMsr': [0xC, ['unsigned long']],
            'MiscMsr': [0x10, ['unsigned long']],
            'ControlData': [0x14, ['unsigned long long']],
        },
    ],
    '__unnamed_233f': [
        0x4,
        {
            'LongFlags2': [0x0, ['unsigned long']],
            'VadFlags2': [0x0, ['_MMVAD_FLAGS2']],
        },
    ],
    '__unnamed_2342': [
        0x4,
        {
            'SequentialVa': [0x0, ['_MI_VAD_SEQUENTIAL_INFO']],
            'ExtendedInfo': [0x0, ['pointer', ['_MMEXTEND_INFO']]],
        },
    ],
    '_MMVAD': [
        0x48,
        {
            'Core': [0x0, ['_MMVAD_SHORT']],
            'u2': [0x28, ['__unnamed_233f']],
            'Subsection': [0x2C, ['pointer', ['_SUBSECTION']]],
            'FirstPrototypePte': [0x30, ['pointer', ['_MMPTE']]],
            'LastContiguousPte': [0x34, ['pointer', ['_MMPTE']]],
            'ViewLinks': [0x38, ['_LIST_ENTRY']],
            'VadsProcess': [0x40, ['pointer', ['_EPROCESS']]],
            'u4': [0x44, ['__unnamed_2342']],
        },
    ],
    '_SEP_SID_VALUES_BLOCK': [
        0x10,
        {
            'BlockLength': [0x0, ['unsigned long']],
            'ReferenceCount': [0x4, ['long']],
            'SidCount': [0x8, ['unsigned long']],
            'SidValuesStart': [0xC, ['unsigned long']],
        },
    ],
    '_CM_RM': [
        0x58,
        {
            'RmListEntry': [0x0, ['_LIST_ENTRY']],
            'TransactionListHead': [0x8, ['_LIST_ENTRY']],
            'TmHandle': [0x10, ['pointer', ['void']]],
            'Tm': [0x14, ['pointer', ['void']]],
            'RmHandle': [0x18, ['pointer', ['void']]],
            'KtmRm': [0x1C, ['pointer', ['void']]],
            'RefCount': [0x20, ['unsigned long']],
            'ContainerNum': [0x24, ['unsigned long']],
            'ContainerSize': [0x28, ['unsigned long long']],
            'CmHive': [0x30, ['pointer', ['_CMHIVE']]],
            'LogFileObject': [0x34, ['pointer', ['void']]],
            'MarshallingContext': [0x38, ['pointer', ['void']]],
            'RmFlags': [0x3C, ['unsigned long']],
            'LogStartStatus1': [0x40, ['long']],
            'LogStartStatus2': [0x44, ['long']],
            'BaseLsn': [0x48, ['unsigned long long']],
            'RmLock': [0x50, ['pointer', ['_ERESOURCE']]],
        },
    ],
    '_NONOPAQUE_OPLOCK': [
        0x50,
        {
            'IrpExclusiveOplock': [0x0, ['pointer', ['_IRP']]],
            'FileObject': [0x4, ['pointer', ['_FILE_OBJECT']]],
            'ExclusiveOplockOwner': [0x8, ['pointer', ['_EPROCESS']]],
            'ExclusiveOplockOwnerThread': [0xC, ['pointer', ['_ETHREAD']]],
            'WaiterPriority': [0x10, ['unsigned char']],
            'IrpOplocksR': [0x14, ['_LIST_ENTRY']],
            'IrpOplocksRH': [0x1C, ['_LIST_ENTRY']],
            'RHBreakQueue': [0x24, ['_LIST_ENTRY']],
            'WaitingIrps': [0x2C, ['_LIST_ENTRY']],
            'DelayAckFileObjectQueue': [0x34, ['_LIST_ENTRY']],
            'AtomicQueue': [0x3C, ['_LIST_ENTRY']],
            'DeleterParentKey': [0x44, ['pointer', ['_GUID']]],
            'OplockState': [0x48, ['unsigned long']],
            'FastMutex': [0x4C, ['pointer', ['_FAST_MUTEX']]],
        },
    ],
    '_OBJECT_HANDLE_COUNT_ENTRY': [
        0x8,
        {
            'Process': [0x0, ['pointer', ['_EPROCESS']]],
            'HandleCount': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'LockCount': [
                0x4,
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
        0x8,
        {
            'UniqueProcess': [0x0, ['pointer', ['void']]],
            'UniqueThread': [0x4, ['pointer', ['void']]],
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
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'Affinity': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Priority': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'Apc': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'UserApc': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'Alert': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_VI_DEADLOCK_RESOURCE': [
        0x80,
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
            'ResourceAddress': [0x8, ['pointer', ['void']]],
            'ThreadOwner': [0xC, ['pointer', ['_VI_DEADLOCK_THREAD']]],
            'ResourceList': [0x10, ['_LIST_ENTRY']],
            'HashChainList': [0x18, ['_LIST_ENTRY']],
            'FreeListEntry': [0x18, ['_LIST_ENTRY']],
            'StackTrace': [0x20, ['array', 8, ['pointer', ['void']]]],
            'LastAcquireTrace': [0x40, ['array', 8, ['pointer', ['void']]]],
            'LastReleaseTrace': [0x60, ['array', 8, ['pointer', ['void']]]],
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
            'AttemptingDelete': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'PrefetchCreated': [
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
            'NoChange': [
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
            'PreferredNode': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'GlobalOnlyPerSession': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'UserWritable': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_SECURITY_CLIENT_CONTEXT': [
        0x3C,
        {
            'SecurityQos': [0x0, ['_SECURITY_QUALITY_OF_SERVICE']],
            'ClientToken': [0xC, ['pointer', ['void']]],
            'DirectlyAccessClientToken': [0x10, ['unsigned char']],
            'DirectAccessEffectiveOnly': [0x11, ['unsigned char']],
            'ServerIsRemote': [0x12, ['unsigned char']],
            'ClientTokenControl': [0x14, ['_TOKEN_CONTROL']],
        },
    ],
    '_MM_PAGED_POOL_INFO': [
        0x38,
        {
            'Mutex': [0x0, ['_FAST_MUTEX']],
            'PagedPoolAllocationMap': [0x20, ['_RTL_BITMAP']],
            'FirstPteForPagedPool': [0x28, ['pointer', ['_MMPTE']]],
            'MaximumSize': [0x2C, ['unsigned long']],
            'PagedPoolHint': [0x30, ['unsigned long']],
            'AllocatedPagedPool': [0x34, ['unsigned long']],
        },
    ],
    '_MI_REVERSE_VIEW_MAP': [
        0x18,
        {
            'ViewLinks': [0x0, ['_LIST_ENTRY']],
            'SystemCacheVa': [0x8, ['pointer', ['void']]],
            'SessionViewVa': [0x8, ['pointer', ['void']]],
            'VadsProcess': [0x8, ['pointer', ['_EPROCESS']]],
            'Type': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Subsection': [0xC, ['pointer', ['_SUBSECTION']]],
            'SubsectionType': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'SectionOffset': [0x10, ['unsigned long long']],
        },
    ],
    '_IO_SECURITY_CONTEXT': [
        0x10,
        {
            'SecurityQos': [
                0x0,
                ['pointer', ['_SECURITY_QUALITY_OF_SERVICE']],
            ],
            'AccessState': [0x4, ['pointer', ['_ACCESS_STATE']]],
            'DesiredAccess': [0x8, ['unsigned long']],
            'FullCreateOptions': [0xC, ['unsigned long']],
        },
    ],
    '_PROC_PERF_DOMAIN': [
        0x90,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'Master': [0x8, ['pointer', ['_KPRCB']]],
            'Members': [0xC, ['_KAFFINITY_EX']],
            'ProcessorCount': [0x18, ['unsigned long']],
            'Processors': [0x1C, ['pointer', ['_PROC_PERF_CONSTRAINT']]],
            'GetFFHThrottleState': [0x20, ['pointer', ['void']]],
            'BoostPolicyHandler': [0x24, ['pointer', ['void']]],
            'BoostModeHandler': [0x28, ['pointer', ['void']]],
            'PerfSelectionHandler': [0x2C, ['pointer', ['void']]],
            'PerfControlHandler': [0x30, ['pointer', ['void']]],
            'MaxFrequency': [0x34, ['unsigned long']],
            'NominalFrequency': [0x38, ['unsigned long']],
            'MaxPercent': [0x3C, ['unsigned long']],
            'MinPerfPercent': [0x40, ['unsigned long']],
            'MinThrottlePercent': [0x44, ['unsigned long']],
            'Coordination': [0x48, ['unsigned char']],
            'HardPlatformCap': [0x49, ['unsigned char']],
            'AffinitizeControl': [0x4A, ['unsigned char']],
            'SelectedPercent': [0x4C, ['unsigned long']],
            'SelectedFrequency': [0x50, ['unsigned long']],
            'DesiredPercent': [0x54, ['unsigned long']],
            'MaxPolicyPercent': [0x58, ['unsigned long']],
            'MinPolicyPercent': [0x5C, ['unsigned long']],
            'ConstrainedMaxPercent': [0x60, ['unsigned long']],
            'ConstrainedMinPercent': [0x64, ['unsigned long']],
            'GuaranteedPercent': [0x68, ['unsigned long']],
            'TolerancePercent': [0x6C, ['unsigned long']],
            'SelectedState': [0x70, ['unsigned long long']],
            'Force': [0x78, ['unsigned char']],
            'PerfChangeTime': [0x80, ['unsigned long long']],
            'PerfChangeIntervalCount': [0x88, ['unsigned long']],
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
        0x50,
        {
            'ClientId': [0x0, ['_CLIENT_ID']],
            'Handle': [0x8, ['pointer', ['void']]],
            'Type': [0xC, ['unsigned long']],
            'StackTrace': [0x10, ['array', 16, ['pointer', ['void']]]],
        },
    ],
    '_WHEA_IPF_CPE_DESCRIPTOR': [
        0x4,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
        },
    ],
    '_DUMMY_FILE_OBJECT': [
        0xA0,
        {
            'ObjectHeader': [0x0, ['_OBJECT_HEADER']],
            'FileObjectBody': [0x20, ['array', 128, ['unsigned char']]],
        },
    ],
    '_RELATION_LIST': [
        0x14,
        {
            'Count': [0x0, ['unsigned long']],
            'TagCount': [0x4, ['unsigned long']],
            'FirstLevel': [0x8, ['unsigned long']],
            'MaxLevel': [0xC, ['unsigned long']],
            'Entries': [
                0x10,
                ['array', 1, ['pointer', ['_RELATION_LIST_ENTRY']]],
            ],
        },
    ],
    '_IO_TIMER': [
        0x18,
        {
            'Type': [0x0, ['short']],
            'TimerFlag': [0x2, ['short']],
            'TimerList': [0x4, ['_LIST_ENTRY']],
            'TimerRoutine': [0xC, ['pointer', ['void']]],
            'Context': [0x10, ['pointer', ['void']]],
            'DeviceObject': [0x14, ['pointer', ['_DEVICE_OBJECT']]],
        },
    ],
    '_ETW_BUFFER_QUEUE': [
        0xC,
        {
            'QueueHead': [0x0, ['pointer', ['_SINGLE_LIST_ENTRY']]],
            'QueueTail': [0x4, ['pointer', ['_SINGLE_LIST_ENTRY']]],
            'QueueEntry': [0x8, ['_SINGLE_LIST_ENTRY']],
        },
    ],
    '_ARBITER_TEST_ALLOCATION_PARAMETERS': [
        0xC,
        {
            'ArbitrationList': [0x0, ['pointer', ['_LIST_ENTRY']]],
            'AllocateFromCount': [0x4, ['unsigned long']],
            'AllocateFrom': [
                0x8,
                ['pointer', ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
        },
    ],
    '_MI_SPECIAL_POOL': [
        0x48,
        {
            'Lock': [0x0, ['unsigned long']],
            'Paged': [0x8, ['_MI_PTE_CHAIN_HEAD']],
            'NonPaged': [0x20, ['_MI_PTE_CHAIN_HEAD']],
            'PagesInUse': [0x38, ['unsigned long']],
            'SpecialPoolPdes': [0x3C, ['_RTL_BITMAP']],
        },
    ],
    '_LOGGED_STREAM_CALLBACK_V2': [
        0x4,
        {
            'LogHandleContext': [0x0, ['pointer', ['_LOG_HANDLE_CONTEXT']]],
        },
    ],
    '_ARBITER_QUERY_CONFLICT_PARAMETERS': [
        0x10,
        {
            'PhysicalDeviceObject': [0x0, ['pointer', ['_DEVICE_OBJECT']]],
            'ConflictingResource': [
                0x4,
                ['pointer', ['_IO_RESOURCE_DESCRIPTOR']],
            ],
            'ConflictCount': [0x8, ['pointer', ['unsigned long']]],
            'Conflicts': [
                0xC,
                ['pointer', ['pointer', ['_ARBITER_CONFLICT_INFO']]],
            ],
        },
    ],
    '_POP_CURRENT_BROADCAST': [
        0x10,
        {
            'InProgress': [0x0, ['unsigned char']],
            'SystemContext': [0x4, ['_SYSTEM_POWER_STATE_CONTEXT']],
            'PowerAction': [
                0x8,
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
            'DeviceState': [0xC, ['pointer', ['_POP_DEVICE_SYS_STATE']]],
        },
    ],
    '_PHYSICAL_MEMORY_DESCRIPTOR': [
        0x10,
        {
            'NumberOfRuns': [0x0, ['unsigned long']],
            'NumberOfPages': [0x4, ['unsigned long']],
            'Run': [0x8, ['array', 1, ['_PHYSICAL_MEMORY_RUN']]],
        },
    ],
    'PEPHANDLE__': [
        0x4,
        {
            'unused': [0x0, ['long']],
        },
    ],
    '_PNP_DEVICE_EVENT_LIST': [
        0x4C,
        {
            'Status': [0x0, ['long']],
            'EventQueueMutex': [0x4, ['_KMUTANT']],
            'Lock': [0x24, ['_FAST_MUTEX']],
            'List': [0x44, ['_LIST_ENTRY']],
        },
    ],
    '_IOV_IRP_TRACE': [
        0x40,
        {
            'Irp': [0x0, ['pointer', ['_IRP']]],
            'Thread': [0x4, ['pointer', ['_KTHREAD']]],
            'KernelApcDisable': [0x8, ['short']],
            'SpecialApcDisable': [0xA, ['short']],
            'CombinedApcDisable': [0x8, ['unsigned long']],
            'Irql': [0xC, ['unsigned char']],
            'StackTrace': [0x10, ['array', 12, ['pointer', ['void']]]],
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
        0x10,
        {
            'DeviceIrpQueue': [0x0, ['_PO_IRP_QUEUE']],
            'SystemIrpQueue': [0x8, ['_PO_IRP_QUEUE']],
        },
    ],
    '_SEP_LOWBOX_HANDLES_TABLE': [
        0x8,
        {
            'Lock': [0x0, ['_EX_PUSH_LOCK']],
            'HashTable': [0x4, ['pointer', ['_RTL_DYNAMIC_HASH_TABLE']]],
        },
    ],
    '_CLIENT_ID64': [
        0x10,
        {
            'UniqueProcess': [0x0, ['unsigned long long']],
            'UniqueThread': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_23c7': [
        0x4,
        {
            'Level': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_23c9': [
        0x4,
        {
            'Type': [0x0, ['unsigned long']],
        },
    ],
    '_POP_ACTION_TRIGGER': [
        0x10,
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
                            8: 'PolicyDeviceWakeAlarm',
                            9: 'PolicyDeviceFan',
                            10: 'PolicyCsBatterySaver',
                            11: 'PolicyDeviceMax',
                        },
                    ),
                ],
            ],
            'Flags': [0x4, ['unsigned long']],
            'Wait': [0x8, ['pointer', ['_POP_TRIGGER_WAIT']]],
            'Battery': [0xC, ['__unnamed_23c7']],
            'Button': [0xC, ['__unnamed_23c9']],
        },
    ],
    '_KDPC_DATA': [
        0x18,
        {
            'DpcList': [0x0, ['_KDPC_LIST']],
            'DpcLock': [0x8, ['unsigned long']],
            'DpcQueueDepth': [0xC, ['long']],
            'DpcCount': [0x10, ['unsigned long']],
            'ActiveDpc': [0x14, ['pointer', ['_KDPC']]],
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
    '_KSCB': [
        0xE0,
        {
            'GenerationCycles': [0x0, ['unsigned long long']],
            'UnderQuotaCycleTarget': [0x8, ['unsigned long long']],
            'RankCycleTarget': [0x10, ['unsigned long long']],
            'LongTermCycles': [0x18, ['unsigned long long']],
            'LastReportedCycles': [0x20, ['unsigned long long']],
            'OverQuotaHistory': [0x28, ['unsigned long long']],
            'ReadyTime': [0x30, ['unsigned long long']],
            'InsertTime': [0x38, ['unsigned long long']],
            'PerProcessorList': [0x40, ['_LIST_ENTRY']],
            'QueueNode': [0x48, ['_RTL_BALANCED_NODE']],
            'Inserted': [
                0x54,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'OverQuota': [
                0x54,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'HardCap': [
                0x54,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'RankBias': [
                0x54,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Spare1': [
                0x54,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Spare2': [0x55, ['unsigned char']],
            'ReadySummary': [0x56, ['unsigned short']],
            'Rank': [0x58, ['unsigned long']],
            'ReadyListHead': [0x5C, ['array', 16, ['_LIST_ENTRY']]],
        },
    ],
    '__unnamed_23d9': [
        0x8,
        {
            'UserData': [0x0, ['pointer', ['void']]],
            'Owner': [0x4, ['pointer', ['void']]],
        },
    ],
    '__unnamed_23db': [
        0x8,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
        },
    ],
    '_RTLP_RANGE_LIST_ENTRY': [
        0x28,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
            'Allocated': [0x10, ['__unnamed_23d9']],
            'Merged': [0x10, ['__unnamed_23db']],
            'Attributes': [0x18, ['unsigned char']],
            'PublicFlags': [0x19, ['unsigned char']],
            'PrivateFlags': [0x1A, ['unsigned short']],
            'ListEntry': [0x1C, ['_LIST_ENTRY']],
        },
    ],
    '_ALPC_COMPLETION_PACKET_LOOKASIDE_ENTRY': [
        0xC,
        {
            'ListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Packet': [0x4, ['pointer', ['_IO_MINI_COMPLETION_PACKET_USER']]],
            'Lookaside': [
                0x8,
                ['pointer', ['_ALPC_COMPLETION_PACKET_LOOKASIDE']],
            ],
        },
    ],
    '_PROC_PERF_HISTORY': [
        0x10,
        {
            'Count': [0x0, ['unsigned long']],
            'Slot': [0x4, ['unsigned long']],
            'HistoryList': [0x8, ['array', 1, ['_PROC_PERF_HISTORY_ENTRY']]],
        },
    ],
    '__unnamed_23e7': [
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
            'Flags': [0x2, ['__unnamed_23e7']],
            'PolicyCount': [0x4, ['unsigned long']],
            'Policy': [0x8, ['array', 3, ['PROCESSOR_IDLESTATE_INFO']]],
        },
    ],
    '_ACTIVATION_CONTEXT_STACK': [
        0x18,
        {
            'ActiveFrame': [
                0x0,
                ['pointer', ['_RTL_ACTIVATION_CONTEXT_STACK_FRAME']],
            ],
            'FrameListCache': [0x4, ['_LIST_ENTRY']],
            'Flags': [0xC, ['unsigned long']],
            'NextCookieSequenceNumber': [0x10, ['unsigned long']],
            'StackId': [0x14, ['unsigned long']],
        },
    ],
    '_RTL_DRIVE_LETTER_CURDIR': [
        0x10,
        {
            'Flags': [0x0, ['unsigned short']],
            'Length': [0x2, ['unsigned short']],
            'TimeStamp': [0x4, ['unsigned long']],
            'DosPath': [0x8, ['_STRING']],
        },
    ],
    '_MI_PTE_CHAIN_HEAD': [
        0x18,
        {
            'Flink': [0x0, ['_MMPTE']],
            'Blink': [0x8, ['_MMPTE']],
            'PteBase': [0x10, ['pointer', ['_MMPTE']]],
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
            'Hiberboot': [0x12, ['unsigned char']],
            'WakeAlarmPresent': [0x13, ['unsigned char']],
            'AoAc': [0x14, ['unsigned char']],
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
    '__unnamed_23fb': [
        0x4,
        {
            'ImageCommitment': [0x0, ['unsigned long']],
            'CreatingProcess': [0x0, ['pointer', ['_EPROCESS']]],
        },
    ],
    '__unnamed_23ff': [
        0x4,
        {
            'ImageInformation': [
                0x0,
                ['pointer', ['_MI_SECTION_IMAGE_INFORMATION']],
            ],
            'FirstMappedVa': [0x0, ['pointer', ['void']]],
        },
    ],
    '_SEGMENT': [
        0x30,
        {
            'ControlArea': [0x0, ['pointer', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x4, ['unsigned long']],
            'SegmentFlags': [0x8, ['_SEGMENT_FLAGS']],
            'NumberOfCommittedPages': [0xC, ['unsigned long']],
            'SizeOfSegment': [0x10, ['unsigned long long']],
            'ExtendInfo': [0x18, ['pointer', ['_MMEXTEND_INFO']]],
            'BasedAddress': [0x18, ['pointer', ['void']]],
            'SegmentLock': [0x1C, ['_EX_PUSH_LOCK']],
            'u1': [0x20, ['__unnamed_23fb']],
            'u2': [0x24, ['__unnamed_23ff']],
            'PrototypePte': [0x28, ['pointer', ['_MMPTE']]],
        },
    ],
    '_DIAGNOSTIC_CONTEXT': [
        0x10,
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
            'Process': [0x4, ['pointer', ['_EPROCESS']]],
            'ServiceTag': [0x8, ['unsigned long']],
            'DeviceObject': [0x4, ['pointer', ['_DEVICE_OBJECT']]],
            'ReasonSize': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_2408': [
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
    '__unnamed_240a': [
        0x4,
        {
            'Flags': [0x0, ['__unnamed_2408']],
            'Whole': [0x0, ['unsigned long']],
        },
    ],
    '_VF_TARGET_VERIFIED_DRIVER_DATA': [
        0x90,
        {
            'SuspectDriverEntry': [
                0x0,
                ['pointer', ['_VF_SUSPECT_DRIVER_ENTRY']],
            ],
            'WMICallback': [0x4, ['pointer', ['void']]],
            'EtwHandlesListHead': [0x8, ['_LIST_ENTRY']],
            'u1': [0x10, ['__unnamed_240a']],
            'Signature': [0x14, ['unsigned long']],
            'PoolPageHeaders': [0x18, ['_SLIST_HEADER']],
            'PoolTrackers': [0x20, ['_SLIST_HEADER']],
            'CurrentPagedPoolAllocations': [0x28, ['unsigned long']],
            'CurrentNonPagedPoolAllocations': [0x2C, ['unsigned long']],
            'PeakPagedPoolAllocations': [0x30, ['unsigned long']],
            'PeakNonPagedPoolAllocations': [0x34, ['unsigned long']],
            'PagedBytes': [0x38, ['unsigned long']],
            'NonPagedBytes': [0x3C, ['unsigned long']],
            'PeakPagedBytes': [0x40, ['unsigned long']],
            'PeakNonPagedBytes': [0x44, ['unsigned long']],
            'RaiseIrqls': [0x48, ['unsigned long']],
            'AcquireSpinLocks': [0x4C, ['unsigned long']],
            'SynchronizeExecutions': [0x50, ['unsigned long']],
            'AllocationsWithNoTag': [0x54, ['unsigned long']],
            'AllocationsFailed': [0x58, ['unsigned long']],
            'AllocationsFailedDeliberately': [0x5C, ['unsigned long']],
            'LockedBytes': [0x60, ['unsigned long']],
            'PeakLockedBytes': [0x64, ['unsigned long']],
            'MappedLockedBytes': [0x68, ['unsigned long']],
            'PeakMappedLockedBytes': [0x6C, ['unsigned long']],
            'MappedIoSpaceBytes': [0x70, ['unsigned long']],
            'PeakMappedIoSpaceBytes': [0x74, ['unsigned long']],
            'PagesForMdlBytes': [0x78, ['unsigned long']],
            'PeakPagesForMdlBytes': [0x7C, ['unsigned long']],
            'ContiguousMemoryBytes': [0x80, ['unsigned long']],
            'PeakContiguousMemoryBytes': [0x84, ['unsigned long']],
            'ContiguousMemoryListHead': [0x88, ['_LIST_ENTRY']],
        },
    ],
    '_MMVAD_FLAGS1': [
        0x4,
        {
            'CommitCharge': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'MemCommit': [
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
    '_PRIVATE_CACHE_MAP': [
        0x68,
        {
            'NodeTypeCode': [0x0, ['short']],
            'Flags': [0x0, ['_PRIVATE_CACHE_MAP_FLAGS']],
            'ReadAheadMask': [0x4, ['unsigned long']],
            'FileObject': [0x8, ['pointer', ['_FILE_OBJECT']]],
            'FileOffset1': [0x10, ['_LARGE_INTEGER']],
            'BeyondLastByte1': [0x18, ['_LARGE_INTEGER']],
            'FileOffset2': [0x20, ['_LARGE_INTEGER']],
            'BeyondLastByte2': [0x28, ['_LARGE_INTEGER']],
            'SequentialReadCount': [0x30, ['unsigned long']],
            'ReadAheadLength': [0x34, ['unsigned long']],
            'ReadAheadOffset': [0x38, ['_LARGE_INTEGER']],
            'ReadAheadBeyondLastByte': [0x40, ['_LARGE_INTEGER']],
            'PrevReadAheadBeyondLastByte': [0x48, ['unsigned long long']],
            'ReadAheadSpinLock': [0x50, ['unsigned long']],
            'PipelinedReadAheadRequestSize': [0x54, ['unsigned long']],
            'ReadAheadGrowth': [0x58, ['unsigned long']],
            'PrivateLinks': [0x5C, ['_LIST_ENTRY']],
            'ReadAheadWorkItem': [0x64, ['pointer', ['void']]],
        },
    ],
    '_CM_KEY_NODE': [
        0x50,
        {
            'Signature': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned short']],
            'LastWriteTime': [0x4, ['_LARGE_INTEGER']],
            'AccessBits': [0xC, ['unsigned long']],
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
    '_AER_ROOTPORT_DESCRIPTOR_FLAGS': [
        0x2,
        {
            'UncorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'UncorrectableErrorSeverityRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'CorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'AdvancedCapsAndControlRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'RootErrorCommandRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AsUSHORT': [0x0, ['unsigned short']],
        },
    ],
    '_PTE_TRACKER': [
        0x44,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Mdl': [0x8, ['pointer', ['_MDL']]],
            'Count': [0xC, ['unsigned long']],
            'SystemVa': [0x10, ['pointer', ['void']]],
            'StartVa': [0x14, ['pointer', ['void']]],
            'Offset': [0x18, ['unsigned long']],
            'Length': [0x1C, ['unsigned long']],
            'Page': [0x20, ['unsigned long']],
            'IoMapping': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Matched': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'CacheAttribute': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Spare': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'StackTrace': [0x28, ['array', 7, ['pointer', ['void']]]],
        },
    ],
    '_KTHREAD_COUNTERS': [
        0x1A8,
        {
            'WaitReasonBitMap': [0x0, ['unsigned long long']],
            'UserData': [0x8, ['pointer', ['_THREAD_PERFORMANCE_DATA']]],
            'Flags': [0xC, ['unsigned long']],
            'ContextSwitches': [0x10, ['unsigned long']],
            'CycleTimeBias': [0x18, ['unsigned long long']],
            'HardwareCounters': [0x20, ['unsigned long long']],
            'HwCounter': [0x28, ['array', 16, ['_COUNTER_READING']]],
        },
    ],
    '_SHARED_CACHE_MAP_LIST_CURSOR': [
        0xC,
        {
            'SharedCacheMapLinks': [0x0, ['_LIST_ENTRY']],
            'Flags': [0x8, ['unsigned long']],
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
    '_PROC_FEEDBACK_COUNTER': [
        0x28,
        {
            'InstantaneousRead': [0x0, ['pointer', ['void']]],
            'DifferentialRead': [0x0, ['pointer', ['void']]],
            'LastActualCount': [0x8, ['unsigned long long']],
            'LastReferenceCount': [0x10, ['unsigned long long']],
            'CachedValue': [0x18, ['unsigned long']],
            'Affinitized': [0x20, ['unsigned char']],
            'Differential': [0x21, ['unsigned char']],
            'DisableInterrupts': [0x22, ['unsigned char']],
            'Context': [0x24, ['unsigned long']],
        },
    ],
    '_PROCESSOR_PLATFORM_STATE_RESIDENCIES': [
        0x18,
        {
            'Count': [0x0, ['unsigned long']],
            'States': [
                0x8,
                ['array', 1, ['_PROCESSOR_PLATFORM_STATE_RESIDENCY']],
            ],
        },
    ],
    '_HMAP_ENTRY': [
        0xC,
        {
            'BlockAddress': [0x0, ['unsigned long']],
            'BinAddress': [0x4, ['unsigned long']],
            'MemAlloc': [0x8, ['unsigned long']],
        },
    ],
    '_RTL_ATOM_TABLE_ENTRY': [
        0x1C,
        {
            'HashLink': [0x0, ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]],
            'HandleIndex': [0x4, ['unsigned short']],
            'Atom': [0x6, ['unsigned short']],
            'Reference': [0x8, ['_RTL_ATOM_TABLE_REFERENCE']],
            'NameLength': [0x18, ['unsigned char']],
            'Name': [0x1A, ['array', 1, ['wchar']]],
        },
    ],
    '_TXN_PARAMETER_BLOCK': [
        0x8,
        {
            'Length': [0x0, ['unsigned short']],
            'TxFsContext': [0x2, ['unsigned short']],
            'TransactionObject': [0x4, ['pointer', ['void']]],
        },
    ],
    '_DUAL': [
        0x19C,
        {
            'Length': [0x0, ['unsigned long']],
            'Map': [0x4, ['pointer', ['_HMAP_DIRECTORY']]],
            'SmallDir': [0x8, ['pointer', ['_HMAP_TABLE']]],
            'Guard': [0xC, ['unsigned long']],
            'FreeDisplay': [0x10, ['array', 24, ['_FREE_DISPLAY']]],
            'FreeBins': [0x190, ['_LIST_ENTRY']],
            'FreeSummary': [0x198, ['unsigned long']],
        },
    ],
    '_MI_VAD_SEQUENTIAL_INFO': [
        0x4,
        {
            'Length': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=11, native_type='unsigned long'),
                ],
            ],
            'Vpn': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_PNP_DEVICE_ACTION_ENTRY': [
        0x20,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'DeviceObject': [0x8, ['pointer', ['_DEVICE_OBJECT']]],
            'RequestType': [
                0xC,
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
                            19: 'NotifyTransportRelationsChange',
                            20: 'NotifyEjectionRelationsChange',
                            21: 'ConfigureDevice',
                            22: 'ConfigureDeviceClass',
                            23: 'ConfigureDeviceExtensions',
                        },
                    ),
                ],
            ],
            'ReorderingBarrier': [0x10, ['unsigned char']],
            'RequestArgument': [0x14, ['unsigned long']],
            'CompletionEvent': [0x18, ['pointer', ['_KEVENT']]],
            'CompletionStatus': [0x1C, ['pointer', ['long']]],
        },
    ],
    '_SEP_LOWBOX_NUMBER_ENTRY': [
        0x1C,
        {
            'HashEntry': [0x0, ['_RTL_DYNAMIC_HASH_TABLE_ENTRY']],
            'ReferenceCount': [0xC, ['long']],
            'PackageSid': [0x10, ['pointer', ['void']]],
            'LowboxNumber': [0x14, ['unsigned long']],
            'AtomTable': [0x18, ['pointer', ['void']]],
        },
    ],
    '_MI_CFG_BITMAP_INFO': [
        0x10,
        {
            'BaseAddress': [0x0, ['pointer', ['void']]],
            'RegionSize': [0x4, ['unsigned long']],
            'VadBaseAddress': [0x8, ['pointer', ['void']]],
            'BitmapVad': [0xC, ['pointer', ['_MMVAD']]],
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
        0x38,
        {
            'SystemSpaceViewLock': [0x0, ['_FAST_MUTEX']],
            'SystemSpaceViewLockPointer': [0x20, ['pointer', ['_FAST_MUTEX']]],
            'SystemSpaceViewTable': [0x24, ['pointer', ['_MMVIEW']]],
            'SystemSpaceHashSize': [0x28, ['unsigned long']],
            'SystemSpaceHashEntries': [0x2C, ['unsigned long']],
            'SystemSpaceHashKey': [0x30, ['unsigned long']],
            'BitmapFailures': [0x34, ['unsigned long']],
        },
    ],
    '_ETW_REG_ENTRY': [
        0x28,
        {
            'RegList': [0x0, ['_LIST_ENTRY']],
            'GuidEntry': [0x8, ['pointer', ['_ETW_GUID_ENTRY']]],
            'ReplyQueue': [0xC, ['pointer', ['_ETW_REPLY_QUEUE']]],
            'ReplySlot': [
                0xC,
                ['array', 4, ['pointer', ['_ETW_QUEUE_ENTRY']]],
            ],
            'Caller': [0xC, ['pointer', ['void']]],
            'SessionId': [0x10, ['unsigned long']],
            'Process': [0x1C, ['pointer', ['_EPROCESS']]],
            'CallbackContext': [0x1C, ['pointer', ['void']]],
            'Callback': [0x20, ['pointer', ['void']]],
            'Index': [0x24, ['unsigned short']],
            'Flags': [0x26, ['unsigned char']],
            'DbgKernelRegistration': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'DbgUserRegistration': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'DbgReplyRegistration': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'DbgClassicRegistration': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'DbgSessionSpaceRegistration': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'DbgModernRegistration': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'DbgClosed': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'DbgInserted': [
                0x26,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'EnableMask': [0x27, ['unsigned char']],
        },
    ],
    '_LPCP_PORT_OBJECT': [
        0xA4,
        {
            'ConnectionPort': [0x0, ['pointer', ['_LPCP_PORT_OBJECT']]],
            'ConnectedPort': [0x4, ['pointer', ['_LPCP_PORT_OBJECT']]],
            'MsgQueue': [0x8, ['_LPCP_PORT_QUEUE']],
            'Creator': [0x18, ['_CLIENT_ID']],
            'ClientSectionBase': [0x20, ['pointer', ['void']]],
            'ServerSectionBase': [0x24, ['pointer', ['void']]],
            'PortContext': [0x28, ['pointer', ['void']]],
            'ClientThread': [0x2C, ['pointer', ['_ETHREAD']]],
            'SecurityQos': [0x30, ['_SECURITY_QUALITY_OF_SERVICE']],
            'StaticSecurity': [0x3C, ['_SECURITY_CLIENT_CONTEXT']],
            'LpcReplyChainHead': [0x78, ['_LIST_ENTRY']],
            'LpcDataInfoChainHead': [0x80, ['_LIST_ENTRY']],
            'ServerProcess': [0x88, ['pointer', ['_EPROCESS']]],
            'MappingProcess': [0x88, ['pointer', ['_EPROCESS']]],
            'MaxMessageLength': [0x8C, ['unsigned short']],
            'MaxConnectionInfoLength': [0x8E, ['unsigned short']],
            'Flags': [0x90, ['unsigned long']],
            'WaitEvent': [0x94, ['_KEVENT']],
        },
    ],
    '_ARBITER_LIST_ENTRY': [
        0x38,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'AlternativeCount': [0x8, ['unsigned long']],
            'Alternatives': [0xC, ['pointer', ['_IO_RESOURCE_DESCRIPTOR']]],
            'PhysicalDeviceObject': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'RequestSource': [
                0x14,
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
            'Flags': [0x18, ['unsigned long']],
            'WorkSpace': [0x1C, ['long']],
            'InterfaceType': [
                0x20,
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
                            17: 'ACPIBus',
                            18: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'SlotNumber': [0x24, ['unsigned long']],
            'BusNumber': [0x28, ['unsigned long']],
            'Assignment': [
                0x2C,
                ['pointer', ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
            'SelectedAlternative': [
                0x30,
                ['pointer', ['_IO_RESOURCE_DESCRIPTOR']],
            ],
            'Result': [
                0x34,
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
    '_INTERRUPT_CONNECTION_DATA': [
        0x88,
        {
            'Count': [0x0, ['unsigned long']],
            'OriginalAffinity': [0x4, ['_GROUP_AFFINITY']],
            'SteeringListEntry': [0x10, ['_LIST_ENTRY']],
            'SteeringListRoot': [0x18, ['pointer', ['void']]],
            'IsrTime': [0x20, ['unsigned long long']],
            'DpcTime': [0x28, ['unsigned long long']],
            'IsrLoad': [0x30, ['unsigned long']],
            'DpcLoad': [0x34, ['unsigned long']],
            'IsPrimaryInterrupt': [0x38, ['unsigned char']],
            'InterruptObjectArray': [
                0x3C,
                ['pointer', ['pointer', ['_KINTERRUPT']]],
            ],
            'InterruptObjectCount': [0x40, ['unsigned long']],
            'Vectors': [0x48, ['array', 1, ['_INTERRUPT_VECTOR_DATA']]],
        },
    ],
    '_LDR_DATA_TABLE_ENTRY': [
        0xA0,
        {
            'InLoadOrderLinks': [0x0, ['_LIST_ENTRY']],
            'InMemoryOrderLinks': [0x8, ['_LIST_ENTRY']],
            'InInitializationOrderLinks': [0x10, ['_LIST_ENTRY']],
            'InProgressLinks': [0x10, ['_LIST_ENTRY']],
            'DllBase': [0x18, ['pointer', ['void']]],
            'EntryPoint': [0x1C, ['pointer', ['void']]],
            'SizeOfImage': [0x20, ['unsigned long']],
            'FullDllName': [0x24, ['_UNICODE_STRING']],
            'BaseDllName': [0x2C, ['_UNICODE_STRING']],
            'FlagGroup': [0x34, ['array', 4, ['unsigned char']]],
            'Flags': [0x34, ['unsigned long']],
            'PackagedBinary': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'MarkedForRemoval': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ImageDll': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'LoadNotificationsSent': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'TelemetryEntryProcessed': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ProcessStaticImport': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'InLegacyLists': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'InIndexes': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ShimDll': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'InExceptionTable': [
                0x34,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags1': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'LoadInProgress': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedFlags2': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'EntryProcessed': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedFlags3': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'DontCallForThreads': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessAttachCalled': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessAttachFailed': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'CorDeferredValidate': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'CorImage': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'DontRelocate': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'CorILOnly': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedFlags5': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'Redirected': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'ReservedFlags6': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'CompatDatabaseProcessed': [
                0x34,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ObsoleteLoadCount': [0x38, ['unsigned short']],
            'TlsIndex': [0x3A, ['unsigned short']],
            'HashLinks': [0x3C, ['_LIST_ENTRY']],
            'TimeDateStamp': [0x44, ['unsigned long']],
            'EntryPointActivationContext': [
                0x48,
                ['pointer', ['_ACTIVATION_CONTEXT']],
            ],
            'Spare': [0x4C, ['pointer', ['void']]],
            'DdagNode': [0x50, ['pointer', ['_LDR_DDAG_NODE']]],
            'NodeModuleLink': [0x54, ['_LIST_ENTRY']],
            'SnapContext': [0x5C, ['pointer', ['_LDRP_DLL_SNAP_CONTEXT']]],
            'ParentDllBase': [0x60, ['pointer', ['void']]],
            'SwitchBackContext': [0x64, ['pointer', ['void']]],
            'BaseAddressIndexNode': [0x68, ['_RTL_BALANCED_NODE']],
            'MappingInfoIndexNode': [0x74, ['_RTL_BALANCED_NODE']],
            'OriginalBase': [0x80, ['unsigned long']],
            'LoadTime': [0x88, ['_LARGE_INTEGER']],
            'BaseNameHashValue': [0x90, ['unsigned long']],
            'LoadReason': [
                0x94,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'LoadReasonStaticDependency',
                            1: 'LoadReasonStaticForwarderDependency',
                            2: 'LoadReasonDynamicForwarderDependency',
                            3: 'LoadReasonDelayloadDependency',
                            4: 'LoadReasonDynamicLoad',
                            5: 'LoadReasonAsImageLoad',
                            6: 'LoadReasonAsDataLoad',
                            -1: 'LoadReasonUnknown',
                        },
                    ),
                ],
            ],
            'ImplicitPathOptions': [0x98, ['unsigned long']],
        },
    ],
    '_LDR_DDAG_NODE': [
        0x30,
        {
            'Modules': [0x0, ['_LIST_ENTRY']],
            'ServiceTagList': [0x8, ['pointer', ['_LDR_SERVICE_TAG_RECORD']]],
            'LoadCount': [0xC, ['unsigned long']],
            'ReferenceCount': [0x10, ['unsigned long']],
            'DependencyCount': [0x14, ['unsigned long']],
            'Dependencies': [0x18, ['_LDRP_CSLIST']],
            'RemovalLink': [0x18, ['_SINGLE_LIST_ENTRY']],
            'IncomingDependencies': [0x1C, ['_LDRP_CSLIST']],
            'State': [
                0x20,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'LdrModulesPlaceHolder',
                            1: 'LdrModulesMapping',
                            2: 'LdrModulesMapped',
                            3: 'LdrModulesWaitingForDependencies',
                            4: 'LdrModulesSnapping',
                            5: 'LdrModulesSnapped',
                            6: 'LdrModulesCondensed',
                            7: 'LdrModulesReadyToInit',
                            8: 'LdrModulesInitializing',
                            9: 'LdrModulesReadyToRun',
                            '\xfb': 'LdrModulesMerged',
                            '\xfd': 'LdrModulesSnapError',
                            '\xfc': 'LdrModulesInitError',
                            -1: 'LdrModulesUnloading',
                            '\xfe': 'LdrModulesUnloaded',
                        },
                    ),
                ],
            ],
            'CondenseLink': [0x24, ['_SINGLE_LIST_ENTRY']],
            'PreorderNumber': [0x28, ['unsigned long']],
            'LowestLink': [0x2C, ['unsigned long']],
        },
    ],
    '_POP_DEVICE_SYS_STATE': [
        0x104,
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
            'SpinLock': [0x8, ['unsigned long']],
            'Thread': [0xC, ['pointer', ['_KTHREAD']]],
            'AbortEvent': [0x10, ['pointer', ['_KEVENT']]],
            'ReadySemaphore': [0x14, ['pointer', ['_KSEMAPHORE']]],
            'FinishedSemaphore': [0x18, ['pointer', ['_KSEMAPHORE']]],
            'Order': [0x1C, ['_PO_DEVICE_NOTIFY_ORDER']],
            'Pending': [0xEC, ['_LIST_ENTRY']],
            'Status': [0xF4, ['long']],
            'FailedDevice': [0xF8, ['pointer', ['_DEVICE_OBJECT']]],
            'Waking': [0xFC, ['unsigned char']],
            'Cancelled': [0xFD, ['unsigned char']],
            'IgnoreErrors': [0xFE, ['unsigned char']],
            'IgnoreNotImplemented': [0xFF, ['unsigned char']],
            'TimeRefreshLockAcquired': [0x100, ['unsigned char']],
        },
    ],
    '_SEGMENT_FLAGS': [
        0x4,
        {
            'TotalNumberOfPtes4132': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0, end_bit=10, native_type='unsigned short'
                    ),
                ],
            ],
            'Spare0': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned short'
                    ),
                ],
            ],
            'LargePages': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned short'
                    ),
                ],
            ],
            'LockedPages': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned short'
                    ),
                ],
            ],
            'DebugSymbolsLoaded': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned short'
                    ),
                ],
            ],
            'WriteCombined': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned short'
                    ),
                ],
            ],
            'NoCache': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'Short0': [0x0, ['unsigned short']],
            'FloppyMedia': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'DefaultProtectionMask': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Binary32': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'ContainsDebug': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'UChar1': [0x2, ['unsigned char']],
            'ILOnly': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ImageSigningType': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ImageSigningLevel': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'UChar2': [0x3, ['unsigned char']],
        },
    ],
    '_VF_KE_CRITICAL_REGION_TRACE': [
        0x20,
        {
            'Thread': [0x0, ['pointer', ['_ETHREAD']]],
            'StackTrace': [0x4, ['array', 7, ['pointer', ['void']]]],
        },
    ],
    '_LOGGED_STREAM_CALLBACK_V1': [
        0x8,
        {
            'LogHandle': [0x0, ['pointer', ['void']]],
            'FlushToLsnRoutine': [0x4, ['pointer', ['void']]],
        },
    ],
    '_DIAGNOSTIC_BUFFER': [
        0x18,
        {
            'Size': [0x0, ['unsigned long']],
            'CallerType': [
                0x4,
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
            'ProcessImageNameOffset': [0x8, ['unsigned long']],
            'ProcessId': [0xC, ['unsigned long']],
            'ServiceTag': [0x10, ['unsigned long']],
            'DeviceDescriptionOffset': [0x8, ['unsigned long']],
            'DevicePathOffset': [0xC, ['unsigned long']],
            'ReasonOffset': [0x14, ['unsigned long']],
        },
    ],
    '_CLIENT_ID32': [
        0x8,
        {
            'UniqueProcess': [0x0, ['unsigned long']],
            'UniqueThread': [0x4, ['unsigned long']],
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
        0x20,
        {
            'Thread': [0x0, ['pointer', ['_KTHREAD']]],
            'CurrentSpinNode': [0x4, ['pointer', ['_VI_DEADLOCK_NODE']]],
            'CurrentOtherNode': [0x8, ['pointer', ['_VI_DEADLOCK_NODE']]],
            'ListEntry': [0xC, ['_LIST_ENTRY']],
            'FreeListEntry': [0xC, ['_LIST_ENTRY']],
            'NodeCount': [0x14, ['unsigned long']],
            'PagingCount': [0x18, ['unsigned long']],
            'ThreadUsesEresources': [0x1C, ['unsigned char']],
        },
    ],
    '_PPM_IDLE_STATE': [
        0x30,
        {
            'DomainMembers': [0x0, ['_KAFFINITY_EX']],
            'Latency': [0xC, ['unsigned long']],
            'BreakEvenDuration': [0x10, ['unsigned long']],
            'Power': [0x14, ['unsigned long']],
            'StateFlags': [0x18, ['unsigned long']],
            'VetoAccounting': [0x1C, ['_PPM_VETO_ACCOUNTING']],
            'StateType': [0x28, ['unsigned char']],
            'InterruptsEnabled': [0x29, ['unsigned char']],
            'Interruptible': [0x2A, ['unsigned char']],
            'ContextRetained': [0x2B, ['unsigned char']],
            'CacheCoherent': [0x2C, ['unsigned char']],
            'WakesSpuriously': [0x2D, ['unsigned char']],
            'PlatformOnly': [0x2E, ['unsigned char']],
            'NoCState': [0x2F, ['unsigned char']],
        },
    ],
    '_KRESOURCEMANAGER': [
        0x154,
        {
            'NotificationAvailable': [0x0, ['_KEVENT']],
            'cookie': [0x10, ['unsigned long']],
            'State': [
                0x14,
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
            'Flags': [0x18, ['unsigned long']],
            'Mutex': [0x1C, ['_KMUTANT']],
            'NamespaceLink': [0x3C, ['_KTMOBJECT_NAMESPACE_LINK']],
            'RmId': [0x50, ['_GUID']],
            'NotificationQueue': [0x60, ['_KQUEUE']],
            'NotificationMutex': [0x88, ['_KMUTANT']],
            'EnlistmentHead': [0xA8, ['_LIST_ENTRY']],
            'EnlistmentCount': [0xB0, ['unsigned long']],
            'NotificationRoutine': [0xB4, ['pointer', ['void']]],
            'Key': [0xB8, ['pointer', ['void']]],
            'ProtocolListHead': [0xBC, ['_LIST_ENTRY']],
            'PendingPropReqListHead': [0xC4, ['_LIST_ENTRY']],
            'CRMListEntry': [0xCC, ['_LIST_ENTRY']],
            'Tm': [0xD4, ['pointer', ['_KTM']]],
            'Description': [0xD8, ['_UNICODE_STRING']],
            'Enlistments': [0xE0, ['_KTMOBJECT_NAMESPACE']],
            'CompletionBinding': [
                0x140,
                ['_KRESOURCEMANAGER_COMPLETION_BINDING'],
            ],
        },
    ],
    '_MMEXTEND_INFO': [
        0x10,
        {
            'CommittedSize': [0x0, ['unsigned long long']],
            'ReferenceCount': [0x8, ['unsigned long']],
        },
    ],
    '_HANDLE_TABLE_FREE_LIST': [
        0x34,
        {
            'FreeListLock': [0x0, ['_EX_PUSH_LOCK']],
            'FirstFreeHandleEntry': [
                0x4,
                ['pointer', ['_HANDLE_TABLE_ENTRY']],
            ],
            'LastFreeHandleEntry': [0x8, ['pointer', ['_HANDLE_TABLE_ENTRY']]],
            'HandleCount': [0xC, ['long']],
            'HighWaterMark': [0x10, ['unsigned long']],
            'Reserved': [0x14, ['array', 8, ['unsigned long']]],
        },
    ],
    '_WHEAP_ERROR_RECORD_WRAPPER_FLAGS': [
        0x4,
        {
            'Preallocated': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'FromPersistentStore': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'PlatformPfaControl': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'PlatformDirectedOffline': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_GDI_TEB_BATCH64': [
        0x4E8,
        {
            'Offset': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=31, native_type='unsigned long'),
                ],
            ],
            'HasRenderingCommand': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'HDC': [0x8, ['unsigned long long']],
            'Buffer': [0x10, ['array', 310, ['unsigned long']]],
        },
    ],
    '__unnamed_24bd': [
        0x4,
        {
            'NodeSize': [0x0, ['unsigned long']],
            'UseLookaside': [0x0, ['unsigned long']],
        },
    ],
    '_VF_AVL_TREE': [
        0x14,
        {
            'NodeRangeSize': [0x0, ['unsigned long']],
            'NodeCount': [0x4, ['unsigned long']],
            'Tables': [0x8, ['pointer', ['_VF_AVL_TABLE']]],
            'TablesNo': [0xC, ['unsigned long']],
            'u1': [0x10, ['__unnamed_24bd']],
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
    '_POP_FX_ACCOUNTING': [
        0x28,
        {
            'Lock': [0x0, ['unsigned long']],
            'Active': [0x4, ['unsigned char']],
            'DripsRequiredState': [0x8, ['unsigned long']],
            'Level': [0xC, ['long']],
            'ActiveStamp': [0x10, ['long long']],
            'CsActiveTime': [0x18, ['unsigned long long']],
            'CriticalActiveTime': [0x20, ['long long']],
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
    '_POP_TRIGGER_WAIT': [
        0x20,
        {
            'Event': [0x0, ['_KEVENT']],
            'Status': [0x10, ['long']],
            'Link': [0x14, ['_LIST_ENTRY']],
            'Trigger': [0x1C, ['pointer', ['_POP_ACTION_TRIGGER']]],
        },
    ],
    '_AER_ENDPOINT_DESCRIPTOR_FLAGS': [
        0x2,
        {
            'UncorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'UncorrectableErrorSeverityRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'CorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'AdvancedCapsAndControlRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=4, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AsUSHORT': [0x0, ['unsigned short']],
        },
    ],
    '_RELATION_LIST_ENTRY': [
        0x14,
        {
            'Count': [0x0, ['unsigned long']],
            'MaxCount': [0x4, ['unsigned long']],
            'Devices': [0x8, ['array', 1, ['_DEVICE_OBJECT_LIST_ENTRY']]],
        },
    ],
    '_HEAP_FREE_ENTRY_EXTRA': [
        0x4,
        {
            'TagIndex': [0x0, ['unsigned short']],
            'FreeBackTraceIndex': [0x2, ['unsigned short']],
        },
    ],
    '_PROC_PERF_HISTORY_ENTRY': [
        0x6,
        {
            'Utility': [0x0, ['unsigned short']],
            'AffinitizedUtility': [0x2, ['unsigned short']],
            'Frequency': [0x4, ['unsigned char']],
            'Reserved': [0x5, ['unsigned char']],
        },
    ],
    '_POP_FX_COMPONENT': [
        0xB8,
        {
            'Id': [0x0, ['_GUID']],
            'Index': [0x10, ['unsigned long']],
            'WorkOrder': [0x14, ['_POP_FX_WORK_ORDER']],
            'Device': [0x30, ['pointer', ['_POP_FX_DEVICE']]],
            'Flags': [0x34, ['_POP_FX_COMPONENT_FLAGS']],
            'Resident': [0x3C, ['long']],
            'ActiveEvent': [0x40, ['_KEVENT']],
            'IdleLock': [0x50, ['unsigned long']],
            'IdleConditionComplete': [0x54, ['long']],
            'IdleStateComplete': [0x58, ['long']],
            'IdleStamp': [0x60, ['unsigned long long']],
            'CurrentIdleState': [0x68, ['unsigned long']],
            'IdleStateCount': [0x6C, ['unsigned long']],
            'IdleStates': [0x70, ['pointer', ['_POP_FX_IDLE_STATE']]],
            'DeepestWakeableIdleState': [0x74, ['unsigned long']],
            'ProviderCount': [0x78, ['unsigned long']],
            'Providers': [0x7C, ['pointer', ['_POP_FX_PROVIDER']]],
            'IdleProviderCount': [0x80, ['unsigned long']],
            'DependentCount': [0x84, ['unsigned long']],
            'Dependents': [0x88, ['pointer', ['_POP_FX_DEPENDENT']]],
            'Accounting': [0x90, ['_POP_FX_ACCOUNTING']],
        },
    ],
    '_PEP_CRASHDUMP_INFORMATION': [
        0x8,
        {
            'DeviceHandle': [0x0, ['pointer', ['PEPHANDLE__']]],
            'DeviceContext': [0x4, ['pointer', ['void']]],
        },
    ],
    '_POP_FX_DRIVER_CALLBACKS': [
        0x1C,
        {
            'ComponentActive': [0x0, ['pointer', ['void']]],
            'ComponentIdle': [0x4, ['pointer', ['void']]],
            'ComponentIdleState': [0x8, ['pointer', ['void']]],
            'DevicePowerRequired': [0xC, ['pointer', ['void']]],
            'DevicePowerNotRequired': [0x10, ['pointer', ['void']]],
            'PowerControl': [0x14, ['pointer', ['void']]],
            'ComponentCriticalTransition': [0x18, ['pointer', ['void']]],
        },
    ],
    '_PROVIDER_BINARY_ENTRY': [
        0x2C,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'ConsumersNotified': [0x8, ['unsigned char']],
            'Spare': [0x9, ['array', 3, ['unsigned char']]],
            'DebugIdSize': [0xC, ['unsigned long']],
            'DebugId': [0x10, ['_CVDD']],
        },
    ],
    '_VI_DEADLOCK_GLOBALS': [
        0x40F0,
        {
            'TimeAcquire': [0x0, ['long long']],
            'TimeRelease': [0x8, ['long long']],
            'ResourceDatabase': [0x10, ['pointer', ['_LIST_ENTRY']]],
            'ResourceDatabaseCount': [0x14, ['unsigned long']],
            'ResourceAddressRange': [
                0x18,
                ['array', 1023, ['_VF_ADDRESS_RANGE']],
            ],
            'ThreadDatabase': [0x2010, ['pointer', ['_LIST_ENTRY']]],
            'ThreadDatabaseCount': [0x2014, ['unsigned long']],
            'ThreadAddressRange': [
                0x2018,
                ['array', 1023, ['_VF_ADDRESS_RANGE']],
            ],
            'AllocationFailures': [0x4010, ['unsigned long']],
            'NodesTrimmedBasedOnAge': [0x4014, ['unsigned long']],
            'NodesTrimmedBasedOnCount': [0x4018, ['unsigned long']],
            'NodesSearched': [0x401C, ['unsigned long']],
            'MaxNodesSearched': [0x4020, ['unsigned long']],
            'SequenceNumber': [0x4024, ['unsigned long']],
            'RecursionDepthLimit': [0x4028, ['unsigned long']],
            'SearchedNodesLimit': [0x402C, ['unsigned long']],
            'DepthLimitHits': [0x4030, ['unsigned long']],
            'SearchLimitHits': [0x4034, ['unsigned long']],
            'StackLimitHits': [0x4038, ['unsigned long']],
            'ABC_ACB_Skipped': [0x403C, ['unsigned long']],
            'OutOfOrderReleases': [0x4040, ['unsigned long']],
            'NodesReleasedOutOfOrder': [0x4044, ['unsigned long']],
            'TotalReleases': [0x4048, ['unsigned long']],
            'RootNodesDeleted': [0x404C, ['unsigned long']],
            'ForgetHistoryCounter': [0x4050, ['unsigned long']],
            'Instigator': [0x4054, ['pointer', ['void']]],
            'NumberOfParticipants': [0x4058, ['unsigned long']],
            'Participant': [
                0x405C,
                ['array', 32, ['pointer', ['_VI_DEADLOCK_NODE']]],
            ],
            'ChildrenCountWatermark': [0x40DC, ['long']],
            'StackType': [
                0x40E0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'BugcheckStackLimits',
                            1: 'DPCStackLimits',
                            2: 'ExpandedStackLimits',
                            3: 'NormalStackLimits',
                            4: 'Win32kStackLimits',
                            5: 'SwapBusyStackLimits',
                            6: 'IsrStackLimits',
                            7: 'MaximumStackLimits',
                        },
                    ),
                ],
            ],
            'StackLowLimit': [0x40E4, ['unsigned long']],
            'StackHighLimit': [0x40E8, ['unsigned long']],
        },
    ],
    '_KTM': [
        0x238,
        {
            'cookie': [0x0, ['unsigned long']],
            'Mutex': [0x4, ['_KMUTANT']],
            'State': [
                0x24,
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
            'NamespaceLink': [0x28, ['_KTMOBJECT_NAMESPACE_LINK']],
            'TmIdentity': [0x3C, ['_GUID']],
            'Flags': [0x4C, ['unsigned long']],
            'VolatileFlags': [0x50, ['unsigned long']],
            'LogFileName': [0x54, ['_UNICODE_STRING']],
            'LogFileObject': [0x5C, ['pointer', ['_FILE_OBJECT']]],
            'MarshallingContext': [0x60, ['pointer', ['void']]],
            'LogManagementContext': [0x64, ['pointer', ['void']]],
            'Transactions': [0x68, ['_KTMOBJECT_NAMESPACE']],
            'ResourceManagers': [0xC8, ['_KTMOBJECT_NAMESPACE']],
            'LsnOrderedMutex': [0x128, ['_KMUTANT']],
            'LsnOrderedList': [0x148, ['_LIST_ENTRY']],
            'CommitVirtualClock': [0x150, ['_LARGE_INTEGER']],
            'CommitVirtualClockMutex': [0x158, ['_FAST_MUTEX']],
            'BaseLsn': [0x178, ['_CLS_LSN']],
            'CurrentReadLsn': [0x180, ['_CLS_LSN']],
            'LastRecoveredLsn': [0x188, ['_CLS_LSN']],
            'TmRmHandle': [0x190, ['pointer', ['void']]],
            'TmRm': [0x194, ['pointer', ['_KRESOURCEMANAGER']]],
            'LogFullNotifyEvent': [0x198, ['_KEVENT']],
            'CheckpointWorkItem': [0x1A8, ['_WORK_QUEUE_ITEM']],
            'CheckpointTargetLsn': [0x1B8, ['_CLS_LSN']],
            'LogFullCompletedWorkItem': [0x1C0, ['_WORK_QUEUE_ITEM']],
            'LogWriteResource': [0x1D0, ['_ERESOURCE']],
            'LogFlags': [0x208, ['unsigned long']],
            'LogFullStatus': [0x20C, ['long']],
            'RecoveryStatus': [0x210, ['long']],
            'LastCheckBaseLsn': [0x218, ['_CLS_LSN']],
            'RestartOrderedList': [0x220, ['_LIST_ENTRY']],
            'OfflineWorkItem': [0x228, ['_WORK_QUEUE_ITEM']],
        },
    ],
    '_VF_BTS_RECORD': [
        0xC,
        {
            'JumpedFrom': [0x0, ['pointer', ['void']]],
            'JumpedTo': [0x4, ['pointer', ['void']]],
            'Unused1': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Predicted': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Unused2': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_KTRANSACTION': [
        0x1E0,
        {
            'OutcomeEvent': [0x0, ['_KEVENT']],
            'cookie': [0x10, ['unsigned long']],
            'Mutex': [0x14, ['_KMUTANT']],
            'TreeTx': [0x34, ['pointer', ['_KTRANSACTION']]],
            'GlobalNamespaceLink': [0x38, ['_KTMOBJECT_NAMESPACE_LINK']],
            'TmNamespaceLink': [0x4C, ['_KTMOBJECT_NAMESPACE_LINK']],
            'UOW': [0x60, ['_GUID']],
            'State': [
                0x70,
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
            'Flags': [0x74, ['unsigned long']],
            'EnlistmentHead': [0x78, ['_LIST_ENTRY']],
            'EnlistmentCount': [0x80, ['unsigned long']],
            'RecoverableEnlistmentCount': [0x84, ['unsigned long']],
            'PrePrepareRequiredEnlistmentCount': [0x88, ['unsigned long']],
            'PrepareRequiredEnlistmentCount': [0x8C, ['unsigned long']],
            'OutcomeRequiredEnlistmentCount': [0x90, ['unsigned long']],
            'PendingResponses': [0x94, ['unsigned long']],
            'SuperiorEnlistment': [0x98, ['pointer', ['_KENLISTMENT']]],
            'LastLsn': [0xA0, ['_CLS_LSN']],
            'PromotedEntry': [0xA8, ['_LIST_ENTRY']],
            'PromoterTransaction': [0xB0, ['pointer', ['_KTRANSACTION']]],
            'PromotePropagation': [0xB4, ['pointer', ['void']]],
            'IsolationLevel': [0xB8, ['unsigned long']],
            'IsolationFlags': [0xBC, ['unsigned long']],
            'Timeout': [0xC0, ['_LARGE_INTEGER']],
            'Description': [0xC8, ['_UNICODE_STRING']],
            'RollbackThread': [0xD0, ['pointer', ['_KTHREAD']]],
            'RollbackWorkItem': [0xD4, ['_WORK_QUEUE_ITEM']],
            'RollbackDpc': [0xE4, ['_KDPC']],
            'RollbackTimer': [0x108, ['_KTIMER']],
            'LsnOrderedEntry': [0x130, ['_LIST_ENTRY']],
            'Outcome': [
                0x138,
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
            'Tm': [0x13C, ['pointer', ['_KTM']]],
            'CommitReservation': [0x140, ['long long']],
            'TransactionHistory': [
                0x148,
                ['array', 10, ['_KTRANSACTION_HISTORY']],
            ],
            'TransactionHistoryCount': [0x198, ['unsigned long']],
            'DTCPrivateInformation': [0x19C, ['pointer', ['void']]],
            'DTCPrivateInformationLength': [0x1A0, ['unsigned long']],
            'DTCPrivateInformationMutex': [0x1A4, ['_KMUTANT']],
            'PromotedTxSelfHandle': [0x1C4, ['pointer', ['void']]],
            'PendingPromotionCount': [0x1C8, ['unsigned long']],
            'PromotionCompletedEvent': [0x1CC, ['_KEVENT']],
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
            'PipelineReadAheads': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'Available': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_CM_KCB_UOW': [
        0x38,
        {
            'TransactionListEntry': [0x0, ['_LIST_ENTRY']],
            'KCBLock': [0x8, ['pointer', ['_CM_INTENT_LOCK']]],
            'KeyLock': [0xC, ['pointer', ['_CM_INTENT_LOCK']]],
            'KCBListEntry': [0x10, ['_LIST_ENTRY']],
            'KeyControlBlock': [0x18, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'Transaction': [0x1C, ['pointer', ['_CM_TRANS']]],
            'UoWState': [0x20, ['unsigned long']],
            'ActionType': [
                0x24,
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
                0x28,
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
            'ChildKCB': [0x30, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'VolatileKeyCell': [0x30, ['unsigned long']],
            'OldValueCell': [0x30, ['unsigned long']],
            'NewValueCell': [0x34, ['unsigned long']],
            'UserFlags': [0x30, ['unsigned long']],
            'LastWriteTime': [0x30, ['_LARGE_INTEGER']],
            'TxSecurityCell': [0x30, ['unsigned long']],
            'OldChildKCB': [0x30, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'NewChildKCB': [0x34, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'OtherChildKCB': [0x30, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'ThisVolatileKeyCell': [0x34, ['unsigned long']],
        },
    ],
    '_KPROCESSOR_STATE': [
        0x320,
        {
            'ContextFrame': [0x0, ['_CONTEXT']],
            'SpecialRegisters': [0x2CC, ['_KSPECIAL_REGISTERS']],
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
            'Spare': [
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
                        end_bit=38,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=38,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_PROCESSOR_IDLE_CONSTRAINTS': [
        0x40,
        {
            'TotalTime': [0x0, ['unsigned long long']],
            'IdleTime': [0x8, ['unsigned long long']],
            'ExpectedIdleDuration': [0x10, ['unsigned long long']],
            'MaxIdleDuration': [0x18, ['unsigned long long']],
            'OverrideState': [0x20, ['unsigned long']],
            'TimeCheck': [0x24, ['unsigned long']],
            'PromotePercent': [0x28, ['unsigned char']],
            'DemotePercent': [0x29, ['unsigned char']],
            'Parked': [0x2A, ['unsigned char']],
            'Interruptible': [0x2B, ['unsigned char']],
            'PlatformIdle': [0x2C, ['unsigned char']],
            'IRHints': [0x30, ['unsigned long']],
            'IRTruncatedHints': [0x34, ['unsigned long']],
            'ExpectedWakeReason': [0x38, ['unsigned char']],
        },
    ],
    '_VF_WATCHDOG_IRP': [
        0x14,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'Irp': [0x8, ['pointer', ['_IRP']]],
            'DueTickCount': [0xC, ['unsigned long']],
            'Inserted': [0x10, ['unsigned char']],
            'TrackedStackLocation': [0x11, ['unsigned char']],
            'CancelTimeoutTicks': [0x12, ['unsigned short']],
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
            'Large': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'TrimBehind': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'Inherit': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'NoValidationNeeded': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
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
    '__unnamed_252b': [
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
    '__unnamed_252d': [
        0x8,
        {
            's1': [0x0, ['__unnamed_252b']],
            'Value': [0x0, ['long long']],
        },
    ],
    '_ALPC_COMPLETION_LIST_STATE': [
        0x8,
        {
            'u1': [0x0, ['__unnamed_252d']],
        },
    ],
    '_CM_KEY_SECURITY_CACHE': [
        0x2C,
        {
            'Cell': [0x0, ['unsigned long']],
            'ConvKey': [0x4, ['unsigned long']],
            'List': [0x8, ['_LIST_ENTRY']],
            'DescriptorLength': [0x10, ['unsigned long']],
            'RealRefCount': [0x14, ['unsigned long']],
            'Descriptor': [0x18, ['_SECURITY_DESCRIPTOR_RELATIVE']],
        },
    ],
    '_CM_NAME_HASH': [
        0xC,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x4, ['pointer', ['_CM_NAME_HASH']]],
            'NameLength': [0x8, ['unsigned short']],
            'Name': [0xA, ['array', 1, ['wchar']]],
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
    '_PO_IRP_QUEUE': [
        0x8,
        {
            'CurrentIrp': [0x0, ['pointer', ['_IRP']]],
            'PendingIrpList': [0x4, ['pointer', ['_IRP']]],
        },
    ],
    '__unnamed_253f': [
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
        0x6C,
        {
            'Parent': [0x0, ['pointer', ['_VI_DEADLOCK_NODE']]],
            'ChildrenList': [0x4, ['_LIST_ENTRY']],
            'SiblingsList': [0xC, ['_LIST_ENTRY']],
            'ResourceList': [0x14, ['_LIST_ENTRY']],
            'FreeListEntry': [0x14, ['_LIST_ENTRY']],
            'Root': [0x1C, ['pointer', ['_VI_DEADLOCK_RESOURCE']]],
            'ThreadEntry': [0x20, ['pointer', ['_VI_DEADLOCK_THREAD']]],
            'u1': [0x24, ['__unnamed_253f']],
            'ChildrenCount': [0x28, ['long']],
            'StackTrace': [0x2C, ['array', 8, ['pointer', ['void']]]],
            'ParentStackTrace': [0x4C, ['array', 8, ['pointer', ['void']]]],
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
        0x60,
        {
            'Table': [0x0, ['_RTL_AVL_TABLE']],
            'Mutex': [0x38, ['_KMUTANT']],
            'LinksOffset': [0x58, ['unsigned short']],
            'GuidOffset': [0x5A, ['unsigned short']],
            'Expired': [0x5C, ['unsigned char']],
        },
    ],
    '_LPCP_PORT_QUEUE': [
        0x10,
        {
            'NonPagedPortQueue': [
                0x0,
                ['pointer', ['_LPCP_NONPAGED_PORT_QUEUE']],
            ],
            'Semaphore': [0x4, ['pointer', ['_KSEMAPHORE']]],
            'ReceiveHead': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_CM_KEY_REFERENCE': [
        0x8,
        {
            'KeyCell': [0x0, ['unsigned long']],
            'KeyHive': [0x4, ['pointer', ['_HHIVE']]],
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
        0x8,
        {
            'Stream': [0x0, ['pointer', ['void']]],
            'Detail': [0x4, ['unsigned long']],
        },
    ],
    '_EVENT_HEADER_EXTENDED_DATA_ITEM': [
        0x10,
        {
            'Reserved1': [0x0, ['unsigned short']],
            'ExtType': [0x2, ['unsigned short']],
            'Linkage': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'Reserved2': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=1, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'DataSize': [0x6, ['unsigned short']],
            'DataPtr': [0x8, ['unsigned long long']],
        },
    ],
    '_VF_ADDRESS_RANGE': [
        0x8,
        {
            'Start': [0x0, ['pointer', ['unsigned char']]],
            'End': [0x4, ['pointer', ['unsigned char']]],
        },
    ],
    '_OBJECT_SYMBOLIC_LINK': [
        0x18,
        {
            'CreationTime': [0x0, ['_LARGE_INTEGER']],
            'LinkTarget': [0x8, ['_UNICODE_STRING']],
            'DosDeviceDriveIndex': [0x10, ['unsigned long']],
        },
    ],
    '_LPCP_NONPAGED_PORT_QUEUE': [
        0x18,
        {
            'Semaphore': [0x0, ['_KSEMAPHORE']],
            'BackPointer': [0x14, ['pointer', ['_LPCP_PORT_OBJECT']]],
        },
    ],
    '_THERMAL_POLICY': [
        0x14,
        {
            'Version': [0x0, ['unsigned long']],
            'WaitForUpdate': [0x4, ['unsigned char']],
            'Hibernate': [0x5, ['unsigned char']],
            'Critical': [0x6, ['unsigned char']],
            'ActivationReasons': [0x8, ['unsigned long']],
            'PassiveLimit': [0xC, ['unsigned long']],
            'ActiveLevel': [0x10, ['unsigned long']],
        },
    ],
    '_KRESOURCEMANAGER_COMPLETION_BINDING': [
        0x14,
        {
            'NotificationListHead': [0x0, ['_LIST_ENTRY']],
            'Port': [0x8, ['pointer', ['void']]],
            'Key': [0xC, ['unsigned long']],
            'BindingProcess': [0x10, ['pointer', ['_EPROCESS']]],
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
        0x204,
        {
            'SpinLock': [0x0, ['unsigned long']],
            'HashTable': [0x4, ['array', 64, ['_LIST_ENTRY']]],
        },
    ],
    '_ARBITER_ALTERNATIVE': [
        0x38,
        {
            'Minimum': [0x0, ['unsigned long long']],
            'Maximum': [0x8, ['unsigned long long']],
            'Length': [0x10, ['unsigned long long']],
            'Alignment': [0x18, ['unsigned long long']],
            'Priority': [0x20, ['long']],
            'Flags': [0x24, ['unsigned long']],
            'Descriptor': [0x28, ['pointer', ['_IO_RESOURCE_DESCRIPTOR']]],
            'Reserved': [0x2C, ['array', 3, ['unsigned long']]],
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
        0x38,
        {
            'ExportedImageInformation': [0x0, ['_SECTION_IMAGE_INFORMATION']],
            'InternalImageInformation': [
                0x30,
                ['_MI_EXTRA_IMAGE_INFORMATION'],
            ],
        },
    ],
    '_STACK_TABLE': [
        0x8040,
        {
            'NumStackTraces': [0x0, ['unsigned short']],
            'TraceCapacity': [0x2, ['unsigned short']],
            'StackTrace': [
                0x4,
                ['array', 16, ['pointer', ['_OBJECT_REF_TRACE']]],
            ],
            'StackTableHash': [0x44, ['array', 16381, ['unsigned short']]],
        },
    ],
    '_CM_INDEX_HINT_BLOCK': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'HashKey': [0x4, ['array', 1, ['unsigned long']]],
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
    '_ETW_GUID_ENTRY': [
        0x160,
        {
            'GuidList': [0x0, ['_LIST_ENTRY']],
            'RefCount': [0x8, ['long']],
            'Guid': [0xC, ['_GUID']],
            'RegListHead': [0x1C, ['_LIST_ENTRY']],
            'SecurityDescriptor': [0x24, ['pointer', ['void']]],
            'LastEnable': [0x28, ['_ETW_LAST_ENABLE_INFO']],
            'MatchId': [0x28, ['unsigned long long']],
            'ProviderEnableInfo': [0x38, ['_TRACE_ENABLE_INFO']],
            'EnableInfo': [0x58, ['array', 8, ['_TRACE_ENABLE_INFO']]],
            'FilterData': [0x158, ['pointer', ['_ETW_FILTER_HEADER']]],
        },
    ],
    '_DEFERRED_WRITE': [
        0x24,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteSize': [0x2, ['short']],
            'FileObject': [0x4, ['pointer', ['_FILE_OBJECT']]],
            'BytesToWrite': [0x8, ['unsigned long']],
            'DeferredWriteLinks': [0xC, ['_LIST_ENTRY']],
            'Event': [0x14, ['pointer', ['_KEVENT']]],
            'PostRoutine': [0x18, ['pointer', ['void']]],
            'Context1': [0x1C, ['pointer', ['void']]],
            'Context2': [0x20, ['pointer', ['void']]],
        },
    ],
    '__unnamed_259b': [
        0x4,
        {
            'DeviceNumber': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'FunctionNumber': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_259d': [
        0x4,
        {
            'bits': [0x0, ['__unnamed_259b']],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_WHEA_PCI_SLOT_NUMBER': [
        0x4,
        {
            'u': [0x0, ['__unnamed_259d']],
        },
    ],
    '_ARBITER_ORDERING_LIST': [
        0x8,
        {
            'Count': [0x0, ['unsigned short']],
            'Maximum': [0x2, ['unsigned short']],
            'Orderings': [0x4, ['pointer', ['_ARBITER_ORDERING']]],
        },
    ],
    '_SECTION_IMAGE_INFORMATION': [
        0x30,
        {
            'TransferAddress': [0x0, ['pointer', ['void']]],
            'ZeroBits': [0x4, ['unsigned long']],
            'MaximumStackSize': [0x8, ['unsigned long']],
            'CommittedStackSize': [0xC, ['unsigned long']],
            'SubSystemType': [0x10, ['unsigned long']],
            'SubSystemMinorVersion': [0x14, ['unsigned short']],
            'SubSystemMajorVersion': [0x16, ['unsigned short']],
            'SubSystemVersion': [0x14, ['unsigned long']],
            'GpValue': [0x18, ['unsigned long']],
            'ImageCharacteristics': [0x1C, ['unsigned short']],
            'DllCharacteristics': [0x1E, ['unsigned short']],
            'Machine': [0x20, ['unsigned short']],
            'ImageContainsCode': [0x22, ['unsigned char']],
            'ImageFlags': [0x23, ['unsigned char']],
            'ComPlusNativeReady': [
                0x23,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ComPlusILOnly': [
                0x23,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'ImageDynamicallyRelocated': [
                0x23,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'ImageMappedFlat': [
                0x23,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'BaseBelow4gb': [
                0x23,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x23,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'LoaderFlags': [0x24, ['unsigned long']],
            'ImageFileSize': [0x28, ['unsigned long']],
            'CheckSum': [0x2C, ['unsigned long']],
        },
    ],
    '_VF_AVL_TABLE': [
        0x80,
        {
            'RtlTable': [0x0, ['_RTL_AVL_TABLE']],
            'ReservedNode': [0x38, ['pointer', ['_VF_AVL_TREE_NODE']]],
            'NodeToFree': [0x3C, ['pointer', ['void']]],
            'Lock': [0x40, ['long']],
        },
    ],
    '_XPF_MC_BANK_FLAGS': [
        0x1,
        {
            'ClearOnInitializationRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ControlDataRW': [
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
    '_TOKEN_AUDIT_POLICY': [
        0x1D,
        {
            'PerUserPolicy': [0x0, ['array', 29, ['unsigned char']]],
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
    '__unnamed_25b1': [
        0x8,
        {
            'EndingOffset': [0x0, ['pointer', ['_LARGE_INTEGER']]],
            'ResourceToRelease': [
                0x4,
                ['pointer', ['pointer', ['_ERESOURCE']]],
            ],
        },
    ],
    '__unnamed_25b3': [
        0x4,
        {
            'ResourceToRelease': [0x0, ['pointer', ['_ERESOURCE']]],
        },
    ],
    '__unnamed_25b7': [
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
    '__unnamed_25bb': [
        0x8,
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
            'SafeToRecurse': [0x4, ['unsigned char']],
        },
    ],
    '__unnamed_25bd': [
        0x14,
        {
            'Argument1': [0x0, ['pointer', ['void']]],
            'Argument2': [0x4, ['pointer', ['void']]],
            'Argument3': [0x8, ['pointer', ['void']]],
            'Argument4': [0xC, ['pointer', ['void']]],
            'Argument5': [0x10, ['pointer', ['void']]],
        },
    ],
    '_FS_FILTER_PARAMETERS': [
        0x14,
        {
            'AcquireForModifiedPageWriter': [0x0, ['__unnamed_25b1']],
            'ReleaseForModifiedPageWriter': [0x0, ['__unnamed_25b3']],
            'AcquireForSectionSynchronization': [0x0, ['__unnamed_25b7']],
            'NotifyStreamFileObject': [0x0, ['__unnamed_25bb']],
            'Others': [0x0, ['__unnamed_25bd']],
        },
    ],
    '_MI_SESSION_DRIVER_UNLOAD': [
        0x4,
        {
            'Function': [0x0, ['pointer', ['void']]],
            'FunctionValue': [0x0, ['unsigned long']],
        },
    ],
    '_PPM_SELECTION_STATISTICS': [
        0x68,
        {
            'PlatformOnlyCount': [0x0, ['unsigned long long']],
            'PreVetoCount': [0x8, ['unsigned long long']],
            'VetoCount': [0x10, ['unsigned long long']],
            'IdleDurationCount': [0x18, ['unsigned long long']],
            'LatencyCount': [0x20, ['unsigned long long']],
            'InterruptibleCount': [0x28, ['unsigned long long']],
            'DeviceDependencyCount': [0x30, ['unsigned long long']],
            'ProcessorDependencyCount': [0x38, ['unsigned long long']],
            'WrongProcessorCount': [0x40, ['unsigned long long']],
            'LegacyOverrideCount': [0x48, ['unsigned long long']],
            'CstateCheckCount': [0x50, ['unsigned long long']],
            'NoCStateCount': [0x58, ['unsigned long long']],
            'SelectedCount': [0x60, ['unsigned long long']],
        },
    ],
    '_LDR_SERVICE_TAG_RECORD': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_LDR_SERVICE_TAG_RECORD']]],
            'ServiceTag': [0x4, ['unsigned long']],
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
    '_HIVE_WAIT_PACKET': [
        0x18,
        {
            'WakeEvent': [0x0, ['_KEVENT']],
            'Status': [0x10, ['long']],
            'Next': [0x14, ['pointer', ['_HIVE_WAIT_PACKET']]],
        },
    ],
    '__unnamed_25cc': [
        0x4,
        {
            'PollInterval': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_25ce': [
        0x18,
        {
            'PollInterval': [0x0, ['unsigned long']],
            'Vector': [0x4, ['unsigned long']],
            'SwitchToPollingThreshold': [0x8, ['unsigned long']],
            'SwitchToPollingWindow': [0xC, ['unsigned long']],
            'ErrorThreshold': [0x10, ['unsigned long']],
            'ErrorThresholdWindow': [0x14, ['unsigned long']],
        },
    ],
    '__unnamed_25d0': [
        0x18,
        {
            'Polled': [0x0, ['__unnamed_25cc']],
            'Interrupt': [0x0, ['__unnamed_25ce']],
            'LocalInterrupt': [0x0, ['__unnamed_25ce']],
            'Sci': [0x0, ['__unnamed_25ce']],
            'Nmi': [0x0, ['__unnamed_25ce']],
        },
    ],
    '_WHEA_NOTIFICATION_DESCRIPTOR': [
        0x1C,
        {
            'Type': [0x0, ['unsigned char']],
            'Length': [0x1, ['unsigned char']],
            'Flags': [0x2, ['_WHEA_NOTIFICATION_FLAGS']],
            'u': [0x4, ['__unnamed_25d0']],
        },
    ],
    '_POP_HIBER_CONTEXT': [
        0x120,
        {
            'Reset': [0x0, ['unsigned char']],
            'HiberFlags': [0x1, ['unsigned char']],
            'WroteHiberFile': [0x2, ['unsigned char']],
            'VerifyKernelPhaseOnResume': [0x3, ['unsigned char']],
            'KernelPhaseVerificationActive': [0x4, ['unsigned char']],
            'InitializationFinished': [0x5, ['unsigned char']],
            'NextTableLockHeld': [0x8, ['long']],
            'BootPhaseFinishedBarrier': [0xC, ['long']],
            'KernelResumeFinishedBarrier': [0x10, ['long']],
            'MapFrozen': [0x14, ['unsigned char']],
            'DiscardMap': [0x18, ['_RTL_BITMAP']],
            'KernelPhaseMap': [0x18, ['_RTL_BITMAP']],
            'BootPhaseMap': [0x20, ['_RTL_BITMAP']],
            'ClonedRanges': [0x28, ['_LIST_ENTRY']],
            'ClonedRangeCount': [0x30, ['unsigned long']],
            'ClonedPageCount': [0x38, ['unsigned long long']],
            'CurrentMap': [0x40, ['pointer', ['_RTL_BITMAP']]],
            'NextCloneRange': [0x44, ['pointer', ['_LIST_ENTRY']]],
            'NextPreserve': [0x48, ['unsigned long']],
            'LoaderMdl': [0x4C, ['pointer', ['_MDL']]],
            'AllocatedMdl': [0x50, ['pointer', ['_MDL']]],
            'PagesOut': [0x58, ['unsigned long long']],
            'IoPages': [0x60, ['pointer', ['void']]],
            'IoPagesCount': [0x64, ['unsigned long']],
            'CurrentMcb': [0x68, ['pointer', ['void']]],
            'DumpStack': [0x6C, ['pointer', ['_DUMP_STACK_CONTEXT']]],
            'WakeState': [0x70, ['pointer', ['_KPROCESSOR_STATE']]],
            'IoProgress': [0x74, ['unsigned long']],
            'Status': [0x78, ['long']],
            'GraphicsProc': [0x7C, ['unsigned long']],
            'MemoryImage': [0x80, ['pointer', ['PO_MEMORY_IMAGE']]],
            'PerformanceStats': [0x84, ['pointer', ['unsigned long']]],
            'BootLoaderLogMdl': [0x88, ['pointer', ['_MDL']]],
            'SiLogOffset': [0x8C, ['unsigned long']],
            'FirmwareRuntimeInformationMdl': [0x90, ['pointer', ['_MDL']]],
            'FirmwareRuntimeInformationVa': [0x94, ['pointer', ['void']]],
            'ResumeContext': [0x98, ['pointer', ['void']]],
            'ResumeContextPages': [0x9C, ['unsigned long']],
            'ProcessorCount': [0xA0, ['unsigned long']],
            'ProcessorContext': [
                0xA4,
                ['pointer', ['_POP_PER_PROCESSOR_CONTEXT']],
            ],
            'ProdConsBuffer': [0xA8, ['pointer', ['unsigned char']]],
            'ProdConsSize': [0xAC, ['unsigned long']],
            'MaxDataPages': [0xB0, ['unsigned long']],
            'ExtraBuffer': [0xB4, ['pointer', ['void']]],
            'ExtraBufferSize': [0xB8, ['unsigned long']],
            'ExtraMapVa': [0xBC, ['pointer', ['void']]],
            'BitlockerKeyPFN': [0xC0, ['unsigned long']],
            'IoInfo': [0xC8, ['_POP_IO_INFO']],
            'HardwareConfigurationSignature': [0x118, ['unsigned long']],
        },
    ],
    '_OBJECT_REF_TRACE': [
        0x40,
        {
            'StackTrace': [0x0, ['array', 16, ['pointer', ['void']]]],
        },
    ],
    '_CVDD': [
        0x1C,
        {
            'Signature': [0x0, ['unsigned long']],
            'NB10': [0x0, ['_NB10']],
            'RsDs': [0x0, ['_RSDS']],
        },
    ],
    '_OBJECT_NAME_INFORMATION': [
        0x8,
        {
            'Name': [0x0, ['_UNICODE_STRING']],
        },
    ],
    '_WHEA_AER_BRIDGE_DESCRIPTOR': [
        0x2C,
        {
            'Type': [0x0, ['unsigned short']],
            'Enabled': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
            'BusNumber': [0x4, ['unsigned long']],
            'Slot': [0x8, ['_WHEA_PCI_SLOT_NUMBER']],
            'DeviceControl': [0xC, ['unsigned short']],
            'Flags': [0xE, ['_AER_BRIDGE_DESCRIPTOR_FLAGS']],
            'UncorrectableErrorMask': [0x10, ['unsigned long']],
            'UncorrectableErrorSeverity': [0x14, ['unsigned long']],
            'CorrectableErrorMask': [0x18, ['unsigned long']],
            'AdvancedCapsAndControl': [0x1C, ['unsigned long']],
            'SecondaryUncorrectableErrorMask': [0x20, ['unsigned long']],
            'SecondaryUncorrectableErrorSev': [0x24, ['unsigned long']],
            'SecondaryCapsAndControl': [0x28, ['unsigned long']],
        },
    ],
    '_PCW_COUNTER_INFORMATION': [
        0x10,
        {
            'CounterMask': [0x0, ['unsigned long long']],
            'InstanceMask': [0x8, ['pointer', ['_UNICODE_STRING']]],
        },
    ],
    '_DUMP_STACK_CONTEXT': [
        0x100,
        {
            'Init': [0x0, ['_DUMP_INITIALIZATION_CONTEXT']],
            'PartitionOffset': [0xC0, ['_LARGE_INTEGER']],
            'DumpPointers': [0xC8, ['pointer', ['void']]],
            'PointersLength': [0xCC, ['unsigned long']],
            'ModulePrefix': [0xD0, ['pointer', ['unsigned short']]],
            'DriverList': [0xD4, ['_LIST_ENTRY']],
            'InitMsg': [0xDC, ['_STRING']],
            'ProgMsg': [0xE4, ['_STRING']],
            'DoneMsg': [0xEC, ['_STRING']],
            'FileObject': [0xF4, ['pointer', ['void']]],
            'UsageType': [
                0xF8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DeviceUsageTypeUndefined',
                            1: 'DeviceUsageTypePaging',
                            2: 'DeviceUsageTypeHibernation',
                            3: 'DeviceUsageTypeDumpFile',
                            4: 'DeviceUsageTypeBoot',
                            5: 'DeviceUsageTypePostDisplay',
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
    '_PPM_VETO_ACCOUNTING': [
        0xC,
        {
            'VetoPresent': [0x0, ['long']],
            'VetoListHead': [0x4, ['_LIST_ENTRY']],
        },
    ],
    '_POP_SHUTDOWN_BUG_CHECK': [
        0x24,
        {
            'InitiatingThread': [0x0, ['pointer', ['_ETHREAD']]],
            'InitiatingProcess': [0x4, ['pointer', ['_EPROCESS']]],
            'ThreadId': [0x8, ['pointer', ['void']]],
            'ProcessId': [0xC, ['pointer', ['void']]],
            'Code': [0x10, ['unsigned long']],
            'Parameter1': [0x14, ['unsigned long']],
            'Parameter2': [0x18, ['unsigned long']],
            'Parameter3': [0x1C, ['unsigned long']],
            'Parameter4': [0x20, ['unsigned long']],
        },
    ],
    '_NB10': [
        0x14,
        {
            'Signature': [0x0, ['unsigned long']],
            'Offset': [0x4, ['unsigned long']],
            'TimeStamp': [0x8, ['unsigned long']],
            'Age': [0xC, ['unsigned long']],
            'PdbName': [0x10, ['array', 1, ['unsigned char']]],
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
        0x20,
        {
            'CounterMask': [0x0, ['unsigned long long']],
            'InstanceMask': [0x8, ['pointer', ['_UNICODE_STRING']]],
            'InstanceId': [0xC, ['unsigned long']],
            'CollectMultiple': [0x10, ['unsigned char']],
            'Buffer': [0x14, ['pointer', ['_PCW_BUFFER']]],
            'CancelEvent': [0x18, ['pointer', ['_KEVENT']]],
        },
    ],
    '_MMVAD_FLAGS': [
        0x4,
        {
            'VadType': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'PreferredNode': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=14, native_type='unsigned long'),
                ],
            ],
            'NoChange': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'PrivateMemory': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'Teb': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'PrivateFixup': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'DeleteInProgress': [
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
    '_MI_VAD_EVENT_BLOCK': [
        0x18,
        {
            'Next': [0x0, ['pointer', ['_MI_VAD_EVENT_BLOCK']]],
            'WaitReason': [0x4, ['unsigned long']],
            'Gate': [0x8, ['_KGATE']],
            'SecureInfo': [0x8, ['_MMADDRESS_LIST']],
            'BitMap': [0x8, ['_RTL_BITMAP']],
            'InPageSupport': [0x8, ['pointer', ['_MMINPAGE_SUPPORT']]],
            'PhysicalMemory': [0x8, ['_MI_PHYSMEM_BLOCK']],
            'LargePage': [0x8, ['pointer', ['_MI_LARGEPAGE_MEMORY_INFO']]],
        },
    ],
    '__unnamed_260b': [
        0x10,
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
        0x10,
        {
            'Parameters': [0x0, ['__unnamed_260b']],
        },
    ],
    '__unnamed_260f': [
        0x8,
        {
            'idxRecord': [0x0, ['unsigned long']],
            'cidContainer': [0x4, ['unsigned long']],
        },
    ],
    '_CLS_LSN': [
        0x8,
        {
            'offset': [0x0, ['__unnamed_260f']],
            'ullOffset': [0x0, ['unsigned long long']],
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
    '_RSDS': [
        0x1C,
        {
            'Signature': [0x0, ['unsigned long']],
            'Guid': [0x4, ['_GUID']],
            'Age': [0x14, ['unsigned long']],
            'PdbName': [0x18, ['array', 1, ['unsigned char']]],
        },
    ],
    'PO_MEMORY_IMAGE': [
        0x2C8,
        {
            'Signature': [0x0, ['unsigned long']],
            'ImageType': [0x4, ['unsigned long']],
            'CheckSum': [0x8, ['unsigned long']],
            'LengthSelf': [0xC, ['unsigned long']],
            'PageSelf': [0x10, ['unsigned long']],
            'PageSize': [0x14, ['unsigned long']],
            'SystemTime': [0x18, ['_LARGE_INTEGER']],
            'InterruptTime': [0x20, ['unsigned long long']],
            'FeatureFlags': [0x28, ['unsigned long']],
            'HiberFlags': [0x2C, ['unsigned char']],
            'spare': [0x2D, ['array', 3, ['unsigned char']]],
            'NoHiberPtes': [0x30, ['unsigned long']],
            'HiberVa': [0x34, ['unsigned long']],
            'NoFreePages': [0x38, ['unsigned long']],
            'FreeMapCheck': [0x3C, ['unsigned long']],
            'WakeCheck': [0x40, ['unsigned long']],
            'NumPagesForLoader': [0x48, ['unsigned long long']],
            'FirstBootRestorePage': [0x50, ['unsigned long']],
            'FirstKernelRestorePage': [0x54, ['unsigned long']],
            'PerfInfo': [0x58, ['_PO_HIBER_PERF']],
            'FirmwareRuntimeInformationPages': [0x200, ['unsigned long']],
            'FirmwareRuntimeInformation': [
                0x204,
                ['array', 1, ['unsigned long']],
            ],
            'SiLogOffset': [0x208, ['unsigned long']],
            'NoBootLoaderLogPages': [0x20C, ['unsigned long']],
            'BootLoaderLogPages': [0x210, ['array', 24, ['unsigned long']]],
            'NotUsed': [0x270, ['unsigned long']],
            'ResumeContextCheck': [0x274, ['unsigned long']],
            'ResumeContextPages': [0x278, ['unsigned long']],
            'Hiberboot': [0x27C, ['unsigned char']],
            'HvCr3': [0x280, ['unsigned long long']],
            'HvEntryPoint': [0x288, ['unsigned long long']],
            'HvReservedTransitionAddress': [0x290, ['unsigned long long']],
            'HvReservedTransitionAddressSize': [0x298, ['unsigned long long']],
            'BootFlags': [0x2A0, ['unsigned long long']],
            'HalEntryPointPhysical': [0x2A8, ['unsigned long long']],
            'HighestPhysicalPage': [0x2B0, ['unsigned long']],
            'BitlockerKeyPfns': [0x2B4, ['array', 4, ['unsigned long']]],
            'HardwareSignature': [0x2C4, ['unsigned long']],
        },
    ],
    'BATTERY_REPORTING_SCALE': [
        0x8,
        {
            'Granularity': [0x0, ['unsigned long']],
            'Capacity': [0x4, ['unsigned long']],
        },
    ],
    '_RTL_ATOM_TABLE_REFERENCE': [
        0x10,
        {
            'LowBoxList': [0x0, ['_LIST_ENTRY']],
            'LowBoxID': [0x8, ['unsigned long']],
            'ReferenceCount': [0xC, ['unsigned short']],
            'Flags': [0xE, ['unsigned short']],
        },
    ],
    '_CURDIR': [
        0xC,
        {
            'DosPath': [0x0, ['_UNICODE_STRING']],
            'Handle': [0x8, ['pointer', ['void']]],
        },
    ],
    '_PO_HIBER_PERF': [
        0x1A8,
        {
            'HiberIoTicks': [0x0, ['unsigned long long']],
            'HiberIoCpuTicks': [0x8, ['unsigned long long']],
            'HiberInitTicks': [0x10, ['unsigned long long']],
            'HiberHiberFileTicks': [0x18, ['unsigned long long']],
            'HiberCompressTicks': [0x20, ['unsigned long long']],
            'HiberSharedBufferTicks': [0x28, ['unsigned long long']],
            'TotalHibernateTime': [0x30, ['_LARGE_INTEGER']],
            'POSTTime': [0x38, ['unsigned long']],
            'ResumeBootMgrTime': [0x3C, ['unsigned long']],
            'BootmgrUserInputTime': [0x40, ['unsigned long']],
            'ResumeAppTicks': [0x48, ['unsigned long long']],
            'ResumeAppStartTimestamp': [0x50, ['unsigned long long']],
            'ResumeLibraryInitTicks': [0x58, ['unsigned long long']],
            'ResumeInitTicks': [0x60, ['unsigned long long']],
            'ResumeRestoreImageStartTimestamp': [0x68, ['unsigned long long']],
            'ResumeHiberFileTicks': [0x70, ['unsigned long long']],
            'ResumeIoTicks': [0x78, ['unsigned long long']],
            'ResumeDecompressTicks': [0x80, ['unsigned long long']],
            'ResumeAllocateTicks': [0x88, ['unsigned long long']],
            'ResumeUserInOutTicks': [0x90, ['unsigned long long']],
            'ResumeMapTicks': [0x98, ['unsigned long long']],
            'ResumeUnmapTicks': [0xA0, ['unsigned long long']],
            'ResumeKernelSwitchTimestamp': [0xA8, ['unsigned long long']],
            'WriteLogDataTimestamp': [0xB0, ['unsigned long long']],
            'KernelReturnFromHandler': [0xB8, ['unsigned long long']],
            'TimeStampCounterAtSwitchTime': [0xC0, ['unsigned long long']],
            'HalTscOffset': [0xC8, ['unsigned long long']],
            'HvlTscOffset': [0xD0, ['unsigned long long']],
            'SleeperThreadEnd': [0xD8, ['unsigned long long']],
            'KernelReturnSystemPowerStateTimestamp': [
                0xE0,
                ['unsigned long long'],
            ],
            'IoBoundedness': [0xE8, ['unsigned long long']],
            'KernelDecompressTicks': [0xF0, ['unsigned long long']],
            'KernelIoTicks': [0xF8, ['unsigned long long']],
            'KernelCopyTicks': [0x100, ['unsigned long long']],
            'ReadCheckCount': [0x108, ['unsigned long long']],
            'KernelInitTicks': [0x110, ['unsigned long long']],
            'KernelResumeHiberFileTicks': [0x118, ['unsigned long long']],
            'KernelIoCpuTicks': [0x120, ['unsigned long long']],
            'KernelSharedBufferTicks': [0x128, ['unsigned long long']],
            'KernelAnimationTicks': [0x130, ['unsigned long long']],
            'AnimationStart': [0x138, ['_LARGE_INTEGER']],
            'AnimationStop': [0x140, ['_LARGE_INTEGER']],
            'DeviceResumeTime': [0x148, ['unsigned long']],
            'BootPagesProcessed': [0x150, ['unsigned long long']],
            'KernelPagesProcessed': [0x158, ['unsigned long long']],
            'BootBytesWritten': [0x160, ['unsigned long long']],
            'KernelBytesWritten': [0x168, ['unsigned long long']],
            'BootPagesWritten': [0x170, ['unsigned long long']],
            'KernelPagesWritten': [0x178, ['unsigned long long']],
            'BytesWritten': [0x180, ['unsigned long long']],
            'PagesWritten': [0x188, ['unsigned long']],
            'FileRuns': [0x18C, ['unsigned long']],
            'NoMultiStageResumeReason': [0x190, ['unsigned long']],
            'MaxHuffRatio': [0x194, ['unsigned long']],
            'AdjustedTotalResumeTime': [0x198, ['unsigned long long']],
            'ResumeCompleteTimestamp': [0x1A0, ['unsigned long long']],
        },
    ],
    '_POP_FX_PROVIDER': [
        0x8,
        {
            'Index': [0x0, ['unsigned long']],
            'Activating': [0x4, ['unsigned char']],
        },
    ],
    '_RTL_BALANCED_LINKS': [
        0x10,
        {
            'Parent': [0x0, ['pointer', ['_RTL_BALANCED_LINKS']]],
            'LeftChild': [0x4, ['pointer', ['_RTL_BALANCED_LINKS']]],
            'RightChild': [0x8, ['pointer', ['_RTL_BALANCED_LINKS']]],
            'Balance': [0xC, ['unsigned char']],
            'Reserved': [0xD, ['array', 3, ['unsigned char']]],
        },
    ],
    '_FREE_DISPLAY': [
        0x10,
        {
            'RealVectorSize': [0x0, ['unsigned long']],
            'Hint': [0x4, ['unsigned long']],
            'Display': [0x8, ['_RTL_BITMAP']],
        },
    ],
    '__unnamed_262b': [
        0x4,
        {
            'Flags': [0x0, ['_MMSECURE_FLAGS']],
            'FlagsLong': [0x0, ['unsigned long']],
            'StartVa': [0x0, ['pointer', ['void']]],
        },
    ],
    '_MMADDRESS_LIST': [
        0x8,
        {
            'u1': [0x0, ['__unnamed_262b']],
            'EndVa': [0x4, ['pointer', ['void']]],
        },
    ],
    '_MI_PHYSMEM_BLOCK': [
        0x4,
        {
            'IoTracker': [0x0, ['pointer', ['_MMIO_TRACKER']]],
        },
    ],
    '_POP_PER_PROCESSOR_CONTEXT': [
        0x70,
        {
            'UncompressedData': [0x0, ['pointer', ['unsigned char']]],
            'MappingVa': [0x4, ['pointer', ['void']]],
            'XpressEncodeWorkspace': [0x8, ['pointer', ['void']]],
            'CompressedDataBuffer': [0xC, ['pointer', ['unsigned char']]],
            'CopyTicks': [0x10, ['unsigned long long']],
            'CompressTicks': [0x18, ['unsigned long long']],
            'BytesCopied': [0x20, ['unsigned long long']],
            'PagesProcessed': [0x28, ['unsigned long long']],
            'DecompressTicks': [0x30, ['unsigned long long']],
            'ResumeCopyTicks': [0x38, ['unsigned long long']],
            'SharedBufferTicks': [0x40, ['unsigned long long']],
            'DecompressTicksByMethod': [
                0x48,
                ['array', 2, ['unsigned long long']],
            ],
            'DecompressSizeByMethod': [
                0x58,
                ['array', 2, ['unsigned long long']],
            ],
            'CompressCount': [0x68, ['unsigned long']],
            'HuffCompressCount': [0x6C, ['unsigned long']],
        },
    ],
    '_DEVICE_OBJECT_LIST_ENTRY': [
        0xC,
        {
            'DeviceObject': [0x0, ['pointer', ['_DEVICE_OBJECT']]],
            'RelationLevel': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'DeviceRelation',
                            1: 'Dependent',
                            2: 'DirectDescendant',
                        },
                    ),
                ],
            ],
            'Flags': [0x8, ['unsigned long']],
        },
    ],
    '_IO_REMOVE_LOCK': [
        0x18,
        {
            'Common': [0x0, ['_IO_REMOVE_LOCK_COMMON_BLOCK']],
        },
    ],
    '_POP_IO_INFO': [
        0x50,
        {
            'DumpMdl': [0x0, ['pointer', ['_MDL']]],
            'IoStatus': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'IoReady', 1: 'IoPending', 2: 'IoDone'},
                    ),
                ],
            ],
            'IoStartCount': [0x8, ['unsigned long long']],
            'IoBytesCompleted': [0x10, ['unsigned long long']],
            'IoBytesInProgress': [0x18, ['unsigned long long']],
            'RequestSize': [0x20, ['unsigned long long']],
            'IoLocation': [0x28, ['_LARGE_INTEGER']],
            'FileOffset': [0x30, ['unsigned long long']],
            'Buffer': [0x38, ['pointer', ['void']]],
            'AsyncCapable': [0x3C, ['unsigned char']],
            'BytesToRead': [0x40, ['unsigned long long']],
            'Pages': [0x48, ['unsigned long']],
        },
    ],
    '_LDRP_CSLIST': [
        0x4,
        {
            'Tail': [0x0, ['pointer', ['_SINGLE_LIST_ENTRY']]],
        },
    ],
    '_MMVIEW': [
        0x28,
        {
            'PteOffset': [0x0, ['unsigned long long']],
            'Entry': [0x8, ['unsigned long']],
            'u1': [0xC, ['_MMVIEW_CONTROL_AREA']],
            'ViewLinks': [0x10, ['_LIST_ENTRY']],
            'SessionViewVa': [0x18, ['pointer', ['void']]],
            'SessionId': [0x1C, ['unsigned long']],
            'SessionIdForGlobalSubsections': [0x20, ['unsigned long']],
        },
    ],
    '_AER_BRIDGE_DESCRIPTOR_FLAGS': [
        0x2,
        {
            'UncorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'UncorrectableErrorSeverityRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'CorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'AdvancedCapsAndControlRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'SecondaryUncorrectableErrorMaskRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'SecondaryUncorrectableErrorSevRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'SecondaryCapsAndControlRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=7, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AsUSHORT': [0x0, ['unsigned short']],
        },
    ],
    '_ETW_FILTER_HEADER': [
        0x24,
        {
            'FilterFlags': [0x0, ['long']],
            'PidFilter': [0x4, ['pointer', ['_ETW_FILTER_PID']]],
            'ExeFilter': [0x8, ['pointer', ['_ETW_FILTER_STRING_TOKEN']]],
            'PkgIdFilter': [0xC, ['pointer', ['_ETW_FILTER_STRING_TOKEN']]],
            'PkgAppIdFilter': [
                0x10,
                ['pointer', ['_ETW_FILTER_STRING_TOKEN']],
            ],
            'StackWalkFilter': [
                0x14,
                ['pointer', ['_ETW_PERFECT_HASH_FUNCTION']],
            ],
            'EventIdFilter': [
                0x18,
                ['pointer', ['_ETW_PERFECT_HASH_FUNCTION']],
            ],
            'PayloadFilter': [0x1C, ['pointer', ['_ETW_PAYLOAD_FILTER']]],
            'ProviderSideFilter': [
                0x20,
                ['pointer', ['_EVENT_FILTER_HEADER']],
            ],
        },
    ],
    '_ETW_PAYLOAD_FILTER': [
        0x58,
        {
            'RefCount': [0x0, ['long']],
            'PayloadFilter': [0x8, ['_AGGREGATED_PAYLOAD_FILTER']],
        },
    ],
    '_MMVIEW_CONTROL_AREA': [
        0x4,
        {
            'ControlArea': [0x0, ['pointer', ['_CONTROL_AREA']]],
            'Writable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ExceptionForInPageErrors': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'UsedForControlArea': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
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
            'LeakedPoolDeliberately': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Filler': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_RTL_CRITICAL_SECTION_DEBUG': [
        0x20,
        {
            'Type': [0x0, ['unsigned short']],
            'CreatorBackTraceIndex': [0x2, ['unsigned short']],
            'CriticalSection': [0x4, ['pointer', ['_RTL_CRITICAL_SECTION']]],
            'ProcessLocksList': [0x8, ['_LIST_ENTRY']],
            'EntryCount': [0x10, ['unsigned long']],
            'ContentionCount': [0x14, ['unsigned long']],
            'Flags': [0x18, ['unsigned long']],
            'CreatorBackTraceIndexHigh': [0x1C, ['unsigned short']],
            'SpareUSHORT': [0x1E, ['unsigned short']],
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
    '__unnamed_2661': [
        0x8,
        {
            'Gsiv': [0x0, ['unsigned long']],
            'WakeInterrupt': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_2663': [
        0x10,
        {
            'Address': [0x0, ['_LARGE_INTEGER']],
            'DataPayload': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_2666': [
        0x8,
        {
            'IntrInfo': [0x0, ['_INTERRUPT_HT_INTR_INFO']],
        },
    ],
    '__unnamed_266a': [
        0x4,
        {
            'DestinationMode': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'ApicDestinationModePhysical',
                            2: 'ApicDestinationModeLogicalFlat',
                            3: 'ApicDestinationModeLogicalClustered',
                            4: 'ApicDestinationModeUnknown',
                        },
                    ),
                ],
            ],
        },
    ],
    '_INTERRUPT_VECTOR_DATA': [
        0x40,
        {
            'Type': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'InterruptTypeControllerInput',
                            1: 'InterruptTypeXapicMessage',
                            2: 'InterruptTypeHypertransport',
                            3: 'InterruptTypeMessageRequest',
                        },
                    ),
                ],
            ],
            'Vector': [0x4, ['unsigned long']],
            'Irql': [0x8, ['unsigned char']],
            'Polarity': [
                0xC,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'InterruptPolarityUnknown',
                            1: 'InterruptRisingEdge',
                            2: 'InterruptFallingEdge',
                            3: 'InterruptActiveBothTriggerLow',
                            4: 'InterruptActiveBothTriggerHigh',
                        },
                    ),
                ],
            ],
            'Mode': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'LevelSensitive', 1: 'Latched'},
                    ),
                ],
            ],
            'TargetProcessors': [0x14, ['_GROUP_AFFINITY']],
            'IntRemapInfo': [0x20, ['_INTERRUPT_REMAPPING_INFO']],
            'ControllerInput': [0x30, ['__unnamed_2661']],
            'XapicMessage': [0x30, ['__unnamed_2663']],
            'Hypertransport': [0x30, ['__unnamed_2666']],
            'GenericMessage': [0x30, ['__unnamed_2663']],
            'MessageRequest': [0x30, ['__unnamed_266a']],
        },
    ],
    '_POP_FX_DEPENDENT': [
        0x8,
        {
            'Index': [0x0, ['unsigned long']],
            'ProviderIndex': [0x4, ['unsigned long']],
        },
    ],
    '_XPF_MCE_FLAGS': [
        0x4,
        {
            'MCG_CapabilityRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'MCG_GlobalControlRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_267d': [
        0x8,
        {
            'Signature': [0x0, ['unsigned long']],
            'CheckSum': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_267f': [
        0x10,
        {
            'DiskId': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_2681': [
        0x10,
        {
            'Mbr': [0x0, ['__unnamed_267d']],
            'Gpt': [0x0, ['__unnamed_267f']],
        },
    ],
    '_DUMP_INITIALIZATION_CONTEXT': [
        0xC0,
        {
            'Length': [0x0, ['unsigned long']],
            'Reserved': [0x4, ['unsigned long']],
            'MemoryBlock': [0x8, ['pointer', ['void']]],
            'CommonBuffer': [0xC, ['array', 2, ['pointer', ['void']]]],
            'PhysicalAddress': [0x18, ['array', 2, ['_LARGE_INTEGER']]],
            'StallRoutine': [0x28, ['pointer', ['void']]],
            'OpenRoutine': [0x2C, ['pointer', ['void']]],
            'WriteRoutine': [0x30, ['pointer', ['void']]],
            'FinishRoutine': [0x34, ['pointer', ['void']]],
            'AdapterObject': [0x38, ['pointer', ['_ADAPTER_OBJECT']]],
            'MappedRegisterBase': [0x3C, ['pointer', ['void']]],
            'PortConfiguration': [0x40, ['pointer', ['void']]],
            'CrashDump': [0x44, ['unsigned char']],
            'MarkMemoryOnly': [0x45, ['unsigned char']],
            'HiberResume': [0x46, ['unsigned char']],
            'Reserved1': [0x47, ['unsigned char']],
            'MaximumTransferSize': [0x48, ['unsigned long']],
            'CommonBufferSize': [0x4C, ['unsigned long']],
            'TargetAddress': [0x50, ['pointer', ['void']]],
            'WritePendingRoutine': [0x54, ['pointer', ['void']]],
            'PartitionStyle': [0x58, ['unsigned long']],
            'DiskInfo': [0x5C, ['__unnamed_2681']],
            'ReadRoutine': [0x6C, ['pointer', ['void']]],
            'GetDriveTelemetryRoutine': [0x70, ['pointer', ['void']]],
            'LogSectionTruncateSize': [0x74, ['unsigned long']],
            'Parameters': [0x78, ['array', 16, ['unsigned long']]],
            'GetTransferSizesRoutine': [0xB8, ['pointer', ['void']]],
            'DumpNotifyRoutine': [0xBC, ['pointer', ['void']]],
        },
    ],
    '_PROCESSOR_PLATFORM_STATE_RESIDENCY': [
        0x10,
        {
            'Residency': [0x0, ['unsigned long long']],
            'TransitionCount': [0x8, ['unsigned long long']],
        },
    ],
    '_ETW_QUEUE_ENTRY': [
        0x20,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'DataBlock': [0x8, ['pointer', ['_ETWP_NOTIFICATION_HEADER']]],
            'RegEntry': [0xC, ['pointer', ['_ETW_REG_ENTRY']]],
            'ReplyObject': [0x10, ['pointer', ['_ETW_REG_ENTRY']]],
            'WakeReference': [0x14, ['pointer', ['void']]],
            'RegIndex': [0x18, ['unsigned short']],
            'ReplyIndex': [0x1A, ['unsigned short']],
            'Flags': [0x1C, ['unsigned long']],
        },
    ],
    '_ETW_FILTER_PID': [
        0x24,
        {
            'Count': [0x0, ['unsigned long']],
            'Pids': [0x4, ['array', 8, ['unsigned long']]],
        },
    ],
    '_KDPC_LIST': [
        0x8,
        {
            'ListHead': [0x0, ['_SINGLE_LIST_ENTRY']],
            'LastEntry': [0x4, ['pointer', ['_SINGLE_LIST_ENTRY']]],
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
        0xD0,
        {
            'Locked': [0x0, ['unsigned char']],
            'WarmEjectPdoPointer': [
                0x4,
                ['pointer', ['pointer', ['_DEVICE_OBJECT']]],
            ],
            'OrderLevel': [0x8, ['array', 5, ['_PO_NOTIFY_ORDER_LEVEL']]],
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
    '_IO_REMOVE_LOCK_COMMON_BLOCK': [
        0x18,
        {
            'Removed': [0x0, ['unsigned char']],
            'Reserved': [0x1, ['array', 3, ['unsigned char']]],
            'IoCount': [0x4, ['long']],
            'RemoveEvent': [0x8, ['_KEVENT']],
        },
    ],
    '_POP_FX_IDLE_STATE': [
        0x18,
        {
            'TransitionLatency': [0x0, ['unsigned long long']],
            'ResidencyRequirement': [0x8, ['unsigned long long']],
            'NominalPower': [0x10, ['unsigned long']],
        },
    ],
    '_WHEA_NOTIFICATION_FLAGS': [
        0x2,
        {
            'PollIntervalRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'SwitchToPollingThresholdRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'SwitchToPollingWindowRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'ErrorThresholdRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'ErrorThresholdWindowRW': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AsUSHORT': [0x0, ['unsigned short']],
        },
    ],
    '_ARBITER_CONFLICT_INFO': [
        0x18,
        {
            'OwningObject': [0x0, ['pointer', ['_DEVICE_OBJECT']]],
            'Start': [0x8, ['unsigned long long']],
            'End': [0x10, ['unsigned long long']],
        },
    ],
    '_PO_NOTIFY_ORDER_LEVEL': [
        0x28,
        {
            'DeviceCount': [0x0, ['unsigned long']],
            'ActiveCount': [0x4, ['unsigned long']],
            'WaitSleep': [0x8, ['_LIST_ENTRY']],
            'ReadySleep': [0x10, ['_LIST_ENTRY']],
            'ReadyS0': [0x18, ['_LIST_ENTRY']],
            'WaitS0': [0x20, ['_LIST_ENTRY']],
        },
    ],
    '_ETWP_NOTIFICATION_HEADER': [
        0x48,
        {
            'NotificationType': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1: 'EtwNotificationTypeNoReply',
                            2: 'EtwNotificationTypeLegacyEnable',
                            3: 'EtwNotificationTypeEnable',
                            4: 'EtwNotificationTypePrivateLogger',
                            5: 'EtwNotificationTypePerflib',
                            6: 'EtwNotificationTypeAudio',
                            7: 'EtwNotificationTypeSession',
                            8: 'EtwNotificationTypeReserved',
                            9: 'EtwNotificationTypeCredentialUI',
                            10: 'EtwNotificationTypeInProcSession',
                            11: 'EtwNotificationTypeMax',
                        },
                    ),
                ],
            ],
            'NotificationSize': [0x4, ['unsigned long']],
            'RefCount': [0x8, ['long']],
            'ReplyRequested': [0xC, ['unsigned char']],
            'ReplyIndex': [0x10, ['unsigned long']],
            'Timeout': [0x10, ['unsigned long']],
            'ReplyCount': [0x14, ['unsigned long']],
            'NotifyeeCount': [0x14, ['unsigned long']],
            'ReplyHandle': [0x18, ['unsigned long long']],
            'ReplyObject': [0x18, ['pointer', ['void']]],
            'RegIndex': [0x18, ['unsigned long']],
            'TargetPID': [0x20, ['unsigned long']],
            'SourcePID': [0x24, ['unsigned long']],
            'DestinationGuid': [0x28, ['_GUID']],
            'SourceGuid': [0x38, ['_GUID']],
        },
    ],
    '__unnamed_26b1': [
        0x4,
        {
            'Mask': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Polarity': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'MessageType': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'RequestEOI': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'DestinationMode': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'MessageType3': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Destination': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'Vector': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'ExtendedAddress': [
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
    '__unnamed_26b3': [
        0x4,
        {
            'bits': [0x0, ['__unnamed_26b1']],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_26b6': [
        0x4,
        {
            'ExtendedDestination': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'PassPW': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'WaitingForEOI': [
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
    '__unnamed_26b8': [
        0x4,
        {
            'bits': [0x0, ['__unnamed_26b6']],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_INTERRUPT_HT_INTR_INFO': [
        0x8,
        {
            'LowPart': [0x0, ['__unnamed_26b3']],
            'HighPart': [0x4, ['__unnamed_26b8']],
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
    '_ETW_REPLY_QUEUE': [
        0x2C,
        {
            'Queue': [0x0, ['_KQUEUE']],
            'EventsLost': [0x28, ['long']],
        },
    ],
    '_ARBITER_QUERY_ALLOCATED_RESOURCES_PARAMETERS': [
        0x4,
        {
            'AllocatedResources': [
                0x0,
                ['pointer', ['pointer', ['_CM_PARTIAL_RESOURCE_LIST']]],
            ],
        },
    ],
    '_MI_LARGEPAGE_MEMORY_INFO': [
        0x10,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'ColoredPageInfoBase': [0x8, ['pointer', ['_COLORED_PAGE_INFO']]],
            'PagesNeedZeroing': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_26c8': [
        0x8,
        {
            'MessageAddressLow': [0x0, ['unsigned long']],
            'MessageData': [0x4, ['unsigned short']],
            'Reserved': [0x6, ['unsigned short']],
        },
    ],
    '__unnamed_26ca': [
        0x8,
        {
            'RemappedFormat': [0x0, ['_ULARGE_INTEGER']],
            'Msi': [0x0, ['__unnamed_26c8']],
        },
    ],
    '_INTERRUPT_REMAPPING_INFO': [
        0x10,
        {
            'IrtIndex': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=30, native_type='unsigned long'),
                ],
            ],
            'FlagHalInternal': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'FlagTranslated': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'u': [0x8, ['__unnamed_26ca']],
        },
    ],
    '_KSPECIAL_REGISTERS': [
        0x54,
        {
            'Cr0': [0x0, ['unsigned long']],
            'Cr2': [0x4, ['unsigned long']],
            'Cr3': [0x8, ['unsigned long']],
            'Cr4': [0xC, ['unsigned long']],
            'KernelDr0': [0x10, ['unsigned long']],
            'KernelDr1': [0x14, ['unsigned long']],
            'KernelDr2': [0x18, ['unsigned long']],
            'KernelDr3': [0x1C, ['unsigned long']],
            'KernelDr6': [0x20, ['unsigned long']],
            'KernelDr7': [0x24, ['unsigned long']],
            'Gdtr': [0x28, ['_DESCRIPTOR']],
            'Idtr': [0x30, ['_DESCRIPTOR']],
            'Tr': [0x38, ['unsigned short']],
            'Ldtr': [0x3A, ['unsigned short']],
            'Xcr0': [0x3C, ['unsigned long long']],
            'ExceptionList': [0x44, ['unsigned long']],
            'Reserved': [0x48, ['array', 3, ['unsigned long']]],
        },
    ],
    '_RTL_ACTIVATION_CONTEXT_STACK_FRAME': [
        0xC,
        {
            'Previous': [
                0x0,
                ['pointer', ['_RTL_ACTIVATION_CONTEXT_STACK_FRAME']],
            ],
            'ActivationContext': [0x4, ['pointer', ['_ACTIVATION_CONTEXT']]],
            'Flags': [0x8, ['unsigned long']],
        },
    ],
    '_MMIO_TRACKER': [
        0x38,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'PageFrameIndex': [0x8, ['unsigned long']],
            'NumberOfPages': [0xC, ['unsigned long']],
            'BaseVa': [0x10, ['pointer', ['void']]],
            'CacheFlushTimeStamp': [0x10, ['unsigned long']],
            'Mdl': [0x14, ['pointer', ['_MDL']]],
            'MdlPages': [0x18, ['unsigned long']],
            'StackTrace': [0x1C, ['array', 6, ['pointer', ['void']]]],
            'CacheInfo': [0x34, ['array', 1, ['_IO_CACHE_INFO']]],
        },
    ],
    '_ARBITER_ORDERING': [
        0x10,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_26d9': [
        0x4,
        {
            'ImagePteOffset': [0x0, ['unsigned long']],
            'TossPage': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_26dc': [
        0x4,
        {
            'e1': [0x0, ['_MMINPAGE_FLAGS']],
            'LongFlags': [0x0, ['unsigned long']],
        },
    ],
    '_MMINPAGE_SUPPORT': [
        0xE0,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'ListHead': [0x8, ['_LIST_ENTRY']],
            'Event': [0x10, ['_KEVENT']],
            'CollidedEvent': [0x20, ['_KEVENT']],
            'IoStatus': [0x30, ['_IO_STATUS_BLOCK']],
            'ReadOffset': [0x38, ['_LARGE_INTEGER']],
            'PteContents': [0x40, ['_MMPTE']],
            'Thread': [0x48, ['pointer', ['_ETHREAD']]],
            'LockedProtoPfn': [0x4C, ['pointer', ['_MMPFN']]],
            'WaitCount': [0x50, ['long']],
            'ByteCount': [0x54, ['unsigned long']],
            'u3': [0x58, ['__unnamed_26d9']],
            'u1': [0x5C, ['__unnamed_26dc']],
            'FilePointer': [0x60, ['pointer', ['_FILE_OBJECT']]],
            'ControlArea': [0x64, ['pointer', ['_CONTROL_AREA']]],
            'Autoboost': [0x68, ['pointer', ['void']]],
            'FaultingAddress': [0x6C, ['pointer', ['void']]],
            'PointerPte': [0x70, ['pointer', ['_MMPTE']]],
            'BasePte': [0x74, ['pointer', ['_MMPTE']]],
            'Pfn': [0x78, ['pointer', ['_MMPFN']]],
            'PrefetchMdl': [0x7C, ['pointer', ['_MDL']]],
            'Mdl': [0x80, ['_MDL']],
            'Page': [0x9C, ['array', 16, ['unsigned long']]],
        },
    ],
    '_RTL_AVL_TABLE': [
        0x38,
        {
            'BalancedRoot': [0x0, ['_RTL_BALANCED_LINKS']],
            'OrderedPointer': [0x10, ['pointer', ['void']]],
            'WhichOrderedElement': [0x14, ['unsigned long']],
            'NumberGenericTableElements': [0x18, ['unsigned long']],
            'DepthOfTree': [0x1C, ['unsigned long']],
            'RestartKey': [0x20, ['pointer', ['_RTL_BALANCED_LINKS']]],
            'DeleteCount': [0x24, ['unsigned long']],
            'CompareRoutine': [0x28, ['pointer', ['void']]],
            'AllocateRoutine': [0x2C, ['pointer', ['void']]],
            'FreeRoutine': [0x30, ['pointer', ['void']]],
            'TableContext': [0x34, ['pointer', ['void']]],
        },
    ],
    '_MMINPAGE_FLAGS': [
        0x4,
        {
            'InjectRetry': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'CrossThreadPadding': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'PrefetchSystemVmType': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'VaPrefetchReadBlock': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'CollidedFlowThrough': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ForceCollisions': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'InPageExpanded': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'IssuedAtLowPriority': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'FaultFromStore': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'PagePriority': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'PerformRelocations': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ClusteredPagePriority': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'MakeClusterValid': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'ZeroLastPage': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'UserFault': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'BoostedPriority': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'StandbyProtectionNeeded': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'PteChanged': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'PageFileFault': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'PageFilePageHashActive': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'CoalescedIo': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_AGGREGATED_PAYLOAD_FILTER': [
        0x50,
        {
            'MagicValue': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0, end_bit=12, native_type='unsigned short'
                    ),
                ],
            ],
            'DescriptorVersion': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'Size': [0x2, ['unsigned short']],
            'PredicateCount': [0x4, ['unsigned short']],
            'Reserved': [0x6, ['unsigned short']],
            'HashedEventIdBitmap': [0x8, ['unsigned long long']],
            'ProviderGuid': [0x10, ['_GUID']],
            'EachEventTableOffset': [0x20, ['unsigned short']],
            'EachEventTableLength': [0x22, ['unsigned short']],
            'PayloadDecoderTableOffset': [0x24, ['unsigned short']],
            'PayloadDecoderTableLength': [0x26, ['unsigned short']],
            'EventFilterTableOffset': [0x28, ['unsigned short']],
            'EventFilterTableLength': [0x2A, ['unsigned short']],
            'UNICODEStringTableOffset': [0x2C, ['unsigned short']],
            'UNICODEStringTableLength': [0x2E, ['unsigned short']],
            'ANSIStringTableOffset': [0x30, ['unsigned short']],
            'ANSIStringTableLength': [0x32, ['unsigned short']],
            'PredicateTable': [
                0x38,
                ['array', 1, ['_EVENT_PAYLOAD_PREDICATE']],
            ],
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
            'ReadWrite': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SecNoChange': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'NoDelete': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'RequiresPteReversal': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'ExclusiveSecure': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=12, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_EVENT_PAYLOAD_PREDICATE': [
        0x18,
        {
            'FieldIndex': [0x0, ['unsigned short']],
            'CompareOp': [0x2, ['unsigned short']],
            'Value': [0x8, ['array', 2, ['unsigned long long']]],
        },
    ],
    '_COLORED_PAGE_INFO': [
        0x10,
        {
            'BeingZeroed': [0x0, ['long']],
            'Processor': [0x4, ['unsigned long']],
            'PagesQueued': [0x8, ['unsigned long']],
            'PfnAllocation': [0xC, ['pointer', ['_MMPFN']]],
        },
    ],
    '_DESCRIPTOR': [
        0x8,
        {
            'Pad': [0x0, ['unsigned short']],
            'Limit': [0x2, ['unsigned short']],
            'Base': [0x4, ['unsigned long']],
        },
    ],
    '_ETW_FILTER_STRING_TOKEN': [
        0xC,
        {
            'Count': [0x0, ['unsigned short']],
            'Tokens': [
                0x4,
                ['array', 1, ['_ETW_FILTER_STRING_TOKEN_ELEMENT']],
            ],
        },
    ],
    '_IO_CACHE_INFO': [
        0x1,
        {
            'CacheAttribute': [0x0, ['unsigned char']],
        },
    ],
    '_ETW_FILTER_STRING_TOKEN_ELEMENT': [
        0x8,
        {
            'Length': [0x0, ['unsigned short']],
            'String': [0x4, ['pointer', ['unsigned short']]],
        },
    ],
}
