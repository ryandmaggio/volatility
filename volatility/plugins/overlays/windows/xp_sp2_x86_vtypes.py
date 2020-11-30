ntkrnlmp_types = {
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
    '_LIST_ENTRY': [
        0x8,
        {
            'Flink': [0x0, ['pointer', ['_LIST_ENTRY']]],
            'Blink': [0x4, ['pointer', ['_LIST_ENTRY']]],
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
    '__unnamed_1016': [
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
            'u': [0x0, ['__unnamed_1016']],
            'QuadPart': [0x0, ['long long']],
        },
    ],
    '__unnamed_101b': [
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
            'u': [0x0, ['__unnamed_101b']],
            'QuadPart': [0x0, ['unsigned long long']],
        },
    ],
    '_LUID': [
        0x8,
        {
            'LowPart': [0x0, ['unsigned long']],
            'HighPart': [0x4, ['long']],
        },
    ],
    '_KAPC': [
        0x30,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'Spare0': [0x4, ['unsigned long']],
            'Thread': [0x8, ['pointer', ['_KTHREAD']]],
            'ApcListEntry': [0xC, ['_LIST_ENTRY']],
            'KernelRoutine': [0x14, ['pointer', ['void']]],
            'RundownRoutine': [0x18, ['pointer', ['void']]],
            'NormalRoutine': [0x1C, ['pointer', ['void']]],
            'NormalContext': [0x20, ['pointer', ['void']]],
            'SystemArgument1': [0x24, ['pointer', ['void']]],
            'SystemArgument2': [0x28, ['pointer', ['void']]],
            'ApcStateIndex': [0x2C, ['unsigned char']],
            'ApcMode': [0x2D, ['unsigned char']],
            'Inserted': [0x2E, ['unsigned char']],
        },
    ],
    '_SINGLE_LIST_ENTRY': [
        0x4,
        {
            'Next': [0x0, ['pointer', ['_SINGLE_LIST_ENTRY']]],
        },
    ],
    '_KPRCB': [
        0xC50,
        {
            'MinorVersion': [0x0, ['unsigned short']],
            'MajorVersion': [0x2, ['unsigned short']],
            'CurrentThread': [0x4, ['pointer', ['_KTHREAD']]],
            'NextThread': [0x8, ['pointer', ['_KTHREAD']]],
            'IdleThread': [0xC, ['pointer', ['_KTHREAD']]],
            'Number': [0x10, ['unsigned char']],
            'Reserved': [0x11, ['unsigned char']],
            'BuildType': [0x12, ['unsigned short']],
            'SetMember': [0x14, ['unsigned long']],
            'CpuType': [0x18, ['unsigned char']],
            'CpuID': [0x19, ['unsigned char']],
            'CpuStep': [0x1A, ['unsigned short']],
            'ProcessorState': [0x1C, ['_KPROCESSOR_STATE']],
            'KernelReserved': [0x33C, ['array', 16, ['unsigned long']]],
            'HalReserved': [0x37C, ['array', 16, ['unsigned long']]],
            'PrcbPad0': [0x3BC, ['array', 92, ['unsigned char']]],
            'LockQueue': [0x418, ['array', 16, ['_KSPIN_LOCK_QUEUE']]],
            'PrcbPad1': [0x498, ['array', 8, ['unsigned char']]],
            'NpxThread': [0x4A0, ['pointer', ['_KTHREAD']]],
            'InterruptCount': [0x4A4, ['unsigned long']],
            'KernelTime': [0x4A8, ['unsigned long']],
            'UserTime': [0x4AC, ['unsigned long']],
            'DpcTime': [0x4B0, ['unsigned long']],
            'DebugDpcTime': [0x4B4, ['unsigned long']],
            'InterruptTime': [0x4B8, ['unsigned long']],
            'AdjustDpcThreshold': [0x4BC, ['unsigned long']],
            'PageColor': [0x4C0, ['unsigned long']],
            'SkipTick': [0x4C4, ['unsigned long']],
            'MultiThreadSetBusy': [0x4C8, ['unsigned char']],
            'Spare2': [0x4C9, ['array', 3, ['unsigned char']]],
            'ParentNode': [0x4CC, ['pointer', ['_KNODE']]],
            'MultiThreadProcessorSet': [0x4D0, ['unsigned long']],
            'MultiThreadSetMaster': [0x4D4, ['pointer', ['_KPRCB']]],
            'ThreadStartCount': [0x4D8, ['array', 2, ['unsigned long']]],
            'CcFastReadNoWait': [0x4E0, ['unsigned long']],
            'CcFastReadWait': [0x4E4, ['unsigned long']],
            'CcFastReadNotPossible': [0x4E8, ['unsigned long']],
            'CcCopyReadNoWait': [0x4EC, ['unsigned long']],
            'CcCopyReadWait': [0x4F0, ['unsigned long']],
            'CcCopyReadNoWaitMiss': [0x4F4, ['unsigned long']],
            'KeAlignmentFixupCount': [0x4F8, ['unsigned long']],
            'KeContextSwitches': [0x4FC, ['unsigned long']],
            'KeDcacheFlushCount': [0x500, ['unsigned long']],
            'KeExceptionDispatchCount': [0x504, ['unsigned long']],
            'KeFirstLevelTbFills': [0x508, ['unsigned long']],
            'KeFloatingEmulationCount': [0x50C, ['unsigned long']],
            'KeIcacheFlushCount': [0x510, ['unsigned long']],
            'KeSecondLevelTbFills': [0x514, ['unsigned long']],
            'KeSystemCalls': [0x518, ['unsigned long']],
            'SpareCounter0': [0x51C, ['array', 1, ['unsigned long']]],
            'PPLookasideList': [0x520, ['array', 16, ['_PP_LOOKASIDE_LIST']]],
            'PPNPagedLookasideList': [
                0x5A0,
                ['array', 32, ['_PP_LOOKASIDE_LIST']],
            ],
            'PPPagedLookasideList': [
                0x6A0,
                ['array', 32, ['_PP_LOOKASIDE_LIST']],
            ],
            'PacketBarrier': [0x7A0, ['unsigned long']],
            'ReverseStall': [0x7A4, ['unsigned long']],
            'IpiFrame': [0x7A8, ['pointer', ['void']]],
            'PrcbPad2': [0x7AC, ['array', 52, ['unsigned char']]],
            'CurrentPacket': [0x7E0, ['array', 3, ['pointer', ['void']]]],
            'TargetSet': [0x7EC, ['unsigned long']],
            'WorkerRoutine': [0x7F0, ['pointer', ['void']]],
            'IpiFrozen': [0x7F4, ['unsigned long']],
            'PrcbPad3': [0x7F8, ['array', 40, ['unsigned char']]],
            'RequestSummary': [0x820, ['unsigned long']],
            'SignalDone': [0x824, ['pointer', ['_KPRCB']]],
            'PrcbPad4': [0x828, ['array', 56, ['unsigned char']]],
            'DpcListHead': [0x860, ['_LIST_ENTRY']],
            'DpcStack': [0x868, ['pointer', ['void']]],
            'DpcCount': [0x86C, ['unsigned long']],
            'DpcQueueDepth': [0x870, ['unsigned long']],
            'DpcRoutineActive': [0x874, ['unsigned long']],
            'DpcInterruptRequested': [0x878, ['unsigned long']],
            'DpcLastCount': [0x87C, ['unsigned long']],
            'DpcRequestRate': [0x880, ['unsigned long']],
            'MaximumDpcQueueDepth': [0x884, ['unsigned long']],
            'MinimumDpcRate': [0x888, ['unsigned long']],
            'QuantumEnd': [0x88C, ['unsigned long']],
            'PrcbPad5': [0x890, ['array', 16, ['unsigned char']]],
            'DpcLock': [0x8A0, ['unsigned long']],
            'PrcbPad6': [0x8A4, ['array', 28, ['unsigned char']]],
            'CallDpc': [0x8C0, ['_KDPC']],
            'ChainedInterruptList': [0x8E0, ['pointer', ['void']]],
            'LookasideIrpFloat': [0x8E4, ['long']],
            'SpareFields0': [0x8E8, ['array', 6, ['unsigned long']]],
            'VendorString': [0x900, ['array', 13, ['unsigned char']]],
            'InitialApicId': [0x90D, ['unsigned char']],
            'LogicalProcessorsPerPhysicalProcessor': [
                0x90E,
                ['unsigned char'],
            ],
            'MHz': [0x910, ['unsigned long']],
            'FeatureBits': [0x914, ['unsigned long']],
            'UpdateSignature': [0x918, ['_LARGE_INTEGER']],
            'NpxSaveArea': [0x920, ['_FX_SAVE_AREA']],
            'PowerState': [0xB30, ['_PROCESSOR_POWER_STATE']],
        },
    ],
    '_SLIST_HEADER': [
        0x8,
        {
            'Alignment': [0x0, ['unsigned long long']],
            'Next': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Depth': [0x4, ['unsigned short']],
            'Sequence': [0x6, ['unsigned short']],
        },
    ],
    '_NPAGED_LOOKASIDE_LIST': [
        0x100,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE']],
            'Lock__ObsoleteButDoNotDelete': [0x80, ['unsigned long']],
        },
    ],
    '_PAGED_LOOKASIDE_LIST': [
        0x100,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE']],
            'Lock__ObsoleteButDoNotDelete': [0x80, ['_FAST_MUTEX']],
        },
    ],
    '_GENERAL_LOOKASIDE': [
        0x80,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
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
            'Tag': [0x20, ['unsigned long']],
            'Size': [0x24, ['unsigned long']],
            'Allocate': [0x28, ['pointer', ['void']]],
            'Free': [0x2C, ['pointer', ['void']]],
            'ListEntry': [0x30, ['_LIST_ENTRY']],
            'LastTotalAllocates': [0x38, ['unsigned long']],
            'LastAllocateMisses': [0x3C, ['unsigned long']],
            'LastAllocateHits': [0x3C, ['unsigned long']],
            'Future': [0x40, ['array', 2, ['unsigned long']]],
        },
    ],
    '_EX_RUNDOWN_REF': [
        0x4,
        {
            'Count': [0x0, ['unsigned long']],
            'Ptr': [0x0, ['pointer', ['void']]],
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
    '_EX_PUSH_LOCK': [
        0x4,
        {
            'Waiting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Exclusive': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Shared': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'Value': [0x0, ['unsigned long']],
            'Ptr': [0x0, ['pointer', ['void']]],
        },
    ],
    '_EX_PUSH_LOCK_WAIT_BLOCK': [
        0x1C,
        {
            'WakeEvent': [0x0, ['_KEVENT']],
            'Next': [0x10, ['pointer', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'ShareCount': [0x14, ['unsigned long']],
            'Exclusive': [0x18, ['unsigned char']],
        },
    ],
    '_EX_PUSH_LOCK_CACHE_AWARE': [
        0x80,
        {
            'Locks': [0x0, ['array', 32, ['pointer', ['_EX_PUSH_LOCK']]]],
        },
    ],
    '_ETHREAD': [
        0x258,
        {
            'Tcb': [0x0, ['_KTHREAD']],
            'CreateTime': [0x1C0, ['_LARGE_INTEGER']],
            'NestedFaultCount': [
                0x1C0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ApcNeeded': [
                0x1C0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ExitTime': [0x1C8, ['_LARGE_INTEGER']],
            'LpcReplyChain': [0x1C8, ['_LIST_ENTRY']],
            'KeyedWaitChain': [0x1C8, ['_LIST_ENTRY']],
            'ExitStatus': [0x1D0, ['long']],
            'OfsChain': [0x1D0, ['pointer', ['void']]],
            'PostBlockList': [0x1D4, ['_LIST_ENTRY']],
            'TerminationPort': [0x1DC, ['pointer', ['_TERMINATION_PORT']]],
            'ReaperLink': [0x1DC, ['pointer', ['_ETHREAD']]],
            'KeyedWaitValue': [0x1DC, ['pointer', ['void']]],
            'ActiveTimerListLock': [0x1E0, ['unsigned long']],
            'ActiveTimerListHead': [0x1E4, ['_LIST_ENTRY']],
            'Cid': [0x1EC, ['_CLIENT_ID']],
            'LpcReplySemaphore': [0x1F4, ['_KSEMAPHORE']],
            'KeyedWaitSemaphore': [0x1F4, ['_KSEMAPHORE']],
            'LpcReplyMessage': [0x208, ['pointer', ['void']]],
            'LpcWaitingOnPort': [0x208, ['pointer', ['void']]],
            'ImpersonationInfo': [
                0x20C,
                ['pointer', ['_PS_IMPERSONATION_INFORMATION']],
            ],
            'IrpList': [0x210, ['_LIST_ENTRY']],
            'TopLevelIrp': [0x218, ['unsigned long']],
            'DeviceToVerify': [0x21C, ['pointer', ['_DEVICE_OBJECT']]],
            'ThreadsProcess': [0x220, ['pointer', ['_EPROCESS']]],
            'StartAddress': [0x224, ['pointer', ['void']]],
            'Win32StartAddress': [0x228, ['pointer', ['void']]],
            'LpcReceivedMessageId': [0x228, ['unsigned long']],
            'ThreadListEntry': [0x22C, ['_LIST_ENTRY']],
            'RundownProtect': [0x234, ['_EX_RUNDOWN_REF']],
            'ThreadLock': [0x238, ['_EX_PUSH_LOCK']],
            'LpcReplyMessageId': [0x23C, ['unsigned long']],
            'ReadClusterSize': [0x240, ['unsigned long']],
            'GrantedAccess': [0x244, ['unsigned long']],
            'CrossThreadFlags': [0x248, ['unsigned long']],
            'Terminated': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DeadThread': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HideFromDebugger': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ActiveImpersonationInfo': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SystemThread': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'HardErrorsAreDisabled': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'BreakOnTermination': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SkipCreationMsg': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SkipTerminationMsg': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'SameThreadPassiveFlags': [0x24C, ['unsigned long']],
            'ActiveExWorker': [
                0x24C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ExWorkerCanWaitUser': [
                0x24C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'MemoryMaker': [
                0x24C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'SameThreadApcFlags': [0x250, ['unsigned long']],
            'LpcReceivedMsgIdValid': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'LpcExitThreadCalled': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'AddressSpaceOwner': [
                0x250,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'ForwardClusterOnly': [0x254, ['unsigned char']],
            'DisablePageFaultClustering': [0x255, ['unsigned char']],
        },
    ],
    '_EPROCESS': [
        0x260,
        {
            'Pcb': [0x0, ['_KPROCESS']],
            'ProcessLock': [0x6C, ['_EX_PUSH_LOCK']],
            'CreateTime': [0x70, ['_LARGE_INTEGER']],
            'ExitTime': [0x78, ['_LARGE_INTEGER']],
            'RundownProtect': [0x80, ['_EX_RUNDOWN_REF']],
            'UniqueProcessId': [0x84, ['pointer', ['void']]],
            'ActiveProcessLinks': [0x88, ['_LIST_ENTRY']],
            'QuotaUsage': [0x90, ['array', 3, ['unsigned long']]],
            'QuotaPeak': [0x9C, ['array', 3, ['unsigned long']]],
            'CommitCharge': [0xA8, ['unsigned long']],
            'PeakVirtualSize': [0xAC, ['unsigned long']],
            'VirtualSize': [0xB0, ['unsigned long']],
            'SessionProcessLinks': [0xB4, ['_LIST_ENTRY']],
            'DebugPort': [0xBC, ['pointer', ['void']]],
            'ExceptionPort': [0xC0, ['pointer', ['void']]],
            'ObjectTable': [0xC4, ['pointer', ['_HANDLE_TABLE']]],
            'Token': [0xC8, ['_EX_FAST_REF']],
            'WorkingSetLock': [0xCC, ['_FAST_MUTEX']],
            'WorkingSetPage': [0xEC, ['unsigned long']],
            'AddressCreationLock': [0xF0, ['_FAST_MUTEX']],
            'HyperSpaceLock': [0x110, ['unsigned long']],
            'ForkInProgress': [0x114, ['pointer', ['_ETHREAD']]],
            'HardwareTrigger': [0x118, ['unsigned long']],
            'VadRoot': [0x11C, ['pointer', ['void']]],
            'VadHint': [0x120, ['pointer', ['void']]],
            'CloneRoot': [0x124, ['pointer', ['void']]],
            'NumberOfPrivatePages': [0x128, ['unsigned long']],
            'NumberOfLockedPages': [0x12C, ['unsigned long']],
            'Win32Process': [0x130, ['pointer', ['void']]],
            'Job': [0x134, ['pointer', ['_EJOB']]],
            'SectionObject': [0x138, ['pointer', ['void']]],
            'SectionBaseAddress': [0x13C, ['pointer', ['void']]],
            'QuotaBlock': [0x140, ['pointer', ['_EPROCESS_QUOTA_BLOCK']]],
            'WorkingSetWatch': [0x144, ['pointer', ['_PAGEFAULT_HISTORY']]],
            'Win32WindowStation': [0x148, ['pointer', ['void']]],
            'InheritedFromUniqueProcessId': [0x14C, ['pointer', ['void']]],
            'LdtInformation': [0x150, ['pointer', ['void']]],
            'VadFreeHint': [0x154, ['pointer', ['void']]],
            'VdmObjects': [0x158, ['pointer', ['void']]],
            'DeviceMap': [0x15C, ['pointer', ['void']]],
            'PhysicalVadList': [0x160, ['_LIST_ENTRY']],
            'PageDirectoryPte': [0x168, ['_HARDWARE_PTE']],
            'Filler': [0x168, ['unsigned long long']],
            'Session': [0x170, ['pointer', ['void']]],
            'ImageFileName': [0x174, ['array', 16, ['unsigned char']]],
            'JobLinks': [0x184, ['_LIST_ENTRY']],
            'LockedPagesList': [0x18C, ['pointer', ['void']]],
            'ThreadListHead': [0x190, ['_LIST_ENTRY']],
            'SecurityPort': [0x198, ['pointer', ['void']]],
            'PaeTop': [0x19C, ['pointer', ['void']]],
            'ActiveThreads': [0x1A0, ['unsigned long']],
            'GrantedAccess': [0x1A4, ['unsigned long']],
            'DefaultHardErrorProcessing': [0x1A8, ['unsigned long']],
            'LastThreadExitStatus': [0x1AC, ['long']],
            'Peb': [0x1B0, ['pointer', ['_PEB']]],
            'PrefetchTrace': [0x1B4, ['_EX_FAST_REF']],
            'ReadOperationCount': [0x1B8, ['_LARGE_INTEGER']],
            'WriteOperationCount': [0x1C0, ['_LARGE_INTEGER']],
            'OtherOperationCount': [0x1C8, ['_LARGE_INTEGER']],
            'ReadTransferCount': [0x1D0, ['_LARGE_INTEGER']],
            'WriteTransferCount': [0x1D8, ['_LARGE_INTEGER']],
            'OtherTransferCount': [0x1E0, ['_LARGE_INTEGER']],
            'CommitChargeLimit': [0x1E8, ['unsigned long']],
            'CommitChargePeak': [0x1EC, ['unsigned long']],
            'AweInfo': [0x1F0, ['pointer', ['void']]],
            'SeAuditProcessCreationInfo': [
                0x1F4,
                ['_SE_AUDIT_PROCESS_CREATION_INFO'],
            ],
            'Vm': [0x1F8, ['_MMSUPPORT']],
            'LastFaultCount': [0x238, ['unsigned long']],
            'ModifiedPageCount': [0x23C, ['unsigned long']],
            'NumberOfVads': [0x240, ['unsigned long']],
            'JobStatus': [0x244, ['unsigned long']],
            'Flags': [0x248, ['unsigned long']],
            'CreateReported': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoDebugInherit': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessExiting': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessDelete': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow64SplitPages': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'VmDeleted': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'OutswapEnabled': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Outswapped': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ForkFailed': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'HasPhysicalVad': [
                0x248,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'AddressSpaceInitialized': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolution': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'BreakOnTermination': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'SessionCreationUnderway': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteWatch': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInSession': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'OverrideAddressSpace': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'HasAddressSpace': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'LaunchPrefetched': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'InjectInpageErrors': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'VmTopDown': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'Unused3': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'Unused4': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'VdmAllowed': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'Unused': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'Unused1': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'Unused2': [
                0x248,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ExitStatus': [0x24C, ['long']],
            'NextPageColor': [0x250, ['unsigned short']],
            'SubSystemMinorVersion': [0x252, ['unsigned char']],
            'SubSystemMajorVersion': [0x253, ['unsigned char']],
            'SubSystemVersion': [0x252, ['unsigned short']],
            'PriorityClass': [0x254, ['unsigned char']],
            'WorkingSetAcquiredUnsafe': [0x255, ['unsigned char']],
            'Cookie': [0x258, ['unsigned long']],
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
        0x190,
        {
            'Mutex': [0x0, ['_ERESOURCE']],
            'TypeList': [0x38, ['_LIST_ENTRY']],
            'Name': [0x40, ['_UNICODE_STRING']],
            'DefaultObject': [0x48, ['pointer', ['void']]],
            'Index': [0x4C, ['unsigned long']],
            'TotalNumberOfObjects': [0x50, ['unsigned long']],
            'TotalNumberOfHandles': [0x54, ['unsigned long']],
            'HighWaterNumberOfObjects': [0x58, ['unsigned long']],
            'HighWaterNumberOfHandles': [0x5C, ['unsigned long']],
            'TypeInfo': [0x60, ['_OBJECT_TYPE_INITIALIZER']],
            'Key': [0xAC, ['unsigned long']],
            'ObjectLocks': [0xB0, ['array', 4, ['_ERESOURCE']]],
        },
    ],
    '_OBJECT_HANDLE_INFORMATION': [
        0x8,
        {
            'HandleAttributes': [0x0, ['unsigned long']],
            'GrantedAccess': [0x4, ['unsigned long']],
        },
    ],
    '_KTHREAD': [
        0x1C0,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'MutantListHead': [0x10, ['_LIST_ENTRY']],
            'InitialStack': [0x18, ['pointer', ['void']]],
            'StackLimit': [0x1C, ['pointer', ['void']]],
            'Teb': [0x20, ['pointer', ['void']]],
            'TlsArray': [0x24, ['pointer', ['void']]],
            'KernelStack': [0x28, ['pointer', ['void']]],
            'DebugActive': [0x2C, ['unsigned char']],
            'State': [0x2D, ['unsigned char']],
            'Alerted': [0x2E, ['array', 2, ['unsigned char']]],
            'Iopl': [0x30, ['unsigned char']],
            'NpxState': [0x31, ['unsigned char']],
            'Saturation': [0x32, ['unsigned char']],
            'Priority': [0x33, ['unsigned char']],
            'ApcState': [0x34, ['_KAPC_STATE']],
            'ContextSwitches': [0x4C, ['unsigned long']],
            'IdleSwapBlock': [0x50, ['unsigned char']],
            'Spare0': [0x51, ['array', 3, ['unsigned char']]],
            'WaitStatus': [0x54, ['long']],
            'WaitIrql': [0x58, ['unsigned char']],
            'WaitMode': [0x59, ['unsigned char']],
            'WaitNext': [0x5A, ['unsigned char']],
            'WaitReason': [0x5B, ['unsigned char']],
            'WaitBlockList': [0x5C, ['pointer', ['_KWAIT_BLOCK']]],
            'WaitListEntry': [0x60, ['_LIST_ENTRY']],
            'SwapListEntry': [0x60, ['_SINGLE_LIST_ENTRY']],
            'WaitTime': [0x68, ['unsigned long']],
            'BasePriority': [0x6C, ['unsigned char']],
            'DecrementCount': [0x6D, ['unsigned char']],
            'PriorityDecrement': [0x6E, ['unsigned char']],
            'Quantum': [0x6F, ['unsigned char']],
            'WaitBlock': [0x70, ['array', 4, ['_KWAIT_BLOCK']]],
            'LegoData': [0xD0, ['pointer', ['void']]],
            'KernelApcDisable': [0xD4, ['unsigned long']],
            'UserAffinity': [0xD8, ['unsigned long']],
            'SystemAffinityActive': [0xDC, ['unsigned char']],
            'PowerState': [0xDD, ['unsigned char']],
            'NpxIrql': [0xDE, ['unsigned char']],
            'InitialNode': [0xDF, ['unsigned char']],
            'ServiceTable': [0xE0, ['pointer', ['void']]],
            'Queue': [0xE4, ['pointer', ['_KQUEUE']]],
            'ApcQueueLock': [0xE8, ['unsigned long']],
            'Timer': [0xF0, ['_KTIMER']],
            'QueueListEntry': [0x118, ['_LIST_ENTRY']],
            'SoftAffinity': [0x120, ['unsigned long']],
            'Affinity': [0x124, ['unsigned long']],
            'Preempted': [0x128, ['unsigned char']],
            'ProcessReadyQueue': [0x129, ['unsigned char']],
            'KernelStackResident': [0x12A, ['unsigned char']],
            'NextProcessor': [0x12B, ['unsigned char']],
            'CallbackStack': [0x12C, ['pointer', ['void']]],
            'Win32Thread': [0x130, ['pointer', ['void']]],
            'TrapFrame': [0x134, ['pointer', ['_KTRAP_FRAME']]],
            'ApcStatePointer': [
                0x138,
                ['array', 2, ['pointer', ['_KAPC_STATE']]],
            ],
            'PreviousMode': [0x140, ['unsigned char']],
            'EnableStackSwap': [0x141, ['unsigned char']],
            'LargeStack': [0x142, ['unsigned char']],
            'ResourceIndex': [0x143, ['unsigned char']],
            'KernelTime': [0x144, ['unsigned long']],
            'UserTime': [0x148, ['unsigned long']],
            'SavedApcState': [0x14C, ['_KAPC_STATE']],
            'Alertable': [0x164, ['unsigned char']],
            'ApcStateIndex': [0x165, ['unsigned char']],
            'ApcQueueable': [0x166, ['unsigned char']],
            'AutoAlignment': [0x167, ['unsigned char']],
            'StackBase': [0x168, ['pointer', ['void']]],
            'SuspendApc': [0x16C, ['_KAPC']],
            'SuspendSemaphore': [0x19C, ['_KSEMAPHORE']],
            'ThreadListEntry': [0x1B0, ['_LIST_ENTRY']],
            'FreezeCount': [0x1B8, ['unsigned char']],
            'SuspendCount': [0x1B9, ['unsigned char']],
            'IdealProcessor': [0x1BA, ['unsigned char']],
            'DisableBoost': [0x1BB, ['unsigned char']],
        },
    ],
    '__unnamed_10f2': [
        0x208,
        {
            'FnArea': [0x0, ['_FNSAVE_FORMAT']],
            'FxArea': [0x0, ['_FXSAVE_FORMAT']],
        },
    ],
    '_FX_SAVE_AREA': [
        0x210,
        {
            'U': [0x0, ['__unnamed_10f2']],
            'NpxSavedCpu': [0x208, ['unsigned long']],
            'Cr0NpxState': [0x20C, ['unsigned long']],
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
    '__unnamed_1163': [
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
        },
    ],
    '_DBGKD_MANIPULATE_STATE64': [
        0x38,
        {
            'ApiNumber': [0x0, ['unsigned long']],
            'ProcessorLevel': [0x4, ['unsigned short']],
            'Processor': [0x6, ['unsigned short']],
            'ReturnStatus': [0x8, ['long']],
            'u': [0x10, ['__unnamed_1163']],
        },
    ],
    '__unnamed_116a': [
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
            'u': [0xC, ['__unnamed_116a']],
        },
    ],
    '__unnamed_1173': [
        0x8,
        {
            'FileOffset': [0x0, ['_LARGE_INTEGER']],
            'ActiveCount': [0x0, ['unsigned short']],
        },
    ],
    '_VACB': [
        0x18,
        {
            'BaseAddress': [0x0, ['pointer', ['void']]],
            'SharedCacheMap': [0x4, ['pointer', ['_SHARED_CACHE_MAP']]],
            'Overlay': [0x8, ['__unnamed_1173']],
            'LruList': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_SHARED_CACHE_MAP': [
        0x130,
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
            'FileObject': [0x44, ['pointer', ['_FILE_OBJECT']]],
            'ActiveVacb': [0x48, ['pointer', ['_VACB']]],
            'NeedToZero': [0x4C, ['pointer', ['void']]],
            'ActivePage': [0x50, ['unsigned long']],
            'NeedToZeroPage': [0x54, ['unsigned long']],
            'ActiveVacbSpinLock': [0x58, ['unsigned long']],
            'VacbActiveCount': [0x5C, ['unsigned long']],
            'DirtyPages': [0x60, ['unsigned long']],
            'SharedCacheMapLinks': [0x64, ['_LIST_ENTRY']],
            'Flags': [0x6C, ['unsigned long']],
            'Status': [0x70, ['long']],
            'Mbcb': [0x74, ['pointer', ['_MBCB']]],
            'Section': [0x78, ['pointer', ['void']]],
            'CreateEvent': [0x7C, ['pointer', ['_KEVENT']]],
            'WaitOnActiveCount': [0x80, ['pointer', ['_KEVENT']]],
            'PagesToWrite': [0x84, ['unsigned long']],
            'BeyondLastFlush': [0x88, ['long long']],
            'Callbacks': [0x90, ['pointer', ['_CACHE_MANAGER_CALLBACKS']]],
            'LazyWriteContext': [0x94, ['pointer', ['void']]],
            'PrivateList': [0x98, ['_LIST_ENTRY']],
            'LogHandle': [0xA0, ['pointer', ['void']]],
            'FlushToLsnRoutine': [0xA4, ['pointer', ['void']]],
            'DirtyPageThreshold': [0xA8, ['unsigned long']],
            'LazyWritePassCount': [0xAC, ['unsigned long']],
            'UninitializeEvent': [
                0xB0,
                ['pointer', ['_CACHE_UNINITIALIZE_EVENT']],
            ],
            'NeedToZeroVacb': [0xB4, ['pointer', ['_VACB']]],
            'BcbSpinLock': [0xB8, ['unsigned long']],
            'Reserved': [0xBC, ['pointer', ['void']]],
            'Event': [0xC0, ['_KEVENT']],
            'VacbPushLock': [0xD0, ['_EX_PUSH_LOCK']],
            'PrivateCacheMap': [0xD8, ['_PRIVATE_CACHE_MAP']],
        },
    ],
    '_VACB_LEVEL_REFERENCE': [
        0x8,
        {
            'Reference': [0x0, ['long']],
            'SpecialReference': [0x4, ['long']],
        },
    ],
    '_HEAP_ENTRY': [
        0x8,
        {
            'Size': [0x0, ['unsigned short']],
            'PreviousSize': [0x2, ['unsigned short']],
            'SubSegmentCode': [0x0, ['pointer', ['void']]],
            'SmallTagIndex': [0x4, ['unsigned char']],
            'Flags': [0x5, ['unsigned char']],
            'UnusedBytes': [0x6, ['unsigned char']],
            'SegmentIndex': [0x7, ['unsigned char']],
        },
    ],
    '__unnamed_119d': [
        0x10,
        {
            'FreeListsInUseUlong': [0x0, ['array', 4, ['unsigned long']]],
            'FreeListsInUseBytes': [0x0, ['array', 16, ['unsigned char']]],
        },
    ],
    '__unnamed_119f': [
        0x2,
        {
            'FreeListsInUseTerminate': [0x0, ['unsigned short']],
            'DecommitCount': [0x0, ['unsigned short']],
        },
    ],
    '_HEAP': [
        0x588,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'Signature': [0x8, ['unsigned long']],
            'Flags': [0xC, ['unsigned long']],
            'ForceFlags': [0x10, ['unsigned long']],
            'VirtualMemoryThreshold': [0x14, ['unsigned long']],
            'SegmentReserve': [0x18, ['unsigned long']],
            'SegmentCommit': [0x1C, ['unsigned long']],
            'DeCommitFreeBlockThreshold': [0x20, ['unsigned long']],
            'DeCommitTotalFreeThreshold': [0x24, ['unsigned long']],
            'TotalFreeSize': [0x28, ['unsigned long']],
            'MaximumAllocationSize': [0x2C, ['unsigned long']],
            'ProcessHeapsListIndex': [0x30, ['unsigned short']],
            'HeaderValidateLength': [0x32, ['unsigned short']],
            'HeaderValidateCopy': [0x34, ['pointer', ['void']]],
            'NextAvailableTagIndex': [0x38, ['unsigned short']],
            'MaximumTagIndex': [0x3A, ['unsigned short']],
            'TagEntries': [0x3C, ['pointer', ['_HEAP_TAG_ENTRY']]],
            'UCRSegments': [0x40, ['pointer', ['_HEAP_UCR_SEGMENT']]],
            'UnusedUnCommittedRanges': [
                0x44,
                ['pointer', ['_HEAP_UNCOMMMTTED_RANGE']],
            ],
            'AlignRound': [0x48, ['unsigned long']],
            'AlignMask': [0x4C, ['unsigned long']],
            'VirtualAllocdBlocks': [0x50, ['_LIST_ENTRY']],
            'Segments': [0x58, ['array', 64, ['pointer', ['_HEAP_SEGMENT']]]],
            'u': [0x158, ['__unnamed_119d']],
            'u2': [0x168, ['__unnamed_119f']],
            'AllocatorBackTraceIndex': [0x16A, ['unsigned short']],
            'NonDedicatedListLength': [0x16C, ['unsigned long']],
            'LargeBlocksIndex': [0x170, ['pointer', ['void']]],
            'PseudoTagEntries': [
                0x174,
                ['pointer', ['_HEAP_PSEUDO_TAG_ENTRY']],
            ],
            'FreeLists': [0x178, ['array', 128, ['_LIST_ENTRY']]],
            'LockVariable': [0x578, ['pointer', ['_HEAP_LOCK']]],
            'CommitRoutine': [0x57C, ['pointer', ['void']]],
            'FrontEndHeap': [0x580, ['pointer', ['void']]],
            'FrontHeapLockCount': [0x584, ['unsigned short']],
            'FrontEndHeapType': [0x586, ['unsigned char']],
            'LastSegmentIndex': [0x587, ['unsigned char']],
        },
    ],
    '_HEAP_SEGMENT': [
        0x3C,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'Signature': [0x8, ['unsigned long']],
            'Flags': [0xC, ['unsigned long']],
            'Heap': [0x10, ['pointer', ['_HEAP']]],
            'LargestUnCommittedRange': [0x14, ['unsigned long']],
            'BaseAddress': [0x18, ['pointer', ['void']]],
            'NumberOfPages': [0x1C, ['unsigned long']],
            'FirstEntry': [0x20, ['pointer', ['_HEAP_ENTRY']]],
            'LastValidEntry': [0x24, ['pointer', ['_HEAP_ENTRY']]],
            'NumberOfUnCommittedPages': [0x28, ['unsigned long']],
            'NumberOfUnCommittedRanges': [0x2C, ['unsigned long']],
            'UnCommittedRanges': [
                0x30,
                ['pointer', ['_HEAP_UNCOMMMTTED_RANGE']],
            ],
            'AllocatorBackTraceIndex': [0x34, ['unsigned short']],
            'Reserved': [0x36, ['unsigned short']],
            'LastEntryInSegment': [0x38, ['pointer', ['_HEAP_ENTRY']]],
        },
    ],
    '_HEAP_SUBSEGMENT': [
        0x20,
        {
            'Bucket': [0x0, ['pointer', ['void']]],
            'UserBlocks': [0x4, ['pointer', ['_HEAP_USERDATA_HEADER']]],
            'AggregateExchg': [0x8, ['_INTERLOCK_SEQ']],
            'BlockSize': [0x10, ['unsigned short']],
            'FreeThreshold': [0x12, ['unsigned short']],
            'BlockCount': [0x14, ['unsigned short']],
            'SizeIndex': [0x16, ['unsigned char']],
            'AffinityIndex': [0x17, ['unsigned char']],
            'Alignment': [0x10, ['array', 2, ['unsigned long']]],
            'SFreeListEntry': [0x18, ['_SINGLE_LIST_ENTRY']],
            'Lock': [0x1C, ['unsigned long']],
        },
    ],
    '_HEAP_UCR_SEGMENT': [
        0x10,
        {
            'Next': [0x0, ['pointer', ['_HEAP_UCR_SEGMENT']]],
            'ReservedSize': [0x4, ['unsigned long']],
            'CommittedSize': [0x8, ['unsigned long']],
            'filler': [0xC, ['unsigned long']],
        },
    ],
    '_HMAP_TABLE': [
        0x2000,
        {
            'Table': [0x0, ['array', 512, ['_HMAP_ENTRY']]],
        },
    ],
    '_OBJECT_SYMBOLIC_LINK': [
        0x20,
        {
            'CreationTime': [0x0, ['_LARGE_INTEGER']],
            'LinkTarget': [0x8, ['_UNICODE_STRING']],
            'LinkTargetRemaining': [0x10, ['_UNICODE_STRING']],
            'LinkTargetObject': [0x18, ['pointer', ['void']]],
            'DosDeviceDriveIndex': [0x1C, ['unsigned long']],
        },
    ],
    '_POOL_BLOCK_HEAD': [
        0x10,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'List': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_DISPATCHER_HEADER': [
        0x10,
        {
            'Type': [0x0, ['unsigned char']],
            'Absolute': [0x1, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'Inserted': [0x3, ['unsigned char']],
            'SignalState': [0x4, ['long']],
            'WaitListHead': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_LDR_DATA_TABLE_ENTRY': [
        0x50,
        {
            'InLoadOrderLinks': [0x0, ['_LIST_ENTRY']],
            'InMemoryOrderLinks': [0x8, ['_LIST_ENTRY']],
            'InInitializationOrderLinks': [0x10, ['_LIST_ENTRY']],
            'DllBase': [0x18, ['pointer', ['void']]],
            'EntryPoint': [0x1C, ['pointer', ['void']]],
            'SizeOfImage': [0x20, ['unsigned long']],
            'FullDllName': [0x24, ['_UNICODE_STRING']],
            'BaseDllName': [0x2C, ['_UNICODE_STRING']],
            'Flags': [0x34, ['unsigned long']],
            'LoadCount': [0x38, ['unsigned short']],
            'TlsIndex': [0x3A, ['unsigned short']],
            'HashLinks': [0x3C, ['_LIST_ENTRY']],
            'SectionPointer': [0x3C, ['pointer', ['void']]],
            'CheckSum': [0x40, ['unsigned long']],
            'TimeDateStamp': [0x44, ['unsigned long']],
            'LoadedImports': [0x44, ['pointer', ['void']]],
            'EntryPointActivationContext': [0x48, ['pointer', ['void']]],
            'PatchInformation': [0x4C, ['pointer', ['void']]],
        },
    ],
    '_HEAP_UNCOMMMTTED_RANGE': [
        0x10,
        {
            'Next': [0x0, ['pointer', ['_HEAP_UNCOMMMTTED_RANGE']]],
            'Address': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long']],
            'filler': [0xC, ['unsigned long']],
        },
    ],
    '_VI_DEADLOCK_GLOBALS': [
        0x110,
        {
            'Nodes': [0x0, ['array', 2, ['unsigned long']]],
            'Resources': [0x8, ['array', 2, ['unsigned long']]],
            'Threads': [0x10, ['array', 2, ['unsigned long']]],
            'TimeAcquire': [0x18, ['long long']],
            'TimeRelease': [0x20, ['long long']],
            'BytesAllocated': [0x28, ['unsigned long']],
            'ResourceDatabase': [0x2C, ['pointer', ['_LIST_ENTRY']]],
            'ThreadDatabase': [0x30, ['pointer', ['_LIST_ENTRY']]],
            'AllocationFailures': [0x34, ['unsigned long']],
            'NodesTrimmedBasedOnAge': [0x38, ['unsigned long']],
            'NodesTrimmedBasedOnCount': [0x3C, ['unsigned long']],
            'NodesSearched': [0x40, ['unsigned long']],
            'MaxNodesSearched': [0x44, ['unsigned long']],
            'SequenceNumber': [0x48, ['unsigned long']],
            'RecursionDepthLimit': [0x4C, ['unsigned long']],
            'SearchedNodesLimit': [0x50, ['unsigned long']],
            'DepthLimitHits': [0x54, ['unsigned long']],
            'SearchLimitHits': [0x58, ['unsigned long']],
            'ABC_ACB_Skipped': [0x5C, ['unsigned long']],
            'FreeResourceList': [0x60, ['_LIST_ENTRY']],
            'FreeThreadList': [0x68, ['_LIST_ENTRY']],
            'FreeNodeList': [0x70, ['_LIST_ENTRY']],
            'FreeResourceCount': [0x78, ['unsigned long']],
            'FreeThreadCount': [0x7C, ['unsigned long']],
            'FreeNodeCount': [0x80, ['unsigned long']],
            'Instigator': [0x84, ['pointer', ['void']]],
            'NumberOfParticipants': [0x88, ['unsigned long']],
            'Participant': [
                0x8C,
                ['array', 32, ['pointer', ['_VI_DEADLOCK_NODE']]],
            ],
            'CacheReductionInProgress': [0x10C, ['unsigned long']],
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
    '_DBGKD_SEARCH_MEMORY': [
        0x18,
        {
            'SearchAddress': [0x0, ['unsigned long long']],
            'FoundAddress': [0x0, ['unsigned long long']],
            'SearchLength': [0x8, ['unsigned long long']],
            'PatternLength': [0x10, ['unsigned long']],
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
    '_SEGMENT_OBJECT': [
        0x30,
        {
            'BaseAddress': [0x0, ['pointer', ['void']]],
            'TotalNumberOfPtes': [0x4, ['unsigned long']],
            'SizeOfSegment': [0x8, ['_LARGE_INTEGER']],
            'NonExtendedPtes': [0x10, ['unsigned long']],
            'ImageCommitment': [0x14, ['unsigned long']],
            'ControlArea': [0x18, ['pointer', ['_CONTROL_AREA']]],
            'Subsection': [0x1C, ['pointer', ['_SUBSECTION']]],
            'LargeControlArea': [0x20, ['pointer', ['_LARGE_CONTROL_AREA']]],
            'MmSectionFlags': [0x24, ['pointer', ['_MMSECTION_FLAGS']]],
            'MmSubSectionFlags': [0x28, ['pointer', ['_MMSUBSECTION_FLAGS']]],
        },
    ],
    '__unnamed_1224': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MMSECTION_FLAGS']],
        },
    ],
    '_CONTROL_AREA': [
        0x30,
        {
            'Segment': [0x0, ['pointer', ['_SEGMENT']]],
            'DereferenceList': [0x4, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0xC, ['unsigned long']],
            'NumberOfPfnReferences': [0x10, ['unsigned long']],
            'NumberOfMappedViews': [0x14, ['unsigned long']],
            'NumberOfSubsections': [0x18, ['unsigned short']],
            'FlushInProgressCount': [0x1A, ['unsigned short']],
            'NumberOfUserReferences': [0x1C, ['unsigned long']],
            'u': [0x20, ['__unnamed_1224']],
            'FilePointer': [0x24, ['pointer', ['_FILE_OBJECT']]],
            'WaitingForDeletion': [0x28, ['pointer', ['_EVENT_COUNTER']]],
            'ModifiedWriteCount': [0x2C, ['unsigned short']],
            'NumberOfSystemCacheViews': [0x2E, ['unsigned short']],
        },
    ],
    '_HANDLE_TABLE': [
        0x44,
        {
            'TableCode': [0x0, ['unsigned long']],
            'QuotaProcess': [0x4, ['pointer', ['_EPROCESS']]],
            'UniqueProcessId': [0x8, ['pointer', ['void']]],
            'HandleTableLock': [0xC, ['array', 4, ['_EX_PUSH_LOCK']]],
            'HandleTableList': [0x1C, ['_LIST_ENTRY']],
            'HandleContentionEvent': [0x24, ['_EX_PUSH_LOCK']],
            'DebugInfo': [0x28, ['pointer', ['_HANDLE_TRACE_DEBUG_INFO']]],
            'ExtraInfoPages': [0x2C, ['long']],
            'FirstFree': [0x30, ['unsigned long']],
            'LastFree': [0x34, ['unsigned long']],
            'NextHandleNeedingPool': [0x38, ['unsigned long']],
            'HandleCount': [0x3C, ['long']],
            'Flags': [0x40, ['unsigned long']],
            'StrictFIFO': [
                0x40,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
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
            'ProcessBilled': [0x4, ['pointer', ['_EPROCESS']]],
            'PoolTag': [0x4, ['unsigned long']],
            'AllocatorBackTraceIndex': [0x4, ['unsigned short']],
            'PoolTagHash': [0x6, ['unsigned short']],
        },
    ],
    '_KWAIT_BLOCK': [
        0x18,
        {
            'WaitListEntry': [0x0, ['_LIST_ENTRY']],
            'Thread': [0x8, ['pointer', ['_KTHREAD']]],
            'Object': [0xC, ['pointer', ['void']]],
            'NextWaitBlock': [0x10, ['pointer', ['_KWAIT_BLOCK']]],
            'WaitKey': [0x14, ['unsigned short']],
            'WaitType': [0x16, ['unsigned short']],
        },
    ],
    '_MMSUPPORT': [
        0x40,
        {
            'LastTrimTime': [0x0, ['_LARGE_INTEGER']],
            'Flags': [0x8, ['_MMSUPPORT_FLAGS']],
            'PageFaultCount': [0xC, ['unsigned long']],
            'PeakWorkingSetSize': [0x10, ['unsigned long']],
            'WorkingSetSize': [0x14, ['unsigned long']],
            'MinimumWorkingSetSize': [0x18, ['unsigned long']],
            'MaximumWorkingSetSize': [0x1C, ['unsigned long']],
            'VmWorkingSetList': [0x20, ['pointer', ['_MMWSL']]],
            'WorkingSetExpansionLinks': [0x24, ['_LIST_ENTRY']],
            'Claim': [0x2C, ['unsigned long']],
            'NextEstimationSlot': [0x30, ['unsigned long']],
            'NextAgingSlot': [0x34, ['unsigned long']],
            'EstimatedAvailable': [0x38, ['unsigned long']],
            'GrowthSinceLastEstimate': [0x3C, ['unsigned long']],
        },
    ],
    '_EX_WORK_QUEUE': [
        0x3C,
        {
            'WorkerQueue': [0x0, ['_KQUEUE']],
            'DynamicThreadCount': [0x28, ['unsigned long']],
            'WorkItemsProcessed': [0x2C, ['unsigned long']],
            'WorkItemsProcessedLastPass': [0x30, ['unsigned long']],
            'QueueDepthLastPass': [0x34, ['unsigned long']],
            'Info': [0x38, ['EX_QUEUE_WORKER_INFO']],
        },
    ],
    '_MMSUBSECTION_FLAGS': [
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
            'SubsectionStatic': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'GlobalMemory': [
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
            'LargePages': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'StartingSector4132': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'SectorEndOffset': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=32, native_type='unsigned long'
                    ),
                ],
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
            'TagName': [0x10, ['array', 24, ['unsigned short']]],
        },
    ],
    '_KEVENT': [
        0x10,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '_EPROCESS_QUOTA_BLOCK': [
        0x40,
        {
            'QuotaEntry': [0x0, ['array', 3, ['_EPROCESS_QUOTA_ENTRY']]],
            'QuotaList': [0x30, ['_LIST_ENTRY']],
            'ReferenceCount': [0x38, ['unsigned long']],
            'ProcessCount': [0x3C, ['unsigned long']],
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
    '_EVENT_COUNTER': [
        0x18,
        {
            'ListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'RefCount': [0x4, ['unsigned long']],
            'Event': [0x8, ['_KEVENT']],
        },
    ],
    '_EJOB': [
        0x180,
        {
            'Event': [0x0, ['_KEVENT']],
            'JobLinks': [0x10, ['_LIST_ENTRY']],
            'ProcessListHead': [0x18, ['_LIST_ENTRY']],
            'JobLock': [0x20, ['_ERESOURCE']],
            'TotalUserTime': [0x58, ['_LARGE_INTEGER']],
            'TotalKernelTime': [0x60, ['_LARGE_INTEGER']],
            'ThisPeriodTotalUserTime': [0x68, ['_LARGE_INTEGER']],
            'ThisPeriodTotalKernelTime': [0x70, ['_LARGE_INTEGER']],
            'TotalPageFaultCount': [0x78, ['unsigned long']],
            'TotalProcesses': [0x7C, ['unsigned long']],
            'ActiveProcesses': [0x80, ['unsigned long']],
            'TotalTerminatedProcesses': [0x84, ['unsigned long']],
            'PerProcessUserTimeLimit': [0x88, ['_LARGE_INTEGER']],
            'PerJobUserTimeLimit': [0x90, ['_LARGE_INTEGER']],
            'LimitFlags': [0x98, ['unsigned long']],
            'MinimumWorkingSetSize': [0x9C, ['unsigned long']],
            'MaximumWorkingSetSize': [0xA0, ['unsigned long']],
            'ActiveProcessLimit': [0xA4, ['unsigned long']],
            'Affinity': [0xA8, ['unsigned long']],
            'PriorityClass': [0xAC, ['unsigned char']],
            'UIRestrictionsClass': [0xB0, ['unsigned long']],
            'SecurityLimitFlags': [0xB4, ['unsigned long']],
            'Token': [0xB8, ['pointer', ['void']]],
            'Filter': [0xBC, ['pointer', ['_PS_JOB_TOKEN_FILTER']]],
            'EndOfJobTimeAction': [0xC0, ['unsigned long']],
            'CompletionPort': [0xC4, ['pointer', ['void']]],
            'CompletionKey': [0xC8, ['pointer', ['void']]],
            'SessionId': [0xCC, ['unsigned long']],
            'SchedulingClass': [0xD0, ['unsigned long']],
            'ReadOperationCount': [0xD8, ['unsigned long long']],
            'WriteOperationCount': [0xE0, ['unsigned long long']],
            'OtherOperationCount': [0xE8, ['unsigned long long']],
            'ReadTransferCount': [0xF0, ['unsigned long long']],
            'WriteTransferCount': [0xF8, ['unsigned long long']],
            'OtherTransferCount': [0x100, ['unsigned long long']],
            'IoInfo': [0x108, ['_IO_COUNTERS']],
            'ProcessMemoryLimit': [0x138, ['unsigned long']],
            'JobMemoryLimit': [0x13C, ['unsigned long']],
            'PeakProcessMemoryUsed': [0x140, ['unsigned long']],
            'PeakJobMemoryUsed': [0x144, ['unsigned long']],
            'CurrentJobMemoryUsed': [0x148, ['unsigned long']],
            'MemoryLimitsLock': [0x14C, ['_FAST_MUTEX']],
            'JobSetLinks': [0x16C, ['_LIST_ENTRY']],
            'MemberLevel': [0x174, ['unsigned long']],
            'JobFlags': [0x178, ['unsigned long']],
        },
    ],
    '_LARGE_CONTROL_AREA': [
        0x40,
        {
            'Segment': [0x0, ['pointer', ['_SEGMENT']]],
            'DereferenceList': [0x4, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0xC, ['unsigned long']],
            'NumberOfPfnReferences': [0x10, ['unsigned long']],
            'NumberOfMappedViews': [0x14, ['unsigned long']],
            'NumberOfSubsections': [0x18, ['unsigned short']],
            'FlushInProgressCount': [0x1A, ['unsigned short']],
            'NumberOfUserReferences': [0x1C, ['unsigned long']],
            'u': [0x20, ['__unnamed_1224']],
            'FilePointer': [0x24, ['pointer', ['_FILE_OBJECT']]],
            'WaitingForDeletion': [0x28, ['pointer', ['_EVENT_COUNTER']]],
            'ModifiedWriteCount': [0x2C, ['unsigned short']],
            'NumberOfSystemCacheViews': [0x2E, ['unsigned short']],
            'StartingFrame': [0x30, ['unsigned long']],
            'UserGlobalList': [0x34, ['_LIST_ENTRY']],
            'SessionId': [0x3C, ['unsigned long']],
        },
    ],
    '_PS_JOB_TOKEN_FILTER': [
        0x24,
        {
            'CapturedSidCount': [0x0, ['unsigned long']],
            'CapturedSids': [0x4, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'CapturedSidsLength': [0x8, ['unsigned long']],
            'CapturedGroupCount': [0xC, ['unsigned long']],
            'CapturedGroups': [0x10, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'CapturedGroupsLength': [0x14, ['unsigned long']],
            'CapturedPrivilegeCount': [0x18, ['unsigned long']],
            'CapturedPrivileges': [
                0x1C,
                ['pointer', ['_LUID_AND_ATTRIBUTES']],
            ],
            'CapturedPrivilegesLength': [0x20, ['unsigned long']],
        },
    ],
    '_FAST_MUTEX': [
        0x20,
        {
            'Count': [0x0, ['long']],
            'Owner': [0x4, ['pointer', ['_KTHREAD']]],
            'Contention': [0x8, ['unsigned long']],
            'Event': [0xC, ['_KEVENT']],
            'OldIrql': [0x1C, ['unsigned long']],
        },
    ],
    '_MM_DRIVER_VERIFIER_DATA': [
        0x70,
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
            'Reserved': [0x68, ['array', 2, ['unsigned long']]],
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
    '_FILE_OBJECT': [
        0x70,
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
        },
    ],
    '_IO_COMPLETION_CONTEXT': [
        0x8,
        {
            'Port': [0x0, ['pointer', ['void']]],
            'Key': [0x4, ['pointer', ['void']]],
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
    '_HMAP_ENTRY': [
        0x10,
        {
            'BlockAddress': [0x0, ['unsigned long']],
            'BinAddress': [0x4, ['unsigned long']],
            'CmView': [0x8, ['pointer', ['_CM_VIEW_OF_FILE']]],
            'MemAlloc': [0xC, ['unsigned long']],
        },
    ],
    '_DBGKD_SET_CONTEXT': [
        0x4,
        {
            'ContextFlags': [0x0, ['unsigned long']],
        },
    ],
    '_KLOCK_QUEUE_HANDLE': [
        0xC,
        {
            'LockQueue': [0x0, ['_KSPIN_LOCK_QUEUE']],
            'OldIrql': [0x8, ['unsigned char']],
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
            'NoCache': [
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
            'FloppyMedia': [
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
            'DebugSymbolsLoaded': [
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
            'HadUserReference': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageMappedInSystemSpace': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'UserWritable': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'Accessed': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'GlobalOnlyPerSession': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'Rom': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'filler': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_DEFERRED_WRITE': [
        0x28,
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
            'LimitModifiedPages': [0x24, ['unsigned char']],
        },
    ],
    '_SID_AND_ATTRIBUTES': [
        0x8,
        {
            'Sid': [0x0, ['pointer', ['void']]],
            'Attributes': [0x4, ['unsigned long']],
        },
    ],
    '_HIVE_LIST_ENTRY': [
        0x18,
        {
            'Name': [0x0, ['pointer', ['unsigned short']]],
            'BaseName': [0x4, ['pointer', ['unsigned short']]],
            'CmHive': [0x8, ['pointer', ['_CMHIVE']]],
            'Flags': [0xC, ['unsigned long']],
            'CmHive2': [0x10, ['pointer', ['_CMHIVE']]],
            'ThreadFinished': [0x14, ['unsigned char']],
            'ThreadStarted': [0x15, ['unsigned char']],
            'Allocate': [0x16, ['unsigned char']],
        },
    ],
    '_KSPIN_LOCK_QUEUE': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_KSPIN_LOCK_QUEUE']]],
            'Lock': [0x4, ['pointer', ['unsigned long']]],
        },
    ],
    '_PS_IMPERSONATION_INFORMATION': [
        0xC,
        {
            'Token': [0x0, ['pointer', ['void']]],
            'CopyOnOpen': [0x4, ['unsigned char']],
            'EffectiveOnly': [0x5, ['unsigned char']],
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
        },
    ],
    '__unnamed_12c3': [
        0x4,
        {
            'LegacyDeviceNode': [0x0, ['pointer', ['_DEVICE_NODE']]],
            'PendingDeviceRelations': [
                0x0,
                ['pointer', ['_DEVICE_RELATIONS']],
            ],
        },
    ],
    '__unnamed_12c5': [
        0x4,
        {
            'NextResourceDeviceNode': [0x0, ['pointer', ['_DEVICE_NODE']]],
        },
    ],
    '__unnamed_12c9': [
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
        0x118,
        {
            'Sibling': [0x0, ['pointer', ['_DEVICE_NODE']]],
            'Child': [0x4, ['pointer', ['_DEVICE_NODE']]],
            'Parent': [0x8, ['pointer', ['_DEVICE_NODE']]],
            'LastChild': [0xC, ['pointer', ['_DEVICE_NODE']]],
            'Level': [0x10, ['unsigned long']],
            'Notify': [0x14, ['pointer', ['_PO_DEVICE_NOTIFY']]],
            'State': [
                0x18,
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
                        },
                    ),
                ],
            ],
            'PreviousState': [
                0x1C,
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
                        },
                    ),
                ],
            ],
            'StateHistory': [
                0x20,
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
                            },
                        ),
                    ],
                ],
            ],
            'StateHistoryEntry': [0x70, ['unsigned long']],
            'CompletionStatus': [0x74, ['long']],
            'PendingIrp': [0x78, ['pointer', ['_IRP']]],
            'Flags': [0x7C, ['unsigned long']],
            'UserFlags': [0x80, ['unsigned long']],
            'Problem': [0x84, ['unsigned long']],
            'PhysicalDeviceObject': [0x88, ['pointer', ['_DEVICE_OBJECT']]],
            'ResourceList': [0x8C, ['pointer', ['_CM_RESOURCE_LIST']]],
            'ResourceListTranslated': [
                0x90,
                ['pointer', ['_CM_RESOURCE_LIST']],
            ],
            'InstancePath': [0x94, ['_UNICODE_STRING']],
            'ServiceName': [0x9C, ['_UNICODE_STRING']],
            'DuplicatePDO': [0xA4, ['pointer', ['_DEVICE_OBJECT']]],
            'ResourceRequirements': [
                0xA8,
                ['pointer', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'InterfaceType': [
                0xAC,
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
                            16: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0xB0, ['unsigned long']],
            'ChildInterfaceType': [
                0xB4,
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
                            16: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'ChildBusNumber': [0xB8, ['unsigned long']],
            'ChildBusTypeIndex': [0xBC, ['unsigned short']],
            'RemovalPolicy': [0xBE, ['unsigned char']],
            'HardwareRemovalPolicy': [0xBF, ['unsigned char']],
            'TargetDeviceNotify': [0xC0, ['_LIST_ENTRY']],
            'DeviceArbiterList': [0xC8, ['_LIST_ENTRY']],
            'DeviceTranslatorList': [0xD0, ['_LIST_ENTRY']],
            'NoTranslatorMask': [0xD8, ['unsigned short']],
            'QueryTranslatorMask': [0xDA, ['unsigned short']],
            'NoArbiterMask': [0xDC, ['unsigned short']],
            'QueryArbiterMask': [0xDE, ['unsigned short']],
            'OverUsed1': [0xE0, ['__unnamed_12c3']],
            'OverUsed2': [0xE4, ['__unnamed_12c5']],
            'BootResources': [0xE8, ['pointer', ['_CM_RESOURCE_LIST']]],
            'CapabilityFlags': [0xEC, ['unsigned long']],
            'DockInfo': [0xF0, ['__unnamed_12c9']],
            'DisableableDepends': [0x100, ['unsigned long']],
            'PendedSetInterfaceState': [0x104, ['_LIST_ENTRY']],
            'LegacyBusListEntry': [0x10C, ['_LIST_ENTRY']],
            'DriverUnloadRetryCount': [0x114, ['unsigned long']],
        },
    ],
    '__unnamed_12ce': [
        0x38,
        {
            'CriticalSection': [0x0, ['_RTL_CRITICAL_SECTION']],
            'Resource': [0x0, ['_ERESOURCE']],
        },
    ],
    '_HEAP_LOCK': [
        0x38,
        {
            'Lock': [0x0, ['__unnamed_12ce']],
        },
    ],
    '_KPCR': [
        0xD70,
        {
            'NtTib': [0x0, ['_NT_TIB']],
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
            'DebugActive': [0x50, ['unsigned char']],
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
    '_MMCOLOR_TABLES': [
        0xC,
        {
            'Flink': [0x0, ['unsigned long']],
            'Blink': [0x4, ['pointer', ['void']]],
            'Count': [0x8, ['unsigned long']],
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
    '_PP_LOOKASIDE_LIST': [
        0x8,
        {
            'P': [0x0, ['pointer', ['_GENERAL_LOOKASIDE']]],
            'L': [0x4, ['pointer', ['_GENERAL_LOOKASIDE']]],
        },
    ],
    '_PHYSICAL_MEMORY_RUN': [
        0x8,
        {
            'BasePage': [0x0, ['unsigned long']],
            'PageCount': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_12ed': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MM_SESSION_SPACE_FLAGS']],
        },
    ],
    '_MM_SESSION_SPACE': [
        0x1278,
        {
            'ReferenceCount': [0x0, ['unsigned long']],
            'u': [0x4, ['__unnamed_12ed']],
            'SessionId': [0x8, ['unsigned long']],
            'SessionPageDirectoryIndex': [0xC, ['unsigned long']],
            'GlobalVirtualAddress': [0x10, ['pointer', ['_MM_SESSION_SPACE']]],
            'ProcessList': [0x14, ['_LIST_ENTRY']],
            'NonPagedPoolBytes': [0x1C, ['unsigned long']],
            'PagedPoolBytes': [0x20, ['unsigned long']],
            'NonPagedPoolAllocations': [0x24, ['unsigned long']],
            'PagedPoolAllocations': [0x28, ['unsigned long']],
            'NonPagablePages': [0x2C, ['unsigned long']],
            'CommittedPages': [0x30, ['unsigned long']],
            'LastProcessSwappedOutTime': [0x38, ['_LARGE_INTEGER']],
            'PageTables': [0x40, ['pointer', ['_MMPTE']]],
            'PagedPoolMutex': [0x44, ['_FAST_MUTEX']],
            'PagedPoolStart': [0x64, ['pointer', ['void']]],
            'PagedPoolEnd': [0x68, ['pointer', ['void']]],
            'PagedPoolBasePde': [0x6C, ['pointer', ['_MMPTE']]],
            'PagedPoolInfo': [0x70, ['_MM_PAGED_POOL_INFO']],
            'Color': [0x94, ['unsigned long']],
            'ProcessOutSwapCount': [0x98, ['unsigned long']],
            'ImageList': [0x9C, ['_LIST_ENTRY']],
            'GlobalPteEntry': [0xA4, ['pointer', ['_MMPTE']]],
            'CopyOnWriteCount': [0xA8, ['unsigned long']],
            'SessionPoolAllocationFailures': [
                0xAC,
                ['array', 4, ['unsigned long']],
            ],
            'AttachCount': [0xBC, ['unsigned long']],
            'AttachEvent': [0xC0, ['_KEVENT']],
            'LastProcess': [0xD0, ['pointer', ['_EPROCESS']]],
            'Vm': [0xD8, ['_MMSUPPORT']],
            'Wsle': [0x118, ['pointer', ['_MMWSLE']]],
            'WsLock': [0x11C, ['_ERESOURCE']],
            'WsListEntry': [0x154, ['_LIST_ENTRY']],
            'Session': [0x15C, ['_MMSESSION']],
            'Win32KDriverObject': [0x198, ['_DRIVER_OBJECT']],
            'WorkingSetLockOwner': [0x240, ['pointer', ['_ETHREAD']]],
            'PagedPool': [0x244, ['_POOL_DESCRIPTOR']],
            'ProcessReferenceToSession': [0x126C, ['long']],
            'LocaleId': [0x1270, ['unsigned long']],
        },
    ],
    '_PEB': [
        0x210,
        {
            'InheritedAddressSpace': [0x0, ['unsigned char']],
            'ReadImageFileExecOptions': [0x1, ['unsigned char']],
            'BeingDebugged': [0x2, ['unsigned char']],
            'SpareBool': [0x3, ['unsigned char']],
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
            'FastPebLockRoutine': [0x20, ['pointer', ['void']]],
            'FastPebUnlockRoutine': [0x24, ['pointer', ['void']]],
            'EnvironmentUpdateCount': [0x28, ['unsigned long']],
            'KernelCallbackTable': [0x2C, ['pointer', ['void']]],
            'SystemReserved': [0x30, ['array', 1, ['unsigned long']]],
            'AtlThunkSListPtr32': [0x34, ['unsigned long']],
            'FreeList': [0x38, ['pointer', ['_PEB_FREE_BLOCK']]],
            'TlsExpansionCounter': [0x3C, ['unsigned long']],
            'TlsBitmap': [0x40, ['pointer', ['void']]],
            'TlsBitmapBits': [0x44, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x4C, ['pointer', ['void']]],
            'ReadOnlySharedMemoryHeap': [0x50, ['pointer', ['void']]],
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
            'LoaderLock': [0xA0, ['pointer', ['void']]],
            'OSMajorVersion': [0xA4, ['unsigned long']],
            'OSMinorVersion': [0xA8, ['unsigned long']],
            'OSBuildNumber': [0xAC, ['unsigned short']],
            'OSCSDVersion': [0xAE, ['unsigned short']],
            'OSPlatformId': [0xB0, ['unsigned long']],
            'ImageSubsystem': [0xB4, ['unsigned long']],
            'ImageSubsystemMajorVersion': [0xB8, ['unsigned long']],
            'ImageSubsystemMinorVersion': [0xBC, ['unsigned long']],
            'ImageProcessAffinityMask': [0xC0, ['unsigned long']],
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
            'ActivationContextData': [0x1F8, ['pointer', ['void']]],
            'ProcessAssemblyStorageMap': [0x1FC, ['pointer', ['void']]],
            'SystemDefaultActivationContextData': [
                0x200,
                ['pointer', ['void']],
            ],
            'SystemAssemblyStorageMap': [0x204, ['pointer', ['void']]],
            'MinimumStackCommit': [0x208, ['unsigned long']],
        },
    ],
    '_HEAP_FREE_ENTRY': [
        0x10,
        {
            'Size': [0x0, ['unsigned short']],
            'PreviousSize': [0x2, ['unsigned short']],
            'SubSegmentCode': [0x0, ['pointer', ['void']]],
            'SmallTagIndex': [0x4, ['unsigned char']],
            'Flags': [0x5, ['unsigned char']],
            'UnusedBytes': [0x6, ['unsigned char']],
            'SegmentIndex': [0x7, ['unsigned char']],
            'FreeList': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_ERESOURCE': [
        0x38,
        {
            'SystemResourcesList': [0x0, ['_LIST_ENTRY']],
            'OwnerTable': [0x8, ['pointer', ['_OWNER_ENTRY']]],
            'ActiveCount': [0xC, ['short']],
            'Flag': [0xE, ['unsigned short']],
            'SharedWaiters': [0x10, ['pointer', ['_KSEMAPHORE']]],
            'ExclusiveWaiters': [0x14, ['pointer', ['_KEVENT']]],
            'OwnerThreads': [0x18, ['array', 2, ['_OWNER_ENTRY']]],
            'ContentionCount': [0x28, ['unsigned long']],
            'NumberOfSharedWaiters': [0x2C, ['unsigned short']],
            'NumberOfExclusiveWaiters': [0x2E, ['unsigned short']],
            'Address': [0x30, ['pointer', ['void']]],
            'CreatorBackTraceIndex': [0x30, ['unsigned long']],
            'SpinLock': [0x34, ['unsigned long']],
        },
    ],
    '_DBGKD_GET_CONTEXT': [
        0x4,
        {
            'Unused': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1317': [
        0x4,
        {
            'Long': [0x0, ['unsigned long']],
            'Hard': [0x0, ['_MMPTE_HARDWARE']],
            'Flush': [0x0, ['_HARDWARE_PTE']],
            'Proto': [0x0, ['_MMPTE_PROTOTYPE']],
            'Soft': [0x0, ['_MMPTE_SOFTWARE']],
            'Trans': [0x0, ['_MMPTE_TRANSITION']],
            'Subsect': [0x0, ['_MMPTE_SUBSECTION']],
            'List': [0x0, ['_MMPTE_LIST']],
        },
    ],
    '_MMPTE': [
        0x4,
        {
            'u': [0x0, ['__unnamed_1317']],
        },
    ],
    '_MMPTE_SOFTWARE': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'PageFileLow': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'Transition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'PageFileHigh': [
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
                            16: 'MaximumInterfaceType',
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
    '_CACHE_UNINITIALIZE_EVENT': [
        0x14,
        {
            'Next': [0x0, ['pointer', ['_CACHE_UNINITIALIZE_EVENT']]],
            'Event': [0x4, ['_KEVENT']],
        },
    ],
    '_CM_RESOURCE_LIST': [
        0x24,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['array', 1, ['_CM_FULL_RESOURCE_DESCRIPTOR']]],
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
                            16: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0x4, ['unsigned long']],
            'PartialResourceList': [0x8, ['_CM_PARTIAL_RESOURCE_LIST']],
        },
    ],
    '_EPROCESS_QUOTA_ENTRY': [
        0x10,
        {
            'Usage': [0x0, ['unsigned long']],
            'Limit': [0x4, ['unsigned long']],
            'Peak': [0x8, ['unsigned long']],
            'Return': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1333': [
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
            'Data': [0x4, ['__unnamed_1333']],
        },
    ],
    '_KSEMAPHORE': [
        0x14,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'Limit': [0x10, ['long']],
        },
    ],
    '_PROCESSOR_POWER_STATE': [
        0x120,
        {
            'IdleFunction': [0x0, ['pointer', ['void']]],
            'Idle0KernelTimeLimit': [0x4, ['unsigned long']],
            'Idle0LastTime': [0x8, ['unsigned long']],
            'IdleHandlers': [0xC, ['pointer', ['void']]],
            'IdleState': [0x10, ['pointer', ['void']]],
            'IdleHandlersCount': [0x14, ['unsigned long']],
            'LastCheck': [0x18, ['unsigned long long']],
            'IdleTimes': [0x20, ['PROCESSOR_IDLE_TIMES']],
            'IdleTime1': [0x40, ['unsigned long']],
            'PromotionCheck': [0x44, ['unsigned long']],
            'IdleTime2': [0x48, ['unsigned long']],
            'CurrentThrottle': [0x4C, ['unsigned char']],
            'ThermalThrottleLimit': [0x4D, ['unsigned char']],
            'CurrentThrottleIndex': [0x4E, ['unsigned char']],
            'ThermalThrottleIndex': [0x4F, ['unsigned char']],
            'LastKernelUserTime': [0x50, ['unsigned long']],
            'PerfIdleTime': [0x54, ['unsigned long']],
            'DebugDelta': [0x58, ['unsigned long long']],
            'DebugCount': [0x60, ['unsigned long']],
            'LastSysTime': [0x64, ['unsigned long']],
            'TotalIdleStateTime': [0x68, ['array', 3, ['unsigned long long']]],
            'TotalIdleTransitions': [0x80, ['array', 3, ['unsigned long']]],
            'PreviousC3StateTime': [0x90, ['unsigned long long']],
            'KneeThrottleIndex': [0x98, ['unsigned char']],
            'ThrottleLimitIndex': [0x99, ['unsigned char']],
            'PerfStatesCount': [0x9A, ['unsigned char']],
            'ProcessorMinThrottle': [0x9B, ['unsigned char']],
            'ProcessorMaxThrottle': [0x9C, ['unsigned char']],
            'LastBusyPercentage': [0x9D, ['unsigned char']],
            'LastC3Percentage': [0x9E, ['unsigned char']],
            'LastAdjustedBusyPercentage': [0x9F, ['unsigned char']],
            'PromotionCount': [0xA0, ['unsigned long']],
            'DemotionCount': [0xA4, ['unsigned long']],
            'ErrorCount': [0xA8, ['unsigned long']],
            'RetryCount': [0xAC, ['unsigned long']],
            'Flags': [0xB0, ['unsigned long']],
            'PerfCounterFrequency': [0xB8, ['_LARGE_INTEGER']],
            'PerfTickCount': [0xC0, ['unsigned long']],
            'PerfTimer': [0xC8, ['_KTIMER']],
            'PerfDpc': [0xF0, ['_KDPC']],
            'PerfStates': [0x110, ['pointer', ['PROCESSOR_PERF_STATE']]],
            'PerfSetThrottle': [0x114, ['pointer', ['void']]],
            'LastC3KernelUserTime': [0x118, ['unsigned long']],
            'Spare1': [0x11C, ['array', 1, ['unsigned long']]],
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
    '_IO_COUNTERS': [
        0x30,
        {
            'ReadOperationCount': [0x0, ['unsigned long long']],
            'WriteOperationCount': [0x8, ['unsigned long long']],
            'OtherOperationCount': [0x10, ['unsigned long long']],
            'ReadTransferCount': [0x18, ['unsigned long long']],
            'WriteTransferCount': [0x20, ['unsigned long long']],
            'OtherTransferCount': [0x28, ['unsigned long long']],
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
    '_DEVICE_OBJECT_POWER_EXTENSION': [
        0x4C,
        {
            'IdleCount': [0x0, ['unsigned long']],
            'ConservationIdleTime': [0x4, ['unsigned long']],
            'PerformanceIdleTime': [0x8, ['unsigned long']],
            'DeviceObject': [0xC, ['pointer', ['_DEVICE_OBJECT']]],
            'IdleList': [0x10, ['_LIST_ENTRY']],
            'DeviceType': [0x18, ['unsigned char']],
            'State': [
                0x1C,
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
            'NotifySourceList': [0x20, ['_LIST_ENTRY']],
            'NotifyTargetList': [0x28, ['_LIST_ENTRY']],
            'PowerChannelSummary': [0x30, ['_POWER_CHANNEL_SUMMARY']],
            'Volume': [0x44, ['_LIST_ENTRY']],
        },
    ],
    '_MMSUPPORT_FLAGS': [
        0x4,
        {
            'SessionSpace': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'BeingTrimmed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SessionLeader': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'TrimHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'WorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'AddressSpaceBeingDeleted': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Available': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'AllowWorkingSetAdjustment': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'MemoryPriority': [
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
    '_TERMINATION_PORT': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_TERMINATION_PORT']]],
            'Port': [0x4, ['pointer', ['void']]],
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
    '_POP_THERMAL_ZONE': [
        0xD0,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'State': [0x8, ['unsigned char']],
            'Flags': [0x9, ['unsigned char']],
            'Mode': [0xA, ['unsigned char']],
            'PendingMode': [0xB, ['unsigned char']],
            'ActivePoint': [0xC, ['unsigned char']],
            'PendingActivePoint': [0xD, ['unsigned char']],
            'Throttle': [0x10, ['long']],
            'LastTime': [0x18, ['unsigned long long']],
            'SampleRate': [0x20, ['unsigned long']],
            'LastTemp': [0x24, ['unsigned long']],
            'PassiveTimer': [0x28, ['_KTIMER']],
            'PassiveDpc': [0x50, ['_KDPC']],
            'OverThrottled': [0x70, ['_POP_ACTION_TRIGGER']],
            'Irp': [0x7C, ['pointer', ['_IRP']]],
            'Info': [0x80, ['_THERMAL_INFORMATION']],
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
    '_PROCESSOR_POWER_POLICY': [
        0x4C,
        {
            'Revision': [0x0, ['unsigned long']],
            'DynamicThrottle': [0x4, ['unsigned char']],
            'Spare': [0x5, ['array', 3, ['unsigned char']]],
            'DisableCStates': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'PolicyCount': [0xC, ['unsigned long']],
            'Policy': [0x10, ['array', 3, ['_PROCESSOR_POWER_POLICY_INFO']]],
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
    '_OWNER_ENTRY': [
        0x8,
        {
            'OwnerThread': [0x0, ['unsigned long']],
            'OwnerCount': [0x4, ['long']],
            'TableSize': [0x4, ['unsigned long']],
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
    '_RTL_ATOM_TABLE': [
        0x44,
        {
            'Signature': [0x0, ['unsigned long']],
            'CriticalSection': [0x4, ['_RTL_CRITICAL_SECTION']],
            'RtlHandleTable': [0x1C, ['_RTL_HANDLE_TABLE']],
            'NumberOfBuckets': [0x3C, ['unsigned long']],
            'Buckets': [
                0x40,
                ['array', 1, ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]],
            ],
        },
    ],
    '_FNSAVE_FORMAT': [
        0x6C,
        {
            'ControlWord': [0x0, ['unsigned long']],
            'StatusWord': [0x4, ['unsigned long']],
            'TagWord': [0x8, ['unsigned long']],
            'ErrorOffset': [0xC, ['unsigned long']],
            'ErrorSelector': [0x10, ['unsigned long']],
            'DataOffset': [0x14, ['unsigned long']],
            'DataSelector': [0x18, ['unsigned long']],
            'RegisterArea': [0x1C, ['array', 80, ['unsigned char']]],
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
    'PROCESSOR_PERF_STATE': [
        0x20,
        {
            'PercentFrequency': [0x0, ['unsigned char']],
            'MinCapacity': [0x1, ['unsigned char']],
            'Power': [0x2, ['unsigned short']],
            'IncreaseLevel': [0x4, ['unsigned char']],
            'DecreaseLevel': [0x5, ['unsigned char']],
            'Flags': [0x6, ['unsigned short']],
            'IncreaseTime': [0x8, ['unsigned long']],
            'DecreaseTime': [0xC, ['unsigned long']],
            'IncreaseCount': [0x10, ['unsigned long']],
            'DecreaseCount': [0x14, ['unsigned long']],
            'PerformanceTime': [0x18, ['unsigned long long']],
        },
    ],
    'PROCESSOR_IDLE_TIMES': [
        0x20,
        {
            'StartTime': [0x0, ['unsigned long long']],
            'EndTime': [0x8, ['unsigned long long']],
            'IdleHandlerReserved': [0x10, ['array', 4, ['unsigned long']]],
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
    '_MMPTE_LIST': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'OneEntry': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'filler0': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'filler1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'NextEntry': [
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
    '_CMHIVE': [
        0x49C,
        {
            'Hive': [0x0, ['_HHIVE']],
            'FileHandles': [0x210, ['array', 3, ['pointer', ['void']]]],
            'NotifyList': [0x21C, ['_LIST_ENTRY']],
            'HiveList': [0x224, ['_LIST_ENTRY']],
            'HiveLock': [0x22C, ['pointer', ['_FAST_MUTEX']]],
            'ViewLock': [0x230, ['pointer', ['_FAST_MUTEX']]],
            'LRUViewListHead': [0x234, ['_LIST_ENTRY']],
            'PinViewListHead': [0x23C, ['_LIST_ENTRY']],
            'FileObject': [0x244, ['pointer', ['_FILE_OBJECT']]],
            'FileFullPath': [0x248, ['_UNICODE_STRING']],
            'FileUserName': [0x250, ['_UNICODE_STRING']],
            'MappedViews': [0x258, ['unsigned short']],
            'PinnedViews': [0x25A, ['unsigned short']],
            'UseCount': [0x25C, ['unsigned long']],
            'SecurityCount': [0x260, ['unsigned long']],
            'SecurityCacheSize': [0x264, ['unsigned long']],
            'SecurityHitHint': [0x268, ['long']],
            'SecurityCache': [
                0x26C,
                ['pointer', ['_CM_KEY_SECURITY_CACHE_ENTRY']],
            ],
            'SecurityHash': [0x270, ['array', 64, ['_LIST_ENTRY']]],
            'UnloadEvent': [0x470, ['pointer', ['_KEVENT']]],
            'RootKcb': [0x474, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'Frozen': [0x478, ['unsigned char']],
            'UnloadWorkItem': [0x47C, ['pointer', ['_WORK_QUEUE_ITEM']]],
            'GrowOnlyMode': [0x480, ['unsigned char']],
            'GrowOffset': [0x484, ['unsigned long']],
            'KcbConvertListHead': [0x488, ['_LIST_ENTRY']],
            'KnodeConvertListHead': [0x490, ['_LIST_ENTRY']],
            'CellRemapArray': [0x498, ['pointer', ['_CM_CELL_REMAP_BLOCK']]],
        },
    ],
    '_HANDLE_TRACE_DEBUG_INFO': [
        0x50004,
        {
            'CurrentStackIndex': [0x0, ['unsigned long']],
            'TraceDb': [0x4, ['array', 4096, ['_HANDLE_TRACE_DB_ENTRY']]],
        },
    ],
    '_HHIVE': [
        0x210,
        {
            'Signature': [0x0, ['unsigned long']],
            'GetCellRoutine': [0x4, ['pointer', ['void']]],
            'ReleaseCellRoutine': [0x8, ['pointer', ['void']]],
            'Allocate': [0xC, ['pointer', ['void']]],
            'Free': [0x10, ['pointer', ['void']]],
            'FileSetSize': [0x14, ['pointer', ['void']]],
            'FileWrite': [0x18, ['pointer', ['void']]],
            'FileRead': [0x1C, ['pointer', ['void']]],
            'FileFlush': [0x20, ['pointer', ['void']]],
            'BaseBlock': [0x24, ['pointer', ['_HBASE_BLOCK']]],
            'DirtyVector': [0x28, ['_RTL_BITMAP']],
            'DirtyCount': [0x30, ['unsigned long']],
            'DirtyAlloc': [0x34, ['unsigned long']],
            'RealWrites': [0x38, ['unsigned char']],
            'Cluster': [0x3C, ['unsigned long']],
            'Flat': [0x40, ['unsigned char']],
            'ReadOnly': [0x41, ['unsigned char']],
            'Log': [0x42, ['unsigned char']],
            'HiveFlags': [0x44, ['unsigned long']],
            'LogSize': [0x48, ['unsigned long']],
            'RefreshCount': [0x4C, ['unsigned long']],
            'StorageTypeCount': [0x50, ['unsigned long']],
            'Version': [0x54, ['unsigned long']],
            'Storage': [0x58, ['array', 2, ['_DUAL']]],
        },
    ],
    '_PAGEFAULT_HISTORY': [
        0x18,
        {
            'CurrentIndex': [0x0, ['unsigned long']],
            'MaxIndex': [0x4, ['unsigned long']],
            'SpinLock': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['pointer', ['void']]],
            'WatchInfo': [
                0x10,
                ['array', 1, ['_PROCESS_WS_WATCH_INFORMATION']],
            ],
        },
    ],
    '_RTL_ATOM_TABLE_ENTRY': [
        0x10,
        {
            'HashLink': [0x0, ['pointer', ['_RTL_ATOM_TABLE_ENTRY']]],
            'HandleIndex': [0x4, ['unsigned short']],
            'Atom': [0x6, ['unsigned short']],
            'ReferenceCount': [0x8, ['unsigned short']],
            'Flags': [0xA, ['unsigned char']],
            'NameLength': [0xB, ['unsigned char']],
            'Name': [0xC, ['array', 1, ['unsigned short']]],
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
            'Filler0': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'HasWsLock': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'DeletePending': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Filler': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=32, native_type='unsigned long'),
                ],
            ],
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
    '__unnamed_13f8': [
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
            'Queue': [0x34, ['__unnamed_13f8']],
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
    '_SECTION_OBJECT_POINTERS': [
        0xC,
        {
            'DataSectionObject': [0x0, ['pointer', ['void']]],
            'SharedCacheMap': [0x4, ['pointer', ['void']]],
            'ImageSectionObject': [0x8, ['pointer', ['void']]],
        },
    ],
    '_RTL_BITMAP': [
        0x8,
        {
            'SizeOfBitMap': [0x0, ['unsigned long']],
            'Buffer': [0x4, ['pointer', ['unsigned long']]],
        },
    ],
    '_MBCB': [
        0x80,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeIsInZone': [0x2, ['short']],
            'PagesToWrite': [0x4, ['unsigned long']],
            'DirtyPages': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
            'BitmapRanges': [0x10, ['_LIST_ENTRY']],
            'ResumeWritePage': [0x18, ['long long']],
            'BitmapRange1': [0x20, ['_BITMAP_RANGE']],
            'BitmapRange2': [0x40, ['_BITMAP_RANGE']],
            'BitmapRange3': [0x60, ['_BITMAP_RANGE']],
        },
    ],
    '_POWER_CHANNEL_SUMMARY': [
        0x14,
        {
            'Signature': [0x0, ['unsigned long']],
            'TotalCount': [0x4, ['unsigned long']],
            'D0Count': [0x8, ['unsigned long']],
            'NotifyList': [0xC, ['_LIST_ENTRY']],
        },
    ],
    '_CM_VIEW_OF_FILE': [
        0x24,
        {
            'LRUViewList': [0x0, ['_LIST_ENTRY']],
            'PinViewList': [0x8, ['_LIST_ENTRY']],
            'FileOffset': [0x10, ['unsigned long']],
            'Size': [0x14, ['unsigned long']],
            'ViewAddress': [0x18, ['pointer', ['unsigned long']]],
            'Bcb': [0x1C, ['pointer', ['void']]],
            'UseCount': [0x20, ['unsigned long']],
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
    '_KUSER_SHARED_DATA': [
        0x338,
        {
            'TickCountLow': [0x0, ['unsigned long']],
            'TickCountMultiplier': [0x4, ['unsigned long']],
            'InterruptTime': [0x8, ['_KSYSTEM_TIME']],
            'SystemTime': [0x14, ['_KSYSTEM_TIME']],
            'TimeZoneBias': [0x20, ['_KSYSTEM_TIME']],
            'ImageNumberLow': [0x2C, ['unsigned short']],
            'ImageNumberHigh': [0x2E, ['unsigned short']],
            'NtSystemRoot': [0x30, ['array', 260, ['unsigned short']]],
            'MaxStackTraceDepth': [0x238, ['unsigned long']],
            'CryptoExponent': [0x23C, ['unsigned long']],
            'TimeZoneId': [0x240, ['unsigned long']],
            'Reserved2': [0x244, ['array', 8, ['unsigned long']]],
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
            'TraceLogging': [0x2F0, ['unsigned long']],
            'TestRetInstruction': [0x2F8, ['unsigned long long']],
            'SystemCall': [0x300, ['unsigned long']],
            'SystemCallReturn': [0x304, ['unsigned long']],
            'SystemCallPad': [0x308, ['array', 3, ['unsigned long long']]],
            'TickCount': [0x320, ['_KSYSTEM_TIME']],
            'TickCountQuad': [0x320, ['unsigned long long']],
            'Cookie': [0x330, ['unsigned long']],
        },
    ],
    '_OBJECT_TYPE_INITIALIZER': [
        0x4C,
        {
            'Length': [0x0, ['unsigned short']],
            'UseDefaultObject': [0x2, ['unsigned char']],
            'CaseInsensitive': [0x3, ['unsigned char']],
            'InvalidAttributes': [0x4, ['unsigned long']],
            'GenericMapping': [0x8, ['_GENERIC_MAPPING']],
            'ValidAccessMask': [0x18, ['unsigned long']],
            'SecurityRequired': [0x1C, ['unsigned char']],
            'MaintainHandleCount': [0x1D, ['unsigned char']],
            'MaintainTypeList': [0x1E, ['unsigned char']],
            'PoolType': [
                0x20,
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
            'DefaultPagedPoolCharge': [0x24, ['unsigned long']],
            'DefaultNonPagedPoolCharge': [0x28, ['unsigned long']],
            'DumpProcedure': [0x2C, ['pointer', ['void']]],
            'OpenProcedure': [0x30, ['pointer', ['void']]],
            'CloseProcedure': [0x34, ['pointer', ['void']]],
            'DeleteProcedure': [0x38, ['pointer', ['void']]],
            'ParseProcedure': [0x3C, ['pointer', ['void']]],
            'SecurityProcedure': [0x40, ['pointer', ['void']]],
            'QueryNameProcedure': [0x44, ['pointer', ['void']]],
            'OkayToCloseProcedure': [0x48, ['pointer', ['void']]],
        },
    ],
    '__unnamed_143e': [
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
            'u': [0x4, ['__unnamed_143e']],
            'StartingSector': [0x8, ['unsigned long']],
            'NumberOfFullSectors': [0xC, ['unsigned long']],
            'SubsectionBase': [0x10, ['pointer', ['_MMPTE']]],
            'UnusedPtes': [0x14, ['unsigned long']],
            'PtesInSubsection': [0x18, ['unsigned long']],
            'NextSubsection': [0x1C, ['pointer', ['_SUBSECTION']]],
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
    '__unnamed_144c': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'VadFlags': [0x0, ['_MMVAD_FLAGS']],
        },
    ],
    '__unnamed_144f': [
        0x4,
        {
            'LongFlags2': [0x0, ['unsigned long']],
            'VadFlags2': [0x0, ['_MMVAD_FLAGS2']],
        },
    ],
    '__unnamed_1452': [
        0x8,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'Secured': [0x0, ['_MMADDRESS_LIST']],
        },
    ],
    '__unnamed_1458': [
        0x4,
        {
            'Banked': [0x0, ['pointer', ['_MMBANKED_SECTION']]],
            'ExtendedInfo': [0x0, ['pointer', ['_MMEXTEND_INFO']]],
        },
    ],
    '_MMVAD_LONG': [
        0x34,
        {
            'StartingVpn': [0x0, ['unsigned long']],
            'EndingVpn': [0x4, ['unsigned long']],
            'Parent': [0x8, ['pointer', ['_MMVAD']]],
            'LeftChild': [0xC, ['pointer', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer', ['_MMVAD']]],
            'u': [0x14, ['__unnamed_144c']],
            'ControlArea': [0x18, ['pointer', ['_CONTROL_AREA']]],
            'FirstPrototypePte': [0x1C, ['pointer', ['_MMPTE']]],
            'LastContiguousPte': [0x20, ['pointer', ['_MMPTE']]],
            'u2': [0x24, ['__unnamed_144f']],
            'u3': [0x28, ['__unnamed_1452']],
            'u4': [0x30, ['__unnamed_1458']],
        },
    ],
    '_MMVAD_FLAGS': [
        0x4,
        {
            'CommitCharge': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=19, native_type='unsigned long'),
                ],
            ],
            'PhysicalMapping': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageMap': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'UserPhysicalPages': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'NoChange': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteWatch': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'LargePages': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'MemCommit': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'PrivateMemory': [
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
    '_POOL_DESCRIPTOR': [
        0x1028,
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
            'PoolIndex': [0x4, ['unsigned long']],
            'RunningAllocs': [0x8, ['unsigned long']],
            'RunningDeAllocs': [0xC, ['unsigned long']],
            'TotalPages': [0x10, ['unsigned long']],
            'TotalBigPages': [0x14, ['unsigned long']],
            'Threshold': [0x18, ['unsigned long']],
            'LockAddress': [0x1C, ['pointer', ['void']]],
            'PendingFrees': [0x20, ['pointer', ['void']]],
            'PendingFreeDepth': [0x24, ['long']],
            'ListHeads': [0x28, ['array', 512, ['_LIST_ENTRY']]],
        },
    ],
    '_HARDWARE_PTE': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Write': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Owner': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WriteThrough': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'CacheDisable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Accessed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Dirty': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'LargePage': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Global': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'PageFrameNumber': [
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
    '_PEB_LDR_DATA': [
        0x28,
        {
            'Length': [0x0, ['unsigned long']],
            'Initialized': [0x4, ['unsigned char']],
            'SsHandle': [0x8, ['pointer', ['void']]],
            'InLoadOrderModuleList': [0xC, ['_LIST_ENTRY']],
            'InMemoryOrderModuleList': [0x14, ['_LIST_ENTRY']],
            'InInitializationOrderModuleList': [0x1C, ['_LIST_ENTRY']],
            'EntryInProgress': [0x24, ['pointer', ['void']]],
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
    '_MM_PAGED_POOL_INFO': [
        0x24,
        {
            'PagedPoolAllocationMap': [0x0, ['pointer', ['_RTL_BITMAP']]],
            'EndOfPagedPoolBitmap': [0x4, ['pointer', ['_RTL_BITMAP']]],
            'PagedPoolLargeSessionAllocationMap': [
                0x8,
                ['pointer', ['_RTL_BITMAP']],
            ],
            'FirstPteForPagedPool': [0xC, ['pointer', ['_MMPTE']]],
            'LastPteForPagedPool': [0x10, ['pointer', ['_MMPTE']]],
            'NextPdeForPagedPoolExpansion': [0x14, ['pointer', ['_MMPTE']]],
            'PagedPoolHint': [0x18, ['unsigned long']],
            'PagedPoolCommit': [0x1C, ['unsigned long']],
            'AllocatedPagedPool': [0x20, ['unsigned long']],
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
            'VolumeLabel': [0x18, ['array', 32, ['unsigned short']]],
        },
    ],
    '_MMSESSION': [
        0x3C,
        {
            'SystemSpaceViewLock': [0x0, ['_FAST_MUTEX']],
            'SystemSpaceViewLockPointer': [0x20, ['pointer', ['_FAST_MUTEX']]],
            'SystemSpaceViewStart': [0x24, ['pointer', ['unsigned char']]],
            'SystemSpaceViewTable': [0x28, ['pointer', ['_MMVIEW']]],
            'SystemSpaceHashSize': [0x2C, ['unsigned long']],
            'SystemSpaceHashEntries': [0x30, ['unsigned long']],
            'SystemSpaceHashKey': [0x34, ['unsigned long']],
            'SystemSpaceBitMap': [0x38, ['pointer', ['_RTL_BITMAP']]],
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
    '_KiIoAccessMap': [
        0x2024,
        {
            'DirectionMap': [0x0, ['array', 32, ['unsigned char']]],
            'IoMap': [0x20, ['array', 8196, ['unsigned char']]],
        },
    ],
    '_DBGKD_RESTORE_BREAKPOINT': [
        0x4,
        {
            'BreakPointHandle': [0x0, ['unsigned long']],
        },
    ],
    '_EXCEPTION_REGISTRATION_RECORD': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_EXCEPTION_REGISTRATION_RECORD']]],
            'Handler': [0x4, ['pointer', ['void']]],
        },
    ],
    '_POOL_TRACKER_BIG_PAGES': [
        0xC,
        {
            'Va': [0x0, ['pointer', ['void']]],
            'Key': [0x4, ['unsigned long']],
            'NumberOfPages': [0x8, ['unsigned long']],
        },
    ],
    '_PROCESS_WS_WATCH_INFORMATION': [
        0x8,
        {
            'FaultingPc': [0x0, ['pointer', ['void']]],
            'FaultingVa': [0x4, ['pointer', ['void']]],
        },
    ],
    '_MMPTE_SUBSECTION': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'SubsectionAddressLow': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'SubsectionAddressHigh': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'WhichPool': [
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
    '_VI_DEADLOCK_NODE': [
        0x68,
        {
            'Parent': [0x0, ['pointer', ['_VI_DEADLOCK_NODE']]],
            'ChildrenList': [0x4, ['_LIST_ENTRY']],
            'SiblingsList': [0xC, ['_LIST_ENTRY']],
            'ResourceList': [0x14, ['_LIST_ENTRY']],
            'FreeListEntry': [0x14, ['_LIST_ENTRY']],
            'Root': [0x1C, ['pointer', ['_VI_DEADLOCK_RESOURCE']]],
            'ThreadEntry': [0x20, ['pointer', ['_VI_DEADLOCK_THREAD']]],
            'Active': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'OnlyTryAcquireUsed': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'SequenceNumber': [
                0x24,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'StackTrace': [0x28, ['array', 8, ['pointer', ['void']]]],
            'ParentStackTrace': [0x48, ['array', 8, ['pointer', ['void']]]],
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
    '_DBGKD_QUERY_SPECIAL_CALLS': [
        0x4,
        {
            'NumberOfSpecialCalls': [0x0, ['unsigned long']],
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
    '_PCI_PDO_EXTENSION': [
        0xC8,
        {
            'Next': [0x0, ['pointer', ['_PCI_PDO_EXTENSION']]],
            'ExtensionType': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1768116272: 'PciPdoExtensionType',
                            1768116273: 'PciFdoExtensionType',
                            1768116274: 'PciArb_Io',
                            1768116275: 'PciArb_Memory',
                            1768116276: 'PciArb_Interrupt',
                            1768116277: 'PciArb_BusNumber',
                            1768116278: 'PciTrans_Interrupt',
                            1768116279: 'PciInterface_BusHandler',
                            1768116280: 'PciInterface_IntRouteHandler',
                            1768116281: 'PciInterface_PciCb',
                            1768116282: 'PciInterface_LegacyDeviceDetection',
                            1768116283: 'PciInterface_PmeHandler',
                            1768116284: 'PciInterface_DevicePresent',
                            1768116285: 'PciInterface_NativeIde',
                            1768116286: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'IrpDispatchTable': [0x8, ['pointer', ['_PCI_MJ_DISPATCH_TABLE']]],
            'DeviceState': [0xC, ['unsigned char']],
            'TentativeNextState': [0xD, ['unsigned char']],
            'SecondaryExtLock': [0x10, ['_KEVENT']],
            'Slot': [0x20, ['_PCI_SLOT_NUMBER']],
            'PhysicalDeviceObject': [0x24, ['pointer', ['_DEVICE_OBJECT']]],
            'ParentFdoExtension': [0x28, ['pointer', ['_PCI_FDO_EXTENSION']]],
            'SecondaryExtension': [0x2C, ['_SINGLE_LIST_ENTRY']],
            'BusInterfaceReferenceCount': [0x30, ['unsigned long']],
            'AgpInterfaceReferenceCount': [0x34, ['unsigned long']],
            'VendorId': [0x38, ['unsigned short']],
            'DeviceId': [0x3A, ['unsigned short']],
            'SubsystemVendorId': [0x3C, ['unsigned short']],
            'SubsystemId': [0x3E, ['unsigned short']],
            'RevisionId': [0x40, ['unsigned char']],
            'ProgIf': [0x41, ['unsigned char']],
            'SubClass': [0x42, ['unsigned char']],
            'BaseClass': [0x43, ['unsigned char']],
            'AdditionalResourceCount': [0x44, ['unsigned char']],
            'AdjustedInterruptLine': [0x45, ['unsigned char']],
            'InterruptPin': [0x46, ['unsigned char']],
            'RawInterruptLine': [0x47, ['unsigned char']],
            'CapabilitiesPtr': [0x48, ['unsigned char']],
            'SavedLatencyTimer': [0x49, ['unsigned char']],
            'SavedCacheLineSize': [0x4A, ['unsigned char']],
            'HeaderType': [0x4B, ['unsigned char']],
            'NotPresent': [0x4C, ['unsigned char']],
            'ReportedMissing': [0x4D, ['unsigned char']],
            'ExpectedWritebackFailure': [0x4E, ['unsigned char']],
            'NoTouchPmeEnable': [0x4F, ['unsigned char']],
            'LegacyDriver': [0x50, ['unsigned char']],
            'UpdateHardware': [0x51, ['unsigned char']],
            'MovedDevice': [0x52, ['unsigned char']],
            'DisablePowerDown': [0x53, ['unsigned char']],
            'NeedsHotPlugConfiguration': [0x54, ['unsigned char']],
            'SwitchedIDEToNativeMode': [0x55, ['unsigned char']],
            'BIOSAllowsIDESwitchToNativeMode': [0x56, ['unsigned char']],
            'IoSpaceUnderNativeIdeControl': [0x57, ['unsigned char']],
            'OnDebugPath': [0x58, ['unsigned char']],
            'PowerState': [0x5C, ['PCI_POWER_STATE']],
            'Dependent': [0x9C, ['PCI_HEADER_TYPE_DEPENDENT']],
            'HackFlags': [0xA0, ['unsigned long long']],
            'Resources': [0xA8, ['pointer', ['PCI_FUNCTION_RESOURCES']]],
            'BridgeFdoExtension': [0xAC, ['pointer', ['_PCI_FDO_EXTENSION']]],
            'NextBridge': [0xB0, ['pointer', ['_PCI_PDO_EXTENSION']]],
            'NextHashEntry': [0xB4, ['pointer', ['_PCI_PDO_EXTENSION']]],
            'Lock': [0xB8, ['_PCI_LOCK']],
            'PowerCapabilities': [0xC0, ['_PCI_PMC']],
            'TargetAgpCapabilityId': [0xC2, ['unsigned char']],
            'CommandEnables': [0xC4, ['unsigned short']],
            'InitialCommand': [0xC6, ['unsigned short']],
        },
    ],
    '_HMAP_DIRECTORY': [
        0x1000,
        {
            'Directory': [0x0, ['array', 1024, ['pointer', ['_HMAP_TABLE']]]],
        },
    ],
    '_OBJECT_HEADER': [
        0x20,
        {
            'PointerCount': [0x0, ['long']],
            'HandleCount': [0x4, ['long']],
            'NextToFree': [0x4, ['pointer', ['void']]],
            'Type': [0x8, ['pointer', ['_OBJECT_TYPE']]],
            'NameInfoOffset': [0xC, ['unsigned char']],
            'HandleInfoOffset': [0xD, ['unsigned char']],
            'QuotaInfoOffset': [0xE, ['unsigned char']],
            'Flags': [0xF, ['unsigned char']],
            'ObjectCreateInfo': [
                0x10,
                ['pointer', ['_OBJECT_CREATE_INFORMATION']],
            ],
            'QuotaBlockCharged': [0x10, ['pointer', ['void']]],
            'SecurityDescriptor': [0x14, ['pointer', ['void']]],
            'Body': [0x18, ['_QUAD']],
        },
    ],
    '_QUAD': [
        0x8,
        {
            'DoNotUseThisField': [0x0, ['double']],
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
    '__unnamed_14ca': [
        0x8,
        {
            'UserData': [0x0, ['pointer', ['void']]],
            'Owner': [0x4, ['pointer', ['void']]],
        },
    ],
    '__unnamed_14cc': [
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
            'Allocated': [0x10, ['__unnamed_14ca']],
            'Merged': [0x10, ['__unnamed_14cc']],
            'Attributes': [0x18, ['unsigned char']],
            'PublicFlags': [0x19, ['unsigned char']],
            'PrivateFlags': [0x1A, ['unsigned short']],
            'ListEntry': [0x1C, ['_LIST_ENTRY']],
        },
    ],
    '_KAPC_STATE': [
        0x18,
        {
            'ApcListHead': [0x0, ['array', 2, ['_LIST_ENTRY']]],
            'Process': [0x10, ['pointer', ['_KPROCESS']]],
            'KernelApcInProgress': [0x14, ['unsigned char']],
            'KernelApcPending': [0x15, ['unsigned char']],
            'UserApcPending': [0x16, ['unsigned char']],
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
    '_DEVICE_RELATIONS': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'Objects': [0x4, ['array', 1, ['pointer', ['_DEVICE_OBJECT']]]],
        },
    ],
    '_KPROCESS': [
        0x6C,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'ProfileListHead': [0x10, ['_LIST_ENTRY']],
            'DirectoryTableBase': [0x18, ['array', 2, ['unsigned long']]],
            'LdtDescriptor': [0x20, ['_KGDTENTRY']],
            'Int21Descriptor': [0x28, ['_KIDTENTRY']],
            'IopmOffset': [0x30, ['unsigned short']],
            'Iopl': [0x32, ['unsigned char']],
            'Unused': [0x33, ['unsigned char']],
            'ActiveProcessors': [0x34, ['unsigned long']],
            'KernelTime': [0x38, ['unsigned long']],
            'UserTime': [0x3C, ['unsigned long']],
            'ReadyListHead': [0x40, ['_LIST_ENTRY']],
            'SwapListEntry': [0x48, ['_SINGLE_LIST_ENTRY']],
            'VdmTrapcHandler': [0x4C, ['pointer', ['void']]],
            'ThreadListHead': [0x50, ['_LIST_ENTRY']],
            'ProcessLock': [0x58, ['unsigned long']],
            'Affinity': [0x5C, ['unsigned long']],
            'StackCount': [0x60, ['unsigned short']],
            'BasePriority': [0x62, ['unsigned char']],
            'ThreadQuantum': [0x63, ['unsigned char']],
            'AutoAlignment': [0x64, ['unsigned char']],
            'State': [0x65, ['unsigned char']],
            'ThreadSeed': [0x66, ['unsigned char']],
            'DisableBoost': [0x67, ['unsigned char']],
            'PowerState': [0x68, ['unsigned char']],
            'DisableQuantum': [0x69, ['unsigned char']],
            'IdealNode': [0x6A, ['unsigned char']],
            'Flags': [0x6B, ['_KEXECUTE_OPTIONS']],
            'ExecuteOptions': [0x6B, ['unsigned char']],
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
        0x20,
        {
            'BasePhysicalPage': [0x0, ['unsigned long']],
            'BasedPte': [0x4, ['pointer', ['_MMPTE']]],
            'BankSize': [0x8, ['unsigned long']],
            'BankShift': [0xC, ['unsigned long']],
            'BankedRoutine': [0x10, ['pointer', ['void']]],
            'Context': [0x14, ['pointer', ['void']]],
            'CurrentMappedPte': [0x18, ['pointer', ['_MMPTE']]],
            'BankTemplate': [0x1C, ['array', 1, ['_MMPTE']]],
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
    '_KTRAP_FRAME': [
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
            'PreviousPreviousMode': [0x48, ['unsigned long']],
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
    '__unnamed_14f5': [
        0x4,
        {
            'BaseMid': [0x0, ['unsigned char']],
            'Flags1': [0x1, ['unsigned char']],
            'Flags2': [0x2, ['unsigned char']],
            'BaseHi': [0x3, ['unsigned char']],
        },
    ],
    '__unnamed_14fc': [
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
    '__unnamed_14fe': [
        0x4,
        {
            'Bytes': [0x0, ['__unnamed_14f5']],
            'Bits': [0x0, ['__unnamed_14fc']],
        },
    ],
    '_KGDTENTRY': [
        0x8,
        {
            'LimitLow': [0x0, ['unsigned short']],
            'BaseLow': [0x2, ['unsigned short']],
            'HighWord': [0x4, ['__unnamed_14fe']],
        },
    ],
    '__unnamed_1508': [
        0x5,
        {
            'Acquired': [0x0, ['unsigned char']],
            'CacheLineSize': [0x1, ['unsigned char']],
            'LatencyTimer': [0x2, ['unsigned char']],
            'EnablePERR': [0x3, ['unsigned char']],
            'EnableSERR': [0x4, ['unsigned char']],
        },
    ],
    '_PCI_FDO_EXTENSION': [
        0xC0,
        {
            'List': [0x0, ['_SINGLE_LIST_ENTRY']],
            'ExtensionType': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1768116272: 'PciPdoExtensionType',
                            1768116273: 'PciFdoExtensionType',
                            1768116274: 'PciArb_Io',
                            1768116275: 'PciArb_Memory',
                            1768116276: 'PciArb_Interrupt',
                            1768116277: 'PciArb_BusNumber',
                            1768116278: 'PciTrans_Interrupt',
                            1768116279: 'PciInterface_BusHandler',
                            1768116280: 'PciInterface_IntRouteHandler',
                            1768116281: 'PciInterface_PciCb',
                            1768116282: 'PciInterface_LegacyDeviceDetection',
                            1768116283: 'PciInterface_PmeHandler',
                            1768116284: 'PciInterface_DevicePresent',
                            1768116285: 'PciInterface_NativeIde',
                            1768116286: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'IrpDispatchTable': [0x8, ['pointer', ['_PCI_MJ_DISPATCH_TABLE']]],
            'DeviceState': [0xC, ['unsigned char']],
            'TentativeNextState': [0xD, ['unsigned char']],
            'SecondaryExtLock': [0x10, ['_KEVENT']],
            'PhysicalDeviceObject': [0x20, ['pointer', ['_DEVICE_OBJECT']]],
            'FunctionalDeviceObject': [0x24, ['pointer', ['_DEVICE_OBJECT']]],
            'AttachedDeviceObject': [0x28, ['pointer', ['_DEVICE_OBJECT']]],
            'ChildListLock': [0x2C, ['_KEVENT']],
            'ChildPdoList': [0x3C, ['pointer', ['_PCI_PDO_EXTENSION']]],
            'BusRootFdoExtension': [0x40, ['pointer', ['_PCI_FDO_EXTENSION']]],
            'ParentFdoExtension': [0x44, ['pointer', ['_PCI_FDO_EXTENSION']]],
            'ChildBridgePdoList': [0x48, ['pointer', ['_PCI_PDO_EXTENSION']]],
            'PciBusInterface': [
                0x4C,
                ['pointer', ['_PCI_BUS_INTERFACE_STANDARD']],
            ],
            'MaxSubordinateBus': [0x50, ['unsigned char']],
            'BusHandler': [0x54, ['pointer', ['_BUS_HANDLER']]],
            'BaseBus': [0x58, ['unsigned char']],
            'Fake': [0x59, ['unsigned char']],
            'ChildDelete': [0x5A, ['unsigned char']],
            'Scanned': [0x5B, ['unsigned char']],
            'ArbitersInitialized': [0x5C, ['unsigned char']],
            'BrokenVideoHackApplied': [0x5D, ['unsigned char']],
            'Hibernated': [0x5E, ['unsigned char']],
            'PowerState': [0x60, ['PCI_POWER_STATE']],
            'SecondaryExtension': [0xA0, ['_SINGLE_LIST_ENTRY']],
            'ChildWaitWakeCount': [0xA4, ['unsigned long']],
            'PreservedConfig': [0xA8, ['pointer', ['_PCI_COMMON_CONFIG']]],
            'Lock': [0xAC, ['_PCI_LOCK']],
            'HotPlugParameters': [0xB4, ['__unnamed_1508']],
            'BusHackFlags': [0xBC, ['unsigned long']],
        },
    ],
    '__unnamed_150c': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_150e': [
        0xC,
        {
            'Level': [0x0, ['unsigned long']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1510': [
        0xC,
        {
            'Channel': [0x0, ['unsigned long']],
            'Port': [0x4, ['unsigned long']],
            'Reserved1': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1512': [
        0xC,
        {
            'Data': [0x0, ['array', 3, ['unsigned long']]],
        },
    ],
    '__unnamed_1514': [
        0xC,
        {
            'Start': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1516': [
        0xC,
        {
            'DataSize': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1518': [
        0xC,
        {
            'Generic': [0x0, ['__unnamed_150c']],
            'Port': [0x0, ['__unnamed_150c']],
            'Interrupt': [0x0, ['__unnamed_150e']],
            'Memory': [0x0, ['__unnamed_150c']],
            'Dma': [0x0, ['__unnamed_1510']],
            'DevicePrivate': [0x0, ['__unnamed_1512']],
            'BusNumber': [0x0, ['__unnamed_1514']],
            'DeviceSpecificData': [0x0, ['__unnamed_1516']],
        },
    ],
    '_CM_PARTIAL_RESOURCE_DESCRIPTOR': [
        0x10,
        {
            'Type': [0x0, ['unsigned char']],
            'ShareDisposition': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned short']],
            'u': [0x4, ['__unnamed_1518']],
        },
    ],
    '_WAIT_CONTEXT_BLOCK': [
        0x28,
        {
            'WaitQueueEntry': [0x0, ['_KDEVICE_QUEUE_ENTRY']],
            'DeviceRoutine': [0x10, ['pointer', ['void']]],
            'DeviceContext': [0x14, ['pointer', ['void']]],
            'NumberOfMapRegisters': [0x18, ['unsigned long']],
            'DeviceObject': [0x1C, ['pointer', ['void']]],
            'CurrentIrp': [0x20, ['pointer', ['void']]],
            'BufferChainingDpc': [0x24, ['pointer', ['_KDPC']]],
        },
    ],
    '_CM_KEY_CONTROL_BLOCK': [
        0x48,
        {
            'RefCount': [0x0, ['unsigned short']],
            'Flags': [0x2, ['unsigned short']],
            'ExtFlags': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'PrivateAlloc': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Delete': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'DelayedCloseIndex': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'TotalLevels': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'KeyHash': [0x8, ['_CM_KEY_HASH']],
            'ConvKey': [0x8, ['unsigned long']],
            'NextHash': [0xC, ['pointer', ['_CM_KEY_HASH']]],
            'KeyHive': [0x10, ['pointer', ['_HHIVE']]],
            'KeyCell': [0x14, ['unsigned long']],
            'ParentKcb': [0x18, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'NameBlock': [0x1C, ['pointer', ['_CM_NAME_CONTROL_BLOCK']]],
            'CachedSecurity': [0x20, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
            'ValueCache': [0x24, ['_CACHED_CHILD_LIST']],
            'IndexHint': [0x2C, ['pointer', ['_CM_INDEX_HINT_BLOCK']]],
            'HashKey': [0x2C, ['unsigned long']],
            'SubKeyCount': [0x2C, ['unsigned long']],
            'KeyBodyListHead': [0x30, ['_LIST_ENTRY']],
            'FreeListEntry': [0x30, ['_LIST_ENTRY']],
            'KcbLastWriteTime': [0x38, ['_LARGE_INTEGER']],
            'KcbMaxNameLen': [0x40, ['unsigned short']],
            'KcbMaxValueNameLen': [0x42, ['unsigned short']],
            'KcbMaxValueDataLen': [0x44, ['unsigned long']],
        },
    ],
    '_KDPC': [
        0x20,
        {
            'Type': [0x0, ['short']],
            'Number': [0x2, ['unsigned char']],
            'Importance': [0x3, ['unsigned char']],
            'DpcListEntry': [0x4, ['_LIST_ENTRY']],
            'DeferredRoutine': [0xC, ['pointer', ['void']]],
            'DeferredContext': [0x10, ['pointer', ['void']]],
            'SystemArgument1': [0x14, ['pointer', ['void']]],
            'SystemArgument2': [0x18, ['pointer', ['void']]],
            'Lock': [0x1C, ['pointer', ['unsigned long']]],
        },
    ],
    '_PCI_BUS_INTERFACE_STANDARD': [
        0x20,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x4, ['pointer', ['void']]],
            'InterfaceReference': [0x8, ['pointer', ['void']]],
            'InterfaceDereference': [0xC, ['pointer', ['void']]],
            'ReadConfig': [0x10, ['pointer', ['void']]],
            'WriteConfig': [0x14, ['pointer', ['void']]],
            'PinToLine': [0x18, ['pointer', ['void']]],
            'LineToPin': [0x1C, ['pointer', ['void']]],
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
    '_PI_RESOURCE_ARBITER_ENTRY': [
        0x38,
        {
            'DeviceArbiterList': [0x0, ['_LIST_ENTRY']],
            'ResourceType': [0x8, ['unsigned char']],
            'ArbiterInterface': [0xC, ['pointer', ['_ARBITER_INTERFACE']]],
            'Level': [0x10, ['unsigned long']],
            'ResourceList': [0x14, ['_LIST_ENTRY']],
            'BestResourceList': [0x1C, ['_LIST_ENTRY']],
            'BestConfig': [0x24, ['_LIST_ENTRY']],
            'ActiveArbiterList': [0x2C, ['_LIST_ENTRY']],
            'State': [0x34, ['unsigned char']],
            'ResourcesChanged': [0x35, ['unsigned char']],
        },
    ],
    '_KTIMER': [
        0x28,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'DueTime': [0x10, ['_ULARGE_INTEGER']],
            'TimerListEntry': [0x18, ['_LIST_ENTRY']],
            'Dpc': [0x20, ['pointer', ['_KDPC']]],
            'Period': [0x24, ['long']],
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
    '__unnamed_1550': [
        0x4,
        {
            'MasterIrp': [0x0, ['pointer', ['_IRP']]],
            'IrpCount': [0x0, ['long']],
            'SystemBuffer': [0x0, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1557': [
        0x8,
        {
            'UserApcRoutine': [0x0, ['pointer', ['void']]],
            'UserApcContext': [0x4, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1559': [
        0x8,
        {
            'AsynchronousParameters': [0x0, ['__unnamed_1557']],
            'AllocationSize': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_155e': [
        0x28,
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
        },
    ],
    '__unnamed_1560': [
        0x30,
        {
            'Overlay': [0x0, ['__unnamed_155e']],
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
            'AssociatedIrp': [0xC, ['__unnamed_1550']],
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
            'Overlay': [0x30, ['__unnamed_1559']],
            'CancelRoutine': [0x38, ['pointer', ['void']]],
            'UserBuffer': [0x3C, ['pointer', ['void']]],
            'Tail': [0x40, ['__unnamed_1560']],
        },
    ],
    '_PCI_LOCK': [
        0x8,
        {
            'Atom': [0x0, ['unsigned long']],
            'OldIrql': [0x4, ['unsigned char']],
        },
    ],
    '_CM_KEY_SECURITY_CACHE_ENTRY': [
        0x8,
        {
            'Cell': [0x0, ['unsigned long']],
            'CachedSecurity': [0x4, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
        },
    ],
    '__unnamed_1569': [
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
            'Misc': [0x8, ['__unnamed_1569']],
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
    '__unnamed_156f': [
        0x4,
        {
            'Level': [0x0, ['unsigned long']],
        },
    ],
    '_POP_ACTION_TRIGGER': [
        0xC,
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
                            3: 'PolicyInitiatePowerActionAPI',
                            4: 'PolicySetPowerStateAPI',
                            5: 'PolicyImmediateDozeS4',
                            6: 'PolicySystemIdle',
                        },
                    ),
                ],
            ],
            'Flags': [0x4, ['unsigned char']],
            'Spare': [0x5, ['array', 3, ['unsigned char']]],
            'Battery': [0x8, ['__unnamed_156f']],
            'Wait': [0x8, ['pointer', ['_POP_TRIGGER_WAIT']]],
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
    '_ETIMER': [
        0x98,
        {
            'KeTimer': [0x0, ['_KTIMER']],
            'TimerApc': [0x28, ['_KAPC']],
            'TimerDpc': [0x58, ['_KDPC']],
            'ActiveTimerListEntry': [0x78, ['_LIST_ENTRY']],
            'Lock': [0x80, ['unsigned long']],
            'Period': [0x84, ['long']],
            'ApcAssociated': [0x88, ['unsigned char']],
            'WakeTimer': [0x89, ['unsigned char']],
            'WakeTimerListEntry': [0x8C, ['_LIST_ENTRY']],
        },
    ],
    '_DBGKD_BREAKPOINTEX': [
        0x8,
        {
            'BreakPointCount': [0x0, ['unsigned long']],
            'ContinueStatus': [0x4, ['long']],
        },
    ],
    '_CM_CELL_REMAP_BLOCK': [
        0x8,
        {
            'OldCell': [0x0, ['unsigned long']],
            'NewCell': [0x4, ['unsigned long']],
        },
    ],
    '_PCI_PMC': [
        0x2,
        {
            'Version': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'PMEClock': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Rsvd1': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'DeviceSpecificInitialization': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'Rsvd2': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'Support': [0x1, ['_PM_SUPPORT']],
        },
    ],
    '_DBGKD_CONTINUE': [
        0x4,
        {
            'ContinueStatus': [0x0, ['long']],
        },
    ],
    '_MMPTE_PROTOTYPE': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ProtoAddressLow': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ReadOnly': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'WhichPool': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'ProtoAddressHigh': [
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
    '__unnamed_15d6': [
        0x4,
        {
            'VirtualAddress': [0x0, ['pointer', ['void']]],
            'Long': [0x0, ['unsigned long']],
            'e1': [0x0, ['_MMWSLENTRY']],
        },
    ],
    '_MMWSLE': [
        0x4,
        {
            'u1': [0x0, ['__unnamed_15d6']],
        },
    ],
    '_EXCEPTION_POINTERS': [
        0x8,
        {
            'ExceptionRecord': [0x0, ['pointer', ['_EXCEPTION_RECORD']]],
            'ContextRecord': [0x4, ['pointer', ['_CONTEXT']]],
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
        0x290,
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
    '_CELL_DATA': [
        0x50,
        {
            'u': [0x0, ['_u']],
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
                            2: 'VfDeadlockFastMutex',
                            3: 'VfDeadlockFastMutexUnsafe',
                            4: 'VfDeadlockSpinLock',
                            5: 'VfDeadlockQueuedSpinLock',
                            6: 'VfDeadlockTypeMaximum',
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
    '_CLIENT_ID': [
        0x8,
        {
            'UniqueProcess': [0x0, ['pointer', ['void']]],
            'UniqueThread': [0x4, ['pointer', ['void']]],
        },
    ],
    '_PEB_FREE_BLOCK': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['_PEB_FREE_BLOCK']]],
            'Size': [0x4, ['unsigned long']],
        },
    ],
    '_PO_DEVICE_NOTIFY': [
        0x28,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'TargetDevice': [0x8, ['pointer', ['_DEVICE_OBJECT']]],
            'WakeNeeded': [0xC, ['unsigned char']],
            'OrderLevel': [0xD, ['unsigned char']],
            'DeviceObject': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'Node': [0x14, ['pointer', ['void']]],
            'DeviceName': [0x18, ['pointer', ['unsigned short']]],
            'DriverName': [0x1C, ['pointer', ['unsigned short']]],
            'ChildCount': [0x20, ['unsigned long']],
            'ActiveChild': [0x24, ['unsigned long']],
        },
    ],
    '_MMPFNLIST': [
        0x10,
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
        },
    ],
    '__unnamed_1603': [
        0x4,
        {
            'Spare': [0x0, ['array', 4, ['unsigned char']]],
        },
    ],
    '__unnamed_1605': [
        0x4,
        {
            'PrimaryBus': [0x0, ['unsigned char']],
            'SecondaryBus': [0x1, ['unsigned char']],
            'SubordinateBus': [0x2, ['unsigned char']],
            'SubtractiveDecode': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'IsaBitSet': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'VgaBitSet': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'WeChangedBusNumbers': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'IsaBitRequired': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
        },
    ],
    'PCI_HEADER_TYPE_DEPENDENT': [
        0x4,
        {
            'type0': [0x0, ['__unnamed_1603']],
            'type1': [0x0, ['__unnamed_1605']],
            'type2': [0x0, ['__unnamed_1605']],
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
    '_OBJECT_HEADER_NAME_INFO': [
        0x10,
        {
            'Directory': [0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
            'Name': [0x4, ['_UNICODE_STRING']],
            'QueryReferences': [0xC, ['unsigned long']],
        },
    ],
    '_KINTERRUPT': [
        0x1E4,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'InterruptListEntry': [0x4, ['_LIST_ENTRY']],
            'ServiceRoutine': [0xC, ['pointer', ['void']]],
            'ServiceContext': [0x10, ['pointer', ['void']]],
            'SpinLock': [0x14, ['unsigned long']],
            'TickCount': [0x18, ['unsigned long']],
            'ActualLock': [0x1C, ['pointer', ['unsigned long']]],
            'DispatchAddress': [0x20, ['pointer', ['void']]],
            'Vector': [0x24, ['unsigned long']],
            'Irql': [0x28, ['unsigned char']],
            'SynchronizeIrql': [0x29, ['unsigned char']],
            'FloatingSave': [0x2A, ['unsigned char']],
            'Connected': [0x2B, ['unsigned char']],
            'Number': [0x2C, ['unsigned char']],
            'ShareVector': [0x2D, ['unsigned char']],
            'Mode': [
                0x30,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'LevelSensitive', 1: 'Latched'},
                    ),
                ],
            ],
            'ServiceCount': [0x34, ['unsigned long']],
            'DispatchCount': [0x38, ['unsigned long']],
            'DispatchCode': [0x3C, ['array', 106, ['unsigned long']]],
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
    '_PCI_ARBITER_INSTANCE': [
        0xE0,
        {
            'Header': [0x0, ['PCI_SECONDARY_EXTENSION']],
            'Interface': [0xC, ['pointer', ['_PCI_INTERFACE']]],
            'BusFdoExtension': [0x10, ['pointer', ['_PCI_FDO_EXTENSION']]],
            'InstanceName': [0x14, ['array', 24, ['unsigned short']]],
            'CommonInstance': [0x44, ['_ARBITER_INSTANCE']],
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
    '_MMPAGING_FILE': [
        0x44,
        {
            'Size': [0x0, ['unsigned long']],
            'MaximumSize': [0x4, ['unsigned long']],
            'MinimumSize': [0x8, ['unsigned long']],
            'FreeSpace': [0xC, ['unsigned long']],
            'CurrentUsage': [0x10, ['unsigned long']],
            'PeakUsage': [0x14, ['unsigned long']],
            'Hint': [0x18, ['unsigned long']],
            'HighestPage': [0x1C, ['unsigned long']],
            'Entry': [
                0x20,
                ['array', 2, ['pointer', ['_MMMOD_WRITER_MDL_ENTRY']]],
            ],
            'Bitmap': [0x28, ['pointer', ['_RTL_BITMAP']]],
            'File': [0x2C, ['pointer', ['_FILE_OBJECT']]],
            'PageFileName': [0x30, ['_UNICODE_STRING']],
            'PageFileNumber': [0x38, ['unsigned long']],
            'Extended': [0x3C, ['unsigned char']],
            'HintSetToZero': [0x3D, ['unsigned char']],
            'BootPartition': [0x3E, ['unsigned char']],
            'FileHandle': [0x40, ['pointer', ['void']]],
        },
    ],
    '_BUS_EXTENSION_LIST': [
        0x8,
        {
            'Next': [0x0, ['pointer', ['void']]],
            'BusExtension': [0x4, ['pointer', ['_PI_BUS_EXTENSION']]],
        },
    ],
    '_PCI_MJ_DISPATCH_TABLE': [
        0x20,
        {
            'PnpIrpMaximumMinorFunction': [0x0, ['unsigned long']],
            'PnpIrpDispatchTable': [
                0x4,
                ['pointer', ['_PCI_MN_DISPATCH_TABLE']],
            ],
            'PowerIrpMaximumMinorFunction': [0x8, ['unsigned long']],
            'PowerIrpDispatchTable': [
                0xC,
                ['pointer', ['_PCI_MN_DISPATCH_TABLE']],
            ],
            'SystemControlIrpDispatchStyle': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IRP_COMPLETE',
                            1: 'IRP_DOWNWARD',
                            2: 'IRP_UPWARD',
                            3: 'IRP_DISPATCH',
                        },
                    ),
                ],
            ],
            'SystemControlIrpDispatchFunction': [0x14, ['pointer', ['void']]],
            'OtherIrpDispatchStyle': [
                0x18,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IRP_COMPLETE',
                            1: 'IRP_DOWNWARD',
                            2: 'IRP_UPWARD',
                            3: 'IRP_DISPATCH',
                        },
                    ),
                ],
            ],
            'OtherIrpDispatchFunction': [0x1C, ['pointer', ['void']]],
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
    '_FXSAVE_FORMAT': [
        0x208,
        {
            'ControlWord': [0x0, ['unsigned short']],
            'StatusWord': [0x2, ['unsigned short']],
            'TagWord': [0x4, ['unsigned short']],
            'ErrorOpcode': [0x6, ['unsigned short']],
            'ErrorOffset': [0x8, ['unsigned long']],
            'ErrorSelector': [0xC, ['unsigned long']],
            'DataOffset': [0x10, ['unsigned long']],
            'DataSelector': [0x14, ['unsigned long']],
            'MXCsr': [0x18, ['unsigned long']],
            'MXCsrMask': [0x1C, ['unsigned long']],
            'RegisterArea': [0x20, ['array', 128, ['unsigned char']]],
            'Reserved3': [0xA0, ['array', 128, ['unsigned char']]],
            'Reserved4': [0x120, ['array', 224, ['unsigned char']]],
            'Align16Byte': [0x200, ['array', 8, ['unsigned char']]],
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
            'LockedInWs': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'LockedInMemory': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Hashed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Direct': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Age': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
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
    '_OBJECT_DIRECTORY': [
        0xA4,
        {
            'HashBuckets': [
                0x0,
                ['array', 37, ['pointer', ['_OBJECT_DIRECTORY_ENTRY']]],
            ],
            'Lock': [0x94, ['_EX_PUSH_LOCK']],
            'DeviceMap': [0x98, ['pointer', ['_DEVICE_MAP']]],
            'SessionId': [0x9C, ['unsigned long']],
            'Reserved': [0xA0, ['unsigned short']],
            'SymbolicLinkUsageCount': [0xA2, ['unsigned short']],
        },
    ],
    '_OBJECT_CREATE_INFORMATION': [
        0x30,
        {
            'Attributes': [0x0, ['unsigned long']],
            'RootDirectory': [0x4, ['pointer', ['void']]],
            'ParseContext': [0x8, ['pointer', ['void']]],
            'ProbeMode': [0xC, ['unsigned char']],
            'PagedPoolCharge': [0x10, ['unsigned long']],
            'NonPagedPoolCharge': [0x14, ['unsigned long']],
            'SecurityDescriptorCharge': [0x18, ['unsigned long']],
            'SecurityDescriptor': [0x1C, ['pointer', ['void']]],
            'SecurityQos': [
                0x20,
                ['pointer', ['_SECURITY_QUALITY_OF_SERVICE']],
            ],
            'SecurityQualityOfService': [
                0x24,
                ['_SECURITY_QUALITY_OF_SERVICE'],
            ],
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
    '_CALL_PERFORMANCE_DATA': [
        0x204,
        {
            'SpinLock': [0x0, ['unsigned long']],
            'HashTable': [0x4, ['array', 64, ['_LIST_ENTRY']]],
        },
    ],
    '_MMWSL': [
        0x69C,
        {
            'Quota': [0x0, ['unsigned long']],
            'FirstFree': [0x4, ['unsigned long']],
            'FirstDynamic': [0x8, ['unsigned long']],
            'LastEntry': [0xC, ['unsigned long']],
            'NextSlot': [0x10, ['unsigned long']],
            'Wsle': [0x14, ['pointer', ['_MMWSLE']]],
            'LastInitializedWsle': [0x18, ['unsigned long']],
            'NonDirectCount': [0x1C, ['unsigned long']],
            'HashTable': [0x20, ['pointer', ['_MMWSLE_HASH']]],
            'HashTableSize': [0x24, ['unsigned long']],
            'NumberOfCommittedPageTables': [0x28, ['unsigned long']],
            'HashTableStart': [0x2C, ['pointer', ['void']]],
            'HighestPermittedHashAddress': [0x30, ['pointer', ['void']]],
            'NumberOfImageWaiters': [0x34, ['unsigned long']],
            'VadBitMapHint': [0x38, ['unsigned long']],
            'UsedPageTableEntries': [0x3C, ['array', 768, ['unsigned short']]],
            'CommittedPageTables': [0x63C, ['array', 24, ['unsigned long']]],
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
    'PCI_FUNCTION_RESOURCES': [
        0x150,
        {
            'Limit': [0x0, ['array', 7, ['_IO_RESOURCE_DESCRIPTOR']]],
            'Current': [
                0xE0,
                ['array', 7, ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
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
    '__unnamed_167b': [
        0x4,
        {
            'ImageCommitment': [0x0, ['unsigned long']],
            'CreatingProcess': [0x0, ['pointer', ['_EPROCESS']]],
        },
    ],
    '__unnamed_167f': [
        0x4,
        {
            'ImageInformation': [
                0x0,
                ['pointer', ['_SECTION_IMAGE_INFORMATION']],
            ],
            'FirstMappedVa': [0x0, ['pointer', ['void']]],
        },
    ],
    '_SEGMENT': [
        0x40,
        {
            'ControlArea': [0x0, ['pointer', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x4, ['unsigned long']],
            'NonExtendedPtes': [0x8, ['unsigned long']],
            'WritableUserReferences': [0xC, ['unsigned long']],
            'SizeOfSegment': [0x10, ['unsigned long long']],
            'SegmentPteTemplate': [0x18, ['_MMPTE']],
            'NumberOfCommittedPages': [0x1C, ['unsigned long']],
            'ExtendInfo': [0x20, ['pointer', ['_MMEXTEND_INFO']]],
            'SystemImageBase': [0x24, ['pointer', ['void']]],
            'BasedAddress': [0x28, ['pointer', ['void']]],
            'u1': [0x2C, ['__unnamed_167b']],
            'u2': [0x30, ['__unnamed_167f']],
            'PrototypePte': [0x34, ['pointer', ['_MMPTE']]],
            'ThePtes': [0x38, ['array', 1, ['_MMPTE']]],
        },
    ],
    '_PCI_COMMON_EXTENSION': [
        0x20,
        {
            'Next': [0x0, ['pointer', ['void']]],
            'ExtensionType': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1768116272: 'PciPdoExtensionType',
                            1768116273: 'PciFdoExtensionType',
                            1768116274: 'PciArb_Io',
                            1768116275: 'PciArb_Memory',
                            1768116276: 'PciArb_Interrupt',
                            1768116277: 'PciArb_BusNumber',
                            1768116278: 'PciTrans_Interrupt',
                            1768116279: 'PciInterface_BusHandler',
                            1768116280: 'PciInterface_IntRouteHandler',
                            1768116281: 'PciInterface_PciCb',
                            1768116282: 'PciInterface_LegacyDeviceDetection',
                            1768116283: 'PciInterface_PmeHandler',
                            1768116284: 'PciInterface_DevicePresent',
                            1768116285: 'PciInterface_NativeIde',
                            1768116286: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'IrpDispatchTable': [0x8, ['pointer', ['_PCI_MJ_DISPATCH_TABLE']]],
            'DeviceState': [0xC, ['unsigned char']],
            'TentativeNextState': [0xD, ['unsigned char']],
            'SecondaryExtLock': [0x10, ['_KEVENT']],
        },
    ],
    '_PRIVATE_CACHE_MAP': [
        0x58,
        {
            'NodeTypeCode': [0x0, ['short']],
            'Flags': [0x0, ['_PRIVATE_CACHE_MAP_FLAGS']],
            'UlongFlags': [0x0, ['unsigned long']],
            'ReadAheadMask': [0x4, ['unsigned long']],
            'FileObject': [0x8, ['pointer', ['_FILE_OBJECT']]],
            'FileOffset1': [0x10, ['_LARGE_INTEGER']],
            'BeyondLastByte1': [0x18, ['_LARGE_INTEGER']],
            'FileOffset2': [0x20, ['_LARGE_INTEGER']],
            'BeyondLastByte2': [0x28, ['_LARGE_INTEGER']],
            'ReadAheadOffset': [0x30, ['array', 2, ['_LARGE_INTEGER']]],
            'ReadAheadLength': [0x40, ['array', 2, ['unsigned long']]],
            'ReadAheadSpinLock': [0x48, ['unsigned long']],
            'PrivateLinks': [0x4C, ['_LIST_ENTRY']],
        },
    ],
    '_RTL_HANDLE_TABLE': [
        0x20,
        {
            'MaximumNumberOfHandles': [0x0, ['unsigned long']],
            'SizeOfHandleTableEntry': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['array', 2, ['unsigned long']]],
            'FreeHandles': [0x10, ['pointer', ['_RTL_HANDLE_TABLE_ENTRY']]],
            'CommittedHandles': [
                0x14,
                ['pointer', ['_RTL_HANDLE_TABLE_ENTRY']],
            ],
            'UnCommittedHandles': [
                0x18,
                ['pointer', ['_RTL_HANDLE_TABLE_ENTRY']],
            ],
            'MaxReservedHandles': [
                0x1C,
                ['pointer', ['_RTL_HANDLE_TABLE_ENTRY']],
            ],
        },
    ],
    '_POP_IDLE_HANDLER': [
        0x20,
        {
            'Latency': [0x0, ['unsigned long']],
            'TimeCheck': [0x4, ['unsigned long']],
            'DemoteLimit': [0x8, ['unsigned long']],
            'PromoteLimit': [0xC, ['unsigned long']],
            'PromoteCount': [0x10, ['unsigned long']],
            'Demote': [0x14, ['unsigned char']],
            'Promote': [0x15, ['unsigned char']],
            'PromotePercent': [0x16, ['unsigned char']],
            'DemotePercent': [0x17, ['unsigned char']],
            'State': [0x18, ['unsigned char']],
            'Spare': [0x19, ['array', 3, ['unsigned char']]],
            'IdleFunction': [0x1C, ['pointer', ['void']]],
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
            'spare2': [0x11, ['array', 4, ['unsigned char']]],
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
    '_DEVOBJ_EXTENSION': [
        0x2C,
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
            'Cr0NpxState': [0x6C, ['unsigned long']],
        },
    ],
    '_DBGKD_GET_VERSION64': [
        0x28,
        {
            'MajorVersion': [0x0, ['unsigned short']],
            'MinorVersion': [0x2, ['unsigned short']],
            'ProtocolVersion': [0x4, ['unsigned short']],
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
    '_MMVIEW': [
        0x8,
        {
            'Entry': [0x0, ['unsigned long']],
            'ControlArea': [0x4, ['pointer', ['_CONTROL_AREA']]],
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
    '_TOKEN': [
        0xA8,
        {
            'TokenSource': [0x0, ['_TOKEN_SOURCE']],
            'TokenId': [0x10, ['_LUID']],
            'AuthenticationId': [0x18, ['_LUID']],
            'ParentTokenId': [0x20, ['_LUID']],
            'ExpirationTime': [0x28, ['_LARGE_INTEGER']],
            'TokenLock': [0x30, ['pointer', ['_ERESOURCE']]],
            'AuditPolicy': [0x38, ['_SEP_AUDIT_POLICY']],
            'ModifiedId': [0x40, ['_LUID']],
            'SessionId': [0x48, ['unsigned long']],
            'UserAndGroupCount': [0x4C, ['unsigned long']],
            'RestrictedSidCount': [0x50, ['unsigned long']],
            'PrivilegeCount': [0x54, ['unsigned long']],
            'VariableLength': [0x58, ['unsigned long']],
            'DynamicCharged': [0x5C, ['unsigned long']],
            'DynamicAvailable': [0x60, ['unsigned long']],
            'DefaultOwnerIndex': [0x64, ['unsigned long']],
            'UserAndGroups': [0x68, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'RestrictedSids': [0x6C, ['pointer', ['_SID_AND_ATTRIBUTES']]],
            'PrimaryGroup': [0x70, ['pointer', ['void']]],
            'Privileges': [0x74, ['pointer', ['_LUID_AND_ATTRIBUTES']]],
            'DynamicPart': [0x78, ['pointer', ['unsigned long']]],
            'DefaultDacl': [0x7C, ['pointer', ['_ACL']]],
            'TokenType': [
                0x80,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={1: 'TokenPrimary', 2: 'TokenImpersonation'},
                    ),
                ],
            ],
            'ImpersonationLevel': [
                0x84,
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
            'TokenFlags': [0x88, ['unsigned long']],
            'TokenInUse': [0x8C, ['unsigned char']],
            'ProxyData': [0x90, ['pointer', ['_SECURITY_TOKEN_PROXY_DATA']]],
            'AuditData': [0x94, ['pointer', ['_SECURITY_TOKEN_AUDIT_DATA']]],
            'OriginatingLogonSession': [0x98, ['_LUID']],
            'VariablePart': [0xA0, ['unsigned long']],
        },
    ],
    '_TEB': [
        0xFB8,
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
            'ActivationContextStack': [0x1A8, ['_ACTIVATION_CONTEXT_STACK']],
            'SpareBytes1': [0x1BC, ['array', 24, ['unsigned char']]],
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
            'StaticUnicodeBuffer': [0xC00, ['array', 261, ['unsigned short']]],
            'DeallocationStack': [0xE0C, ['pointer', ['void']]],
            'TlsSlots': [0xE10, ['array', 64, ['pointer', ['void']]]],
            'TlsLinks': [0xF10, ['_LIST_ENTRY']],
            'Vdm': [0xF18, ['pointer', ['void']]],
            'ReservedForNtRpc': [0xF1C, ['pointer', ['void']]],
            'DbgSsReserved': [0xF20, ['array', 2, ['pointer', ['void']]]],
            'HardErrorsAreDisabled': [0xF28, ['unsigned long']],
            'Instrumentation': [0xF2C, ['array', 16, ['pointer', ['void']]]],
            'WinSockData': [0xF6C, ['pointer', ['void']]],
            'GdiBatchCount': [0xF70, ['unsigned long']],
            'InDbgPrint': [0xF74, ['unsigned char']],
            'FreeStackOnTermination': [0xF75, ['unsigned char']],
            'HasFiberData': [0xF76, ['unsigned char']],
            'IdealProcessor': [0xF77, ['unsigned char']],
            'Spare3': [0xF78, ['unsigned long']],
            'ReservedForPerf': [0xF7C, ['pointer', ['void']]],
            'ReservedForOle': [0xF80, ['pointer', ['void']]],
            'WaitingOnLoaderLock': [0xF84, ['unsigned long']],
            'Wx86Thread': [0xF88, ['_Wx86ThreadState']],
            'TlsExpansionSlots': [0xF94, ['pointer', ['pointer', ['void']]]],
            'ImpersonationLocale': [0xF98, ['unsigned long']],
            'IsImpersonating': [0xF9C, ['unsigned long']],
            'NlsCache': [0xFA0, ['pointer', ['void']]],
            'pShimData': [0xFA4, ['pointer', ['void']]],
            'HeapVirtualAffinity': [0xFA8, ['unsigned long']],
            'CurrentTransactionHandle': [0xFAC, ['pointer', ['void']]],
            'ActiveFrame': [0xFB0, ['pointer', ['_TEB_ACTIVE_FRAME']]],
            'SafeThunkCall': [0xFB4, ['unsigned char']],
            'BooleanSpare': [0xFB5, ['array', 3, ['unsigned char']]],
        },
    ],
    'PCI_SECONDARY_EXTENSION': [
        0xC,
        {
            'List': [0x0, ['_SINGLE_LIST_ENTRY']],
            'ExtensionType': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1768116272: 'PciPdoExtensionType',
                            1768116273: 'PciFdoExtensionType',
                            1768116274: 'PciArb_Io',
                            1768116275: 'PciArb_Memory',
                            1768116276: 'PciArb_Interrupt',
                            1768116277: 'PciArb_BusNumber',
                            1768116278: 'PciTrans_Interrupt',
                            1768116279: 'PciInterface_BusHandler',
                            1768116280: 'PciInterface_IntRouteHandler',
                            1768116281: 'PciInterface_PciCb',
                            1768116282: 'PciInterface_LegacyDeviceDetection',
                            1768116283: 'PciInterface_PmeHandler',
                            1768116284: 'PciInterface_DevicePresent',
                            1768116285: 'PciInterface_NativeIde',
                            1768116286: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'Destructor': [0x8, ['pointer', ['void']]],
        },
    ],
    '__unnamed_16c6': [
        0x30,
        {
            'type0': [0x0, ['_PCI_HEADER_TYPE_0']],
            'type1': [0x0, ['_PCI_HEADER_TYPE_1']],
            'type2': [0x0, ['_PCI_HEADER_TYPE_2']],
        },
    ],
    '_PCI_COMMON_CONFIG': [
        0x100,
        {
            'VendorID': [0x0, ['unsigned short']],
            'DeviceID': [0x2, ['unsigned short']],
            'Command': [0x4, ['unsigned short']],
            'Status': [0x6, ['unsigned short']],
            'RevisionID': [0x8, ['unsigned char']],
            'ProgIf': [0x9, ['unsigned char']],
            'SubClass': [0xA, ['unsigned char']],
            'BaseClass': [0xB, ['unsigned char']],
            'CacheLineSize': [0xC, ['unsigned char']],
            'LatencyTimer': [0xD, ['unsigned char']],
            'HeaderType': [0xE, ['unsigned char']],
            'BIST': [0xF, ['unsigned char']],
            'u': [0x10, ['__unnamed_16c6']],
            'DeviceSpecific': [0x40, ['array', 192, ['unsigned char']]],
        },
    ],
    '_HEAP_FREE_ENTRY_EXTRA': [
        0x4,
        {
            'TagIndex': [0x0, ['unsigned short']],
            'FreeBackTraceIndex': [0x2, ['unsigned short']],
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
            'Spare1': [0x23, ['unsigned char']],
            'LoaderFlags': [0x24, ['unsigned long']],
            'ImageFileSize': [0x28, ['unsigned long']],
            'Reserved': [0x2C, ['array', 1, ['unsigned long']]],
        },
    ],
    '_POOL_TRACKER_TABLE': [
        0x1C,
        {
            'Key': [0x0, ['unsigned long']],
            'NonPagedAllocs': [0x4, ['unsigned long']],
            'NonPagedFrees': [0x8, ['unsigned long']],
            'NonPagedBytes': [0xC, ['unsigned long']],
            'PagedAllocs': [0x10, ['unsigned long']],
            'PagedFrees': [0x14, ['unsigned long']],
            'PagedBytes': [0x18, ['unsigned long']],
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
    '_KNODE': [
        0x30,
        {
            'ProcessorMask': [0x0, ['unsigned long']],
            'Color': [0x4, ['unsigned long']],
            'MmShiftedColor': [0x8, ['unsigned long']],
            'FreeCount': [0xC, ['array', 2, ['unsigned long']]],
            'DeadStackList': [0x18, ['_SLIST_HEADER']],
            'PfnDereferenceSListHead': [0x20, ['_SLIST_HEADER']],
            'PfnDeferredList': [0x28, ['pointer', ['_SINGLE_LIST_ENTRY']]],
            'Seed': [0x2C, ['unsigned char']],
            'Flags': [0x2D, ['_flags']],
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
    '_PI_BUS_EXTENSION': [
        0x44,
        {
            'Flags': [0x0, ['unsigned long']],
            'NumberCSNs': [0x4, ['unsigned long']],
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
    '_VI_DEADLOCK_THREAD': [
        0x1C,
        {
            'Thread': [0x0, ['pointer', ['_KTHREAD']]],
            'CurrentSpinNode': [0x4, ['pointer', ['_VI_DEADLOCK_NODE']]],
            'CurrentOtherNode': [0x8, ['pointer', ['_VI_DEADLOCK_NODE']]],
            'ListEntry': [0xC, ['_LIST_ENTRY']],
            'FreeListEntry': [0xC, ['_LIST_ENTRY']],
            'NodeCount': [0x14, ['unsigned long']],
            'PagingCount': [0x18, ['unsigned long']],
        },
    ],
    '_MMEXTEND_INFO': [
        0x10,
        {
            'CommittedSize': [0x0, ['unsigned long long']],
            'ReferenceCount': [0x8, ['unsigned long']],
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
    '_PCI_INTERFACE': [
        0x1C,
        {
            'InterfaceType': [0x0, ['pointer', ['_GUID']]],
            'MinSize': [0x4, ['unsigned short']],
            'MinVersion': [0x6, ['unsigned short']],
            'MaxVersion': [0x8, ['unsigned short']],
            'Flags': [0xA, ['unsigned short']],
            'ReferenceCount': [0xC, ['long']],
            'Signature': [
                0x10,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            1768116272: 'PciPdoExtensionType',
                            1768116273: 'PciFdoExtensionType',
                            1768116274: 'PciArb_Io',
                            1768116275: 'PciArb_Memory',
                            1768116276: 'PciArb_Interrupt',
                            1768116277: 'PciArb_BusNumber',
                            1768116278: 'PciTrans_Interrupt',
                            1768116279: 'PciInterface_BusHandler',
                            1768116280: 'PciInterface_IntRouteHandler',
                            1768116281: 'PciInterface_PciCb',
                            1768116282: 'PciInterface_LegacyDeviceDetection',
                            1768116283: 'PciInterface_PmeHandler',
                            1768116284: 'PciInterface_DevicePresent',
                            1768116285: 'PciInterface_NativeIde',
                            1768116286: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'Constructor': [0x14, ['pointer', ['void']]],
            'Initializer': [0x18, ['pointer', ['void']]],
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
    '_MMVAD': [
        0x28,
        {
            'StartingVpn': [0x0, ['unsigned long']],
            'EndingVpn': [0x4, ['unsigned long']],
            'Parent': [0x8, ['pointer', ['_MMVAD']]],
            'LeftChild': [0xC, ['pointer', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer', ['_MMVAD']]],
            'u': [0x14, ['__unnamed_144c']],
            'ControlArea': [0x18, ['pointer', ['_CONTROL_AREA']]],
            'FirstPrototypePte': [0x1C, ['pointer', ['_MMPTE']]],
            'LastContiguousPte': [0x20, ['pointer', ['_MMPTE']]],
            'u2': [0x24, ['__unnamed_144f']],
        },
    ],
    '__unnamed_16fb': [
        0x8,
        {
            'IoStatus': [0x0, ['_IO_STATUS_BLOCK']],
            'LastByte': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '_MMMOD_WRITER_MDL_ENTRY': [
        0x58,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'WriteOffset': [0x8, ['_LARGE_INTEGER']],
            'u': [0x10, ['__unnamed_16fb']],
            'Irp': [0x18, ['pointer', ['_IRP']]],
            'LastPageToWrite': [0x1C, ['unsigned long']],
            'PagingListHead': [0x20, ['pointer', ['_MMMOD_WRITER_LISTHEAD']]],
            'CurrentList': [0x24, ['pointer', ['_LIST_ENTRY']]],
            'PagingFile': [0x28, ['pointer', ['_MMPAGING_FILE']]],
            'File': [0x2C, ['pointer', ['_FILE_OBJECT']]],
            'ControlArea': [0x30, ['pointer', ['_CONTROL_AREA']]],
            'FileResource': [0x34, ['pointer', ['_ERESOURCE']]],
            'Mdl': [0x38, ['_MDL']],
            'Page': [0x54, ['array', 1, ['unsigned long']]],
        },
    ],
    '_POP_POWER_ACTION': [
        0x40,
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
            'IrpMinor': [0x14, ['unsigned char']],
            'SystemState': [
                0x18,
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
                0x1C,
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
                0x20,
                ['pointer', ['_POP_SHUTDOWN_BUG_CHECK']],
            ],
            'DevState': [0x24, ['pointer', ['_POP_DEVICE_SYS_STATE']]],
            'HiberContext': [0x28, ['pointer', ['_POP_HIBER_CONTEXT']]],
            'LastWakeState': [
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
            'WakeTime': [0x30, ['unsigned long long']],
            'SleepTime': [0x38, ['unsigned long long']],
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
    '_MMVAD_SHORT': [
        0x18,
        {
            'StartingVpn': [0x0, ['unsigned long']],
            'EndingVpn': [0x4, ['unsigned long']],
            'Parent': [0x8, ['pointer', ['_MMVAD']]],
            'LeftChild': [0xC, ['pointer', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer', ['_MMVAD']]],
            'u': [0x14, ['__unnamed_144c']],
        },
    ],
    '__unnamed_1717': [
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
            'Privileges': [0x34, ['__unnamed_1717']],
            'AuditPrivileges': [0x60, ['unsigned char']],
            'ObjectName': [0x64, ['_UNICODE_STRING']],
            'ObjectTypeName': [0x6C, ['_UNICODE_STRING']],
        },
    ],
    '_PNP_DEVICE_EVENT_ENTRY': [
        0x58,
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
            'Data': [0x20, ['_PLUGPLAY_EVENT_BLOCK']],
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
            'Available': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
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
    '_KPROCESSOR_STATE': [
        0x320,
        {
            'ContextFrame': [0x0, ['_CONTEXT']],
            'SpecialRegisters': [0x2CC, ['_KSPECIAL_REGISTERS']],
        },
    ],
    '_MMPTE_TRANSITION': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Write': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Owner': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WriteThrough': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'CacheDisable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Protection': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'Transition': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'PageFrameNumber': [
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
    '_TOKEN_SOURCE': [
        0x10,
        {
            'SourceName': [0x0, ['array', 8, ['unsigned char']]],
            'SourceIdentifier': [0x8, ['_LUID']],
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
            'ReadOnly': [
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
    '_flags': [
        0x1,
        {
            'Removable': [0x0, ['unsigned char']],
        },
    ],
    '_CM_KEY_SECURITY_CACHE': [
        0x28,
        {
            'Cell': [0x0, ['unsigned long']],
            'ConvKey': [0x4, ['unsigned long']],
            'List': [0x8, ['_LIST_ENTRY']],
            'DescriptorLength': [0x10, ['unsigned long']],
            'Descriptor': [0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
        },
    ],
    '_PROCESSOR_POWER_POLICY_INFO': [
        0x14,
        {
            'TimeCheck': [0x0, ['unsigned long']],
            'DemoteLimit': [0x4, ['unsigned long']],
            'PromoteLimit': [0x8, ['unsigned long']],
            'DemotePercent': [0xC, ['unsigned char']],
            'PromotePercent': [0xD, ['unsigned char']],
            'Spare': [0xE, ['array', 2, ['unsigned char']]],
            'AllowDemotion': [
                0x10,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AllowPromotion': [
                0x10,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x10,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
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
    '_ARBITER_INSTANCE': [
        0x9C,
        {
            'Signature': [0x0, ['unsigned long']],
            'MutexEvent': [0x4, ['pointer', ['_KEVENT']]],
            'Name': [0x8, ['pointer', ['unsigned short']]],
            'ResourceType': [0xC, ['long']],
            'Allocation': [0x10, ['pointer', ['_RTL_RANGE_LIST']]],
            'PossibleAllocation': [0x14, ['pointer', ['_RTL_RANGE_LIST']]],
            'OrderingList': [0x18, ['_ARBITER_ORDERING_LIST']],
            'ReservedList': [0x20, ['_ARBITER_ORDERING_LIST']],
            'ReferenceCount': [0x28, ['long']],
            'Interface': [0x2C, ['pointer', ['_ARBITER_INTERFACE']]],
            'AllocationStackMaxSize': [0x30, ['unsigned long']],
            'AllocationStack': [
                0x34,
                ['pointer', ['_ARBITER_ALLOCATION_STATE']],
            ],
            'UnpackRequirement': [0x38, ['pointer', ['void']]],
            'PackResource': [0x3C, ['pointer', ['void']]],
            'UnpackResource': [0x40, ['pointer', ['void']]],
            'ScoreRequirement': [0x44, ['pointer', ['void']]],
            'TestAllocation': [0x48, ['pointer', ['void']]],
            'RetestAllocation': [0x4C, ['pointer', ['void']]],
            'CommitAllocation': [0x50, ['pointer', ['void']]],
            'RollbackAllocation': [0x54, ['pointer', ['void']]],
            'BootAllocation': [0x58, ['pointer', ['void']]],
            'QueryArbitrate': [0x5C, ['pointer', ['void']]],
            'QueryConflict': [0x60, ['pointer', ['void']]],
            'AddReserved': [0x64, ['pointer', ['void']]],
            'StartArbiter': [0x68, ['pointer', ['void']]],
            'PreprocessEntry': [0x6C, ['pointer', ['void']]],
            'AllocateEntry': [0x70, ['pointer', ['void']]],
            'GetNextAllocationRange': [0x74, ['pointer', ['void']]],
            'FindSuitableRange': [0x78, ['pointer', ['void']]],
            'AddAllocation': [0x7C, ['pointer', ['void']]],
            'BacktrackAllocation': [0x80, ['pointer', ['void']]],
            'OverrideConflict': [0x84, ['pointer', ['void']]],
            'TransactionInProgress': [0x88, ['unsigned char']],
            'Extension': [0x8C, ['pointer', ['void']]],
            'BusDeviceObject': [0x90, ['pointer', ['_DEVICE_OBJECT']]],
            'ConflictCallbackContext': [0x94, ['pointer', ['void']]],
            'ConflictCallback': [0x98, ['pointer', ['void']]],
        },
    ],
    '_BUS_HANDLER': [
        0x6C,
        {
            'Version': [0x0, ['unsigned long']],
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
                            16: 'MaximumInterfaceType',
                            -1: 'InterfaceTypeUndefined',
                        },
                    ),
                ],
            ],
            'ConfigurationType': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'Cmos',
                            1: 'EisaConfiguration',
                            2: 'Pos',
                            3: 'CbusConfiguration',
                            4: 'PCIConfiguration',
                            5: 'VMEConfiguration',
                            6: 'NuBusConfiguration',
                            7: 'PCMCIAConfiguration',
                            8: 'MPIConfiguration',
                            9: 'MPSAConfiguration',
                            10: 'PNPISAConfiguration',
                            11: 'SgiInternalConfiguration',
                            12: 'MaximumBusDataType',
                            -1: 'ConfigurationSpaceUndefined',
                        },
                    ),
                ],
            ],
            'BusNumber': [0xC, ['unsigned long']],
            'DeviceObject': [0x10, ['pointer', ['_DEVICE_OBJECT']]],
            'ParentHandler': [0x14, ['pointer', ['_BUS_HANDLER']]],
            'BusData': [0x18, ['pointer', ['void']]],
            'DeviceControlExtensionSize': [0x1C, ['unsigned long']],
            'BusAddresses': [0x20, ['pointer', ['_SUPPORTED_RANGES']]],
            'Reserved': [0x24, ['array', 4, ['unsigned long']]],
            'GetBusData': [0x34, ['pointer', ['void']]],
            'SetBusData': [0x38, ['pointer', ['void']]],
            'AdjustResourceList': [0x3C, ['pointer', ['void']]],
            'AssignSlotResources': [0x40, ['pointer', ['void']]],
            'GetInterruptVector': [0x44, ['pointer', ['void']]],
            'TranslateBusAddress': [0x48, ['pointer', ['void']]],
            'Spare1': [0x4C, ['pointer', ['void']]],
            'Spare2': [0x50, ['pointer', ['void']]],
            'Spare3': [0x54, ['pointer', ['void']]],
            'Spare4': [0x58, ['pointer', ['void']]],
            'Spare5': [0x5C, ['pointer', ['void']]],
            'Spare6': [0x60, ['pointer', ['void']]],
            'Spare7': [0x64, ['pointer', ['void']]],
            'Spare8': [0x68, ['pointer', ['void']]],
        },
    ],
    '_PCI_MN_DISPATCH_TABLE': [
        0x8,
        {
            'DispatchStyle': [
                0x0,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IRP_COMPLETE',
                            1: 'IRP_DOWNWARD',
                            2: 'IRP_UPWARD',
                            3: 'IRP_DISPATCH',
                        },
                    ),
                ],
            ],
            'DispatchFunction': [0x4, ['pointer', ['void']]],
        },
    ],
    '_POP_DEVICE_SYS_STATE': [
        0x620,
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
            'Event': [0x8, ['_KEVENT']],
            'SpinLock': [0x18, ['unsigned long']],
            'Thread': [0x1C, ['pointer', ['_KTHREAD']]],
            'GetNewDeviceList': [0x20, ['unsigned char']],
            'Order': [0x24, ['_PO_DEVICE_NOTIFY_ORDER']],
            'Status': [0x26C, ['long']],
            'FailedDevice': [0x270, ['pointer', ['_DEVICE_OBJECT']]],
            'Waking': [0x274, ['unsigned char']],
            'Cancelled': [0x275, ['unsigned char']],
            'IgnoreErrors': [0x276, ['unsigned char']],
            'IgnoreNotImplemented': [0x277, ['unsigned char']],
            'WaitAny': [0x278, ['unsigned char']],
            'WaitAll': [0x279, ['unsigned char']],
            'PresentIrpQueue': [0x27C, ['_LIST_ENTRY']],
            'Head': [0x284, ['_POP_DEVICE_POWER_IRP']],
            'PowerIrpState': [0x2B0, ['array', 20, ['_POP_DEVICE_POWER_IRP']]],
        },
    ],
    '_OBJECT_DUMP_CONTROL': [
        0x8,
        {
            'Stream': [0x0, ['pointer', ['void']]],
            'Detail': [0x4, ['unsigned long']],
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
    '_HEAP_STOP_ON_TAG': [
        0x4,
        {
            'HeapAndTagIndex': [0x0, ['unsigned long']],
            'TagIndex': [0x0, ['unsigned short']],
            'HeapIndex': [0x2, ['unsigned short']],
        },
    ],
    '_ACTIVATION_CONTEXT_STACK': [
        0x14,
        {
            'Flags': [0x0, ['unsigned long']],
            'NextCookieSequenceNumber': [0x4, ['unsigned long']],
            'ActiveFrame': [0x8, ['pointer', ['void']]],
            'FrameListCache': [0xC, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_179d': [
        0x4,
        {
            'Flink': [0x0, ['unsigned long']],
            'WsIndex': [0x0, ['unsigned long']],
            'Event': [0x0, ['pointer', ['_KEVENT']]],
            'ReadStatus': [0x0, ['long']],
            'NextStackPfn': [0x0, ['_SINGLE_LIST_ENTRY']],
        },
    ],
    '__unnamed_179f': [
        0x4,
        {
            'Blink': [0x0, ['unsigned long']],
            'ShareCount': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_17a2': [
        0x4,
        {
            'ShortFlags': [0x0, ['unsigned short']],
            'ReferenceCount': [0x2, ['unsigned short']],
        },
    ],
    '__unnamed_17a4': [
        0x4,
        {
            'e1': [0x0, ['_MMPFNENTRY']],
            'e2': [0x0, ['__unnamed_17a2']],
        },
    ],
    '__unnamed_17aa': [
        0x4,
        {
            'EntireFrame': [0x0, ['unsigned long']],
            'PteFrame': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=26, native_type='unsigned long'),
                ],
            ],
            'InPageError': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'VerifierAllocation': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'AweAllocation': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=29, native_type='unsigned long'
                    ),
                ],
            ],
            'LockCharged': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=29, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'KernelStack': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved': [
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
    '_MMPFN': [
        0x18,
        {
            'u1': [0x0, ['__unnamed_179d']],
            'PteAddress': [0x4, ['pointer', ['_MMPTE']]],
            'u2': [0x8, ['__unnamed_179f']],
            'u3': [0xC, ['__unnamed_17a4']],
            'OriginalPte': [0x10, ['_MMPTE']],
            'u4': [0x14, ['__unnamed_17aa']],
        },
    ],
    '_MMWSLE_HASH': [
        0x8,
        {
            'Key': [0x0, ['pointer', ['void']]],
            'Index': [0x4, ['unsigned long']],
        },
    ],
    '_CM_NAME_CONTROL_BLOCK': [
        0x10,
        {
            'Compressed': [0x0, ['unsigned char']],
            'RefCount': [0x2, ['unsigned short']],
            'NameHash': [0x4, ['_CM_NAME_HASH']],
            'ConvKey': [0x4, ['unsigned long']],
            'NextHash': [0x8, ['pointer', ['_CM_KEY_HASH']]],
            'NameLength': [0xC, ['unsigned short']],
            'Name': [0xE, ['array', 1, ['unsigned short']]],
        },
    ],
    '_SECURITY_TOKEN_PROXY_DATA': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'ProxyClass': [
                0x4,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'ProxyFull',
                            1: 'ProxyService',
                            2: 'ProxyTree',
                            3: 'ProxyDirectory',
                        },
                    ),
                ],
            ],
            'PathInfo': [0x8, ['_UNICODE_STRING']],
            'ContainerMask': [0x10, ['unsigned long']],
            'ObjectMask': [0x14, ['unsigned long']],
        },
    ],
    '_HANDLE_TABLE_ENTRY': [
        0x8,
        {
            'Object': [0x0, ['pointer', ['void']]],
            'ObAttributes': [0x0, ['unsigned long']],
            'InfoTable': [0x0, ['pointer', ['_HANDLE_TABLE_ENTRY_INFO']]],
            'Value': [0x0, ['unsigned long']],
            'GrantedAccess': [0x4, ['unsigned long']],
            'GrantedAccessIndex': [0x4, ['unsigned short']],
            'CreatorBackTraceIndex': [0x6, ['unsigned short']],
            'NextFreeTableEntry': [0x4, ['long']],
        },
    ],
    '_HEAP_USERDATA_HEADER': [
        0x10,
        {
            'SFreeListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'SubSegment': [0x0, ['pointer', ['_HEAP_SUBSEGMENT']]],
            'HeapHandle': [0x4, ['pointer', ['void']]],
            'SizeIndex': [0x8, ['unsigned long']],
            'Signature': [0xC, ['unsigned long']],
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
    'PCI_POWER_STATE': [
        0x40,
        {
            'CurrentSystemState': [
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
            'CurrentDeviceState': [
                0x4,
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
            'SystemWakeLevel': [
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
            'DeviceWakeLevel': [
                0xC,
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
            'SystemStateMapping': [
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
            'WaitWakeIrp': [0x2C, ['pointer', ['_IRP']]],
            'SavedCancelRoutine': [0x30, ['pointer', ['void']]],
            'Paging': [0x34, ['long']],
            'Hibernate': [0x38, ['long']],
            'CrashDump': [0x3C, ['long']],
        },
    ],
    '_POOL_HACKER': [
        0x28,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'Contents': [0x8, ['array', 8, ['unsigned long']]],
        },
    ],
    '_CM_INDEX_HINT_BLOCK': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'HashKey': [0x4, ['array', 1, ['unsigned long']]],
        },
    ],
    '__unnamed_17ce': [
        0x10,
        {
            'SecurityContext': [0x0, ['pointer', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x4, ['unsigned long']],
            'FileAttributes': [0x8, ['unsigned short']],
            'ShareAccess': [0xA, ['unsigned short']],
            'EaLength': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_17d2': [
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
    '__unnamed_17d6': [
        0x10,
        {
            'SecurityContext': [0x0, ['pointer', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned short']],
            'ShareAccess': [0xA, ['unsigned short']],
            'Parameters': [0xC, ['pointer', ['_MAILSLOT_CREATE_PARAMETERS']]],
        },
    ],
    '__unnamed_17d8': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'Key': [0x4, ['unsigned long']],
            'ByteOffset': [0x8, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_17dd': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'FileName': [0x4, ['pointer', ['_STRING']]],
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
                            41: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileIndex': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_17df': [
        0x8,
        {
            'Length': [0x0, ['unsigned long']],
            'CompletionFilter': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_17e1': [
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
                            41: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_17e3': [
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
                            41: 'FileMaximumInformation',
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
    '__unnamed_17e5': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'EaList': [0x4, ['pointer', ['void']]],
            'EaListLength': [0x8, ['unsigned long']],
            'EaIndex': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_17e7': [
        0x4,
        {
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_17eb': [
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
                            10: 'FileFsMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_17ed': [
        0x10,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x4, ['unsigned long']],
            'FsControlCode': [0x8, ['unsigned long']],
            'Type3InputBuffer': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_17ef': [
        0x10,
        {
            'Length': [0x0, ['pointer', ['_LARGE_INTEGER']]],
            'Key': [0x4, ['unsigned long']],
            'ByteOffset': [0x8, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_17f1': [
        0x10,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x4, ['unsigned long']],
            'IoControlCode': [0x8, ['unsigned long']],
            'Type3InputBuffer': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_17f3': [
        0x8,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_17f5': [
        0x8,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'SecurityDescriptor': [0x4, ['pointer', ['void']]],
        },
    ],
    '__unnamed_17f7': [
        0x8,
        {
            'Vpb': [0x0, ['pointer', ['_VPB']]],
            'DeviceObject': [0x4, ['pointer', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_17fb': [
        0x4,
        {
            'Srb': [0x0, ['pointer', ['_SCSI_REQUEST_BLOCK']]],
        },
    ],
    '__unnamed_17ff': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'StartSid': [0x4, ['pointer', ['void']]],
            'SidList': [0x8, ['pointer', ['_FILE_GET_QUOTA_INFORMATION']]],
            'SidListLength': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1803': [
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
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1805': [
        0x10,
        {
            'InterfaceType': [0x0, ['pointer', ['_GUID']]],
            'Size': [0x4, ['unsigned short']],
            'Version': [0x6, ['unsigned short']],
            'Interface': [0x8, ['pointer', ['_INTERFACE']]],
            'InterfaceSpecificData': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1809': [
        0x4,
        {
            'Capabilities': [0x0, ['pointer', ['_DEVICE_CAPABILITIES']]],
        },
    ],
    '__unnamed_180b': [
        0x4,
        {
            'IoResourceRequirementList': [
                0x0,
                ['pointer', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
        },
    ],
    '__unnamed_180d': [
        0x10,
        {
            'WhichSpace': [0x0, ['unsigned long']],
            'Buffer': [0x4, ['pointer', ['void']]],
            'Offset': [0x8, ['unsigned long']],
            'Length': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_180f': [
        0x1,
        {
            'Lock': [0x0, ['unsigned char']],
        },
    ],
    '__unnamed_1813': [
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
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1817': [
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
    '__unnamed_181b': [
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
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_181d': [
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
    '__unnamed_1821': [
        0x4,
        {
            'PowerSequence': [0x0, ['pointer', ['_POWER_SEQUENCE']]],
        },
    ],
    '__unnamed_1825': [
        0x10,
        {
            'SystemContext': [0x0, ['unsigned long']],
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
    '__unnamed_1827': [
        0x8,
        {
            'AllocatedResources': [0x0, ['pointer', ['_CM_RESOURCE_LIST']]],
            'AllocatedResourcesTranslated': [
                0x4,
                ['pointer', ['_CM_RESOURCE_LIST']],
            ],
        },
    ],
    '__unnamed_1829': [
        0x10,
        {
            'ProviderId': [0x0, ['unsigned long']],
            'DataPath': [0x4, ['pointer', ['void']]],
            'BufferSize': [0x8, ['unsigned long']],
            'Buffer': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_182b': [
        0x10,
        {
            'Argument1': [0x0, ['pointer', ['void']]],
            'Argument2': [0x4, ['pointer', ['void']]],
            'Argument3': [0x8, ['pointer', ['void']]],
            'Argument4': [0xC, ['pointer', ['void']]],
        },
    ],
    '__unnamed_182d': [
        0x10,
        {
            'Create': [0x0, ['__unnamed_17ce']],
            'CreatePipe': [0x0, ['__unnamed_17d2']],
            'CreateMailslot': [0x0, ['__unnamed_17d6']],
            'Read': [0x0, ['__unnamed_17d8']],
            'Write': [0x0, ['__unnamed_17d8']],
            'QueryDirectory': [0x0, ['__unnamed_17dd']],
            'NotifyDirectory': [0x0, ['__unnamed_17df']],
            'QueryFile': [0x0, ['__unnamed_17e1']],
            'SetFile': [0x0, ['__unnamed_17e3']],
            'QueryEa': [0x0, ['__unnamed_17e5']],
            'SetEa': [0x0, ['__unnamed_17e7']],
            'QueryVolume': [0x0, ['__unnamed_17eb']],
            'SetVolume': [0x0, ['__unnamed_17eb']],
            'FileSystemControl': [0x0, ['__unnamed_17ed']],
            'LockControl': [0x0, ['__unnamed_17ef']],
            'DeviceIoControl': [0x0, ['__unnamed_17f1']],
            'QuerySecurity': [0x0, ['__unnamed_17f3']],
            'SetSecurity': [0x0, ['__unnamed_17f5']],
            'MountVolume': [0x0, ['__unnamed_17f7']],
            'VerifyVolume': [0x0, ['__unnamed_17f7']],
            'Scsi': [0x0, ['__unnamed_17fb']],
            'QueryQuota': [0x0, ['__unnamed_17ff']],
            'SetQuota': [0x0, ['__unnamed_17e7']],
            'QueryDeviceRelations': [0x0, ['__unnamed_1803']],
            'QueryInterface': [0x0, ['__unnamed_1805']],
            'DeviceCapabilities': [0x0, ['__unnamed_1809']],
            'FilterResourceRequirements': [0x0, ['__unnamed_180b']],
            'ReadWriteConfig': [0x0, ['__unnamed_180d']],
            'SetLock': [0x0, ['__unnamed_180f']],
            'QueryId': [0x0, ['__unnamed_1813']],
            'QueryDeviceText': [0x0, ['__unnamed_1817']],
            'UsageNotification': [0x0, ['__unnamed_181b']],
            'WaitWake': [0x0, ['__unnamed_181d']],
            'PowerSequence': [0x0, ['__unnamed_1821']],
            'Power': [0x0, ['__unnamed_1825']],
            'StartDevice': [0x0, ['__unnamed_1827']],
            'WMI': [0x0, ['__unnamed_1829']],
            'Others': [0x0, ['__unnamed_182b']],
        },
    ],
    '_IO_STACK_LOCATION': [
        0x24,
        {
            'MajorFunction': [0x0, ['unsigned char']],
            'MinorFunction': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned char']],
            'Control': [0x3, ['unsigned char']],
            'Parameters': [0x4, ['__unnamed_182d']],
            'DeviceObject': [0x14, ['pointer', ['_DEVICE_OBJECT']]],
            'FileObject': [0x18, ['pointer', ['_FILE_OBJECT']]],
            'CompletionRoutine': [0x1C, ['pointer', ['void']]],
            'Context': [0x20, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1834': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Alignment': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1836': [
        0x8,
        {
            'MinimumVector': [0x0, ['unsigned long']],
            'MaximumVector': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1838': [
        0x8,
        {
            'MinimumChannel': [0x0, ['unsigned long']],
            'MaximumChannel': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_183a': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'MinBusNumber': [0x4, ['unsigned long']],
            'MaxBusNumber': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_183c': [
        0xC,
        {
            'Priority': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_183e': [
        0x18,
        {
            'Port': [0x0, ['__unnamed_1834']],
            'Memory': [0x0, ['__unnamed_1834']],
            'Interrupt': [0x0, ['__unnamed_1836']],
            'Dma': [0x0, ['__unnamed_1838']],
            'Generic': [0x0, ['__unnamed_1834']],
            'DevicePrivate': [0x0, ['__unnamed_1512']],
            'BusNumber': [0x0, ['__unnamed_183a']],
            'ConfigData': [0x0, ['__unnamed_183c']],
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
            'u': [0x8, ['__unnamed_183e']],
        },
    ],
    '_LUID_AND_ATTRIBUTES': [
        0xC,
        {
            'Luid': [0x0, ['_LUID']],
            'Attributes': [0x8, ['unsigned long']],
        },
    ],
    '_MI_VERIFIER_POOL_HEADER': [
        0x8,
        {
            'ListIndex': [0x0, ['unsigned long']],
            'Verifier': [0x4, ['pointer', ['_MI_VERIFIER_DRIVER_ENTRY']]],
        },
    ],
    '_CM_KEY_BODY': [
        0x44,
        {
            'Type': [0x0, ['unsigned long']],
            'KeyControlBlock': [0x4, ['pointer', ['_CM_KEY_CONTROL_BLOCK']]],
            'NotifyBlock': [0x8, ['pointer', ['_CM_NOTIFY_BLOCK']]],
            'ProcessID': [0xC, ['pointer', ['void']]],
            'Callers': [0x10, ['unsigned long']],
            'CallerAddress': [0x14, ['array', 10, ['pointer', ['void']]]],
            'KeyBodyList': [0x3C, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_184f': [
        0x4,
        {
            'DataLength': [0x0, ['short']],
            'TotalLength': [0x2, ['short']],
        },
    ],
    '__unnamed_1851': [
        0x4,
        {
            's1': [0x0, ['__unnamed_184f']],
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1853': [
        0x4,
        {
            'Type': [0x0, ['short']],
            'DataInfoOffset': [0x2, ['short']],
        },
    ],
    '__unnamed_1855': [
        0x4,
        {
            's2': [0x0, ['__unnamed_1853']],
            'ZeroInit': [0x0, ['unsigned long']],
        },
    ],
    '_PORT_MESSAGE': [
        0x18,
        {
            'u1': [0x0, ['__unnamed_1851']],
            'u2': [0x4, ['__unnamed_1855']],
            'ClientId': [0x8, ['_CLIENT_ID']],
            'DoNotUseThisField': [0x8, ['double']],
            'MessageId': [0x10, ['unsigned long']],
            'ClientViewSize': [0x14, ['unsigned long']],
            'CallbackId': [0x14, ['unsigned long']],
        },
    ],
    '_DBGKD_ANY_CONTROL_SET': [
        0x1C,
        {
            'X86ControlSet': [0x0, ['_X86_DBGKD_CONTROL_SET']],
            'AlphaControlSet': [0x0, ['unsigned long']],
            'IA64ControlSet': [0x0, ['_IA64_DBGKD_CONTROL_SET']],
            'Amd64ControlSet': [0x0, ['_AMD64_DBGKD_CONTROL_SET']],
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
            'Reserved1': [0x70, ['array', 99, ['unsigned long']]],
            'CheckSum': [0x1FC, ['unsigned long']],
            'Reserved2': [0x200, ['array', 894, ['unsigned long']]],
            'BootType': [0xFF8, ['unsigned long']],
            'BootRecover': [0xFFC, ['unsigned long']],
        },
    ],
    '_DUAL': [
        0xDC,
        {
            'Length': [0x0, ['unsigned long']],
            'Map': [0x4, ['pointer', ['_HMAP_DIRECTORY']]],
            'SmallDir': [0x8, ['pointer', ['_HMAP_TABLE']]],
            'Guard': [0xC, ['unsigned long']],
            'FreeDisplay': [0x10, ['array', 24, ['_RTL_BITMAP']]],
            'FreeSummary': [0xD0, ['unsigned long']],
            'FreeBins': [0xD4, ['_LIST_ENTRY']],
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
    '_INITIAL_PRIVILEGE_SET': [
        0x2C,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Control': [0x4, ['unsigned long']],
            'Privilege': [0x8, ['array', 3, ['_LUID_AND_ATTRIBUTES']]],
        },
    ],
    '_POP_HIBER_CONTEXT': [
        0xE0,
        {
            'WriteToFile': [0x0, ['unsigned char']],
            'ReserveLoaderMemory': [0x1, ['unsigned char']],
            'ReserveFreeMemory': [0x2, ['unsigned char']],
            'VerifyOnWake': [0x3, ['unsigned char']],
            'Reset': [0x4, ['unsigned char']],
            'HiberFlags': [0x5, ['unsigned char']],
            'LinkFile': [0x6, ['unsigned char']],
            'LinkFileHandle': [0x8, ['pointer', ['void']]],
            'Lock': [0xC, ['unsigned long']],
            'MapFrozen': [0x10, ['unsigned char']],
            'MemoryMap': [0x14, ['_RTL_BITMAP']],
            'ClonedRanges': [0x1C, ['_LIST_ENTRY']],
            'ClonedRangeCount': [0x24, ['unsigned long']],
            'NextCloneRange': [0x28, ['pointer', ['_LIST_ENTRY']]],
            'NextPreserve': [0x2C, ['unsigned long']],
            'LoaderMdl': [0x30, ['pointer', ['_MDL']]],
            'Clones': [0x34, ['pointer', ['_MDL']]],
            'NextClone': [0x38, ['pointer', ['unsigned char']]],
            'NoClones': [0x3C, ['unsigned long']],
            'Spares': [0x40, ['pointer', ['_MDL']]],
            'PagesOut': [0x48, ['unsigned long long']],
            'IoPage': [0x50, ['pointer', ['void']]],
            'CurrentMcb': [0x54, ['pointer', ['void']]],
            'DumpStack': [0x58, ['pointer', ['_DUMP_STACK_CONTEXT']]],
            'WakeState': [0x5C, ['pointer', ['_KPROCESSOR_STATE']]],
            'NoRanges': [0x60, ['unsigned long']],
            'HiberVa': [0x64, ['unsigned long']],
            'HiberPte': [0x68, ['_LARGE_INTEGER']],
            'Status': [0x70, ['long']],
            'MemoryImage': [0x74, ['pointer', ['PO_MEMORY_IMAGE']]],
            'TableHead': [0x78, ['pointer', ['_PO_MEMORY_RANGE_ARRAY']]],
            'CompressionWorkspace': [0x7C, ['pointer', ['unsigned char']]],
            'CompressedWriteBuffer': [0x80, ['pointer', ['unsigned char']]],
            'PerformanceStats': [0x84, ['pointer', ['unsigned long']]],
            'CompressionBlock': [0x88, ['pointer', ['void']]],
            'DmaIO': [0x8C, ['pointer', ['void']]],
            'TemporaryHeap': [0x90, ['pointer', ['void']]],
            'PerfInfo': [0x98, ['_PO_HIBER_PERF']],
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
    '_MMADDRESS_LIST': [
        0x8,
        {
            'StartVpn': [0x0, ['unsigned long']],
            'EndVpn': [0x4, ['unsigned long']],
        },
    ],
    '_OBJECT_NAME_INFORMATION': [
        0x8,
        {
            'Name': [0x0, ['_UNICODE_STRING']],
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
    '_DUMP_STACK_CONTEXT': [
        0xB0,
        {
            'Init': [0x0, ['_DUMP_INITIALIZATION_CONTEXT']],
            'PartitionOffset': [0x70, ['_LARGE_INTEGER']],
            'DumpPointers': [0x78, ['pointer', ['void']]],
            'PointersLength': [0x7C, ['unsigned long']],
            'ModulePrefix': [0x80, ['pointer', ['unsigned short']]],
            'DriverList': [0x84, ['_LIST_ENTRY']],
            'InitMsg': [0x8C, ['_STRING']],
            'ProgMsg': [0x94, ['_STRING']],
            'DoneMsg': [0x9C, ['_STRING']],
            'FileObject': [0xA4, ['pointer', ['void']]],
            'UsageType': [
                0xA8,
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
        0x14,
        {
            'Code': [0x0, ['unsigned long']],
            'Parameter1': [0x4, ['unsigned long']],
            'Parameter2': [0x8, ['unsigned long']],
            'Parameter3': [0xC, ['unsigned long']],
            'Parameter4': [0x10, ['unsigned long']],
        },
    ],
    '__unnamed_1894': [
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
    '__unnamed_1896': [
        0x4,
        {
            'bits': [0x0, ['__unnamed_1894']],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_PCI_SLOT_NUMBER': [
        0x4,
        {
            'u': [0x0, ['__unnamed_1896']],
        },
    ],
    '_Wx86ThreadState': [
        0xC,
        {
            'CallBx86Eip': [0x0, ['pointer', ['unsigned long']]],
            'DeallocationCpu': [0x4, ['pointer', ['void']]],
            'UseKnownWx86Dll': [0x8, ['unsigned char']],
            'OleStubInvoked': [0x9, ['unsigned char']],
        },
    ],
    '_DRIVER_EXTENSION': [
        0x1C,
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
    '_SID': [
        0xC,
        {
            'Revision': [0x0, ['unsigned char']],
            'SubAuthorityCount': [0x1, ['unsigned char']],
            'IdentifierAuthority': [0x2, ['_SID_IDENTIFIER_AUTHORITY']],
            'SubAuthority': [0x8, ['array', 1, ['unsigned long']]],
        },
    ],
    '_RTL_HANDLE_TABLE_ENTRY': [
        0x4,
        {
            'Flags': [0x0, ['unsigned long']],
            'NextFree': [0x0, ['pointer', ['_RTL_HANDLE_TABLE_ENTRY']]],
        },
    ],
    '_MMPTE_HARDWARE': [
        0x4,
        {
            'Valid': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Writable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Owner': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WriteThrough': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'CacheDisable': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Accessed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'Dirty': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'LargePage': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Global': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'CopyOnWrite': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'Prototype': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'Write': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'PageFrameNumber': [
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
    '_SUPPORTED_RANGES': [
        0xA0,
        {
            'Version': [0x0, ['unsigned short']],
            'Sorted': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
            'NoIO': [0x4, ['unsigned long']],
            'IO': [0x8, ['_SUPPORTED_RANGE']],
            'NoMemory': [0x28, ['unsigned long']],
            'Memory': [0x30, ['_SUPPORTED_RANGE']],
            'NoPrefetchMemory': [0x50, ['unsigned long']],
            'PrefetchMemory': [0x58, ['_SUPPORTED_RANGE']],
            'NoDma': [0x78, ['unsigned long']],
            'Dma': [0x80, ['_SUPPORTED_RANGE']],
        },
    ],
    '_SID_IDENTIFIER_AUTHORITY': [
        0x6,
        {
            'Value': [0x0, ['array', 6, ['unsigned char']]],
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
    '_PM_SUPPORT': [
        0x1,
        {
            'Rsvd2': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'D1': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'D2': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'PMED0': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'PMED1': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'PMED2': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'PMED3Hot': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'PMED3Cold': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '__unnamed_18be': [
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
    '__unnamed_18c0': [
        0x4,
        {
            'ArbitrationList': [0x0, ['pointer', ['_LIST_ENTRY']]],
        },
    ],
    '__unnamed_18c4': [
        0x4,
        {
            'AllocatedResources': [
                0x0,
                ['pointer', ['pointer', ['_CM_PARTIAL_RESOURCE_LIST']]],
            ],
        },
    ],
    '__unnamed_18c6': [
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
    '__unnamed_18c8': [
        0x4,
        {
            'ReserveDevice': [0x0, ['pointer', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_18ca': [
        0x10,
        {
            'TestAllocation': [0x0, ['__unnamed_18be']],
            'RetestAllocation': [0x0, ['__unnamed_18be']],
            'BootAllocation': [0x0, ['__unnamed_18c0']],
            'QueryAllocatedResources': [0x0, ['__unnamed_18c4']],
            'QueryConflict': [0x0, ['__unnamed_18c6']],
            'QueryArbitrate': [0x0, ['__unnamed_18c0']],
            'AddReserved': [0x0, ['__unnamed_18c8']],
        },
    ],
    '_ARBITER_PARAMETERS': [
        0x10,
        {
            'Parameters': [0x0, ['__unnamed_18ca']],
        },
    ],
    '_SECURITY_TOKEN_AUDIT_DATA': [
        0xC,
        {
            'Length': [0x0, ['unsigned long']],
            'GrantMask': [0x4, ['unsigned long']],
            'DenyMask': [0x8, ['unsigned long']],
        },
    ],
    '_HANDLE_TABLE_ENTRY_INFO': [
        0x4,
        {
            'AuditMask': [0x0, ['unsigned long']],
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
    '_IMAGE_DATA_DIRECTORY': [
        0x8,
        {
            'VirtualAddress': [0x0, ['unsigned long']],
            'Size': [0x4, ['unsigned long']],
        },
    ],
    '_MMPFNENTRY': [
        0x4,
        {
            'Modified': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReadInProgress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'WriteInProgress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'PrototypePte': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'PageColor': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'ParityError': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'PageLocation': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=11, native_type='unsigned long'),
                ],
            ],
            'RemovalRequested': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'CacheAttribute': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'Rom': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'LockCharged': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'DontUse': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
        },
    ],
    '_MI_VERIFIER_DRIVER_ENTRY': [
        0x60,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'Loads': [0x8, ['unsigned long']],
            'Unloads': [0xC, ['unsigned long']],
            'BaseName': [0x10, ['_UNICODE_STRING']],
            'StartAddress': [0x18, ['pointer', ['void']]],
            'EndAddress': [0x1C, ['pointer', ['void']]],
            'Flags': [0x20, ['unsigned long']],
            'Signature': [0x24, ['unsigned long']],
            'Reserved': [0x28, ['unsigned long']],
            'VerifierPoolLock': [0x2C, ['unsigned long']],
            'PoolHash': [0x30, ['pointer', ['_VI_POOL_ENTRY']]],
            'PoolHashSize': [0x34, ['unsigned long']],
            'PoolHashFree': [0x38, ['unsigned long']],
            'PoolHashReserved': [0x3C, ['unsigned long']],
            'CurrentPagedPoolAllocations': [0x40, ['unsigned long']],
            'CurrentNonPagedPoolAllocations': [0x44, ['unsigned long']],
            'PeakPagedPoolAllocations': [0x48, ['unsigned long']],
            'PeakNonPagedPoolAllocations': [0x4C, ['unsigned long']],
            'PagedBytes': [0x50, ['unsigned long']],
            'NonPagedBytes': [0x54, ['unsigned long']],
            'PeakPagedBytes': [0x58, ['unsigned long']],
            'PeakNonPagedBytes': [0x5C, ['unsigned long']],
        },
    ],
    '_CURDIR': [
        0xC,
        {
            'DosPath': [0x0, ['_UNICODE_STRING']],
            'Handle': [0x8, ['pointer', ['void']]],
        },
    ],
    '_MMMOD_WRITER_LISTHEAD': [
        0x18,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Event': [0x8, ['_KEVENT']],
        },
    ],
    '_PO_HIBER_PERF': [
        0x48,
        {
            'IoTicks': [0x0, ['unsigned long long']],
            'InitTicks': [0x8, ['unsigned long long']],
            'CopyTicks': [0x10, ['unsigned long long']],
            'StartCount': [0x18, ['unsigned long long']],
            'ElapsedTime': [0x20, ['unsigned long']],
            'IoTime': [0x24, ['unsigned long']],
            'CopyTime': [0x28, ['unsigned long']],
            'InitTime': [0x2C, ['unsigned long']],
            'PagesWritten': [0x30, ['unsigned long']],
            'PagesProcessed': [0x34, ['unsigned long']],
            'BytesCopied': [0x38, ['unsigned long']],
            'DumpCount': [0x3C, ['unsigned long']],
            'FileRuns': [0x40, ['unsigned long']],
        },
    ],
    '_GDI_TEB_BATCH': [
        0x4E0,
        {
            'Offset': [0x0, ['unsigned long']],
            'HDC': [0x4, ['unsigned long']],
            'Buffer': [0x8, ['array', 310, ['unsigned long']]],
        },
    ],
    'PO_MEMORY_IMAGE': [
        0xA8,
        {
            'Signature': [0x0, ['unsigned long']],
            'Version': [0x4, ['unsigned long']],
            'CheckSum': [0x8, ['unsigned long']],
            'LengthSelf': [0xC, ['unsigned long']],
            'PageSelf': [0x10, ['unsigned long']],
            'PageSize': [0x14, ['unsigned long']],
            'ImageType': [0x18, ['unsigned long']],
            'SystemTime': [0x20, ['_LARGE_INTEGER']],
            'InterruptTime': [0x28, ['unsigned long long']],
            'FeatureFlags': [0x30, ['unsigned long']],
            'HiberFlags': [0x34, ['unsigned char']],
            'spare': [0x35, ['array', 3, ['unsigned char']]],
            'NoHiberPtes': [0x38, ['unsigned long']],
            'HiberVa': [0x3C, ['unsigned long']],
            'HiberPte': [0x40, ['_LARGE_INTEGER']],
            'NoFreePages': [0x48, ['unsigned long']],
            'FreeMapCheck': [0x4C, ['unsigned long']],
            'WakeCheck': [0x50, ['unsigned long']],
            'TotalPages': [0x54, ['unsigned long']],
            'FirstTablePage': [0x58, ['unsigned long']],
            'LastFilePage': [0x5C, ['unsigned long']],
            'PerfInfo': [0x60, ['_PO_HIBER_PERF']],
        },
    ],
    'BATTERY_REPORTING_SCALE': [
        0x8,
        {
            'Granularity': [0x0, ['unsigned long']],
            'Capacity': [0x4, ['unsigned long']],
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
            'Reserved': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=32, native_type='unsigned long'
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
    '_TEB_ACTIVE_FRAME_CONTEXT': [
        0x8,
        {
            'Flags': [0x0, ['unsigned long']],
            'FrameName': [0x4, ['pointer', ['unsigned char']]],
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
    '_RTL_CRITICAL_SECTION_DEBUG': [
        0x20,
        {
            'Type': [0x0, ['unsigned short']],
            'CreatorBackTraceIndex': [0x2, ['unsigned short']],
            'CriticalSection': [0x4, ['pointer', ['_RTL_CRITICAL_SECTION']]],
            'ProcessLocksList': [0x8, ['_LIST_ENTRY']],
            'EntryCount': [0x10, ['unsigned long']],
            'ContentionCount': [0x14, ['unsigned long']],
            'Spare': [0x18, ['array', 2, ['unsigned long']]],
        },
    ],
    '_SEP_AUDIT_POLICY': [
        0x8,
        {
            'PolicyElements': [0x0, ['_SEP_AUDIT_POLICY_CATEGORIES']],
            'PolicyOverlay': [0x0, ['_SEP_AUDIT_POLICY_OVERLAY']],
            'Overlay': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_18fe': [
        0x14,
        {
            'ClassGuid': [0x0, ['_GUID']],
            'SymbolicLinkName': [0x10, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1900': [
        0x2,
        {
            'DeviceIds': [0x0, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1902': [
        0x2,
        {
            'DeviceId': [0x0, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1904': [
        0x8,
        {
            'NotificationStructure': [0x0, ['pointer', ['void']]],
            'DeviceIds': [0x4, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1906': [
        0x4,
        {
            'Notification': [0x0, ['pointer', ['void']]],
        },
    ],
    '__unnamed_1908': [
        0x8,
        {
            'NotificationCode': [0x0, ['unsigned long']],
            'NotificationData': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_190a': [
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
            'DeviceIdVetoNameBuffer': [0x4, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_190c': [
        0x10,
        {
            'BlockedDriverGuid': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_190e': [
        0x14,
        {
            'DeviceClass': [0x0, ['__unnamed_18fe']],
            'TargetDevice': [0x0, ['__unnamed_1900']],
            'InstallDevice': [0x0, ['__unnamed_1902']],
            'CustomNotification': [0x0, ['__unnamed_1904']],
            'ProfileNotification': [0x0, ['__unnamed_1906']],
            'PowerNotification': [0x0, ['__unnamed_1908']],
            'VetoNotification': [0x0, ['__unnamed_190a']],
            'BlockedDriverNotification': [0x0, ['__unnamed_190c']],
        },
    ],
    '_PLUGPLAY_EVENT_BLOCK': [
        0x38,
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
                            6: 'PowerEvent',
                            7: 'VetoEvent',
                            8: 'BlockedDriverEvent',
                            9: 'MaxPlugEventCategory',
                        },
                    ),
                ],
            ],
            'Result': [0x14, ['pointer', ['unsigned long']]],
            'Flags': [0x18, ['unsigned long']],
            'TotalSize': [0x1C, ['unsigned long']],
            'DeviceObject': [0x20, ['pointer', ['void']]],
            'u': [0x24, ['__unnamed_190e']],
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
    '__unnamed_1914': [
        0x10,
        {
            'PageNo': [0x0, ['unsigned long']],
            'StartPage': [0x4, ['unsigned long']],
            'EndPage': [0x8, ['unsigned long']],
            'CheckSum': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1916': [
        0x10,
        {
            'Next': [0x0, ['pointer', ['_PO_MEMORY_RANGE_ARRAY']]],
            'NextTable': [0x4, ['unsigned long']],
            'CheckSum': [0x8, ['unsigned long']],
            'EntryCount': [0xC, ['unsigned long']],
        },
    ],
    '_PO_MEMORY_RANGE_ARRAY': [
        0x10,
        {
            'Range': [0x0, ['__unnamed_1914']],
            'Link': [0x0, ['__unnamed_1916']],
        },
    ],
    '__unnamed_1928': [
        0x8,
        {
            'Signature': [0x0, ['unsigned long']],
            'CheckSum': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_192a': [
        0x10,
        {
            'DiskId': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_192c': [
        0x10,
        {
            'Mbr': [0x0, ['__unnamed_1928']],
            'Gpt': [0x0, ['__unnamed_192a']],
        },
    ],
    '_DUMP_INITIALIZATION_CONTEXT': [
        0x70,
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
            'MaximumTransferSize': [0x48, ['unsigned long']],
            'CommonBufferSize': [0x4C, ['unsigned long']],
            'TargetAddress': [0x50, ['pointer', ['void']]],
            'WritePendingRoutine': [0x54, ['pointer', ['void']]],
            'PartitionStyle': [0x58, ['unsigned long']],
            'DiskInfo': [0x5C, ['__unnamed_192c']],
        },
    ],
    '_IO_CLIENT_EXTENSION': [
        0x8,
        {
            'NextExtension': [0x0, ['pointer', ['_IO_CLIENT_EXTENSION']]],
            'ClientIdentificationAddress': [0x4, ['pointer', ['void']]],
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
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '_CM_NAME_HASH': [
        0xC,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x4, ['pointer', ['_CM_NAME_HASH']]],
            'NameLength': [0x8, ['unsigned short']],
            'Name': [0xA, ['array', 1, ['unsigned short']]],
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
    '_SEP_AUDIT_POLICY_OVERLAY': [
        0x8,
        {
            'PolicyBits': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=36,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'SetBit': [
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
        },
    ],
    '_PCI_HEADER_TYPE_0': [
        0x30,
        {
            'BaseAddresses': [0x0, ['array', 6, ['unsigned long']]],
            'CIS': [0x18, ['unsigned long']],
            'SubVendorID': [0x1C, ['unsigned short']],
            'SubSystemID': [0x1E, ['unsigned short']],
            'ROMBaseAddress': [0x20, ['unsigned long']],
            'CapabilitiesPtr': [0x24, ['unsigned char']],
            'Reserved1': [0x25, ['array', 3, ['unsigned char']]],
            'Reserved2': [0x28, ['unsigned long']],
            'InterruptLine': [0x2C, ['unsigned char']],
            'InterruptPin': [0x2D, ['unsigned char']],
            'MinimumGrant': [0x2E, ['unsigned char']],
            'MaximumLatency': [0x2F, ['unsigned char']],
        },
    ],
    '_PO_DEVICE_NOTIFY_ORDER': [
        0x248,
        {
            'DevNodeSequence': [0x0, ['unsigned long']],
            'WarmEjectPdoPointer': [
                0x4,
                ['pointer', ['pointer', ['_DEVICE_OBJECT']]],
            ],
            'OrderLevel': [0x8, ['array', 8, ['_PO_NOTIFY_ORDER_LEVEL']]],
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
    '_IA64_DBGKD_CONTROL_SET': [
        0x14,
        {
            'Continue': [0x0, ['unsigned long']],
            'CurrentSymbolStart': [0x4, ['unsigned long long']],
            'CurrentSymbolEnd': [0xC, ['unsigned long long']],
        },
    ],
    '_DEVICE_MAP': [
        0x30,
        {
            'DosDevicesDirectory': [0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
            'GlobalDosDevicesDirectory': [
                0x4,
                ['pointer', ['_OBJECT_DIRECTORY']],
            ],
            'ReferenceCount': [0x8, ['unsigned long']],
            'DriveMap': [0xC, ['unsigned long']],
            'DriveType': [0x10, ['array', 32, ['unsigned char']]],
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
            'KeyString': [0x0, ['array', 1, ['unsigned short']]],
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
        0x48,
        {
            'LevelReady': [0x0, ['_KEVENT']],
            'DeviceCount': [0x10, ['unsigned long']],
            'ActiveCount': [0x14, ['unsigned long']],
            'WaitSleep': [0x18, ['_LIST_ENTRY']],
            'ReadySleep': [0x20, ['_LIST_ENTRY']],
            'Pending': [0x28, ['_LIST_ENTRY']],
            'Complete': [0x30, ['_LIST_ENTRY']],
            'ReadyS0': [0x38, ['_LIST_ENTRY']],
            'WaitS0': [0x40, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1961': [
        0x8,
        {
            'Base': [0x0, ['unsigned long']],
            'Limit': [0x4, ['unsigned long']],
        },
    ],
    '_PCI_HEADER_TYPE_2': [
        0x30,
        {
            'SocketRegistersBaseAddress': [0x0, ['unsigned long']],
            'CapabilitiesPtr': [0x4, ['unsigned char']],
            'Reserved': [0x5, ['unsigned char']],
            'SecondaryStatus': [0x6, ['unsigned short']],
            'PrimaryBus': [0x8, ['unsigned char']],
            'SecondaryBus': [0x9, ['unsigned char']],
            'SubordinateBus': [0xA, ['unsigned char']],
            'SecondaryLatency': [0xB, ['unsigned char']],
            'Range': [0xC, ['array', 4, ['__unnamed_1961']]],
            'InterruptLine': [0x2C, ['unsigned char']],
            'InterruptPin': [0x2D, ['unsigned char']],
            'BridgeControl': [0x2E, ['unsigned short']],
        },
    ],
    '_SEP_AUDIT_POLICY_CATEGORIES': [
        0x8,
        {
            'System': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Logon': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ObjectAccess': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=12, native_type='unsigned long'),
                ],
            ],
            'PrivilegeUse': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'DetailedTracking': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'PolicyChange': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'AccountManagement': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=28, native_type='unsigned long'
                    ),
                ],
            ],
            'DirectoryServiceAccess': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=28, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'AccountLogon': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
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
            'Name': [0x14, ['array', 1, ['unsigned short']]],
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
    '_OBJECT_DIRECTORY_ENTRY': [
        0x8,
        {
            'ChainLink': [0x0, ['pointer', ['_OBJECT_DIRECTORY_ENTRY']]],
            'Object': [0x4, ['pointer', ['void']]],
        },
    ],
    '_VI_POOL_ENTRY': [
        0x10,
        {
            'InUse': [0x0, ['_VI_POOL_ENTRY_INUSE']],
            'FreeListNext': [0x0, ['unsigned long']],
        },
    ],
    '_POP_DEVICE_POWER_IRP': [
        0x2C,
        {
            'Free': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Irp': [0x4, ['pointer', ['_IRP']]],
            'Notify': [0x8, ['pointer', ['_PO_DEVICE_NOTIFY']]],
            'Pending': [0xC, ['_LIST_ENTRY']],
            'Complete': [0x14, ['_LIST_ENTRY']],
            'Abort': [0x1C, ['_LIST_ENTRY']],
            'Failed': [0x24, ['_LIST_ENTRY']],
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
    '_PCI_HEADER_TYPE_1': [
        0x30,
        {
            'BaseAddresses': [0x0, ['array', 2, ['unsigned long']]],
            'PrimaryBus': [0x8, ['unsigned char']],
            'SecondaryBus': [0x9, ['unsigned char']],
            'SubordinateBus': [0xA, ['unsigned char']],
            'SecondaryLatency': [0xB, ['unsigned char']],
            'IOBase': [0xC, ['unsigned char']],
            'IOLimit': [0xD, ['unsigned char']],
            'SecondaryStatus': [0xE, ['unsigned short']],
            'MemoryBase': [0x10, ['unsigned short']],
            'MemoryLimit': [0x12, ['unsigned short']],
            'PrefetchBase': [0x14, ['unsigned short']],
            'PrefetchLimit': [0x16, ['unsigned short']],
            'PrefetchBaseUpper32': [0x18, ['unsigned long']],
            'PrefetchLimitUpper32': [0x1C, ['unsigned long']],
            'IOBaseUpper16': [0x20, ['unsigned short']],
            'IOLimitUpper16': [0x22, ['unsigned short']],
            'CapabilitiesPtr': [0x24, ['unsigned char']],
            'Reserved1': [0x25, ['array', 3, ['unsigned char']]],
            'ROMBaseAddress': [0x28, ['unsigned long']],
            'InterruptLine': [0x2C, ['unsigned char']],
            'InterruptPin': [0x2D, ['unsigned char']],
            'BridgeControl': [0x2E, ['unsigned short']],
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
            'Reserved': [0x3C, ['array', 6, ['unsigned long']]],
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
    '_SUPPORTED_RANGE': [
        0x20,
        {
            'Next': [0x0, ['pointer', ['_SUPPORTED_RANGE']]],
            'SystemAddressSpace': [0x4, ['unsigned long']],
            'SystemBase': [0x8, ['long long']],
            'Base': [0x10, ['long long']],
            'Limit': [0x18, ['long long']],
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
            'MaxNameLen': [0x34, ['unsigned long']],
            'MaxClassLen': [0x38, ['unsigned long']],
            'MaxValueNameLen': [0x3C, ['unsigned long']],
            'MaxValueDataLen': [0x40, ['unsigned long']],
            'WorkVar': [0x44, ['unsigned long']],
            'NameLength': [0x48, ['unsigned short']],
            'ClassLength': [0x4A, ['unsigned short']],
            'Name': [0x4C, ['array', 1, ['unsigned short']]],
        },
    ],
    '_ARBITER_ORDERING': [
        0x10,
        {
            'Start': [0x0, ['unsigned long long']],
            'End': [0x8, ['unsigned long long']],
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
                            16: 'MaximumInterfaceType',
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
    '_LPCP_NONPAGED_PORT_QUEUE': [
        0x18,
        {
            'Semaphore': [0x0, ['_KSEMAPHORE']],
            'BackPointer': [0x14, ['pointer', ['_LPCP_PORT_OBJECT']]],
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
    '_CM_KEY_REFERENCE': [
        0x8,
        {
            'KeyCell': [0x0, ['unsigned long']],
            'KeyHive': [0x4, ['pointer', ['_HHIVE']]],
        },
    ],
    '_ARBITER_ALTERNATIVE': [
        0x30,
        {
            'Minimum': [0x0, ['unsigned long long']],
            'Maximum': [0x8, ['unsigned long long']],
            'Length': [0x10, ['unsigned long']],
            'Alignment': [0x14, ['unsigned long']],
            'Priority': [0x18, ['long']],
            'Flags': [0x1C, ['unsigned long']],
            'Descriptor': [0x20, ['pointer', ['_IO_RESOURCE_DESCRIPTOR']]],
            'Reserved': [0x24, ['array', 3, ['unsigned long']]],
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
    '__unnamed_19ab': [
        0x8,
        {
            'EndingOffset': [0x0, ['pointer', ['_LARGE_INTEGER']]],
            'ResourceToRelease': [
                0x4,
                ['pointer', ['pointer', ['_ERESOURCE']]],
            ],
        },
    ],
    '__unnamed_19ad': [
        0x4,
        {
            'ResourceToRelease': [0x0, ['pointer', ['_ERESOURCE']]],
        },
    ],
    '__unnamed_19b1': [
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
    '__unnamed_19b3': [
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
            'AcquireForModifiedPageWriter': [0x0, ['__unnamed_19ab']],
            'ReleaseForModifiedPageWriter': [0x0, ['__unnamed_19ad']],
            'AcquireForSectionSynchronization': [0x0, ['__unnamed_19b1']],
            'Others': [0x0, ['__unnamed_19b3']],
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
    '_VI_POOL_ENTRY_INUSE': [
        0x10,
        {
            'VirtualAddress': [0x0, ['pointer', ['void']]],
            'CallingAddress': [0x4, ['pointer', ['void']]],
            'NumberOfBytes': [0x8, ['unsigned long']],
            'Tag': [0xC, ['unsigned long']],
        },
    ],
    '_CHILD_LIST': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['unsigned long']],
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
}
