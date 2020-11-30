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
    '__unnamed_1015': [
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
            'u': [0x0, ['__unnamed_1015']],
            'QuadPart': [0x0, ['unsigned long long']],
        },
    ],
    '_LIST_ENTRY': [
        0x10,
        {
            'Flink': [0x0, ['pointer64', ['_LIST_ENTRY']]],
            'Blink': [0x8, ['pointer64', ['_LIST_ENTRY']]],
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
    '__unnamed_1026': [
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
            'u': [0x0, ['__unnamed_1026']],
            'QuadPart': [0x0, ['long long']],
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
    '_KPRCB': [
        0x2480,
        {
            'MxCsr': [0x0, ['unsigned long']],
            'Number': [0x4, ['unsigned char']],
            'NestingLevel': [0x5, ['unsigned char']],
            'InterruptRequest': [0x6, ['unsigned char']],
            'IdleHalt': [0x7, ['unsigned char']],
            'CurrentThread': [0x8, ['pointer64', ['_KTHREAD']]],
            'NextThread': [0x10, ['pointer64', ['_KTHREAD']]],
            'IdleThread': [0x18, ['pointer64', ['_KTHREAD']]],
            'UserRsp': [0x20, ['unsigned long long']],
            'RspBase': [0x28, ['unsigned long long']],
            'PrcbLock': [0x30, ['unsigned long long']],
            'SetMember': [0x38, ['unsigned long long']],
            'ProcessorState': [0x40, ['_KPROCESSOR_STATE']],
            'CpuType': [0x5F0, ['unsigned char']],
            'CpuID': [0x5F1, ['unsigned char']],
            'CpuStep': [0x5F2, ['unsigned short']],
            'MHz': [0x5F4, ['unsigned long']],
            'HalReserved': [0x5F8, ['array', 8, ['unsigned long long']]],
            'MinorVersion': [0x638, ['unsigned short']],
            'MajorVersion': [0x63A, ['unsigned short']],
            'BuildType': [0x63C, ['unsigned char']],
            'CpuVendor': [0x63D, ['unsigned char']],
            'InitialApicId': [0x63E, ['unsigned char']],
            'LogicalProcessorsPerPhysicalProcessor': [
                0x63F,
                ['unsigned char'],
            ],
            'ApicMask': [0x640, ['unsigned long']],
            'CFlushSize': [0x644, ['unsigned char']],
            'PrcbPad0x': [0x645, ['array', 3, ['unsigned char']]],
            'AcpiReserved': [0x648, ['pointer64', ['void']]],
            'PrcbPad00': [0x650, ['array', 4, ['unsigned long long']]],
            'LockQueue': [0x670, ['array', 33, ['_KSPIN_LOCK_QUEUE']]],
            'PPLookasideList': [0x880, ['array', 16, ['_PP_LOOKASIDE_LIST']]],
            'PPNPagedLookasideList': [
                0x980,
                ['array', 32, ['_PP_LOOKASIDE_LIST']],
            ],
            'PPPagedLookasideList': [
                0xB80,
                ['array', 32, ['_PP_LOOKASIDE_LIST']],
            ],
            'PacketBarrier': [0xD80, ['unsigned long long']],
            'DeferredReadyListHead': [0xD88, ['_SINGLE_LIST_ENTRY']],
            'MmPageFaultCount': [0xD90, ['long']],
            'MmCopyOnWriteCount': [0xD94, ['long']],
            'MmTransitionCount': [0xD98, ['long']],
            'MmCacheTransitionCount': [0xD9C, ['long']],
            'MmDemandZeroCount': [0xDA0, ['long']],
            'MmPageReadCount': [0xDA4, ['long']],
            'MmPageReadIoCount': [0xDA8, ['long']],
            'MmCacheReadCount': [0xDAC, ['long']],
            'MmCacheIoCount': [0xDB0, ['long']],
            'MmDirtyPagesWriteCount': [0xDB4, ['long']],
            'MmDirtyWriteIoCount': [0xDB8, ['long']],
            'MmMappedPagesWriteCount': [0xDBC, ['long']],
            'MmMappedWriteIoCount': [0xDC0, ['long']],
            'LookasideIrpFloat': [0xDC4, ['long']],
            'KeSystemCalls': [0xDC8, ['unsigned long']],
            'IoReadOperationCount': [0xDCC, ['long']],
            'IoWriteOperationCount': [0xDD0, ['long']],
            'IoOtherOperationCount': [0xDD4, ['long']],
            'IoReadTransferCount': [0xDD8, ['_LARGE_INTEGER']],
            'IoWriteTransferCount': [0xDE0, ['_LARGE_INTEGER']],
            'IoOtherTransferCount': [0xDE8, ['_LARGE_INTEGER']],
            'KeContextSwitches': [0xDF0, ['unsigned long']],
            'PrcbPad2': [0xDF4, ['array', 12, ['unsigned char']]],
            'TargetSet': [0xE00, ['unsigned long long']],
            'IpiFrozen': [0xE08, ['unsigned long']],
            'PrcbPad3': [0xE0C, ['array', 116, ['unsigned char']]],
            'RequestMailbox': [0xE80, ['array', 64, ['_REQUEST_MAILBOX']]],
            'SenderSummary': [0x1E80, ['unsigned long long']],
            'PrcbPad4': [0x1E88, ['array', 120, ['unsigned char']]],
            'DpcData': [0x1F00, ['array', 2, ['_KDPC_DATA']]],
            'DpcStack': [0x1F40, ['pointer64', ['void']]],
            'SavedRsp': [0x1F48, ['pointer64', ['void']]],
            'MaximumDpcQueueDepth': [0x1F50, ['long']],
            'DpcRequestRate': [0x1F54, ['unsigned long']],
            'MinimumDpcRate': [0x1F58, ['unsigned long']],
            'DpcInterruptRequested': [0x1F5C, ['unsigned char']],
            'DpcThreadRequested': [0x1F5D, ['unsigned char']],
            'DpcRoutineActive': [0x1F5E, ['unsigned char']],
            'DpcThreadActive': [0x1F5F, ['unsigned char']],
            'TimerHand': [0x1F60, ['unsigned long long']],
            'TimerRequest': [0x1F60, ['unsigned long long']],
            'TickOffset': [0x1F68, ['long']],
            'MasterOffset': [0x1F6C, ['long']],
            'DpcLastCount': [0x1F70, ['unsigned long']],
            'ThreadDpcEnable': [0x1F74, ['unsigned char']],
            'QuantumEnd': [0x1F75, ['unsigned char']],
            'PrcbPad50': [0x1F76, ['unsigned char']],
            'IdleSchedule': [0x1F77, ['unsigned char']],
            'DpcSetEventRequest': [0x1F78, ['long']],
            'PrcbPad40': [0x1F7C, ['long']],
            'DpcThread': [0x1F80, ['pointer64', ['void']]],
            'DpcEvent': [0x1F88, ['_KEVENT']],
            'CallDpc': [0x1FA0, ['_KDPC']],
            'PrcbPad7': [0x1FE0, ['array', 4, ['unsigned long long']]],
            'WaitListHead': [0x2000, ['_LIST_ENTRY']],
            'ReadySummary': [0x2010, ['unsigned long']],
            'QueueIndex': [0x2014, ['unsigned long']],
            'DispatcherReadyListHead': [
                0x2018,
                ['array', 32, ['_LIST_ENTRY']],
            ],
            'InterruptCount': [0x2218, ['unsigned long']],
            'KernelTime': [0x221C, ['unsigned long']],
            'UserTime': [0x2220, ['unsigned long']],
            'DpcTime': [0x2224, ['unsigned long']],
            'InterruptTime': [0x2228, ['unsigned long']],
            'AdjustDpcThreshold': [0x222C, ['unsigned long']],
            'SkipTick': [0x2230, ['unsigned char']],
            'DebuggerSavedIRQL': [0x2231, ['unsigned char']],
            'PollSlot': [0x2232, ['unsigned char']],
            'PrcbPad8': [0x2233, ['array', 13, ['unsigned char']]],
            'ParentNode': [0x2240, ['pointer64', ['_KNODE']]],
            'MultiThreadProcessorSet': [0x2248, ['unsigned long long']],
            'MultiThreadSetMaster': [0x2250, ['pointer64', ['_KPRCB']]],
            'Sleeping': [0x2258, ['long']],
            'PrcbPad90': [0x225C, ['array', 1, ['unsigned long']]],
            'DebugDpcTime': [0x2260, ['unsigned long']],
            'PageColor': [0x2264, ['unsigned long']],
            'NodeColor': [0x2268, ['unsigned long']],
            'NodeShiftedColor': [0x226C, ['unsigned long']],
            'SecondaryColorMask': [0x2270, ['unsigned long']],
            'PrcbPad9': [0x2274, ['array', 12, ['unsigned char']]],
            'CcFastReadNoWait': [0x2280, ['unsigned long']],
            'CcFastReadWait': [0x2284, ['unsigned long']],
            'CcFastReadNotPossible': [0x2288, ['unsigned long']],
            'CcCopyReadNoWait': [0x228C, ['unsigned long']],
            'CcCopyReadWait': [0x2290, ['unsigned long']],
            'CcCopyReadNoWaitMiss': [0x2294, ['unsigned long']],
            'KeAlignmentFixupCount': [0x2298, ['unsigned long']],
            'KeDcacheFlushCount': [0x229C, ['unsigned long']],
            'KeExceptionDispatchCount': [0x22A0, ['unsigned long']],
            'KeFirstLevelTbFills': [0x22A4, ['unsigned long']],
            'KeFloatingEmulationCount': [0x22A8, ['unsigned long']],
            'KeIcacheFlushCount': [0x22AC, ['unsigned long']],
            'KeSecondLevelTbFills': [0x22B0, ['unsigned long']],
            'VendorString': [0x22B4, ['array', 13, ['unsigned char']]],
            'PrcbPad10': [0x22C1, ['array', 2, ['unsigned char']]],
            'FeatureBits': [0x22C4, ['unsigned long']],
            'UpdateSignature': [0x22C8, ['_LARGE_INTEGER']],
            'PowerState': [0x22D0, ['_PROCESSOR_POWER_STATE']],
            'Cache': [0x2440, ['array', 5, ['_CACHE_DESCRIPTOR']]],
            'CacheCount': [0x247C, ['unsigned long']],
        },
    ],
    '_SINGLE_LIST_ENTRY': [
        0x8,
        {
            'Next': [0x0, ['pointer64', ['_SINGLE_LIST_ENTRY']]],
        },
    ],
    '_KDPC': [
        0x40,
        {
            'Type': [0x0, ['unsigned char']],
            'Importance': [0x1, ['unsigned char']],
            'Number': [0x2, ['unsigned char']],
            'Expedite': [0x3, ['unsigned char']],
            'DpcListEntry': [0x8, ['_LIST_ENTRY']],
            'DeferredRoutine': [0x18, ['pointer64', ['void']]],
            'DeferredContext': [0x20, ['pointer64', ['void']]],
            'SystemArgument1': [0x28, ['pointer64', ['void']]],
            'SystemArgument2': [0x30, ['pointer64', ['void']]],
            'DpcData': [0x38, ['pointer64', ['void']]],
        },
    ],
    '_KERNEL_STACK_CONTROL': [
        0x200,
        {
            'XmmSaveArea': [0x0, ['_XMM_SAVE_AREA32']],
            'Fill': [0x0, ['array', 432, ['unsigned char']]],
            'Current': [0x1B0, ['_KERNEL_STACK_SEGMENT']],
            'Previous': [0x1D8, ['_KERNEL_STACK_SEGMENT']],
        },
    ],
    '_KTHREAD': [
        0x308,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'MutantListHead': [0x18, ['_LIST_ENTRY']],
            'InitialStack': [0x28, ['pointer64', ['void']]],
            'StackLimit': [0x30, ['pointer64', ['void']]],
            'KernelStack': [0x38, ['pointer64', ['void']]],
            'ThreadLock': [0x40, ['unsigned long long']],
            'ApcState': [0x48, ['_KAPC_STATE']],
            'ApcStateFill': [0x48, ['array', 43, ['unsigned char']]],
            'ApcQueueable': [0x73, ['unsigned char']],
            'NextProcessor': [0x74, ['unsigned char']],
            'DeferredProcessor': [0x75, ['unsigned char']],
            'AdjustReason': [0x76, ['unsigned char']],
            'AdjustIncrement': [0x77, ['unsigned char']],
            'ApcQueueLock': [0x78, ['unsigned long long']],
            'WaitStatus': [0x80, ['long long']],
            'WaitBlockList': [0x88, ['pointer64', ['_KWAIT_BLOCK']]],
            'GateObject': [0x88, ['pointer64', ['_KGATE']]],
            'Alertable': [0x90, ['unsigned char']],
            'WaitNext': [0x91, ['unsigned char']],
            'WaitReason': [0x92, ['unsigned char']],
            'Priority': [0x93, ['unsigned char']],
            'EnableStackSwap': [0x94, ['unsigned char']],
            'SwapBusy': [0x95, ['unsigned char']],
            'Alerted': [0x96, ['array', 2, ['unsigned char']]],
            'WaitListEntry': [0x98, ['_LIST_ENTRY']],
            'SwapListEntry': [0x98, ['_SINGLE_LIST_ENTRY']],
            'Queue': [0xA8, ['pointer64', ['_KQUEUE']]],
            'Teb': [0xB0, ['pointer64', ['void']]],
            'Timer': [0xB8, ['_KTIMER']],
            'TimerFill': [0xB8, ['array', 60, ['unsigned char']]],
            'AutoAlignment': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DisableBoost': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'GuiThread': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'ThreadFlags': [0xF4, ['long']],
            'WaitBlock': [0xF8, ['array', 4, ['_KWAIT_BLOCK']]],
            'WaitBlockFill0': [0xF8, ['array', 43, ['unsigned char']]],
            'SystemAffinityActive': [0x123, ['unsigned char']],
            'WaitBlockFill1': [0xF8, ['array', 91, ['unsigned char']]],
            'PreviousMode': [0x153, ['unsigned char']],
            'WaitBlockFill2': [0xF8, ['array', 139, ['unsigned char']]],
            'ResourceIndex': [0x183, ['unsigned char']],
            'WaitBlockFill3': [0xF8, ['array', 187, ['unsigned char']]],
            'LargeStack': [0x1B3, ['unsigned char']],
            'WaitBlockFill4': [0xF8, ['array', 44, ['unsigned char']]],
            'ContextSwitches': [0x124, ['unsigned long']],
            'WaitBlockFill5': [0xF8, ['array', 92, ['unsigned char']]],
            'State': [0x154, ['unsigned char']],
            'NpxState': [0x155, ['unsigned char']],
            'WaitIrql': [0x156, ['unsigned char']],
            'WaitMode': [0x157, ['unsigned char']],
            'WaitBlockFill6': [0xF8, ['array', 140, ['unsigned char']]],
            'WaitTime': [0x184, ['unsigned long']],
            'WaitBlockFill7': [0xF8, ['array', 188, ['unsigned char']]],
            'KernelApcDisable': [0x1B4, ['short']],
            'SpecialApcDisable': [0x1B6, ['short']],
            'CombinedApcDisable': [0x1B4, ['unsigned long']],
            'QueueListEntry': [0x1B8, ['_LIST_ENTRY']],
            'TrapFrame': [0x1C8, ['pointer64', ['_KTRAP_FRAME']]],
            'CallbackStack': [0x1D0, ['pointer64', ['void']]],
            'ApcStateIndex': [0x1D8, ['unsigned char']],
            'IdealProcessor': [0x1D9, ['unsigned char']],
            'Preempted': [0x1DA, ['unsigned char']],
            'ProcessReadyQueue': [0x1DB, ['unsigned char']],
            'KernelStackResident': [0x1DC, ['unsigned char']],
            'BasePriority': [0x1DD, ['unsigned char']],
            'PriorityDecrement': [0x1DE, ['unsigned char']],
            'Saturation': [0x1DF, ['unsigned char']],
            'UserAffinity': [0x1E0, ['unsigned long long']],
            'Process': [0x1E8, ['pointer64', ['_KPROCESS']]],
            'Affinity': [0x1F0, ['unsigned long long']],
            'ApcStatePointer': [
                0x1F8,
                ['array', 2, ['pointer64', ['_KAPC_STATE']]],
            ],
            'SavedApcState': [0x208, ['_KAPC_STATE']],
            'SavedApcStateFill': [0x208, ['array', 43, ['unsigned char']]],
            'FreezeCount': [0x233, ['unsigned char']],
            'SuspendCount': [0x234, ['unsigned char']],
            'UserIdealProcessor': [0x235, ['unsigned char']],
            'CalloutActive': [0x236, ['unsigned char']],
            'CodePatchInProgress': [0x237, ['unsigned char']],
            'Win32Thread': [0x238, ['pointer64', ['void']]],
            'StackBase': [0x240, ['pointer64', ['void']]],
            'SuspendApc': [0x248, ['_KAPC']],
            'SuspendApcFill0': [0x248, ['array', 1, ['unsigned char']]],
            'Quantum': [0x249, ['unsigned char']],
            'SuspendApcFill1': [0x248, ['array', 3, ['unsigned char']]],
            'QuantumReset': [0x24B, ['unsigned char']],
            'SuspendApcFill2': [0x248, ['array', 4, ['unsigned char']]],
            'KernelTime': [0x24C, ['unsigned long']],
            'SuspendApcFill3': [0x248, ['array', 64, ['unsigned char']]],
            'TlsArray': [0x288, ['pointer64', ['void']]],
            'SuspendApcFill4': [0x248, ['array', 72, ['unsigned char']]],
            'LegoData': [0x290, ['pointer64', ['void']]],
            'SuspendApcFill5': [0x248, ['array', 83, ['unsigned char']]],
            'PowerState': [0x29B, ['unsigned char']],
            'UserTime': [0x29C, ['unsigned long']],
            'SuspendSemaphore': [0x2A0, ['_KSEMAPHORE']],
            'SuspendSemaphorefill': [0x2A0, ['array', 28, ['unsigned char']]],
            'SListFaultCount': [0x2BC, ['unsigned long']],
            'ThreadListEntry': [0x2C0, ['_LIST_ENTRY']],
            'SListFaultAddress': [0x2D0, ['pointer64', ['void']]],
            'ReadOperationCount': [0x2D8, ['long long']],
            'WriteOperationCount': [0x2E0, ['long long']],
            'OtherOperationCount': [0x2E8, ['long long']],
            'ReadTransferCount': [0x2F0, ['long long']],
            'WriteTransferCount': [0x2F8, ['long long']],
            'OtherTransferCount': [0x300, ['long long']],
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
    '_FAST_MUTEX': [
        0x38,
        {
            'Count': [0x0, ['long']],
            'Owner': [0x8, ['pointer64', ['_KTHREAD']]],
            'Contention': [0x10, ['unsigned long']],
            'Gate': [0x18, ['_KEVENT']],
            'OldIrql': [0x30, ['unsigned long']],
        },
    ],
    '_SLIST_HEADER': [
        0x10,
        {
            'Alignment': [0x0, ['unsigned long long']],
            'Region': [0x8, ['unsigned long long']],
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
    '_GENERAL_LOOKASIDE': [
        0x80,
        {
            'ListHead': [0x0, ['_SLIST_HEADER']],
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
            'Allocate': [0x30, ['pointer64', ['void']]],
            'Free': [0x38, ['pointer64', ['void']]],
            'ListEntry': [0x40, ['_LIST_ENTRY']],
            'LastTotalAllocates': [0x50, ['unsigned long']],
            'LastAllocateMisses': [0x54, ['unsigned long']],
            'LastAllocateHits': [0x54, ['unsigned long']],
            'Future': [0x58, ['array', 2, ['unsigned long']]],
        },
    ],
    '_QUAD': [
        0x8,
        {
            'UseThisFieldToCopy': [0x0, ['long long']],
            'DoNotUseThisField': [0x0, ['double']],
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
    '_IO_STATUS_BLOCK': [
        0x10,
        {
            'Status': [0x0, ['long']],
            'Pointer': [0x0, ['pointer64', ['void']]],
            'Information': [0x8, ['unsigned long long']],
        },
    ],
    '_EX_RUNDOWN_REF': [
        0x8,
        {
            'Count': [0x0, ['unsigned long long']],
            'Ptr': [0x0, ['pointer64', ['void']]],
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
    '_EX_PUSH_LOCK_WAIT_BLOCK': [
        0x40,
        {
            'WakeGate': [0x0, ['_KGATE']],
            'WakeEvent': [0x0, ['_KEVENT']],
            'Next': [0x18, ['pointer64', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'Last': [0x20, ['pointer64', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'Previous': [0x28, ['pointer64', ['_EX_PUSH_LOCK_WAIT_BLOCK']]],
            'ShareCount': [0x30, ['long']],
            'Flags': [0x34, ['long']],
        },
    ],
    '_EX_PUSH_LOCK_CACHE_AWARE': [
        0x100,
        {
            'Locks': [0x0, ['array', 32, ['pointer64', ['_EX_PUSH_LOCK']]]],
        },
    ],
    '_ETHREAD': [
        0x410,
        {
            'Tcb': [0x0, ['_KTHREAD']],
            'CreateTime': [0x308, ['_LARGE_INTEGER']],
            'ExitTime': [0x310, ['_LARGE_INTEGER']],
            'LpcReplyChain': [0x310, ['_LIST_ENTRY']],
            'KeyedWaitChain': [0x310, ['_LIST_ENTRY']],
            'ExitStatus': [0x320, ['long']],
            'OfsChain': [0x320, ['pointer64', ['void']]],
            'PostBlockList': [0x328, ['_LIST_ENTRY']],
            'TerminationPort': [0x338, ['pointer64', ['_TERMINATION_PORT']]],
            'ReaperLink': [0x338, ['pointer64', ['_ETHREAD']]],
            'KeyedWaitValue': [0x338, ['pointer64', ['void']]],
            'ActiveTimerListLock': [0x340, ['unsigned long long']],
            'ActiveTimerListHead': [0x348, ['_LIST_ENTRY']],
            'Cid': [0x358, ['_CLIENT_ID']],
            'LpcReplySemaphore': [0x368, ['_KSEMAPHORE']],
            'KeyedWaitSemaphore': [0x368, ['_KSEMAPHORE']],
            'LpcReplyMessage': [0x388, ['pointer64', ['void']]],
            'LpcWaitingOnPort': [0x388, ['pointer64', ['void']]],
            'ImpersonationInfo': [
                0x390,
                ['pointer64', ['_PS_IMPERSONATION_INFORMATION']],
            ],
            'IrpList': [0x398, ['_LIST_ENTRY']],
            'TopLevelIrp': [0x3A8, ['unsigned long long']],
            'DeviceToVerify': [0x3B0, ['pointer64', ['_DEVICE_OBJECT']]],
            'ThreadsProcess': [0x3B8, ['pointer64', ['_EPROCESS']]],
            'StartAddress': [0x3C0, ['pointer64', ['void']]],
            'Win32StartAddress': [0x3C8, ['pointer64', ['void']]],
            'LpcReceivedMessageId': [0x3C8, ['unsigned long']],
            'ThreadListEntry': [0x3D0, ['_LIST_ENTRY']],
            'RundownProtect': [0x3E0, ['_EX_RUNDOWN_REF']],
            'ThreadLock': [0x3E8, ['_EX_PUSH_LOCK']],
            'LpcReplyMessageId': [0x3F0, ['unsigned long']],
            'ReadClusterSize': [0x3F4, ['unsigned long']],
            'GrantedAccess': [0x3F8, ['unsigned long']],
            'CrossThreadFlags': [0x3FC, ['unsigned long']],
            'Terminated': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'DeadThread': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HideFromDebugger': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ActiveImpersonationInfo': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SystemThread': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'HardErrorsAreDisabled': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'BreakOnTermination': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SkipCreationMsg': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SkipTerminationMsg': [
                0x3FC,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'SameThreadPassiveFlags': [0x400, ['unsigned long']],
            'ActiveExWorker': [
                0x400,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ExWorkerCanWaitUser': [
                0x400,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'MemoryMaker': [
                0x400,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'KeyedEventInUse': [
                0x400,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SameThreadApcFlags': [0x404, ['unsigned long']],
            'LpcReceivedMsgIdValid': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'LpcExitThreadCalled': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'AddressSpaceOwner': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetExclusive': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetShared': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemWorkingSetExclusive': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemWorkingSetShared': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetExclusive': [
                0x404,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetShared': [
                0x405,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ApcNeeded': [
                0x405,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'ForwardClusterOnly': [0x408, ['unsigned char']],
            'DisablePageFaultClustering': [0x409, ['unsigned char']],
            'ActiveFaultCount': [0x40A, ['unsigned char']],
        },
    ],
    '_EPROCESS': [
        0x3E0,
        {
            'Pcb': [0x0, ['_KPROCESS']],
            'ProcessLock': [0xB8, ['_EX_PUSH_LOCK']],
            'CreateTime': [0xC0, ['_LARGE_INTEGER']],
            'ExitTime': [0xC8, ['_LARGE_INTEGER']],
            'RundownProtect': [0xD0, ['_EX_RUNDOWN_REF']],
            'UniqueProcessId': [0xD8, ['pointer64', ['void']]],
            'ActiveProcessLinks': [0xE0, ['_LIST_ENTRY']],
            'QuotaUsage': [0xF0, ['array', 3, ['unsigned long long']]],
            'QuotaPeak': [0x108, ['array', 3, ['unsigned long long']]],
            'CommitCharge': [0x120, ['unsigned long long']],
            'PeakVirtualSize': [0x128, ['unsigned long long']],
            'VirtualSize': [0x130, ['unsigned long long']],
            'SessionProcessLinks': [0x138, ['_LIST_ENTRY']],
            'DebugPort': [0x148, ['pointer64', ['void']]],
            'ExceptionPort': [0x150, ['pointer64', ['void']]],
            'ObjectTable': [0x158, ['pointer64', ['_HANDLE_TABLE']]],
            'Token': [0x160, ['_EX_FAST_REF']],
            'WorkingSetPage': [0x168, ['unsigned long long']],
            'AddressCreationLock': [0x170, ['_KGUARDED_MUTEX']],
            'HyperSpaceLock': [0x1A8, ['unsigned long long']],
            'ForkInProgress': [0x1B0, ['pointer64', ['_ETHREAD']]],
            'HardwareTrigger': [0x1B8, ['unsigned long long']],
            'PhysicalVadRoot': [0x1C0, ['pointer64', ['_MM_AVL_TABLE']]],
            'CloneRoot': [0x1C8, ['pointer64', ['void']]],
            'NumberOfPrivatePages': [0x1D0, ['unsigned long long']],
            'NumberOfLockedPages': [0x1D8, ['unsigned long long']],
            'Win32Process': [0x1E0, ['pointer64', ['void']]],
            'Job': [0x1E8, ['pointer64', ['_EJOB']]],
            'SectionObject': [0x1F0, ['pointer64', ['void']]],
            'SectionBaseAddress': [0x1F8, ['pointer64', ['void']]],
            'QuotaBlock': [0x200, ['pointer64', ['_EPROCESS_QUOTA_BLOCK']]],
            'WorkingSetWatch': [0x208, ['pointer64', ['_PAGEFAULT_HISTORY']]],
            'Win32WindowStation': [0x210, ['pointer64', ['void']]],
            'InheritedFromUniqueProcessId': [0x218, ['pointer64', ['void']]],
            'LdtInformation': [0x220, ['pointer64', ['void']]],
            'VadFreeHint': [0x228, ['pointer64', ['void']]],
            'VdmObjects': [0x230, ['pointer64', ['void']]],
            'DeviceMap': [0x238, ['pointer64', ['void']]],
            'Spare0': [0x240, ['array', 3, ['pointer64', ['void']]]],
            'PageDirectoryPte': [0x258, ['_HARDWARE_PTE']],
            'Filler': [0x258, ['unsigned long long']],
            'Session': [0x260, ['pointer64', ['void']]],
            'ImageFileName': [0x268, ['array', 16, ['unsigned char']]],
            'JobLinks': [0x278, ['_LIST_ENTRY']],
            'LockedPagesList': [0x288, ['pointer64', ['void']]],
            'ThreadListHead': [0x290, ['_LIST_ENTRY']],
            'SecurityPort': [0x2A0, ['pointer64', ['void']]],
            'Wow64Process': [0x2A8, ['pointer64', ['_WOW64_PROCESS']]],
            'ActiveThreads': [0x2B0, ['unsigned long']],
            'GrantedAccess': [0x2B4, ['unsigned long']],
            'DefaultHardErrorProcessing': [0x2B8, ['unsigned long']],
            'LastThreadExitStatus': [0x2BC, ['long']],
            'Peb': [0x2C0, ['pointer64', ['_PEB']]],
            'PrefetchTrace': [0x2C8, ['_EX_FAST_REF']],
            'ReadOperationCount': [0x2D0, ['_LARGE_INTEGER']],
            'WriteOperationCount': [0x2D8, ['_LARGE_INTEGER']],
            'OtherOperationCount': [0x2E0, ['_LARGE_INTEGER']],
            'ReadTransferCount': [0x2E8, ['_LARGE_INTEGER']],
            'WriteTransferCount': [0x2F0, ['_LARGE_INTEGER']],
            'OtherTransferCount': [0x2F8, ['_LARGE_INTEGER']],
            'CommitChargeLimit': [0x300, ['unsigned long long']],
            'CommitChargePeak': [0x308, ['unsigned long long']],
            'AweInfo': [0x310, ['pointer64', ['void']]],
            'SeAuditProcessCreationInfo': [
                0x318,
                ['_SE_AUDIT_PROCESS_CREATION_INFO'],
            ],
            'Vm': [0x320, ['_MMSUPPORT']],
            'Spares': [0x378, ['array', 2, ['unsigned long']]],
            'ModifiedPageCount': [0x380, ['unsigned long']],
            'JobStatus': [0x384, ['unsigned long']],
            'Flags': [0x388, ['unsigned long']],
            'CreateReported': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoDebugInherit': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessExiting': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessDelete': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow64SplitPages': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'VmDeleted': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'OutswapEnabled': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Outswapped': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ForkFailed': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Wow64VaSpace4Gb': [
                0x388,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'AddressSpaceInitialized': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolution': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'BreakOnTermination': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'SessionCreationUnderway': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteWatch': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInSession': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'OverrideAddressSpace': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'HasAddressSpace': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'LaunchPrefetched': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'InjectInpageErrors': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'VmTopDown': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageNotifyDone': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'PdeUpdateNeeded': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'VdmAllowed': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'SmapAllowed': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'CreateFailed': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultIoPriority': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare1': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'Spare2': [
                0x388,
                [
                    'BitField',
                    dict(
                        start_bit=31, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ExitStatus': [0x38C, ['long']],
            'NextPageColor': [0x390, ['unsigned short']],
            'SubSystemMinorVersion': [0x392, ['unsigned char']],
            'SubSystemMajorVersion': [0x393, ['unsigned char']],
            'SubSystemVersion': [0x392, ['unsigned short']],
            'PriorityClass': [0x394, ['unsigned char']],
            'VadRoot': [0x398, ['_MM_AVL_TABLE']],
            'Cookie': [0x3D8, ['unsigned long']],
        },
    ],
    '_OBJECT_HEADER': [
        0x38,
        {
            'PointerCount': [0x0, ['long long']],
            'HandleCount': [0x8, ['long long']],
            'NextToFree': [0x8, ['pointer64', ['void']]],
            'Type': [0x10, ['pointer64', ['_OBJECT_TYPE']]],
            'NameInfoOffset': [0x18, ['unsigned char']],
            'HandleInfoOffset': [0x19, ['unsigned char']],
            'QuotaInfoOffset': [0x1A, ['unsigned char']],
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
            'ExclusiveProcess': [0x10, ['pointer64', ['_EPROCESS']]],
            'Reserved': [0x18, ['unsigned long long']],
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
            'QueryReferences': [0x18, ['unsigned long']],
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
    '_OBJECT_TYPE': [
        0x2C0,
        {
            'Mutex': [0x0, ['_ERESOURCE']],
            'TypeList': [0x68, ['_LIST_ENTRY']],
            'Name': [0x78, ['_UNICODE_STRING']],
            'DefaultObject': [0x88, ['pointer64', ['void']]],
            'Index': [0x90, ['unsigned long']],
            'TotalNumberOfObjects': [0x94, ['unsigned long']],
            'TotalNumberOfHandles': [0x98, ['unsigned long']],
            'HighWaterNumberOfObjects': [0x9C, ['unsigned long']],
            'HighWaterNumberOfHandles': [0xA0, ['unsigned long']],
            'TypeInfo': [0xA8, ['_OBJECT_TYPE_INITIALIZER']],
            'Key': [0x118, ['unsigned long']],
            'ObjectLocks': [0x120, ['array', 4, ['_ERESOURCE']]],
        },
    ],
    '_OBJECT_HANDLE_INFORMATION': [
        0x8,
        {
            'HandleAttributes': [0x0, ['unsigned long']],
            'GrantedAccess': [0x4, ['unsigned long']],
        },
    ],
    '_PERFINFO_GROUPMASK': [
        0x20,
        {
            'Masks': [0x0, ['array', 8, ['unsigned long']]],
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
    '__unnamed_115f': [
        0x8,
        {
            'Long': [0x0, ['unsigned long long']],
            'Hard': [0x0, ['_MMPTE_HARDWARE']],
            'HardLarge': [0x0, ['_MMPTE_HARDWARE_LARGEPAGE']],
            'Flush': [0x0, ['_HARDWARE_PTE']],
            'Proto': [0x0, ['_MMPTE_PROTOTYPE']],
            'Soft': [0x0, ['_MMPTE_SOFTWARE']],
            'Trans': [0x0, ['_MMPTE_TRANSITION']],
            'Subsect': [0x0, ['_MMPTE_SUBSECTION']],
            'List': [0x0, ['_MMPTE_LIST']],
        },
    ],
    '_MMPTE': [
        0x8,
        {
            'u': [0x0, ['__unnamed_115f']],
        },
    ],
    '__unnamed_116a': [
        0x8,
        {
            'Flink': [0x0, ['unsigned long long']],
            'WsIndex': [0x0, ['unsigned long']],
            'Event': [0x0, ['pointer64', ['_KEVENT']]],
            'ReadStatus': [0x0, ['long']],
            'NextStackPfn': [0x0, ['_SINGLE_LIST_ENTRY']],
        },
    ],
    '__unnamed_116c': [
        0x8,
        {
            'Blink': [0x0, ['unsigned long long']],
            'ShareCount': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_116f': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'ShortFlags': [0x2, ['unsigned short']],
        },
    ],
    '__unnamed_1171': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'e1': [0x2, ['_MMPFNENTRY']],
            'e2': [0x0, ['__unnamed_116f']],
        },
    ],
    '__unnamed_1179': [
        0x8,
        {
            'EntireFrame': [0x0, ['unsigned long long']],
            'PteFrame': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=57,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'InPageError': [
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
            'VerifierAllocation': [
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
            'AweAllocation': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=59,
                        end_bit=60,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Priority': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=60,
                        end_bit=63,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'MustBeCached': [
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
    '_MMPFN': [
        0x30,
        {
            'u1': [0x0, ['__unnamed_116a']],
            'PteAddress': [0x8, ['pointer64', ['_MMPTE']]],
            'u2': [0x10, ['__unnamed_116c']],
            'u3': [0x18, ['__unnamed_1171']],
            'UsedPageTableEntries': [0x1C, ['unsigned long']],
            'OriginalPte': [0x20, ['_MMPTE']],
            'AweReferenceCount': [0x20, ['long']],
            'u4': [0x28, ['__unnamed_1179']],
        },
    ],
    '__unnamed_1180': [
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
    '__unnamed_1183': [
        0x8,
        {
            'LongFlags': [0x0, ['unsigned long long']],
            'VadFlags': [0x0, ['_MMVAD_FLAGS']],
        },
    ],
    '__unnamed_1188': [
        0x4,
        {
            'LongFlags2': [0x0, ['unsigned long']],
            'VadFlags2': [0x0, ['_MMVAD_FLAGS2']],
        },
    ],
    '_MMVAD': [
        0x50,
        {
            'u1': [0x0, ['__unnamed_1180']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_1183']],
            'ControlArea': [0x30, ['pointer64', ['_CONTROL_AREA']]],
            'FirstPrototypePte': [0x38, ['pointer64', ['_MMPTE']]],
            'LastContiguousPte': [0x40, ['pointer64', ['_MMPTE']]],
            'u2': [0x48, ['__unnamed_1188']],
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
    '_MMPTE_FLUSH_LIST': [
        0xA8,
        {
            'Count': [0x0, ['unsigned long']],
            'FlushVa': [0x8, ['array', 20, ['pointer64', ['void']]]],
        },
    ],
    '__unnamed_119a': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'SubsectionFlags': [0x0, ['_MMSUBSECTION_FLAGS']],
        },
    ],
    '_SUBSECTION': [
        0x30,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'u': [0x8, ['__unnamed_119a']],
            'StartingSector': [0xC, ['unsigned long']],
            'NumberOfFullSectors': [0x10, ['unsigned long']],
            'SubsectionBase': [0x18, ['pointer64', ['_MMPTE']]],
            'UnusedPtes': [0x20, ['unsigned long']],
            'PtesInSubsection': [0x24, ['unsigned long']],
            'NextSubsection': [0x28, ['pointer64', ['_SUBSECTION']]],
        },
    ],
    '_MMPAGING_FILE': [
        0x78,
        {
            'Size': [0x0, ['unsigned long long']],
            'MaximumSize': [0x8, ['unsigned long long']],
            'MinimumSize': [0x10, ['unsigned long long']],
            'FreeSpace': [0x18, ['unsigned long long']],
            'CurrentUsage': [0x20, ['unsigned long long']],
            'PeakUsage': [0x28, ['unsigned long long']],
            'HighestPage': [0x30, ['unsigned long long']],
            'File': [0x38, ['pointer64', ['_FILE_OBJECT']]],
            'Entry': [
                0x40,
                ['array', 2, ['pointer64', ['_MMMOD_WRITER_MDL_ENTRY']]],
            ],
            'PageFileName': [0x50, ['_UNICODE_STRING']],
            'Bitmap': [0x60, ['pointer64', ['_RTL_BITMAP']]],
            'PageFileNumber': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ReferenceCount': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'BootPartition': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'FileHandle': [0x70, ['pointer64', ['void']]],
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
    '_KTIMER': [
        0x40,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'DueTime': [0x18, ['_ULARGE_INTEGER']],
            'TimerListEntry': [0x20, ['_LIST_ENTRY']],
            'Dpc': [0x30, ['pointer64', ['_KDPC']]],
            'Period': [0x38, ['long']],
        },
    ],
    '_KEVENT': [
        0x18,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '_KLOCK_QUEUE_HANDLE': [
        0x18,
        {
            'LockQueue': [0x0, ['_KSPIN_LOCK_QUEUE']],
            'OldIrql': [0x10, ['unsigned char']],
        },
    ],
    '_KSPIN_LOCK_QUEUE': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_KSPIN_LOCK_QUEUE']]],
            'Lock': [0x8, ['pointer64', ['unsigned long long']]],
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
    '_KWAIT_BLOCK': [
        0x30,
        {
            'WaitListEntry': [0x0, ['_LIST_ENTRY']],
            'Thread': [0x10, ['pointer64', ['_KTHREAD']]],
            'Object': [0x18, ['pointer64', ['void']]],
            'NextWaitBlock': [0x20, ['pointer64', ['_KWAIT_BLOCK']]],
            'WaitKey': [0x28, ['unsigned short']],
            'WaitType': [0x2A, ['unsigned char']],
            'SpareByte': [0x2B, ['unsigned char']],
            'SpareLong': [0x2C, ['long']],
        },
    ],
    '_KTIMER_TABLE_ENTRY': [
        0x18,
        {
            'Entry': [0x0, ['_LIST_ENTRY']],
            'Time': [0x10, ['_ULARGE_INTEGER']],
        },
    ],
    '_KPROCESS': [
        0xB8,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'ProfileListHead': [0x18, ['_LIST_ENTRY']],
            'DirectoryTableBase': [0x28, ['array', 2, ['unsigned long long']]],
            'IopmOffset': [0x38, ['unsigned short']],
            'ActiveProcessors': [0x40, ['unsigned long long']],
            'KernelTime': [0x48, ['unsigned long']],
            'UserTime': [0x4C, ['unsigned long']],
            'ReadyListHead': [0x50, ['_LIST_ENTRY']],
            'SwapListEntry': [0x60, ['_SINGLE_LIST_ENTRY']],
            'Reserved1': [0x68, ['pointer64', ['void']]],
            'ThreadListHead': [0x70, ['_LIST_ENTRY']],
            'ProcessLock': [0x80, ['unsigned long long']],
            'Affinity': [0x88, ['unsigned long long']],
            'AutoAlignment': [
                0x90,
                ['BitField', dict(start_bit=0, end_bit=1, native_type='long')],
            ],
            'DisableBoost': [
                0x90,
                ['BitField', dict(start_bit=1, end_bit=2, native_type='long')],
            ],
            'DisableQuantum': [
                0x90,
                ['BitField', dict(start_bit=2, end_bit=3, native_type='long')],
            ],
            'ReservedFlags': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='long'),
                ],
            ],
            'ProcessFlags': [0x90, ['long']],
            'BasePriority': [0x94, ['unsigned char']],
            'QuantumReset': [0x95, ['unsigned char']],
            'State': [0x96, ['unsigned char']],
            'ThreadSeed': [0x97, ['unsigned char']],
            'PowerState': [0x98, ['unsigned char']],
            'IdealNode': [0x99, ['unsigned char']],
            'Visited': [0x9A, ['unsigned char']],
            'Flags': [0x9B, ['_KEXECUTE_OPTIONS']],
            'ExecuteOptions': [0x9B, ['unsigned char']],
            'StackCount': [0xA0, ['unsigned long long']],
            'ProcessListEntry': [0xA8, ['_LIST_ENTRY']],
        },
    ],
    '_KEXCEPTION_FRAME': [
        0x180,
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
            'ExceptionRecord': [0xF0, ['array', 64, ['unsigned char']]],
            'MxCsr': [0x130, ['unsigned long long']],
            'Rbp': [0x138, ['unsigned long long']],
            'Rbx': [0x140, ['unsigned long long']],
            'Rdi': [0x148, ['unsigned long long']],
            'Rsi': [0x150, ['unsigned long long']],
            'R12': [0x158, ['unsigned long long']],
            'R13': [0x160, ['unsigned long long']],
            'R14': [0x168, ['unsigned long long']],
            'R15': [0x170, ['unsigned long long']],
            'Return': [0x178, ['unsigned long long']],
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
            'TimeStamp': [0xD0, ['unsigned long long']],
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
            'Rip': [0x168, ['unsigned long long']],
            'SegCs': [0x170, ['unsigned short']],
            'Fill1': [0x172, ['array', 3, ['unsigned short']]],
            'EFlags': [0x178, ['unsigned long']],
            'Fill2': [0x17C, ['unsigned long']],
            'Rsp': [0x180, ['unsigned long long']],
            'SegSs': [0x188, ['unsigned short']],
            'Fill3': [0x18A, ['array', 1, ['unsigned short']]],
            'CodePatchCycle': [0x18C, ['long']],
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
    '__unnamed_1240': [
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
            'u': [0x10, ['__unnamed_1240']],
        },
    ],
    '__unnamed_1247': [
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
            'u': [0xC, ['__unnamed_1247']],
        },
    ],
    '_SHARED_CACHE_MAP': [
        0x1B8,
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
            'FileObject': [0x60, ['pointer64', ['_FILE_OBJECT']]],
            'ActiveVacb': [0x68, ['pointer64', ['_VACB']]],
            'NeedToZero': [0x70, ['pointer64', ['void']]],
            'ActivePage': [0x78, ['unsigned long']],
            'NeedToZeroPage': [0x7C, ['unsigned long']],
            'ActiveVacbSpinLock': [0x80, ['unsigned long long']],
            'VacbActiveCount': [0x88, ['unsigned long']],
            'DirtyPages': [0x8C, ['unsigned long']],
            'SharedCacheMapLinks': [0x90, ['_LIST_ENTRY']],
            'Flags': [0xA0, ['unsigned long']],
            'Status': [0xA4, ['long']],
            'Mbcb': [0xA8, ['pointer64', ['_MBCB']]],
            'Section': [0xB0, ['pointer64', ['void']]],
            'CreateEvent': [0xB8, ['pointer64', ['_KEVENT']]],
            'WaitOnActiveCount': [0xC0, ['pointer64', ['_KEVENT']]],
            'PagesToWrite': [0xC8, ['unsigned long']],
            'BeyondLastFlush': [0xD0, ['long long']],
            'Callbacks': [0xD8, ['pointer64', ['_CACHE_MANAGER_CALLBACKS']]],
            'LazyWriteContext': [0xE0, ['pointer64', ['void']]],
            'PrivateList': [0xE8, ['_LIST_ENTRY']],
            'LogHandle': [0xF8, ['pointer64', ['void']]],
            'FlushToLsnRoutine': [0x100, ['pointer64', ['void']]],
            'DirtyPageThreshold': [0x108, ['unsigned long']],
            'LazyWritePassCount': [0x10C, ['unsigned long']],
            'UninitializeEvent': [
                0x110,
                ['pointer64', ['_CACHE_UNINITIALIZE_EVENT']],
            ],
            'NeedToZeroVacb': [0x118, ['pointer64', ['_VACB']]],
            'BcbSpinLock': [0x120, ['unsigned long long']],
            'Reserved': [0x128, ['pointer64', ['void']]],
            'Event': [0x130, ['_KEVENT']],
            'VacbPushLock': [0x148, ['_EX_PUSH_LOCK']],
            'PrivateCacheMap': [0x150, ['_PRIVATE_CACHE_MAP']],
            'WriteBehindWorkQueueEntry': [0x1B0, ['pointer64', ['void']]],
        },
    ],
    '_FILE_OBJECT': [
        0xB8,
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
        },
    ],
    '__unnamed_126d': [
        0x8,
        {
            'FileOffset': [0x0, ['_LARGE_INTEGER']],
            'ActiveCount': [0x0, ['unsigned short']],
        },
    ],
    '_VACB': [
        0x28,
        {
            'BaseAddress': [0x0, ['pointer64', ['void']]],
            'SharedCacheMap': [0x8, ['pointer64', ['_SHARED_CACHE_MAP']]],
            'Overlay': [0x10, ['__unnamed_126d']],
            'LruList': [0x18, ['_LIST_ENTRY']],
        },
    ],
    '_VACB_LEVEL_REFERENCE': [
        0x8,
        {
            'Reference': [0x0, ['long']],
            'SpecialReference': [0x4, ['long']],
        },
    ],
    '__unnamed_1282': [
        0x10,
        {
            'FreeListsInUseUlong': [0x0, ['array', 4, ['unsigned long']]],
            'FreeListsInUseBytes': [0x0, ['array', 16, ['unsigned char']]],
        },
    ],
    '__unnamed_1284': [
        0x2,
        {
            'FreeListsInUseTerminate': [0x0, ['unsigned short']],
            'DecommitCount': [0x0, ['unsigned short']],
        },
    ],
    '_HEAP': [
        0xAE8,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'Signature': [0x10, ['unsigned long']],
            'Flags': [0x14, ['unsigned long']],
            'ForceFlags': [0x18, ['unsigned long']],
            'VirtualMemoryThreshold': [0x1C, ['unsigned long']],
            'SegmentReserve': [0x20, ['unsigned long long']],
            'SegmentCommit': [0x28, ['unsigned long long']],
            'DeCommitFreeBlockThreshold': [0x30, ['unsigned long long']],
            'DeCommitTotalFreeThreshold': [0x38, ['unsigned long long']],
            'TotalFreeSize': [0x40, ['unsigned long long']],
            'MaximumAllocationSize': [0x48, ['unsigned long long']],
            'ProcessHeapsListIndex': [0x50, ['unsigned short']],
            'HeaderValidateLength': [0x52, ['unsigned short']],
            'HeaderValidateCopy': [0x58, ['pointer64', ['void']]],
            'NextAvailableTagIndex': [0x60, ['unsigned short']],
            'MaximumTagIndex': [0x62, ['unsigned short']],
            'TagEntries': [0x68, ['pointer64', ['_HEAP_TAG_ENTRY']]],
            'UCRSegments': [0x70, ['pointer64', ['_HEAP_UCR_SEGMENT']]],
            'UnusedUnCommittedRanges': [
                0x78,
                ['pointer64', ['_HEAP_UNCOMMMTTED_RANGE']],
            ],
            'AlignRound': [0x80, ['unsigned long long']],
            'AlignMask': [0x88, ['unsigned long long']],
            'VirtualAllocdBlocks': [0x90, ['_LIST_ENTRY']],
            'Segments': [
                0xA0,
                ['array', 64, ['pointer64', ['_HEAP_SEGMENT']]],
            ],
            'u': [0x2A0, ['__unnamed_1282']],
            'u2': [0x2B0, ['__unnamed_1284']],
            'AllocatorBackTraceIndex': [0x2B2, ['unsigned short']],
            'NonDedicatedListLength': [0x2B4, ['unsigned long']],
            'LargeBlocksIndex': [0x2B8, ['pointer64', ['void']]],
            'PseudoTagEntries': [
                0x2C0,
                ['pointer64', ['_HEAP_PSEUDO_TAG_ENTRY']],
            ],
            'FreeLists': [0x2C8, ['array', 128, ['_LIST_ENTRY']]],
            'LockVariable': [0xAC8, ['pointer64', ['_HEAP_LOCK']]],
            'CommitRoutine': [0xAD0, ['pointer64', ['void']]],
            'FrontEndHeap': [0xAD8, ['pointer64', ['void']]],
            'FrontHeapLockCount': [0xAE0, ['unsigned short']],
            'FrontEndHeapType': [0xAE2, ['unsigned char']],
            'LastSegmentIndex': [0xAE3, ['unsigned char']],
        },
    ],
    '_HEAP_ENTRY': [
        0x10,
        {
            'PreviousBlockPrivateData': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned short']],
            'PreviousSize': [0xA, ['unsigned short']],
            'SmallTagIndex': [0xC, ['unsigned char']],
            'Flags': [0xD, ['unsigned char']],
            'UnusedBytes': [0xE, ['unsigned char']],
            'SegmentIndex': [0xF, ['unsigned char']],
            'CompactHeader': [0x8, ['unsigned long long']],
        },
    ],
    '_HEAP_SEGMENT': [
        0x68,
        {
            'Entry': [0x0, ['_HEAP_ENTRY']],
            'Signature': [0x10, ['unsigned long']],
            'Flags': [0x14, ['unsigned long']],
            'Heap': [0x18, ['pointer64', ['_HEAP']]],
            'LargestUnCommittedRange': [0x20, ['unsigned long long']],
            'BaseAddress': [0x28, ['pointer64', ['void']]],
            'NumberOfPages': [0x30, ['unsigned long']],
            'FirstEntry': [0x38, ['pointer64', ['_HEAP_ENTRY']]],
            'LastValidEntry': [0x40, ['pointer64', ['_HEAP_ENTRY']]],
            'NumberOfUnCommittedPages': [0x48, ['unsigned long']],
            'NumberOfUnCommittedRanges': [0x4C, ['unsigned long']],
            'UnCommittedRanges': [
                0x50,
                ['pointer64', ['_HEAP_UNCOMMMTTED_RANGE']],
            ],
            'AllocatorBackTraceIndex': [0x58, ['unsigned short']],
            'Reserved': [0x5A, ['unsigned short']],
            'LastEntryInSegment': [0x60, ['pointer64', ['_HEAP_ENTRY']]],
        },
    ],
    '_HEAP_SUBSEGMENT': [
        0x30,
        {
            'Bucket': [0x0, ['pointer64', ['void']]],
            'UserBlocks': [0x8, ['pointer64', ['_HEAP_USERDATA_HEADER']]],
            'AggregateExchg': [0x10, ['_INTERLOCK_SEQ']],
            'BlockSize': [0x18, ['unsigned short']],
            'FreeThreshold': [0x1A, ['unsigned short']],
            'BlockCount': [0x1C, ['unsigned short']],
            'SizeIndex': [0x1E, ['unsigned char']],
            'AffinityIndex': [0x1F, ['unsigned char']],
            'Alignment': [0x18, ['array', 2, ['unsigned long']]],
            'SFreeListEntry': [0x20, ['_SINGLE_LIST_ENTRY']],
            'Lock': [0x28, ['unsigned long']],
        },
    ],
    '_TOKEN': [
        0xD0,
        {
            'TokenSource': [0x0, ['_TOKEN_SOURCE']],
            'TokenId': [0x10, ['_LUID']],
            'AuthenticationId': [0x18, ['_LUID']],
            'ParentTokenId': [0x20, ['_LUID']],
            'ExpirationTime': [0x28, ['_LARGE_INTEGER']],
            'TokenLock': [0x30, ['pointer64', ['_ERESOURCE']]],
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
            'UserAndGroups': [0x68, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'RestrictedSids': [0x70, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'PrimaryGroup': [0x78, ['pointer64', ['void']]],
            'Privileges': [0x80, ['pointer64', ['_LUID_AND_ATTRIBUTES']]],
            'DynamicPart': [0x88, ['pointer64', ['unsigned long']]],
            'DefaultDacl': [0x90, ['pointer64', ['_ACL']]],
            'TokenType': [
                0x98,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={1: 'TokenPrimary', 2: 'TokenImpersonation'},
                    ),
                ],
            ],
            'ImpersonationLevel': [
                0x9C,
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
            'TokenFlags': [0xA0, ['unsigned char']],
            'TokenInUse': [0xA1, ['unsigned char']],
            'ProxyData': [0xA8, ['pointer64', ['_SECURITY_TOKEN_PROXY_DATA']]],
            'AuditData': [0xB0, ['pointer64', ['_SECURITY_TOKEN_AUDIT_DATA']]],
            'LogonSession': [
                0xB8,
                ['pointer64', ['_SEP_LOGON_SESSION_REFERENCES']],
            ],
            'OriginatingLogonSession': [0xC0, ['_LUID']],
            'VariablePart': [0xC8, ['unsigned long']],
        },
    ],
    '_SEP_LOGON_SESSION_REFERENCES': [
        0x20,
        {
            'Next': [0x0, ['pointer64', ['_SEP_LOGON_SESSION_REFERENCES']]],
            'LogonId': [0x8, ['_LUID']],
            'ReferenceCount': [0x10, ['unsigned long']],
            'Flags': [0x14, ['unsigned long']],
            'pDeviceMap': [0x18, ['pointer64', ['_DEVICE_MAP']]],
        },
    ],
    '_TEB': [
        0x17D8,
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
            'SpareBytes1': [0x2D0, ['array', 28, ['unsigned char']]],
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
            'StaticUnicodeBuffer': [
                0x1268,
                ['array', 261, ['unsigned short']],
            ],
            'DeallocationStack': [0x1478, ['pointer64', ['void']]],
            'TlsSlots': [0x1480, ['array', 64, ['pointer64', ['void']]]],
            'TlsLinks': [0x1680, ['_LIST_ENTRY']],
            'Vdm': [0x1690, ['pointer64', ['void']]],
            'ReservedForNtRpc': [0x1698, ['pointer64', ['void']]],
            'DbgSsReserved': [0x16A0, ['array', 2, ['pointer64', ['void']]]],
            'HardErrorMode': [0x16B0, ['unsigned long']],
            'Instrumentation': [
                0x16B8,
                ['array', 14, ['pointer64', ['void']]],
            ],
            'SubProcessTag': [0x1728, ['pointer64', ['void']]],
            'EtwTraceData': [0x1730, ['pointer64', ['void']]],
            'WinSockData': [0x1738, ['pointer64', ['void']]],
            'GdiBatchCount': [0x1740, ['unsigned long']],
            'InDbgPrint': [0x1744, ['unsigned char']],
            'FreeStackOnTermination': [0x1745, ['unsigned char']],
            'HasFiberData': [0x1746, ['unsigned char']],
            'IdealProcessor': [0x1747, ['unsigned char']],
            'GuaranteedStackBytes': [0x1748, ['unsigned long']],
            'ReservedForPerf': [0x1750, ['pointer64', ['void']]],
            'ReservedForOle': [0x1758, ['pointer64', ['void']]],
            'WaitingOnLoaderLock': [0x1760, ['unsigned long']],
            'SparePointer1': [0x1768, ['unsigned long long']],
            'SoftPatchPtr1': [0x1770, ['unsigned long long']],
            'SoftPatchPtr2': [0x1778, ['unsigned long long']],
            'TlsExpansionSlots': [
                0x1780,
                ['pointer64', ['pointer64', ['void']]],
            ],
            'DeallocationBStore': [0x1788, ['pointer64', ['void']]],
            'BStoreLimit': [0x1790, ['pointer64', ['void']]],
            'ImpersonationLocale': [0x1798, ['unsigned long']],
            'IsImpersonating': [0x179C, ['unsigned long']],
            'NlsCache': [0x17A0, ['pointer64', ['void']]],
            'pShimData': [0x17A8, ['pointer64', ['void']]],
            'HeapVirtualAffinity': [0x17B0, ['unsigned long']],
            'CurrentTransactionHandle': [0x17B8, ['pointer64', ['void']]],
            'ActiveFrame': [0x17C0, ['pointer64', ['_TEB_ACTIVE_FRAME']]],
            'FlsData': [0x17C8, ['pointer64', ['void']]],
            'SafeThunkCall': [0x17D0, ['unsigned char']],
            'BooleanSpare': [0x17D1, ['array', 3, ['unsigned char']]],
        },
    ],
    '_HEAP_UCR_SEGMENT': [
        0x20,
        {
            'Next': [0x0, ['pointer64', ['_HEAP_UCR_SEGMENT']]],
            'ReservedSize': [0x8, ['unsigned long long']],
            'CommittedSize': [0x10, ['unsigned long long']],
            'filler': [0x18, ['unsigned long']],
        },
    ],
    '_HMAP_TABLE': [
        0x4000,
        {
            'Table': [0x0, ['array', 512, ['_HMAP_ENTRY']]],
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
            'OwnerThreads': [0x30, ['array', 2, ['_OWNER_ENTRY']]],
            'ContentionCount': [0x50, ['unsigned long']],
            'NumberOfSharedWaiters': [0x54, ['unsigned short']],
            'NumberOfExclusiveWaiters': [0x56, ['unsigned short']],
            'Address': [0x58, ['pointer64', ['void']]],
            'CreatorBackTraceIndex': [0x58, ['unsigned long long']],
            'SpinLock': [0x60, ['unsigned long long']],
        },
    ],
    '_OBJECT_SYMBOLIC_LINK': [
        0x38,
        {
            'CreationTime': [0x0, ['_LARGE_INTEGER']],
            'LinkTarget': [0x8, ['_UNICODE_STRING']],
            'LinkTargetRemaining': [0x18, ['_UNICODE_STRING']],
            'LinkTargetObject': [0x28, ['pointer64', ['void']]],
            'DosDeviceDriveIndex': [0x30, ['unsigned long']],
        },
    ],
    '_POOL_BLOCK_HEAD': [
        0x20,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'List': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_DISPATCHER_HEADER': [
        0x18,
        {
            'Type': [0x0, ['unsigned char']],
            'Absolute': [0x1, ['unsigned char']],
            'NpxIrql': [0x1, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'Hand': [0x2, ['unsigned char']],
            'Inserted': [0x3, ['unsigned char']],
            'DebugActive': [0x3, ['unsigned char']],
            'Lock': [0x0, ['long']],
            'SignalState': [0x4, ['long']],
            'WaitListHead': [0x8, ['_LIST_ENTRY']],
        },
    ],
    '_LDR_DATA_TABLE_ENTRY': [
        0x98,
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
        },
    ],
    '_HEAP_UNCOMMMTTED_RANGE': [
        0x20,
        {
            'Next': [0x0, ['pointer64', ['_HEAP_UNCOMMMTTED_RANGE']]],
            'Address': [0x8, ['unsigned long long']],
            'Size': [0x10, ['unsigned long long']],
            'filler': [0x18, ['unsigned long']],
        },
    ],
    '_LUID_AND_ATTRIBUTES': [
        0xC,
        {
            'Luid': [0x0, ['_LUID']],
            'Attributes': [0x8, ['unsigned long']],
        },
    ],
    '_VI_DEADLOCK_GLOBALS': [
        0x1E0,
        {
            'Nodes': [0x0, ['array', 2, ['unsigned long']]],
            'Resources': [0x8, ['array', 2, ['unsigned long']]],
            'Threads': [0x10, ['array', 2, ['unsigned long']]],
            'TimeAcquire': [0x18, ['long long']],
            'TimeRelease': [0x20, ['long long']],
            'BytesAllocated': [0x28, ['unsigned long long']],
            'ResourceDatabase': [0x30, ['pointer64', ['_LIST_ENTRY']]],
            'ThreadDatabase': [0x38, ['pointer64', ['_LIST_ENTRY']]],
            'AllocationFailures': [0x40, ['unsigned long']],
            'NodesTrimmedBasedOnAge': [0x44, ['unsigned long']],
            'NodesTrimmedBasedOnCount': [0x48, ['unsigned long']],
            'NodesSearched': [0x4C, ['unsigned long']],
            'MaxNodesSearched': [0x50, ['unsigned long']],
            'SequenceNumber': [0x54, ['unsigned long']],
            'RecursionDepthLimit': [0x58, ['unsigned long']],
            'SearchedNodesLimit': [0x5C, ['unsigned long']],
            'DepthLimitHits': [0x60, ['unsigned long']],
            'SearchLimitHits': [0x64, ['unsigned long']],
            'ABC_ACB_Skipped': [0x68, ['unsigned long']],
            'OutOfOrderReleases': [0x6C, ['unsigned long']],
            'NodesReleasedOutOfOrder': [0x70, ['unsigned long']],
            'TotalReleases': [0x74, ['unsigned long']],
            'RootNodesDeleted': [0x78, ['unsigned long']],
            'ForgetHistoryCounter': [0x7C, ['unsigned long']],
            'PoolTrimCounter': [0x80, ['unsigned long']],
            'FreeResourceList': [0x88, ['_LIST_ENTRY']],
            'FreeThreadList': [0x98, ['_LIST_ENTRY']],
            'FreeNodeList': [0xA8, ['_LIST_ENTRY']],
            'FreeResourceCount': [0xB8, ['unsigned long']],
            'FreeThreadCount': [0xBC, ['unsigned long']],
            'FreeNodeCount': [0xC0, ['unsigned long']],
            'Instigator': [0xC8, ['pointer64', ['void']]],
            'NumberOfParticipants': [0xD0, ['unsigned long']],
            'Participant': [
                0xD8,
                ['array', 32, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            ],
            'CacheReductionInProgress': [0x1D8, ['unsigned long']],
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
    '_WMI_LOGGER_CONTEXT': [
        0x280,
        {
            'BufferSpinLock': [0x0, ['unsigned long long']],
            'StartTime': [0x8, ['_LARGE_INTEGER']],
            'LogFileHandle': [0x10, ['pointer64', ['void']]],
            'LoggerSemaphore': [0x18, ['_KSEMAPHORE']],
            'LoggerThread': [0x38, ['pointer64', ['_ETHREAD']]],
            'LoggerEvent': [0x40, ['_KEVENT']],
            'FlushEvent': [0x58, ['_KEVENT']],
            'LoggerStatus': [0x70, ['long']],
            'LoggerId': [0x74, ['unsigned long']],
            'BuffersAvailable': [0x78, ['long']],
            'UsePerfClock': [0x7C, ['unsigned long']],
            'WriteFailureLimit': [0x80, ['unsigned long']],
            'BuffersDirty': [0x84, ['long']],
            'BuffersInUse': [0x88, ['long']],
            'SwitchingInProgress': [0x8C, ['unsigned long']],
            'FreeList': [0x90, ['_SLIST_HEADER']],
            'FlushList': [0xA0, ['_SLIST_HEADER']],
            'WaitList': [0xB0, ['_SLIST_HEADER']],
            'GlobalList': [0xC0, ['_SLIST_HEADER']],
            'ProcessorBuffers': [
                0xD0,
                ['pointer64', ['pointer64', ['_WMI_BUFFER_HEADER']]],
            ],
            'LoggerName': [0xD8, ['_UNICODE_STRING']],
            'LogFileName': [0xE8, ['_UNICODE_STRING']],
            'LogFilePattern': [0xF8, ['_UNICODE_STRING']],
            'NewLogFileName': [0x108, ['_UNICODE_STRING']],
            'EndPageMarker': [0x118, ['pointer64', ['unsigned char']]],
            'CollectionOn': [0x120, ['long']],
            'KernelTraceOn': [0x124, ['unsigned long']],
            'PerfLogInTransition': [0x128, ['long']],
            'RequestFlag': [0x12C, ['unsigned long']],
            'EnableFlags': [0x130, ['unsigned long']],
            'MaximumFileSize': [0x134, ['unsigned long']],
            'LoggerMode': [0x138, ['unsigned long']],
            'LoggerModeFlags': [0x138, ['_WMI_LOGGER_MODE']],
            'Wow': [0x13C, ['unsigned long']],
            'LastFlushedBuffer': [0x140, ['unsigned long']],
            'RefCount': [0x144, ['unsigned long']],
            'FlushTimer': [0x148, ['unsigned long']],
            'FirstBufferOffset': [0x150, ['_LARGE_INTEGER']],
            'ByteOffset': [0x158, ['_LARGE_INTEGER']],
            'BufferAgeLimit': [0x160, ['_LARGE_INTEGER']],
            'MaximumBuffers': [0x168, ['unsigned long']],
            'MinimumBuffers': [0x16C, ['unsigned long']],
            'EventsLost': [0x170, ['unsigned long']],
            'BuffersWritten': [0x174, ['unsigned long']],
            'LogBuffersLost': [0x178, ['unsigned long']],
            'RealTimeBuffersLost': [0x17C, ['unsigned long']],
            'BufferSize': [0x180, ['unsigned long']],
            'NumberOfBuffers': [0x184, ['long']],
            'SequencePtr': [0x188, ['pointer64', ['long']]],
            'InstanceGuid': [0x190, ['_GUID']],
            'LoggerHeader': [0x1A0, ['pointer64', ['void']]],
            'GetCpuClock': [0x1A8, ['pointer64', ['void']]],
            'ClientSecurityContext': [0x1B0, ['_SECURITY_CLIENT_CONTEXT']],
            'LoggerExtension': [0x1F8, ['pointer64', ['void']]],
            'ReleaseQueue': [0x200, ['long']],
            'EnableFlagExtension': [0x204, ['_TRACE_ENABLE_FLAG_EXTENSION']],
            'LocalSequence': [0x208, ['unsigned long']],
            'MaximumIrql': [0x20C, ['unsigned long']],
            'EnableFlagArray': [0x210, ['pointer64', ['unsigned long']]],
            'LoggerMutex': [0x218, ['_KMUTANT']],
            'MutexCount': [0x250, ['long']],
            'FileCounter': [0x254, ['long']],
            'BufferCallback': [0x258, ['pointer64', ['void']]],
            'CallbackContext': [0x260, ['pointer64', ['void']]],
            'PoolType': [
                0x268,
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
            'ReferenceSystemTime': [0x270, ['_LARGE_INTEGER']],
            'ReferenceTimeStamp': [0x278, ['_LARGE_INTEGER']],
        },
    ],
    '_SEGMENT_OBJECT': [
        0x48,
        {
            'BaseAddress': [0x0, ['pointer64', ['void']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'SizeOfSegment': [0x10, ['_LARGE_INTEGER']],
            'NonExtendedPtes': [0x18, ['unsigned long']],
            'ImageCommitment': [0x1C, ['unsigned long']],
            'ControlArea': [0x20, ['pointer64', ['_CONTROL_AREA']]],
            'Subsection': [0x28, ['pointer64', ['_SUBSECTION']]],
            'LargeControlArea': [0x30, ['pointer64', ['_LARGE_CONTROL_AREA']]],
            'MmSectionFlags': [0x38, ['pointer64', ['_MMSECTION_FLAGS']]],
            'MmSubSectionFlags': [
                0x40,
                ['pointer64', ['_MMSUBSECTION_FLAGS']],
            ],
        },
    ],
    '__unnamed_13b7': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MMSECTION_FLAGS']],
        },
    ],
    '_CONTROL_AREA': [
        0x48,
        {
            'Segment': [0x0, ['pointer64', ['_SEGMENT']]],
            'DereferenceList': [0x8, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0x18, ['unsigned long']],
            'NumberOfPfnReferences': [0x1C, ['unsigned long']],
            'NumberOfMappedViews': [0x20, ['unsigned long']],
            'NumberOfSystemCacheViews': [0x24, ['unsigned long']],
            'NumberOfUserReferences': [0x28, ['unsigned long']],
            'u': [0x2C, ['__unnamed_13b7']],
            'FilePointer': [0x30, ['pointer64', ['_FILE_OBJECT']]],
            'WaitingForDeletion': [0x38, ['pointer64', ['_EVENT_COUNTER']]],
            'ModifiedWriteCount': [0x40, ['unsigned short']],
            'FlushInProgressCount': [0x42, ['unsigned short']],
            'WritableUserReferences': [0x44, ['unsigned long']],
        },
    ],
    '_HANDLE_TABLE': [
        0x70,
        {
            'TableCode': [0x0, ['unsigned long long']],
            'QuotaProcess': [0x8, ['pointer64', ['_EPROCESS']]],
            'UniqueProcessId': [0x10, ['pointer64', ['void']]],
            'HandleTableLock': [0x18, ['array', 4, ['_EX_PUSH_LOCK']]],
            'HandleTableList': [0x38, ['_LIST_ENTRY']],
            'HandleContentionEvent': [0x48, ['_EX_PUSH_LOCK']],
            'DebugInfo': [0x50, ['pointer64', ['_HANDLE_TRACE_DEBUG_INFO']]],
            'ExtraInfoPages': [0x58, ['long']],
            'FirstFree': [0x5C, ['unsigned long']],
            'LastFree': [0x60, ['unsigned long']],
            'NextHandleNeedingPool': [0x64, ['unsigned long']],
            'HandleCount': [0x68, ['long']],
            'Flags': [0x6C, ['unsigned long']],
            'StrictFIFO': [
                0x6C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
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
    '_TEB_ACTIVE_FRAME': [
        0x18,
        {
            'Flags': [0x0, ['unsigned long']],
            'Previous': [0x8, ['pointer64', ['_TEB_ACTIVE_FRAME']]],
            'Context': [0x10, ['pointer64', ['_TEB_ACTIVE_FRAME_CONTEXT']]],
        },
    ],
    '_XMM_SAVE_AREA32': [
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
    '_MMSUPPORT': [
        0x58,
        {
            'WorkingSetExpansionLinks': [0x0, ['_LIST_ENTRY']],
            'LastTrimTime': [0x10, ['_LARGE_INTEGER']],
            'Flags': [0x18, ['_MMSUPPORT_FLAGS']],
            'PageFaultCount': [0x1C, ['unsigned long']],
            'PeakWorkingSetSize': [0x20, ['unsigned long']],
            'GrowthSinceLastEstimate': [0x24, ['unsigned long']],
            'MinimumWorkingSetSize': [0x28, ['unsigned long']],
            'MaximumWorkingSetSize': [0x2C, ['unsigned long']],
            'VmWorkingSetList': [0x30, ['pointer64', ['_MMWSL']]],
            'Claim': [0x38, ['unsigned long']],
            'NextEstimationSlot': [0x3C, ['unsigned long']],
            'NextAgingSlot': [0x40, ['unsigned long']],
            'EstimatedAvailable': [0x44, ['unsigned long']],
            'WorkingSetSize': [0x48, ['unsigned long']],
            'WorkingSetMutex': [0x50, ['_EX_PUSH_LOCK']],
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
            'Spare': [
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
    '_HEAP_TAG_ENTRY': [
        0x48,
        {
            'Allocs': [0x0, ['unsigned long']],
            'Frees': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long long']],
            'TagIndex': [0x10, ['unsigned short']],
            'CreatorBackTraceIndex': [0x12, ['unsigned short']],
            'TagName': [0x14, ['array', 24, ['unsigned short']]],
        },
    ],
    '_EPROCESS_QUOTA_BLOCK': [
        0x78,
        {
            'QuotaEntry': [0x0, ['array', 3, ['_EPROCESS_QUOTA_ENTRY']]],
            'QuotaList': [0x60, ['_LIST_ENTRY']],
            'ReferenceCount': [0x70, ['unsigned long']],
            'ProcessCount': [0x74, ['unsigned long']],
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
    '_EVENT_COUNTER': [
        0x30,
        {
            'ListEntry': [0x0, ['_SLIST_ENTRY']],
            'RefCount': [0x10, ['unsigned long']],
            'Event': [0x18, ['_KEVENT']],
        },
    ],
    '_EJOB': [
        0x220,
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
            'LimitFlags': [0xE0, ['unsigned long']],
            'MinimumWorkingSetSize': [0xE8, ['unsigned long long']],
            'MaximumWorkingSetSize': [0xF0, ['unsigned long long']],
            'ActiveProcessLimit': [0xF8, ['unsigned long']],
            'Affinity': [0x100, ['unsigned long long']],
            'PriorityClass': [0x108, ['unsigned char']],
            'UIRestrictionsClass': [0x10C, ['unsigned long']],
            'SecurityLimitFlags': [0x110, ['unsigned long']],
            'Token': [0x118, ['pointer64', ['void']]],
            'Filter': [0x120, ['pointer64', ['_PS_JOB_TOKEN_FILTER']]],
            'EndOfJobTimeAction': [0x128, ['unsigned long']],
            'CompletionPort': [0x130, ['pointer64', ['void']]],
            'CompletionKey': [0x138, ['pointer64', ['void']]],
            'SessionId': [0x140, ['unsigned long']],
            'SchedulingClass': [0x144, ['unsigned long']],
            'ReadOperationCount': [0x148, ['unsigned long long']],
            'WriteOperationCount': [0x150, ['unsigned long long']],
            'OtherOperationCount': [0x158, ['unsigned long long']],
            'ReadTransferCount': [0x160, ['unsigned long long']],
            'WriteTransferCount': [0x168, ['unsigned long long']],
            'OtherTransferCount': [0x170, ['unsigned long long']],
            'IoInfo': [0x178, ['_IO_COUNTERS']],
            'ProcessMemoryLimit': [0x1A8, ['unsigned long long']],
            'JobMemoryLimit': [0x1B0, ['unsigned long long']],
            'PeakProcessMemoryUsed': [0x1B8, ['unsigned long long']],
            'PeakJobMemoryUsed': [0x1C0, ['unsigned long long']],
            'CurrentJobMemoryUsed': [0x1C8, ['unsigned long long']],
            'MemoryLimitsLock': [0x1D0, ['_KGUARDED_MUTEX']],
            'JobSetLinks': [0x208, ['_LIST_ENTRY']],
            'MemberLevel': [0x218, ['unsigned long']],
            'JobFlags': [0x21C, ['unsigned long']],
        },
    ],
    '_LARGE_CONTROL_AREA': [
        0x68,
        {
            'Segment': [0x0, ['pointer64', ['_SEGMENT']]],
            'DereferenceList': [0x8, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0x18, ['unsigned long']],
            'NumberOfPfnReferences': [0x1C, ['unsigned long']],
            'NumberOfMappedViews': [0x20, ['unsigned long']],
            'NumberOfSystemCacheViews': [0x24, ['unsigned long']],
            'NumberOfUserReferences': [0x28, ['unsigned long']],
            'u': [0x2C, ['__unnamed_13b7']],
            'FilePointer': [0x30, ['pointer64', ['_FILE_OBJECT']]],
            'WaitingForDeletion': [0x38, ['pointer64', ['_EVENT_COUNTER']]],
            'ModifiedWriteCount': [0x40, ['unsigned short']],
            'FlushInProgressCount': [0x42, ['unsigned short']],
            'WritableUserReferences': [0x44, ['unsigned long']],
            'StartingFrame': [0x48, ['unsigned long long']],
            'UserGlobalList': [0x50, ['_LIST_ENTRY']],
            'SessionId': [0x60, ['unsigned long']],
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
    '_KGATE': [
        0x18,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '_PS_JOB_TOKEN_FILTER': [
        0x38,
        {
            'CapturedSidCount': [0x0, ['unsigned long']],
            'CapturedSids': [0x8, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'CapturedSidsLength': [0x10, ['unsigned long']],
            'CapturedGroupCount': [0x14, ['unsigned long']],
            'CapturedGroups': [0x18, ['pointer64', ['_SID_AND_ATTRIBUTES']]],
            'CapturedGroupsLength': [0x20, ['unsigned long']],
            'CapturedPrivilegeCount': [0x24, ['unsigned long']],
            'CapturedPrivileges': [
                0x28,
                ['pointer64', ['_LUID_AND_ATTRIBUTES']],
            ],
            'CapturedPrivilegesLength': [0x30, ['unsigned long']],
        },
    ],
    '_MM_DRIVER_VERIFIER_DATA': [
        0x80,
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
            'Reserved': [0x78, ['array', 2, ['unsigned long']]],
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
            'Writable': [
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
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
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
    '_CALL_HASH_ENTRY': [
        0x28,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'CallersAddress': [0x10, ['pointer64', ['void']]],
            'CallersCaller': [0x18, ['pointer64', ['void']]],
            'CallCount': [0x20, ['unsigned long']],
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
    '_DBGKD_SET_CONTEXT': [
        0x4,
        {
            'ContextFlags': [0x0, ['unsigned long']],
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
            'filler0': [
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
            'WriteCombined': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=31, native_type='unsigned long'
                    ),
                ],
            ],
            'filler': [
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
    '_DEFERRED_WRITE': [
        0x50,
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
            'LimitModifiedPages': [0x48, ['unsigned char']],
        },
    ],
    '_TRACE_ENABLE_FLAG_EXTENSION': [
        0x4,
        {
            'Offset': [0x0, ['unsigned short']],
            'Length': [0x2, ['unsigned char']],
            'Flag': [0x3, ['unsigned char']],
        },
    ],
    '_SID_AND_ATTRIBUTES': [
        0x10,
        {
            'Sid': [0x0, ['pointer64', ['void']]],
            'Attributes': [0x8, ['unsigned long']],
        },
    ],
    '_HIVE_LIST_ENTRY': [
        0x30,
        {
            'Name': [0x0, ['pointer64', ['unsigned short']]],
            'BaseName': [0x8, ['pointer64', ['unsigned short']]],
            'CmHive': [0x10, ['pointer64', ['_CMHIVE']]],
            'HHiveFlags': [0x18, ['unsigned long']],
            'CmHiveFlags': [0x1C, ['unsigned long']],
            'CmHive2': [0x20, ['pointer64', ['_CMHIVE']]],
            'ThreadFinished': [0x28, ['unsigned char']],
            'ThreadStarted': [0x29, ['unsigned char']],
            'Allocate': [0x2A, ['unsigned char']],
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
    '_PS_IMPERSONATION_INFORMATION': [
        0x10,
        {
            'Token': [0x0, ['pointer64', ['void']]],
            'CopyOnOpen': [0x8, ['unsigned char']],
            'EffectiveOnly': [0x9, ['unsigned char']],
            'ImpersonationLevel': [
                0xC,
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
    '__unnamed_1472': [
        0x8,
        {
            'LegacyDeviceNode': [0x0, ['pointer64', ['_DEVICE_NODE']]],
            'PendingDeviceRelations': [
                0x0,
                ['pointer64', ['_DEVICE_RELATIONS']],
            ],
        },
    ],
    '__unnamed_1474': [
        0x8,
        {
            'NextResourceDeviceNode': [0x0, ['pointer64', ['_DEVICE_NODE']]],
        },
    ],
    '__unnamed_1478': [
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
        0x1C0,
        {
            'Sibling': [0x0, ['pointer64', ['_DEVICE_NODE']]],
            'Child': [0x8, ['pointer64', ['_DEVICE_NODE']]],
            'Parent': [0x10, ['pointer64', ['_DEVICE_NODE']]],
            'LastChild': [0x18, ['pointer64', ['_DEVICE_NODE']]],
            'Level': [0x20, ['unsigned long']],
            'Notify': [0x28, ['pointer64', ['_PO_DEVICE_NOTIFY']]],
            'State': [
                0x30,
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
                0x34,
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
                0x38,
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
            'StateHistoryEntry': [0x88, ['unsigned long']],
            'CompletionStatus': [0x8C, ['long']],
            'PendingIrp': [0x90, ['pointer64', ['_IRP']]],
            'Flags': [0x98, ['unsigned long']],
            'UserFlags': [0x9C, ['unsigned long']],
            'Problem': [0xA0, ['unsigned long']],
            'PhysicalDeviceObject': [0xA8, ['pointer64', ['_DEVICE_OBJECT']]],
            'ResourceList': [0xB0, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'ResourceListTranslated': [
                0xB8,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
            'InstancePath': [0xC0, ['_UNICODE_STRING']],
            'ServiceName': [0xD0, ['_UNICODE_STRING']],
            'DuplicatePDO': [0xE0, ['pointer64', ['_DEVICE_OBJECT']]],
            'ResourceRequirements': [
                0xE8,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'InterfaceType': [
                0xF0,
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
            'BusNumber': [0xF4, ['unsigned long']],
            'ChildInterfaceType': [
                0xF8,
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
            'ChildBusNumber': [0xFC, ['unsigned long']],
            'ChildBusTypeIndex': [0x100, ['unsigned short']],
            'RemovalPolicy': [0x102, ['unsigned char']],
            'HardwareRemovalPolicy': [0x103, ['unsigned char']],
            'TargetDeviceNotify': [0x108, ['_LIST_ENTRY']],
            'DeviceArbiterList': [0x118, ['_LIST_ENTRY']],
            'DeviceTranslatorList': [0x128, ['_LIST_ENTRY']],
            'NoTranslatorMask': [0x138, ['unsigned short']],
            'QueryTranslatorMask': [0x13A, ['unsigned short']],
            'NoArbiterMask': [0x13C, ['unsigned short']],
            'QueryArbiterMask': [0x13E, ['unsigned short']],
            'OverUsed1': [0x140, ['__unnamed_1472']],
            'OverUsed2': [0x148, ['__unnamed_1474']],
            'BootResources': [0x150, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'CapabilityFlags': [0x158, ['unsigned long']],
            'DockInfo': [0x160, ['__unnamed_1478']],
            'DisableableDepends': [0x180, ['unsigned long']],
            'PendedSetInterfaceState': [0x188, ['_LIST_ENTRY']],
            'LegacyBusListEntry': [0x198, ['_LIST_ENTRY']],
            'DriverUnloadRetryCount': [0x1A8, ['unsigned long']],
            'PreviousParent': [0x1B0, ['pointer64', ['_DEVICE_NODE']]],
            'DeletedChildren': [0x1B8, ['unsigned long']],
        },
    ],
    '__unnamed_147d': [
        0x68,
        {
            'CriticalSection': [0x0, ['_RTL_CRITICAL_SECTION']],
            'Resource': [0x0, ['_ERESOURCE']],
        },
    ],
    '_HEAP_LOCK': [
        0x68,
        {
            'Lock': [0x0, ['__unnamed_147d']],
        },
    ],
    '_PEB64': [
        0x358,
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
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
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
            'SparePtr2': [0x48, ['unsigned long long']],
            'EnvironmentUpdateCount': [0x50, ['unsigned long']],
            'KernelCallbackTable': [0x58, ['unsigned long long']],
            'SystemReserved': [0x60, ['array', 1, ['unsigned long']]],
            'SpareUlong': [0x64, ['unsigned long']],
            'FreeList': [0x68, ['unsigned long long']],
            'TlsExpansionCounter': [0x70, ['unsigned long']],
            'TlsBitmap': [0x78, ['unsigned long long']],
            'TlsBitmapBits': [0x80, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x88, ['unsigned long long']],
            'ReadOnlySharedMemoryHeap': [0x90, ['unsigned long long']],
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
            'ImageProcessAffinityMask': [0x138, ['unsigned long long']],
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
    '_KPCR': [
        0x2600,
        {
            'NtTib': [0x0, ['_NT_TIB']],
            'GdtBase': [0x0, ['pointer64', ['_KGDTENTRY64']]],
            'TssBase': [0x8, ['pointer64', ['_KTSS64']]],
            'PerfGlobalGroupMask': [0x10, ['pointer64', ['void']]],
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
    '_MMCOLOR_TABLES': [
        0x18,
        {
            'Flink': [0x0, ['unsigned long long']],
            'Blink': [0x8, ['pointer64', ['void']]],
            'Count': [0x10, ['unsigned long long']],
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
        0x10,
        {
            'P': [0x0, ['pointer64', ['_GENERAL_LOOKASIDE']]],
            'L': [0x8, ['pointer64', ['_GENERAL_LOOKASIDE']]],
        },
    ],
    '_PHYSICAL_MEMORY_RUN': [
        0x10,
        {
            'BasePage': [0x0, ['unsigned long long']],
            'PageCount': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_14ad': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MM_SESSION_SPACE_FLAGS']],
        },
    ],
    '_MM_SESSION_SPACE': [
        0x1D80,
        {
            'GlobalVirtualAddress': [
                0x0,
                ['pointer64', ['_MM_SESSION_SPACE']],
            ],
            'ReferenceCount': [0x8, ['long']],
            'u': [0xC, ['__unnamed_14ad']],
            'SessionId': [0x10, ['unsigned long']],
            'ProcessList': [0x18, ['_LIST_ENTRY']],
            'LastProcessSwappedOutTime': [0x28, ['_LARGE_INTEGER']],
            'SessionPageDirectoryIndex': [0x30, ['unsigned long long']],
            'NonPagablePages': [0x38, ['unsigned long long']],
            'CommittedPages': [0x40, ['unsigned long long']],
            'PagedPoolStart': [0x48, ['pointer64', ['void']]],
            'PagedPoolEnd': [0x50, ['pointer64', ['void']]],
            'PagedPoolBasePde': [0x58, ['pointer64', ['_MMPTE']]],
            'Color': [0x60, ['unsigned long']],
            'ResidentProcessCount': [0x64, ['long']],
            'SessionPoolAllocationFailures': [
                0x68,
                ['array', 4, ['unsigned long']],
            ],
            'ImageList': [0x78, ['_LIST_ENTRY']],
            'LocaleId': [0x88, ['unsigned long']],
            'AttachCount': [0x8C, ['unsigned long']],
            'AttachEvent': [0x90, ['_KEVENT']],
            'LastProcess': [0xA8, ['pointer64', ['_EPROCESS']]],
            'ProcessReferenceToSession': [0xB0, ['long']],
            'WsListEntry': [0xB8, ['_LIST_ENTRY']],
            'Lookaside': [0x100, ['array', 21, ['_GENERAL_LOOKASIDE']]],
            'Session': [0xB80, ['_MMSESSION']],
            'PagedPoolMutex': [0xBE8, ['_KGUARDED_MUTEX']],
            'PagedPoolInfo': [0xC20, ['_MM_PAGED_POOL_INFO']],
            'Vm': [0xC60, ['_MMSUPPORT']],
            'Wsle': [0xCB8, ['pointer64', ['_MMWSLE']]],
            'Win32KDriverUnload': [0xCC0, ['pointer64', ['void']]],
            'PagedPool': [0xCC8, ['_POOL_DESCRIPTOR']],
            'PageDirectory': [0x1D10, ['_MMPTE']],
            'SpecialPoolFirstPte': [0x1D18, ['pointer64', ['_MMPTE']]],
            'SpecialPoolLastPte': [0x1D20, ['pointer64', ['_MMPTE']]],
            'NextPdeForSpecialPoolExpansion': [
                0x1D28,
                ['pointer64', ['_MMPTE']],
            ],
            'LastPdeForSpecialPoolExpansion': [
                0x1D30,
                ['pointer64', ['_MMPTE']],
            ],
            'SpecialPagesInUse': [0x1D38, ['unsigned long long']],
            'ImageLoadingCount': [0x1D40, ['long']],
        },
    ],
    '_PEB': [
        0x358,
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
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
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
            'SparePtr2': [0x48, ['pointer64', ['void']]],
            'EnvironmentUpdateCount': [0x50, ['unsigned long']],
            'KernelCallbackTable': [0x58, ['pointer64', ['void']]],
            'SystemReserved': [0x60, ['array', 1, ['unsigned long']]],
            'SpareUlong': [0x64, ['unsigned long']],
            'FreeList': [0x68, ['pointer64', ['_PEB_FREE_BLOCK']]],
            'TlsExpansionCounter': [0x70, ['unsigned long']],
            'TlsBitmap': [0x78, ['pointer64', ['void']]],
            'TlsBitmapBits': [0x80, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x88, ['pointer64', ['void']]],
            'ReadOnlySharedMemoryHeap': [0x90, ['pointer64', ['void']]],
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
            'ImageProcessAffinityMask': [0x138, ['unsigned long long']],
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
            'FlsCallback': [0x320, ['pointer64', ['pointer64', ['void']]]],
            'FlsListHead': [0x328, ['_LIST_ENTRY']],
            'FlsBitmap': [0x338, ['pointer64', ['void']]],
            'FlsBitmapBits': [0x340, ['array', 4, ['unsigned long']]],
            'FlsHighIndex': [0x350, ['unsigned long']],
        },
    ],
    '_HEAP_FREE_ENTRY': [
        0x20,
        {
            'PreviousBlockPrivateData': [0x0, ['pointer64', ['void']]],
            'Size': [0x8, ['unsigned short']],
            'PreviousSize': [0xA, ['unsigned short']],
            'SmallTagIndex': [0xC, ['unsigned char']],
            'Flags': [0xD, ['unsigned char']],
            'UnusedBytes': [0xE, ['unsigned char']],
            'SegmentIndex': [0xF, ['unsigned char']],
            'CompactHeader': [0x8, ['unsigned long long']],
            'FreeList': [0x10, ['_LIST_ENTRY']],
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
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=22,
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
    '__unnamed_14dd': [
        0x10,
        {
            'IoStatus': [0x0, ['_IO_STATUS_BLOCK']],
            'LastByte': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '_MMMOD_WRITER_MDL_ENTRY': [
        0xA8,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'WriteOffset': [0x10, ['_LARGE_INTEGER']],
            'u': [0x18, ['__unnamed_14dd']],
            'Irp': [0x28, ['pointer64', ['_IRP']]],
            'LastPageToWrite': [0x30, ['unsigned long long']],
            'PagingListHead': [
                0x38,
                ['pointer64', ['_MMMOD_WRITER_LISTHEAD']],
            ],
            'CurrentList': [0x40, ['pointer64', ['_LIST_ENTRY']]],
            'PagingFile': [0x48, ['pointer64', ['_MMPAGING_FILE']]],
            'File': [0x50, ['pointer64', ['_FILE_OBJECT']]],
            'ControlArea': [0x58, ['pointer64', ['_CONTROL_AREA']]],
            'FileResource': [0x60, ['pointer64', ['_ERESOURCE']]],
            'IssueTime': [0x68, ['_LARGE_INTEGER']],
            'Mdl': [0x70, ['_MDL']],
            'Page': [0xA0, ['array', 1, ['unsigned long long']]],
        },
    ],
    '_CACHE_UNINITIALIZE_EVENT': [
        0x20,
        {
            'Next': [0x0, ['pointer64', ['_CACHE_UNINITIALIZE_EVENT']]],
            'Event': [0x8, ['_KEVENT']],
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
    '_CM_RESOURCE_LIST': [
        0x28,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['array', 1, ['_CM_FULL_RESOURCE_DESCRIPTOR']]],
        },
    ],
    '_TEB32': [
        0xFBC,
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
            'SpareBytes1': [0x1AC, ['array', 40, ['unsigned char']]],
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
            'StaticUnicodeBuffer': [0xC00, ['array', 261, ['unsigned short']]],
            'DeallocationStack': [0xE0C, ['unsigned long']],
            'TlsSlots': [0xE10, ['array', 64, ['unsigned long']]],
            'TlsLinks': [0xF10, ['LIST_ENTRY32']],
            'Vdm': [0xF18, ['unsigned long']],
            'ReservedForNtRpc': [0xF1C, ['unsigned long']],
            'DbgSsReserved': [0xF20, ['array', 2, ['unsigned long']]],
            'HardErrorMode': [0xF28, ['unsigned long']],
            'Instrumentation': [0xF2C, ['array', 14, ['unsigned long']]],
            'SubProcessTag': [0xF64, ['unsigned long']],
            'EtwTraceData': [0xF68, ['unsigned long']],
            'WinSockData': [0xF6C, ['unsigned long']],
            'GdiBatchCount': [0xF70, ['unsigned long']],
            'InDbgPrint': [0xF74, ['unsigned char']],
            'FreeStackOnTermination': [0xF75, ['unsigned char']],
            'HasFiberData': [0xF76, ['unsigned char']],
            'IdealProcessor': [0xF77, ['unsigned char']],
            'GuaranteedStackBytes': [0xF78, ['unsigned long']],
            'ReservedForPerf': [0xF7C, ['unsigned long']],
            'ReservedForOle': [0xF80, ['unsigned long']],
            'WaitingOnLoaderLock': [0xF84, ['unsigned long']],
            'SparePointer1': [0xF88, ['unsigned long']],
            'SoftPatchPtr1': [0xF8C, ['unsigned long']],
            'SoftPatchPtr2': [0xF90, ['unsigned long']],
            'TlsExpansionSlots': [0xF94, ['unsigned long']],
            'ImpersonationLocale': [0xF98, ['unsigned long']],
            'IsImpersonating': [0xF9C, ['unsigned long']],
            'NlsCache': [0xFA0, ['unsigned long']],
            'pShimData': [0xFA4, ['unsigned long']],
            'HeapVirtualAffinity': [0xFA8, ['unsigned long']],
            'CurrentTransactionHandle': [0xFAC, ['unsigned long']],
            'ActiveFrame': [0xFB0, ['unsigned long']],
            'FlsData': [0xFB4, ['unsigned long']],
            'SafeThunkCall': [0xFB8, ['unsigned char']],
            'BooleanSpare': [0xFB9, ['array', 3, ['unsigned char']]],
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
        0x20,
        {
            'Usage': [0x0, ['unsigned long long']],
            'Limit': [0x8, ['unsigned long long']],
            'Peak': [0x10, ['unsigned long long']],
            'Return': [0x18, ['unsigned long long']],
        },
    ],
    '__unnamed_1502': [
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
            'Data': [0x8, ['__unnamed_1502']],
        },
    ],
    '_WMI_BUFFER_HEADER': [
        0x48,
        {
            'Wnode': [0x0, ['_WNODE_HEADER']],
            'Reserved1': [0x0, ['unsigned long long']],
            'Reserved2': [0x8, ['unsigned long long']],
            'Reserved3': [0x10, ['_LARGE_INTEGER']],
            'Alignment': [0x18, ['pointer64', ['void']]],
            'SlistEntry': [0x20, ['_SINGLE_LIST_ENTRY']],
            'Entry': [0x18, ['_LIST_ENTRY']],
            'ReferenceCount': [0x0, ['long']],
            'SavedOffset': [0x4, ['unsigned long']],
            'CurrentOffset': [0x8, ['unsigned long']],
            'UsePerfClock': [0xC, ['unsigned long']],
            'TimeStamp': [0x10, ['_LARGE_INTEGER']],
            'Guid': [0x18, ['_GUID']],
            'ClientContext': [0x28, ['_WMI_CLIENT_CONTEXT']],
            'State': [0x2C, ['_WMI_BUFFER_STATE']],
            'Flags': [0x2C, ['unsigned long']],
            'Offset': [0x30, ['unsigned long']],
            'BufferFlag': [0x34, ['unsigned short']],
            'BufferType': [0x36, ['unsigned short']],
            'InstanceGuid': [0x38, ['_GUID']],
            'LoggerContext': [0x38, ['pointer64', ['void']]],
            'GlobalEntry': [0x40, ['_SINGLE_LIST_ENTRY']],
        },
    ],
    '_KSEMAPHORE': [
        0x20,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'Limit': [0x18, ['long']],
        },
    ],
    '_PROCESSOR_POWER_STATE': [
        0x170,
        {
            'IdleFunction': [0x0, ['pointer64', ['void']]],
            'Idle0KernelTimeLimit': [0x8, ['unsigned long']],
            'Idle0LastTime': [0xC, ['unsigned long']],
            'IdleHandlers': [0x10, ['pointer64', ['void']]],
            'IdleState': [0x18, ['pointer64', ['void']]],
            'IdleHandlersCount': [0x20, ['unsigned long']],
            'LastCheck': [0x28, ['unsigned long long']],
            'IdleTimes': [0x30, ['PROCESSOR_IDLE_TIMES']],
            'IdleTime1': [0x50, ['unsigned long']],
            'PromotionCheck': [0x54, ['unsigned long']],
            'IdleTime2': [0x58, ['unsigned long']],
            'CurrentThrottle': [0x5C, ['unsigned char']],
            'ThermalThrottleLimit': [0x5D, ['unsigned char']],
            'CurrentThrottleIndex': [0x5E, ['unsigned char']],
            'ThermalThrottleIndex': [0x5F, ['unsigned char']],
            'LastKernelUserTime': [0x60, ['unsigned long']],
            'LastIdleThreadKernelTime': [0x64, ['unsigned long']],
            'PackageIdleStartTime': [0x68, ['unsigned long']],
            'PackageIdleTime': [0x6C, ['unsigned long']],
            'DebugCount': [0x70, ['unsigned long']],
            'LastSysTime': [0x74, ['unsigned long']],
            'TotalIdleStateTime': [0x78, ['array', 3, ['unsigned long long']]],
            'TotalIdleTransitions': [0x90, ['array', 3, ['unsigned long']]],
            'PreviousC3StateTime': [0xA0, ['unsigned long long']],
            'KneeThrottleIndex': [0xA8, ['unsigned char']],
            'ThrottleLimitIndex': [0xA9, ['unsigned char']],
            'PerfStatesCount': [0xAA, ['unsigned char']],
            'ProcessorMinThrottle': [0xAB, ['unsigned char']],
            'ProcessorMaxThrottle': [0xAC, ['unsigned char']],
            'EnableIdleAccounting': [0xAD, ['unsigned char']],
            'LastC3Percentage': [0xAE, ['unsigned char']],
            'LastAdjustedBusyPercentage': [0xAF, ['unsigned char']],
            'PromotionCount': [0xB0, ['unsigned long']],
            'DemotionCount': [0xB4, ['unsigned long']],
            'ErrorCount': [0xB8, ['unsigned long']],
            'RetryCount': [0xBC, ['unsigned long']],
            'Flags': [0xC0, ['unsigned long']],
            'PerfCounterFrequency': [0xC8, ['_LARGE_INTEGER']],
            'PerfTickCount': [0xD0, ['unsigned long']],
            'PerfTimer': [0xD8, ['_KTIMER']],
            'PerfDpc': [0x118, ['_KDPC']],
            'PerfStates': [0x158, ['pointer64', ['PROCESSOR_PERF_STATE']]],
            'PerfSetThrottle': [0x160, ['pointer64', ['void']]],
            'LastC3KernelUserTime': [0x168, ['unsigned long']],
            'LastPackageIdleTime': [0x16C, ['unsigned long']],
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
    '_MMPFNENTRY': [
        0x2,
        {
            'Modified': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'ReadInProgress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'WriteInProgress': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'PrototypePte': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'PageColor': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'PageLocation': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=8, end_bit=11, native_type='unsigned short'
                    ),
                ],
            ],
            'RemovalRequested': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned short'
                    ),
                ],
            ],
            'CacheAttribute': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=14, native_type='unsigned short'
                    ),
                ],
            ],
            'Rom': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned short'
                    ),
                ],
            ],
            'ParityError': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
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
    '_DEVICE_OBJECT_POWER_EXTENSION': [
        0x80,
        {
            'IdleCount': [0x0, ['long']],
            'ConservationIdleTime': [0x4, ['unsigned long']],
            'PerformanceIdleTime': [0x8, ['unsigned long']],
            'DeviceObject': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'IdleList': [0x18, ['_LIST_ENTRY']],
            'DeviceType': [0x28, ['unsigned char']],
            'State': [
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
            'NotifySourceList': [0x30, ['_LIST_ENTRY']],
            'NotifyTargetList': [0x40, ['_LIST_ENTRY']],
            'PowerChannelSummary': [0x50, ['_POWER_CHANNEL_SUMMARY']],
            'Volume': [0x70, ['_LIST_ENTRY']],
        },
    ],
    '_MMSUPPORT_FLAGS': [
        0x4,
        {
            'SessionSpace': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'BeingTrimmed': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'SessionLeader': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'TrimHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'MaximumWorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'ForceTrim': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'MinimumWorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'Available0': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'MemoryPriority': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'GrowWsleHash': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'AcquiredUnsafe': [
                0x2,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'Available': [
                0x2,
                [
                    'BitField',
                    dict(
                        start_bit=2, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
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
    '_TERMINATION_PORT': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_TERMINATION_PORT']]],
            'Port': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_MMMOD_WRITER_LISTHEAD': [
        0x28,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Event': [0x10, ['_KEVENT']],
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
    '_GDI_TEB_BATCH': [
        0x4E8,
        {
            'Offset': [0x0, ['unsigned long']],
            'HDC': [0x8, ['unsigned long long']],
            'Buffer': [0x10, ['array', 310, ['unsigned long']]],
        },
    ],
    '_POP_THERMAL_ZONE': [
        0x120,
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
            'Irp': [0xC0, ['pointer64', ['_IRP']]],
            'Info': [0xC8, ['_THERMAL_INFORMATION']],
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
    '_SECURITY_TOKEN_PROXY_DATA': [
        0x20,
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
            'ContainerMask': [0x18, ['unsigned long']],
            'ObjectMask': [0x1C, ['unsigned long']],
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
        0x10,
        {
            'OwnerThread': [0x0, ['unsigned long long']],
            'OwnerCount': [0x8, ['long']],
            'TableSize': [0x8, ['unsigned long']],
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
    '_TEB64': [
        0x17D8,
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
            'SpareBytes1': [0x2D0, ['array', 28, ['unsigned char']]],
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
            'StaticUnicodeBuffer': [
                0x1268,
                ['array', 261, ['unsigned short']],
            ],
            'DeallocationStack': [0x1478, ['unsigned long long']],
            'TlsSlots': [0x1480, ['array', 64, ['unsigned long long']]],
            'TlsLinks': [0x1680, ['LIST_ENTRY64']],
            'Vdm': [0x1690, ['unsigned long long']],
            'ReservedForNtRpc': [0x1698, ['unsigned long long']],
            'DbgSsReserved': [0x16A0, ['array', 2, ['unsigned long long']]],
            'HardErrorMode': [0x16B0, ['unsigned long']],
            'Instrumentation': [0x16B8, ['array', 14, ['unsigned long long']]],
            'SubProcessTag': [0x1728, ['unsigned long long']],
            'EtwTraceData': [0x1730, ['unsigned long long']],
            'WinSockData': [0x1738, ['unsigned long long']],
            'GdiBatchCount': [0x1740, ['unsigned long']],
            'InDbgPrint': [0x1744, ['unsigned char']],
            'FreeStackOnTermination': [0x1745, ['unsigned char']],
            'HasFiberData': [0x1746, ['unsigned char']],
            'IdealProcessor': [0x1747, ['unsigned char']],
            'GuaranteedStackBytes': [0x1748, ['unsigned long']],
            'ReservedForPerf': [0x1750, ['unsigned long long']],
            'ReservedForOle': [0x1758, ['unsigned long long']],
            'WaitingOnLoaderLock': [0x1760, ['unsigned long']],
            'SparePointer1': [0x1768, ['unsigned long long']],
            'SoftPatchPtr1': [0x1770, ['unsigned long long']],
            'SoftPatchPtr2': [0x1778, ['unsigned long long']],
            'TlsExpansionSlots': [0x1780, ['unsigned long long']],
            'DeallocationBStore': [0x1788, ['unsigned long long']],
            'BStoreLimit': [0x1790, ['unsigned long long']],
            'ImpersonationLocale': [0x1798, ['unsigned long']],
            'IsImpersonating': [0x179C, ['unsigned long']],
            'NlsCache': [0x17A0, ['unsigned long long']],
            'pShimData': [0x17A8, ['unsigned long long']],
            'HeapVirtualAffinity': [0x17B0, ['unsigned long']],
            'CurrentTransactionHandle': [0x17B8, ['unsigned long long']],
            'ActiveFrame': [0x17C0, ['unsigned long long']],
            'FlsData': [0x17C8, ['unsigned long long']],
            'SafeThunkCall': [0x17D0, ['unsigned char']],
            'BooleanSpare': [0x17D1, ['array', 3, ['unsigned char']]],
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
    '_CMHIVE': [
        0xAB8,
        {
            'Hive': [0x0, ['_HHIVE']],
            'FileHandles': [0x578, ['array', 3, ['pointer64', ['void']]]],
            'NotifyList': [0x590, ['_LIST_ENTRY']],
            'HiveList': [0x5A0, ['_LIST_ENTRY']],
            'HiveLock': [0x5B0, ['_EX_PUSH_LOCK']],
            'ViewLock': [0x5B8, ['pointer64', ['_KGUARDED_MUTEX']]],
            'WriterLock': [0x5C0, ['_EX_PUSH_LOCK']],
            'FlusherLock': [0x5C8, ['_EX_PUSH_LOCK']],
            'SecurityLock': [0x5D0, ['_EX_PUSH_LOCK']],
            'LRUViewListHead': [0x5D8, ['_LIST_ENTRY']],
            'PinViewListHead': [0x5E8, ['_LIST_ENTRY']],
            'FileObject': [0x5F8, ['pointer64', ['_FILE_OBJECT']]],
            'FileFullPath': [0x600, ['_UNICODE_STRING']],
            'FileUserName': [0x610, ['_UNICODE_STRING']],
            'MappedViews': [0x620, ['unsigned short']],
            'PinnedViews': [0x622, ['unsigned short']],
            'UseCount': [0x624, ['unsigned long']],
            'SecurityCount': [0x628, ['unsigned long']],
            'SecurityCacheSize': [0x62C, ['unsigned long']],
            'SecurityHitHint': [0x630, ['long']],
            'SecurityCache': [
                0x638,
                ['pointer64', ['_CM_KEY_SECURITY_CACHE_ENTRY']],
            ],
            'SecurityHash': [0x640, ['array', 64, ['_LIST_ENTRY']]],
            'UnloadEvent': [0xA40, ['pointer64', ['_KEVENT']]],
            'RootKcb': [0xA48, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'Frozen': [0xA50, ['unsigned char']],
            'UnloadWorkItem': [0xA58, ['pointer64', ['_WORK_QUEUE_ITEM']]],
            'GrowOnlyMode': [0xA60, ['unsigned char']],
            'GrowOffset': [0xA64, ['unsigned long']],
            'KcbConvertListHead': [0xA68, ['_LIST_ENTRY']],
            'KnodeConvertListHead': [0xA78, ['_LIST_ENTRY']],
            'CellRemapArray': [0xA88, ['pointer64', ['_CM_CELL_REMAP_BLOCK']]],
            'Flags': [0xA90, ['unsigned long']],
            'TrustClassEntry': [0xA98, ['_LIST_ENTRY']],
            'FlushCount': [0xAA8, ['unsigned long']],
            'CreatorOwner': [0xAB0, ['pointer64', ['_KTHREAD']]],
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
        0x578,
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
            'BaseBlock': [0x48, ['pointer64', ['_HBASE_BLOCK']]],
            'DirtyVector': [0x50, ['_RTL_BITMAP']],
            'DirtyCount': [0x60, ['unsigned long']],
            'DirtyAlloc': [0x64, ['unsigned long']],
            'BaseBlockAlloc': [0x68, ['unsigned long']],
            'Cluster': [0x6C, ['unsigned long']],
            'Flat': [0x70, ['unsigned char']],
            'ReadOnly': [0x71, ['unsigned char']],
            'Log': [0x72, ['unsigned char']],
            'DirtyFlag': [0x73, ['unsigned char']],
            'HiveFlags': [0x74, ['unsigned long']],
            'LogSize': [0x78, ['unsigned long']],
            'RefreshCount': [0x7C, ['unsigned long']],
            'StorageTypeCount': [0x80, ['unsigned long']],
            'Version': [0x84, ['unsigned long']],
            'Storage': [0x88, ['array', 2, ['_DUAL']]],
        },
    ],
    '_PAGEFAULT_HISTORY': [
        0x28,
        {
            'CurrentIndex': [0x0, ['unsigned long']],
            'MaxIndex': [0x4, ['unsigned long']],
            'SpinLock': [0x8, ['unsigned long long']],
            'Reserved': [0x10, ['pointer64', ['void']]],
            'WatchInfo': [
                0x18,
                ['array', 1, ['_PROCESS_WS_WATCH_INFORMATION']],
            ],
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
            'Name': [0x10, ['array', 1, ['unsigned short']]],
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
            'Filler': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
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
    '_OBJECT_CREATE_INFORMATION': [
        0x48,
        {
            'Attributes': [0x0, ['unsigned long']],
            'RootDirectory': [0x8, ['pointer64', ['void']]],
            'ParseContext': [0x10, ['pointer64', ['void']]],
            'ProbeMode': [0x18, ['unsigned char']],
            'PagedPoolCharge': [0x1C, ['unsigned long']],
            'NonPagedPoolCharge': [0x20, ['unsigned long']],
            'SecurityDescriptorCharge': [0x24, ['unsigned long']],
            'SecurityDescriptor': [0x28, ['pointer64', ['void']]],
            'SecurityQos': [
                0x30,
                ['pointer64', ['_SECURITY_QUALITY_OF_SERVICE']],
            ],
            'SecurityQualityOfService': [
                0x38,
                ['_SECURITY_QUALITY_OF_SERVICE'],
            ],
        },
    ],
    '_WMI_BUFFER_STATE': [
        0x4,
        {
            'Free': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'InUse': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'Flush': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '_MMFREE_POOL_ENTRY': [
        0x28,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'Size': [0x10, ['unsigned long long']],
            'Signature': [0x18, ['unsigned long']],
            'Owner': [0x20, ['pointer64', ['_MMFREE_POOL_ENTRY']]],
        },
    ],
    '__unnamed_15d3': [
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
            'Queue': [0x50, ['__unnamed_15d3']],
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
    '_SECTION_OBJECT_POINTERS': [
        0x18,
        {
            'DataSectionObject': [0x0, ['pointer64', ['void']]],
            'SharedCacheMap': [0x8, ['pointer64', ['void']]],
            'ImageSectionObject': [0x10, ['pointer64', ['void']]],
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
    '_PEB32': [
        0x230,
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
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
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
            'SparePtr2': [0x24, ['unsigned long']],
            'EnvironmentUpdateCount': [0x28, ['unsigned long']],
            'KernelCallbackTable': [0x2C, ['unsigned long']],
            'SystemReserved': [0x30, ['array', 1, ['unsigned long']]],
            'SpareUlong': [0x34, ['unsigned long']],
            'FreeList': [0x38, ['unsigned long']],
            'TlsExpansionCounter': [0x3C, ['unsigned long']],
            'TlsBitmap': [0x40, ['unsigned long']],
            'TlsBitmapBits': [0x44, ['array', 2, ['unsigned long']]],
            'ReadOnlySharedMemoryBase': [0x4C, ['unsigned long']],
            'ReadOnlySharedMemoryHeap': [0x50, ['unsigned long']],
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
            'ImageProcessAffinityMask': [0xC0, ['unsigned long']],
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
        },
    ],
    '_MBCB': [
        0xB8,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeIsInZone': [0x2, ['short']],
            'PagesToWrite': [0x4, ['unsigned long']],
            'DirtyPages': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
            'BitmapRanges': [0x10, ['_LIST_ENTRY']],
            'ResumeWritePage': [0x20, ['long long']],
            'BitmapRange1': [0x28, ['_BITMAP_RANGE']],
            'BitmapRange2': [0x58, ['_BITMAP_RANGE']],
            'BitmapRange3': [0x88, ['_BITMAP_RANGE']],
        },
    ],
    '_POWER_CHANNEL_SUMMARY': [
        0x20,
        {
            'Signature': [0x0, ['unsigned long']],
            'TotalCount': [0x4, ['unsigned long']],
            'D0Count': [0x8, ['unsigned long']],
            'NotifyList': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_CM_VIEW_OF_FILE': [
        0x40,
        {
            'LRUViewList': [0x0, ['_LIST_ENTRY']],
            'PinViewList': [0x10, ['_LIST_ENTRY']],
            'FileOffset': [0x20, ['unsigned long']],
            'Size': [0x24, ['unsigned long']],
            'ViewAddress': [0x28, ['pointer64', ['unsigned long long']]],
            'Bcb': [0x30, ['pointer64', ['void']]],
            'UseCount': [0x38, ['unsigned long']],
        },
    ],
    '_SLIST_ENTRY': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
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
    '_KUSER_SHARED_DATA': [
        0x378,
        {
            'TickCountLowDeprecated': [0x0, ['unsigned long']],
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
            'Wow64SharedInformation': [
                0x334,
                ['array', 16, ['unsigned long']],
            ],
        },
    ],
    '_OBJECT_TYPE_INITIALIZER': [
        0x70,
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
    '_WMI_LOGGER_MODE': [
        0x4,
        {
            'SequentialFile': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'CircularFile': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'AppendFile': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'Unused1': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'RealTime': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'DelayOpenFile': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'BufferOnly': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'PrivateLogger': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'AddHeader': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'UseExisting': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'UseGlobalSequence': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'UseLocalSequence': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'Unused2': [
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
    '_KPROCESSOR_STATE': [
        0x5B0,
        {
            'SpecialRegisters': [0x0, ['_KSPECIAL_REGISTERS']],
            'ContextFrame': [0xE0, ['_CONTEXT']],
        },
    ],
    '__unnamed_162d': [
        0x10,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'Secured': [0x0, ['_MMADDRESS_LIST']],
        },
    ],
    '__unnamed_1633': [
        0x8,
        {
            'Banked': [0x0, ['pointer64', ['_MMBANKED_SECTION']]],
            'ExtendedInfo': [0x0, ['pointer64', ['_MMEXTEND_INFO']]],
        },
    ],
    '_MMVAD_LONG': [
        0x68,
        {
            'u1': [0x0, ['__unnamed_1180']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_1183']],
            'ControlArea': [0x30, ['pointer64', ['_CONTROL_AREA']]],
            'FirstPrototypePte': [0x38, ['pointer64', ['_MMPTE']]],
            'LastContiguousPte': [0x40, ['pointer64', ['_MMPTE']]],
            'u2': [0x48, ['__unnamed_1188']],
            'u3': [0x50, ['__unnamed_162d']],
            'u4': [0x60, ['__unnamed_1633']],
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
    '_POOL_DESCRIPTOR': [
        0x1048,
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
            'LockAddress': [0x20, ['pointer64', ['void']]],
            'PendingFrees': [0x28, ['pointer64', ['void']]],
            'PendingFreeDepth': [0x30, ['long']],
            'TotalBytes': [0x38, ['unsigned long long']],
            'Spare0': [0x40, ['unsigned long long']],
            'ListHeads': [0x48, ['array', 256, ['_LIST_ENTRY']]],
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
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
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
    '_WOW64_PROCESS': [
        0x8,
        {
            'Wow64': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_PEB_LDR_DATA': [
        0x48,
        {
            'Length': [0x0, ['unsigned long']],
            'Initialized': [0x4, ['unsigned char']],
            'SsHandle': [0x8, ['pointer64', ['void']]],
            'InLoadOrderModuleList': [0x10, ['_LIST_ENTRY']],
            'InMemoryOrderModuleList': [0x20, ['_LIST_ENTRY']],
            'InInitializationOrderModuleList': [0x30, ['_LIST_ENTRY']],
            'EntryInProgress': [0x40, ['pointer64', ['void']]],
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
    '_MM_PAGED_POOL_INFO': [
        0x40,
        {
            'PagedPoolAllocationMap': [0x0, ['pointer64', ['_RTL_BITMAP']]],
            'EndOfPagedPoolBitmap': [0x8, ['pointer64', ['_RTL_BITMAP']]],
            'FirstPteForPagedPool': [0x10, ['pointer64', ['_MMPTE']]],
            'LastPteForPagedPool': [0x18, ['pointer64', ['_MMPTE']]],
            'NextPdeForPagedPoolExpansion': [0x20, ['pointer64', ['_MMPTE']]],
            'PagedPoolHint': [0x28, ['unsigned long']],
            'PagedPoolCommit': [0x30, ['unsigned long long']],
            'AllocatedPagedPool': [0x38, ['unsigned long long']],
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
            'VolumeLabel': [0x20, ['array', 32, ['unsigned short']]],
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
    '_MMSESSION': [
        0x68,
        {
            'SystemSpaceViewLock': [0x0, ['_KGUARDED_MUTEX']],
            'SystemSpaceViewLockPointer': [
                0x38,
                ['pointer64', ['_KGUARDED_MUTEX']],
            ],
            'SystemSpaceViewStart': [0x40, ['pointer64', ['unsigned char']]],
            'SystemSpaceViewTable': [0x48, ['pointer64', ['_MMVIEW']]],
            'SystemSpaceHashSize': [0x50, ['unsigned long']],
            'SystemSpaceHashEntries': [0x54, ['unsigned long']],
            'SystemSpaceHashKey': [0x58, ['unsigned long']],
            'BitmapFailures': [0x5C, ['unsigned long']],
            'SystemSpaceBitMap': [0x60, ['pointer64', ['_RTL_BITMAP']]],
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
    '_DBGKD_RESTORE_BREAKPOINT': [
        0x4,
        {
            'BreakPointHandle': [0x0, ['unsigned long']],
        },
    ],
    '_EXCEPTION_REGISTRATION_RECORD': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_EXCEPTION_REGISTRATION_RECORD']]],
            'Handler': [0x8, ['pointer64', ['void']]],
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
    '_POOL_TRACKER_BIG_PAGES': [
        0x18,
        {
            'Va': [0x0, ['pointer64', ['void']]],
            'Key': [0x8, ['unsigned long']],
            'NumberOfPages': [0xC, ['unsigned long']],
            'QuotaObject': [0x10, ['pointer64', ['void']]],
        },
    ],
    '_PROCESS_WS_WATCH_INFORMATION': [
        0x10,
        {
            'FaultingPc': [0x0, ['pointer64', ['void']]],
            'FaultingVa': [0x8, ['pointer64', ['void']]],
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
            'Active': [
                0x48,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'OnlyTryAcquireUsed': [
                0x48,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ReleasedOutOfOrder': [
                0x48,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'SequenceNumber': [
                0x48,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'StackTrace': [0x50, ['array', 8, ['pointer64', ['void']]]],
            'ParentStackTrace': [0x90, ['array', 8, ['pointer64', ['void']]]],
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
            'FltSave': [0x100, ['_XMM_SAVE_AREA32']],
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
    '_MMPTE_HARDWARE_LARGEPAGE': [
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
            'PAT': [
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
            'reserved1': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=13,
                        end_bit=21,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'PageFrameNumber': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21,
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'reserved2': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
            ],
        },
    ],
    '_DBGKD_QUERY_SPECIAL_CALLS': [
        0x4,
        {
            'NumberOfSpecialCalls': [0x0, ['unsigned long']],
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
    '_PCI_PDO_EXTENSION': [
        0x120,
        {
            'Next': [0x0, ['pointer64', ['_PCI_PDO_EXTENSION']]],
            'ExtensionType': [
                0x8,
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
                            1768116286: 'PciInterface_Location',
                            1768116287: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'IrpDispatchTable': [
                0x10,
                ['pointer64', ['_PCI_MJ_DISPATCH_TABLE']],
            ],
            'DeviceState': [0x18, ['unsigned char']],
            'TentativeNextState': [0x19, ['unsigned char']],
            'SecondaryExtLock': [0x20, ['_KEVENT']],
            'Slot': [0x38, ['_PCI_SLOT_NUMBER']],
            'PhysicalDeviceObject': [0x40, ['pointer64', ['_DEVICE_OBJECT']]],
            'ParentFdoExtension': [
                0x48,
                ['pointer64', ['_PCI_FDO_EXTENSION']],
            ],
            'SecondaryExtension': [0x50, ['_SINGLE_LIST_ENTRY']],
            'BusInterfaceReferenceCount': [0x58, ['unsigned long']],
            'AgpInterfaceReferenceCount': [0x5C, ['unsigned long']],
            'VendorId': [0x60, ['unsigned short']],
            'DeviceId': [0x62, ['unsigned short']],
            'SubsystemVendorId': [0x64, ['unsigned short']],
            'SubsystemId': [0x66, ['unsigned short']],
            'RevisionId': [0x68, ['unsigned char']],
            'ProgIf': [0x69, ['unsigned char']],
            'SubClass': [0x6A, ['unsigned char']],
            'BaseClass': [0x6B, ['unsigned char']],
            'AdditionalResourceCount': [0x6C, ['unsigned char']],
            'AdjustedInterruptLine': [0x6D, ['unsigned char']],
            'InterruptPin': [0x6E, ['unsigned char']],
            'RawInterruptLine': [0x6F, ['unsigned char']],
            'CapabilitiesPtr': [0x70, ['unsigned char']],
            'SavedLatencyTimer': [0x71, ['unsigned char']],
            'SavedCacheLineSize': [0x72, ['unsigned char']],
            'HeaderType': [0x73, ['unsigned char']],
            'NotPresent': [0x74, ['unsigned char']],
            'ReportedMissing': [0x75, ['unsigned char']],
            'ExpectedWritebackFailure': [0x76, ['unsigned char']],
            'NoTouchPmeEnable': [0x77, ['unsigned char']],
            'LegacyDriver': [0x78, ['unsigned char']],
            'UpdateHardware': [0x79, ['unsigned char']],
            'MovedDevice': [0x7A, ['unsigned char']],
            'DisablePowerDown': [0x7B, ['unsigned char']],
            'NeedsHotPlugConfiguration': [0x7C, ['unsigned char']],
            'IDEInNativeMode': [0x7D, ['unsigned char']],
            'BIOSAllowsIDESwitchToNativeMode': [0x7E, ['unsigned char']],
            'IoSpaceUnderNativeIdeControl': [0x7F, ['unsigned char']],
            'OnDebugPath': [0x80, ['unsigned char']],
            'IoSpaceNotRequired': [0x81, ['unsigned char']],
            'PowerState': [0x88, ['PCI_POWER_STATE']],
            'Dependent': [0xD8, ['PCI_HEADER_TYPE_DEPENDENT']],
            'HackFlags': [0xE0, ['unsigned long long']],
            'Resources': [0xE8, ['pointer64', ['PCI_FUNCTION_RESOURCES']]],
            'BridgeFdoExtension': [
                0xF0,
                ['pointer64', ['_PCI_FDO_EXTENSION']],
            ],
            'NextBridge': [0xF8, ['pointer64', ['_PCI_PDO_EXTENSION']]],
            'NextHashEntry': [0x100, ['pointer64', ['_PCI_PDO_EXTENSION']]],
            'Lock': [0x108, ['_PCI_LOCK']],
            'PowerCapabilities': [0x118, ['_PCI_PMC']],
            'TargetAgpCapabilityId': [0x11A, ['unsigned char']],
            'CommandEnables': [0x11C, ['unsigned short']],
            'InitialCommand': [0x11E, ['unsigned short']],
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
    '__unnamed_16a5': [
        0x10,
        {
            'UserData': [0x0, ['pointer64', ['void']]],
            'Owner': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_16a7': [
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
            'Allocated': [0x10, ['__unnamed_16a5']],
            'Merged': [0x10, ['__unnamed_16a7']],
            'Attributes': [0x20, ['unsigned char']],
            'PublicFlags': [0x21, ['unsigned char']],
            'PrivateFlags': [0x22, ['unsigned short']],
            'ListEntry': [0x28, ['_LIST_ENTRY']],
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
    '_DEVICE_RELATIONS': [
        0x10,
        {
            'Count': [0x0, ['unsigned long']],
            'Objects': [0x8, ['array', 1, ['pointer64', ['_DEVICE_OBJECT']]]],
        },
    ],
    '_DEVICE_MAP': [
        0x38,
        {
            'DosDevicesDirectory': [0x0, ['pointer64', ['_OBJECT_DIRECTORY']]],
            'GlobalDosDevicesDirectory': [
                0x8,
                ['pointer64', ['_OBJECT_DIRECTORY']],
            ],
            'ReferenceCount': [0x10, ['unsigned long']],
            'DriveMap': [0x14, ['unsigned long']],
            'DriveType': [0x18, ['array', 32, ['unsigned char']]],
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
    '__unnamed_16d2': [
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
        0x130,
        {
            'List': [0x0, ['_SINGLE_LIST_ENTRY']],
            'ExtensionType': [
                0x8,
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
                            1768116286: 'PciInterface_Location',
                            1768116287: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'IrpDispatchTable': [
                0x10,
                ['pointer64', ['_PCI_MJ_DISPATCH_TABLE']],
            ],
            'DeviceState': [0x18, ['unsigned char']],
            'TentativeNextState': [0x19, ['unsigned char']],
            'SecondaryExtLock': [0x20, ['_KEVENT']],
            'PhysicalDeviceObject': [0x38, ['pointer64', ['_DEVICE_OBJECT']]],
            'FunctionalDeviceObject': [
                0x40,
                ['pointer64', ['_DEVICE_OBJECT']],
            ],
            'AttachedDeviceObject': [0x48, ['pointer64', ['_DEVICE_OBJECT']]],
            'ChildListLock': [0x50, ['_KEVENT']],
            'ChildPdoList': [0x68, ['pointer64', ['_PCI_PDO_EXTENSION']]],
            'BusRootFdoExtension': [
                0x70,
                ['pointer64', ['_PCI_FDO_EXTENSION']],
            ],
            'ParentFdoExtension': [
                0x78,
                ['pointer64', ['_PCI_FDO_EXTENSION']],
            ],
            'ChildBridgePdoList': [
                0x80,
                ['pointer64', ['_PCI_PDO_EXTENSION']],
            ],
            'PciBusInterface': [
                0x88,
                ['pointer64', ['_PCI_BUS_INTERFACE_STANDARD']],
            ],
            'MaxSubordinateBus': [0x90, ['unsigned char']],
            'BusHandler': [0x98, ['pointer64', ['_BUS_HANDLER']]],
            'BaseBus': [0xA0, ['unsigned char']],
            'Fake': [0xA1, ['unsigned char']],
            'ChildDelete': [0xA2, ['unsigned char']],
            'Scanned': [0xA3, ['unsigned char']],
            'ArbitersInitialized': [0xA4, ['unsigned char']],
            'BrokenVideoHackApplied': [0xA5, ['unsigned char']],
            'Hibernated': [0xA6, ['unsigned char']],
            'PowerState': [0xA8, ['PCI_POWER_STATE']],
            'SecondaryExtension': [0xF8, ['_SINGLE_LIST_ENTRY']],
            'ChildWaitWakeCount': [0x100, ['unsigned long']],
            'PreservedConfig': [0x108, ['pointer64', ['_PCI_COMMON_CONFIG']]],
            'Lock': [0x110, ['_PCI_LOCK']],
            'HotPlugParameters': [0x120, ['__unnamed_16d2']],
            'BusHackFlags': [0x128, ['unsigned long']],
        },
    ],
    '__unnamed_16d6': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_16d8': [
        0x10,
        {
            'Level': [0x0, ['unsigned long']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_16da': [
        0xC,
        {
            'Channel': [0x0, ['unsigned long']],
            'Port': [0x4, ['unsigned long']],
            'Reserved1': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_16dc': [
        0xC,
        {
            'Data': [0x0, ['array', 3, ['unsigned long']]],
        },
    ],
    '__unnamed_16de': [
        0xC,
        {
            'Start': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_16e0': [
        0xC,
        {
            'DataSize': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_16e2': [
        0x10,
        {
            'Generic': [0x0, ['__unnamed_16d6']],
            'Port': [0x0, ['__unnamed_16d6']],
            'Interrupt': [0x0, ['__unnamed_16d8']],
            'Memory': [0x0, ['__unnamed_16d6']],
            'Dma': [0x0, ['__unnamed_16da']],
            'DevicePrivate': [0x0, ['__unnamed_16dc']],
            'BusNumber': [0x0, ['__unnamed_16de']],
            'DeviceSpecificData': [0x0, ['__unnamed_16e0']],
        },
    ],
    '_CM_PARTIAL_RESOURCE_DESCRIPTOR': [
        0x14,
        {
            'Type': [0x0, ['unsigned char']],
            'ShareDisposition': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned short']],
            'u': [0x4, ['__unnamed_16e2']],
        },
    ],
    '_SYSPTES_HEADER': [
        0x18,
        {
            'ListHead': [0x0, ['_LIST_ENTRY']],
            'Count': [0x10, ['unsigned long long']],
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
    '_REQUEST_MAILBOX': [
        0x40,
        {
            'RequestSummary': [0x0, ['long long']],
            'RequestPacket': [0x8, ['_KREQUEST_PACKET']],
            'Virtual': [0x8, ['array', 7, ['pointer64', ['void']]]],
        },
    ],
    '_CM_KEY_CONTROL_BLOCK': [
        0xB0,
        {
            'RefCount': [0x0, ['unsigned long']],
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
            'NextHash': [0x10, ['pointer64', ['_CM_KEY_HASH']]],
            'KeyHive': [0x18, ['pointer64', ['_HHIVE']]],
            'KeyCell': [0x20, ['unsigned long']],
            'ParentKcb': [0x28, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'NameBlock': [0x30, ['pointer64', ['_CM_NAME_CONTROL_BLOCK']]],
            'CachedSecurity': [
                0x38,
                ['pointer64', ['_CM_KEY_SECURITY_CACHE']],
            ],
            'ValueCache': [0x40, ['_CACHED_CHILD_LIST']],
            'IndexHint': [0x50, ['pointer64', ['_CM_INDEX_HINT_BLOCK']]],
            'HashKey': [0x50, ['unsigned long']],
            'SubKeyCount': [0x50, ['unsigned long']],
            'KeyBodyListHead': [0x58, ['_LIST_ENTRY']],
            'FreeListEntry': [0x58, ['_LIST_ENTRY']],
            'KeyBodyArray': [
                0x68,
                ['array', 4, ['pointer64', ['_CM_KEY_BODY']]],
            ],
            'DelayCloseEntry': [0x88, ['pointer64', ['void']]],
            'KcbLastWriteTime': [0x90, ['_LARGE_INTEGER']],
            'KcbMaxNameLen': [0x98, ['unsigned short']],
            'KcbMaxValueNameLen': [0x9A, ['unsigned short']],
            'KcbMaxValueDataLen': [0x9C, ['unsigned long']],
            'KcbUserFlags': [
                0xA0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'KcbVirtControlFlags': [
                0xA0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'KcbDebug': [
                0xA0,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=16, native_type='unsigned long'),
                ],
            ],
            'Flags': [
                0xA0,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'RealKeyName': [0xA8, ['pointer64', ['unsigned char']]],
        },
    ],
    '_M128A': [
        0x10,
        {
            'Low': [0x0, ['unsigned long long']],
            'High': [0x8, ['long long']],
        },
    ],
    '_PCI_BUS_INTERFACE_STANDARD': [
        0x40,
        {
            'Size': [0x0, ['unsigned short']],
            'Version': [0x2, ['unsigned short']],
            'Context': [0x8, ['pointer64', ['void']]],
            'InterfaceReference': [0x10, ['pointer64', ['void']]],
            'InterfaceDereference': [0x18, ['pointer64', ['void']]],
            'ReadConfig': [0x20, ['pointer64', ['void']]],
            'WriteConfig': [0x28, ['pointer64', ['void']]],
            'PinToLine': [0x30, ['pointer64', ['void']]],
            'LineToPin': [0x38, ['pointer64', ['void']]],
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
    '_PI_RESOURCE_ARBITER_ENTRY': [
        0x70,
        {
            'DeviceArbiterList': [0x0, ['_LIST_ENTRY']],
            'ResourceType': [0x10, ['unsigned char']],
            'ArbiterInterface': [0x18, ['pointer64', ['_ARBITER_INTERFACE']]],
            'Level': [0x20, ['unsigned long']],
            'ResourceList': [0x28, ['_LIST_ENTRY']],
            'BestResourceList': [0x38, ['_LIST_ENTRY']],
            'BestConfig': [0x48, ['_LIST_ENTRY']],
            'ActiveArbiterList': [0x58, ['_LIST_ENTRY']],
            'State': [0x68, ['unsigned char']],
            'ResourcesChanged': [0x69, ['unsigned char']],
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
    '_CM_KEY_HASH': [
        0x20,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x8, ['pointer64', ['_CM_KEY_HASH']]],
            'KeyHive': [0x10, ['pointer64', ['_HHIVE']]],
            'KeyCell': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1726': [
        0x8,
        {
            'MasterIrp': [0x0, ['pointer64', ['_IRP']]],
            'IrpCount': [0x0, ['long']],
            'SystemBuffer': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_172b': [
        0x10,
        {
            'UserApcRoutine': [0x0, ['pointer64', ['void']]],
            'UserApcContext': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_172d': [
        0x10,
        {
            'AsynchronousParameters': [0x0, ['__unnamed_172b']],
            'AllocationSize': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1735': [
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
    '__unnamed_1737': [
        0x58,
        {
            'Overlay': [0x0, ['__unnamed_1735']],
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
            'AssociatedIrp': [0x18, ['__unnamed_1726']],
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
            'Overlay': [0x58, ['__unnamed_172d']],
            'CancelRoutine': [0x68, ['pointer64', ['void']]],
            'UserBuffer': [0x70, ['pointer64', ['void']]],
            'Tail': [0x78, ['__unnamed_1737']],
        },
    ],
    '_PCI_LOCK': [
        0x10,
        {
            'Atom': [0x0, ['unsigned long long']],
            'OldIrql': [0x8, ['unsigned char']],
        },
    ],
    '_CM_KEY_SECURITY_CACHE_ENTRY': [
        0x10,
        {
            'Cell': [0x0, ['unsigned long']],
            'CachedSecurity': [0x8, ['pointer64', ['_CM_KEY_SECURITY_CACHE']]],
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
    '__unnamed_1744': [
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
            'Misc': [0x8, ['__unnamed_1744']],
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
    '__unnamed_174a': [
        0x4,
        {
            'Level': [0x0, ['unsigned long']],
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
            'Battery': [0x8, ['__unnamed_174a']],
            'Wait': [0x8, ['pointer64', ['_POP_TRIGGER_WAIT']]],
        },
    ],
    '_ETIMER': [
        0x108,
        {
            'KeTimer': [0x0, ['_KTIMER']],
            'TimerApc': [0x40, ['_KAPC']],
            'TimerDpc': [0x98, ['_KDPC']],
            'ActiveTimerListEntry': [0xD8, ['_LIST_ENTRY']],
            'Lock': [0xE8, ['unsigned long long']],
            'Period': [0xF0, ['long']],
            'ApcAssociated': [0xF4, ['unsigned char']],
            'WakeTimer': [0xF5, ['unsigned char']],
            'WakeTimerListEntry': [0xF8, ['_LIST_ENTRY']],
        },
    ],
    '_DBGKD_BREAKPOINTEX': [
        0x8,
        {
            'BreakPointCount': [0x0, ['unsigned long']],
            'ContinueStatus': [0x4, ['long']],
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
    '__unnamed_1764': [
        0x8,
        {
            'VirtualAddress': [0x0, ['pointer64', ['void']]],
            'Long': [0x0, ['unsigned long long']],
            'e1': [0x0, ['_MMWSLENTRY']],
        },
    ],
    '_MMWSLE': [
        0x8,
        {
            'u1': [0x0, ['__unnamed_1764']],
        },
    ],
    '_EXCEPTION_POINTERS': [
        0x10,
        {
            'ExceptionRecord': [0x0, ['pointer64', ['_EXCEPTION_RECORD']]],
            'ContextRecord': [0x8, ['pointer64', ['_CONTEXT']]],
        },
    ],
    '__unnamed_176c': [
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
            'u1': [0x0, ['__unnamed_176c']],
            'LeftChild': [0x8, ['pointer64', ['_MMADDRESS_NODE']]],
            'RightChild': [0x10, ['pointer64', ['_MMADDRESS_NODE']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
        },
    ],
    '_RTL_USER_PROCESS_PARAMETERS': [
        0x3F0,
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
    '_CELL_DATA': [
        0x50,
        {
            'u': [0x0, ['_u']],
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
                            6: 'VfDeadlockQueuedSpinLock',
                            7: 'VfDeadlockTypeMaximum',
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
    '_OBJECT_HANDLE_COUNT_ENTRY': [
        0x10,
        {
            'Process': [0x0, ['pointer64', ['_EPROCESS']]],
            'HandleCount': [0x8, ['unsigned long']],
        },
    ],
    '_CLIENT_ID': [
        0x10,
        {
            'UniqueProcess': [0x0, ['pointer64', ['void']]],
            'UniqueThread': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_PEB_FREE_BLOCK': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_PEB_FREE_BLOCK']]],
            'Size': [0x8, ['unsigned long']],
        },
    ],
    '_PO_DEVICE_NOTIFY': [
        0x48,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'TargetDevice': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'WakeNeeded': [0x18, ['unsigned char']],
            'OrderLevel': [0x19, ['unsigned char']],
            'DeviceObject': [0x20, ['pointer64', ['_DEVICE_OBJECT']]],
            'Node': [0x28, ['pointer64', ['void']]],
            'DeviceName': [0x30, ['pointer64', ['unsigned short']]],
            'DriverName': [0x38, ['pointer64', ['unsigned short']]],
            'ChildCount': [0x40, ['unsigned long']],
            'ActiveChild': [0x44, ['unsigned long']],
        },
    ],
    '_MMPFNLIST': [
        0x20,
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
        },
    ],
    '__unnamed_1795': [
        0x4,
        {
            'Spare': [0x0, ['array', 4, ['unsigned char']]],
        },
    ],
    '__unnamed_1797': [
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
            'type0': [0x0, ['__unnamed_1795']],
            'type1': [0x0, ['__unnamed_1797']],
            'type2': [0x0, ['__unnamed_1797']],
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
    '_KINTERRUPT': [
        0x80,
        {
            'Type': [0x0, ['short']],
            'Size': [0x2, ['short']],
            'InterruptListEntry': [0x8, ['_LIST_ENTRY']],
            'ServiceRoutine': [0x18, ['pointer64', ['void']]],
            'ServiceContext': [0x20, ['pointer64', ['void']]],
            'SpinLock': [0x28, ['unsigned long long']],
            'TickCount': [0x30, ['unsigned long']],
            'ActualLock': [0x38, ['pointer64', ['unsigned long long']]],
            'DispatchAddress': [0x40, ['pointer64', ['void']]],
            'Vector': [0x48, ['unsigned long']],
            'Irql': [0x4C, ['unsigned char']],
            'SynchronizeIrql': [0x4D, ['unsigned char']],
            'FloatingSave': [0x4E, ['unsigned char']],
            'Connected': [0x4F, ['unsigned char']],
            'Number': [0x50, ['unsigned char']],
            'ShareVector': [0x51, ['unsigned char']],
            'Mode': [
                0x54,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'LevelSensitive', 1: 'Latched'},
                    ),
                ],
            ],
            'ServiceCount': [0x58, ['unsigned long']],
            'DispatchCount': [0x5C, ['unsigned long']],
            'TrapFrame': [0x60, ['pointer64', ['_KTRAP_FRAME']]],
            'Reserved': [0x68, ['pointer64', ['void']]],
            'DispatchCode': [0x70, ['array', 4, ['unsigned long']]],
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
    '_PCI_ARBITER_INSTANCE': [
        0x190,
        {
            'Header': [0x0, ['PCI_SECONDARY_EXTENSION']],
            'Interface': [0x18, ['pointer64', ['_PCI_INTERFACE']]],
            'BusFdoExtension': [0x20, ['pointer64', ['_PCI_FDO_EXTENSION']]],
            'InstanceName': [0x28, ['array', 24, ['unsigned short']]],
            'CommonInstance': [0x58, ['_ARBITER_INSTANCE']],
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
    '_HANDLE_TRACE_DB_ENTRY': [
        0xA0,
        {
            'ClientId': [0x0, ['_CLIENT_ID']],
            'Handle': [0x10, ['pointer64', ['void']]],
            'Type': [0x18, ['unsigned long']],
            'StackTrace': [0x20, ['array', 16, ['pointer64', ['void']]]],
        },
    ],
    '_BUS_EXTENSION_LIST': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['void']]],
            'BusExtension': [0x8, ['pointer64', ['_PI_BUS_EXTENSION']]],
        },
    ],
    '_PCI_MJ_DISPATCH_TABLE': [
        0x40,
        {
            'PnpIrpMaximumMinorFunction': [0x0, ['unsigned long']],
            'PnpIrpDispatchTable': [
                0x8,
                ['pointer64', ['_PCI_MN_DISPATCH_TABLE']],
            ],
            'PowerIrpMaximumMinorFunction': [0x10, ['unsigned long']],
            'PowerIrpDispatchTable': [
                0x18,
                ['pointer64', ['_PCI_MN_DISPATCH_TABLE']],
            ],
            'SystemControlIrpDispatchStyle': [
                0x20,
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
            'SystemControlIrpDispatchFunction': [
                0x28,
                ['pointer64', ['void']],
            ],
            'OtherIrpDispatchStyle': [
                0x30,
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
            'OtherIrpDispatchFunction': [0x38, ['pointer64', ['void']]],
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
            'LockedInWs': [
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
            'LockedInMemory': [
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
            'Protection': [
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
            'Hashed': [
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
            'Direct': [
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
            'Age': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=10,
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
    '__unnamed_17da': [
        0x4,
        {
            'BaseMiddle': [0x0, ['unsigned char']],
            'Flags1': [0x1, ['unsigned char']],
            'Flags2': [0x2, ['unsigned char']],
            'BaseHigh': [0x3, ['unsigned char']],
        },
    ],
    '__unnamed_17de': [
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
            'Bytes': [0x4, ['__unnamed_17da']],
            'Bits': [0x4, ['__unnamed_17de']],
            'BaseUpper': [0x8, ['unsigned long']],
            'MustBeZero': [0xC, ['unsigned long']],
            'Alignment': [0x0, ['unsigned long long']],
        },
    ],
    '_OBJECT_DIRECTORY': [
        0x140,
        {
            'HashBuckets': [
                0x0,
                ['array', 37, ['pointer64', ['_OBJECT_DIRECTORY_ENTRY']]],
            ],
            'Lock': [0x128, ['_EX_PUSH_LOCK']],
            'DeviceMap': [0x130, ['pointer64', ['_DEVICE_MAP']]],
            'SessionId': [0x138, ['unsigned long']],
        },
    ],
    '_WMI_CLIENT_CONTEXT': [
        0x4,
        {
            'ProcessorNumber': [0x0, ['unsigned char']],
            'Alignment': [0x1, ['unsigned char']],
            'LoggerId': [0x2, ['unsigned short']],
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
    '_AMD64_DBGKD_CONTROL_SET': [
        0x1C,
        {
            'TraceFlag': [0x0, ['unsigned long']],
            'Dr7': [0x4, ['unsigned long long']],
            'CurrentSymbolStart': [0xC, ['unsigned long long']],
            'CurrentSymbolEnd': [0x14, ['unsigned long long']],
        },
    ],
    '_CALL_PERFORMANCE_DATA': [
        0x408,
        {
            'SpinLock': [0x0, ['unsigned long long']],
            'HashTable': [0x8, ['array', 64, ['_LIST_ENTRY']]],
        },
    ],
    '_MMWSL': [
        0x80,
        {
            'FirstFree': [0x0, ['unsigned long']],
            'FirstDynamic': [0x4, ['unsigned long']],
            'LastEntry': [0x8, ['unsigned long']],
            'NextSlot': [0xC, ['unsigned long']],
            'Wsle': [0x10, ['pointer64', ['_MMWSLE']]],
            'LastInitializedWsle': [0x18, ['unsigned long']],
            'NonDirectCount': [0x1C, ['unsigned long']],
            'HashTable': [0x20, ['pointer64', ['_MMWSLE_HASH']]],
            'HashTableSize': [0x28, ['unsigned long']],
            'NumberOfCommittedPageTables': [0x2C, ['unsigned long']],
            'HashTableStart': [0x30, ['pointer64', ['void']]],
            'HighestPermittedHashAddress': [0x38, ['pointer64', ['void']]],
            'NumberOfImageWaiters': [0x40, ['unsigned long']],
            'VadBitMapHint': [0x44, ['unsigned long']],
            'HighestUserAddress': [0x48, ['pointer64', ['void']]],
            'MaximumUserPageTablePages': [0x50, ['unsigned long']],
            'MaximumUserPageDirectoryPages': [0x54, ['unsigned long']],
            'CommittedPageTables': [0x58, ['pointer64', ['unsigned long']]],
            'NumberOfCommittedPageDirectories': [0x60, ['unsigned long']],
            'CommittedPageDirectories': [
                0x68,
                ['pointer64', ['unsigned long']],
            ],
            'NumberOfCommittedPageDirectoryParents': [0x70, ['unsigned long']],
            'CommittedPageDirectoryParents': [
                0x78,
                ['array', 1, ['unsigned long long']],
            ],
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
    '_RTL_DRIVE_LETTER_CURDIR': [
        0x18,
        {
            'Flags': [0x0, ['unsigned short']],
            'Length': [0x2, ['unsigned short']],
            'TimeStamp': [0x4, ['unsigned long']],
            'DosPath': [0x8, ['_STRING']],
        },
    ],
    'PCI_FUNCTION_RESOURCES': [
        0x170,
        {
            'Limit': [0x0, ['array', 7, ['_IO_RESOURCE_DESCRIPTOR']]],
            'Current': [
                0xE0,
                ['array', 7, ['_CM_PARTIAL_RESOURCE_DESCRIPTOR']],
            ],
        },
    ],
    '_WNODE_HEADER': [
        0x30,
        {
            'BufferSize': [0x0, ['unsigned long']],
            'ProviderId': [0x4, ['unsigned long']],
            'HistoricalContext': [0x8, ['unsigned long long']],
            'Version': [0x8, ['unsigned long']],
            'Linkage': [0xC, ['unsigned long']],
            'CountLost': [0x10, ['unsigned long']],
            'KernelHandle': [0x10, ['pointer64', ['void']]],
            'TimeStamp': [0x10, ['_LARGE_INTEGER']],
            'Guid': [0x18, ['_GUID']],
            'ClientContext': [0x28, ['unsigned long']],
            'Flags': [0x2C, ['unsigned long']],
        },
    ],
    '__unnamed_1811': [
        0x8,
        {
            'ImageCommitment': [0x0, ['unsigned long long']],
            'CreatingProcess': [0x0, ['pointer64', ['_EPROCESS']]],
        },
    ],
    '__unnamed_1815': [
        0x8,
        {
            'ImageInformation': [
                0x0,
                ['pointer64', ['_SECTION_IMAGE_INFORMATION']],
            ],
            'FirstMappedVa': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_SEGMENT': [
        0x68,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'NonExtendedPtes': [0xC, ['unsigned long']],
            'Spare0': [0x10, ['unsigned long']],
            'SizeOfSegment': [0x18, ['unsigned long long']],
            'SegmentPteTemplate': [0x20, ['_MMPTE']],
            'NumberOfCommittedPages': [0x28, ['unsigned long long']],
            'ExtendInfo': [0x30, ['pointer64', ['_MMEXTEND_INFO']]],
            'SegmentFlags': [0x38, ['_SEGMENT_FLAGS']],
            'BasedAddress': [0x40, ['pointer64', ['void']]],
            'u1': [0x48, ['__unnamed_1811']],
            'u2': [0x50, ['__unnamed_1815']],
            'PrototypePte': [0x58, ['pointer64', ['_MMPTE']]],
            'ThePtes': [0x60, ['array', 1, ['_MMPTE']]],
        },
    ],
    '_PCI_COMMON_EXTENSION': [
        0x38,
        {
            'Next': [0x0, ['pointer64', ['void']]],
            'ExtensionType': [
                0x8,
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
                            1768116286: 'PciInterface_Location',
                            1768116287: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'IrpDispatchTable': [
                0x10,
                ['pointer64', ['_PCI_MJ_DISPATCH_TABLE']],
            ],
            'DeviceState': [0x18, ['unsigned char']],
            'TentativeNextState': [0x19, ['unsigned char']],
            'SecondaryExtLock': [0x20, ['_KEVENT']],
        },
    ],
    '_MI_VERIFIER_DRIVER_ENTRY': [
        0xA0,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'Loads': [0x10, ['unsigned long']],
            'Unloads': [0x14, ['unsigned long']],
            'BaseName': [0x18, ['_UNICODE_STRING']],
            'StartAddress': [0x28, ['pointer64', ['void']]],
            'EndAddress': [0x30, ['pointer64', ['void']]],
            'Flags': [0x38, ['unsigned long']],
            'Signature': [0x40, ['unsigned long long']],
            'PoolPageHeaders': [0x50, ['_SLIST_HEADER']],
            'PoolTrackers': [0x60, ['_SLIST_HEADER']],
            'CurrentPagedPoolAllocations': [0x70, ['unsigned long']],
            'CurrentNonPagedPoolAllocations': [0x74, ['unsigned long']],
            'PeakPagedPoolAllocations': [0x78, ['unsigned long']],
            'PeakNonPagedPoolAllocations': [0x7C, ['unsigned long']],
            'PagedBytes': [0x80, ['unsigned long long']],
            'NonPagedBytes': [0x88, ['unsigned long long']],
            'PeakPagedBytes': [0x90, ['unsigned long long']],
            'PeakNonPagedBytes': [0x98, ['unsigned long long']],
        },
    ],
    '_PRIVATE_CACHE_MAP': [
        0x60,
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
            'ReadAheadOffset': [0x30, ['array', 2, ['_LARGE_INTEGER']]],
            'ReadAheadLength': [0x40, ['array', 2, ['unsigned long']]],
            'ReadAheadSpinLock': [0x48, ['unsigned long long']],
            'PrivateLinks': [0x50, ['_LIST_ENTRY']],
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
    '_POP_IDLE_HANDLER': [
        0x28,
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
            'IdleFunction': [0x20, ['pointer64', ['void']]],
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
        0x50,
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
    '_MMVIEW': [
        0x10,
        {
            'Entry': [0x0, ['unsigned long long']],
            'ControlArea': [0x8, ['pointer64', ['_CONTROL_AREA']]],
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
    'PCI_SECONDARY_EXTENSION': [
        0x18,
        {
            'List': [0x0, ['_SINGLE_LIST_ENTRY']],
            'ExtensionType': [
                0x8,
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
                            1768116286: 'PciInterface_Location',
                            1768116287: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'Destructor': [0x10, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1842': [
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
            'u': [0x10, ['__unnamed_1842']],
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
            'Spare1': [0x33, ['unsigned char']],
            'LoaderFlags': [0x34, ['unsigned long']],
            'ImageFileSize': [0x38, ['unsigned long']],
            'Reserved': [0x3C, ['array', 1, ['unsigned long']]],
        },
    ],
    '_POOL_TRACKER_TABLE': [
        0x28,
        {
            'Key': [0x0, ['unsigned long']],
            'NonPagedAllocs': [0x4, ['unsigned long']],
            'NonPagedFrees': [0x8, ['unsigned long']],
            'NonPagedBytes': [0x10, ['unsigned long long']],
            'PagedAllocs': [0x18, ['unsigned long']],
            'PagedFrees': [0x1C, ['unsigned long']],
            'PagedBytes': [0x20, ['unsigned long long']],
        },
    ],
    '_KNODE': [
        0x40,
        {
            'DeadStackList': [0x0, ['_SLIST_HEADER']],
            'PfnDereferenceSListHead': [0x10, ['_SLIST_HEADER']],
            'Alignment': [0x10, ['unsigned long long']],
            'ProcessorMask': [0x18, ['unsigned long long']],
            'Color': [0x20, ['unsigned char']],
            'Seed': [0x21, ['unsigned char']],
            'NodeNumber': [0x22, ['unsigned char']],
            'Flags': [0x23, ['_flags']],
            'MmShiftedColor': [0x24, ['unsigned long']],
            'FreeCount': [0x28, ['array', 2, ['unsigned long long']]],
            'PfnDeferredList': [0x38, ['pointer64', ['_SLIST_ENTRY']]],
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
    '_SEGMENT_FLAGS': [
        0x8,
        {
            'TotalNumberOfPtes4132': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=10,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ExtraSharedWowSubsections': [
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
            'LargePages': [
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
            'Spare': [
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
    '_CLIENT_ID32': [
        0x8,
        {
            'UniqueProcess': [0x0, ['unsigned long']],
            'UniqueThread': [0x4, ['unsigned long']],
        },
    ],
    '_VI_DEADLOCK_THREAD': [
        0x30,
        {
            'Thread': [0x0, ['pointer64', ['_KTHREAD']]],
            'CurrentSpinNode': [0x8, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            'CurrentOtherNode': [0x10, ['pointer64', ['_VI_DEADLOCK_NODE']]],
            'ListEntry': [0x18, ['_LIST_ENTRY']],
            'FreeListEntry': [0x18, ['_LIST_ENTRY']],
            'NodeCount': [0x28, ['unsigned long']],
            'PagingCount': [0x2C, ['unsigned long']],
        },
    ],
    '_MMEXTEND_INFO': [
        0x10,
        {
            'CommittedSize': [0x0, ['unsigned long long']],
            'ReferenceCount': [0x8, ['unsigned long']],
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
        0x28,
        {
            'InterfaceType': [0x0, ['pointer64', ['_GUID']]],
            'MinSize': [0x8, ['unsigned short']],
            'MinVersion': [0xA, ['unsigned short']],
            'MaxVersion': [0xC, ['unsigned short']],
            'Flags': [0xE, ['unsigned short']],
            'ReferenceCount': [0x10, ['long']],
            'Signature': [
                0x14,
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
                            1768116286: 'PciInterface_Location',
                            1768116287: 'PciInterface_AgpTarget',
                        },
                    ),
                ],
            ],
            'Constructor': [0x18, ['pointer64', ['void']]],
            'Initializer': [0x20, ['pointer64', ['void']]],
        },
    ],
    '_POP_POWER_ACTION': [
        0x50,
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
                ['pointer64', ['_POP_SHUTDOWN_BUG_CHECK']],
            ],
            'DevState': [0x28, ['pointer64', ['_POP_DEVICE_SYS_STATE']]],
            'HiberContext': [0x30, ['pointer64', ['_POP_HIBER_CONTEXT']]],
            'LastWakeState': [
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
            'WakeTime': [0x40, ['unsigned long long']],
            'SleepTime': [0x48, ['unsigned long long']],
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
    '_MMVAD_SHORT': [
        0x30,
        {
            'u1': [0x0, ['__unnamed_1180']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_1183']],
        },
    ],
    '__unnamed_188b': [
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
            'Privileges': [0x50, ['__unnamed_188b']],
            'AuditPrivileges': [0x7C, ['unsigned char']],
            'ObjectName': [0x80, ['_UNICODE_STRING']],
            'ObjectTypeName': [0x90, ['_UNICODE_STRING']],
        },
    ],
    '_PNP_DEVICE_EVENT_ENTRY': [
        0x88,
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
        0x88,
        {
            'Status': [0x0, ['long']],
            'EventQueueMutex': [0x8, ['_KMUTANT']],
            'Lock': [0x40, ['_KGUARDED_MUTEX']],
            'List': [0x78, ['_LIST_ENTRY']],
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
                        end_bit=40,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Unused': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
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
    '_STRING': [
        0x10,
        {
            'Length': [0x0, ['unsigned short']],
            'MaximumLength': [0x2, ['unsigned short']],
            'Buffer': [0x8, ['pointer64', ['unsigned char']]],
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
            'Fill': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
                ],
            ],
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
    '_ARBITER_INSTANCE': [
        0x138,
        {
            'Signature': [0x0, ['unsigned long']],
            'MutexEvent': [0x8, ['pointer64', ['_KEVENT']]],
            'Name': [0x10, ['pointer64', ['unsigned short']]],
            'ResourceType': [0x18, ['long']],
            'Allocation': [0x20, ['pointer64', ['_RTL_RANGE_LIST']]],
            'PossibleAllocation': [0x28, ['pointer64', ['_RTL_RANGE_LIST']]],
            'OrderingList': [0x30, ['_ARBITER_ORDERING_LIST']],
            'ReservedList': [0x40, ['_ARBITER_ORDERING_LIST']],
            'ReferenceCount': [0x50, ['long']],
            'Interface': [0x58, ['pointer64', ['_ARBITER_INTERFACE']]],
            'AllocationStackMaxSize': [0x60, ['unsigned long']],
            'AllocationStack': [
                0x68,
                ['pointer64', ['_ARBITER_ALLOCATION_STATE']],
            ],
            'UnpackRequirement': [0x70, ['pointer64', ['void']]],
            'PackResource': [0x78, ['pointer64', ['void']]],
            'UnpackResource': [0x80, ['pointer64', ['void']]],
            'ScoreRequirement': [0x88, ['pointer64', ['void']]],
            'TestAllocation': [0x90, ['pointer64', ['void']]],
            'RetestAllocation': [0x98, ['pointer64', ['void']]],
            'CommitAllocation': [0xA0, ['pointer64', ['void']]],
            'RollbackAllocation': [0xA8, ['pointer64', ['void']]],
            'BootAllocation': [0xB0, ['pointer64', ['void']]],
            'QueryArbitrate': [0xB8, ['pointer64', ['void']]],
            'QueryConflict': [0xC0, ['pointer64', ['void']]],
            'AddReserved': [0xC8, ['pointer64', ['void']]],
            'StartArbiter': [0xD0, ['pointer64', ['void']]],
            'PreprocessEntry': [0xD8, ['pointer64', ['void']]],
            'AllocateEntry': [0xE0, ['pointer64', ['void']]],
            'GetNextAllocationRange': [0xE8, ['pointer64', ['void']]],
            'FindSuitableRange': [0xF0, ['pointer64', ['void']]],
            'AddAllocation': [0xF8, ['pointer64', ['void']]],
            'BacktrackAllocation': [0x100, ['pointer64', ['void']]],
            'OverrideConflict': [0x108, ['pointer64', ['void']]],
            'TransactionInProgress': [0x110, ['unsigned char']],
            'Extension': [0x118, ['pointer64', ['void']]],
            'BusDeviceObject': [0x120, ['pointer64', ['_DEVICE_OBJECT']]],
            'ConflictCallbackContext': [0x128, ['pointer64', ['void']]],
            'ConflictCallback': [0x130, ['pointer64', ['void']]],
        },
    ],
    '_BUS_HANDLER': [
        0xB8,
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
            'DeviceObject': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'ParentHandler': [0x18, ['pointer64', ['_BUS_HANDLER']]],
            'BusData': [0x20, ['pointer64', ['void']]],
            'DeviceControlExtensionSize': [0x28, ['unsigned long']],
            'BusAddresses': [0x30, ['pointer64', ['_SUPPORTED_RANGES']]],
            'Reserved': [0x38, ['array', 4, ['unsigned long']]],
            'GetBusData': [0x48, ['pointer64', ['void']]],
            'SetBusData': [0x50, ['pointer64', ['void']]],
            'AdjustResourceList': [0x58, ['pointer64', ['void']]],
            'AssignSlotResources': [0x60, ['pointer64', ['void']]],
            'GetInterruptVector': [0x68, ['pointer64', ['void']]],
            'TranslateBusAddress': [0x70, ['pointer64', ['void']]],
            'Spare1': [0x78, ['pointer64', ['void']]],
            'Spare2': [0x80, ['pointer64', ['void']]],
            'Spare3': [0x88, ['pointer64', ['void']]],
            'Spare4': [0x90, ['pointer64', ['void']]],
            'Spare5': [0x98, ['pointer64', ['void']]],
            'Spare6': [0xA0, ['pointer64', ['void']]],
            'Spare7': [0xA8, ['pointer64', ['void']]],
            'Spare8': [0xB0, ['pointer64', ['void']]],
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
    '_PCI_MN_DISPATCH_TABLE': [
        0x10,
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
            'DispatchFunction': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_POP_DEVICE_SYS_STATE': [
        0xBA8,
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
            'SpinLock': [0x20, ['unsigned long long']],
            'Thread': [0x28, ['pointer64', ['_KTHREAD']]],
            'GetNewDeviceList': [0x30, ['unsigned char']],
            'Order': [0x38, ['_PO_DEVICE_NOTIFY_ORDER']],
            'Status': [0x448, ['long']],
            'FailedDevice': [0x450, ['pointer64', ['_DEVICE_OBJECT']]],
            'Waking': [0x458, ['unsigned char']],
            'Cancelled': [0x459, ['unsigned char']],
            'IgnoreErrors': [0x45A, ['unsigned char']],
            'IgnoreNotImplemented': [0x45B, ['unsigned char']],
            'WaitAny': [0x45C, ['unsigned char']],
            'WaitAll': [0x45D, ['unsigned char']],
            'PresentIrpQueue': [0x460, ['_LIST_ENTRY']],
            'Head': [0x470, ['_POP_DEVICE_POWER_IRP']],
            'PowerIrpState': [0x4C8, ['array', 20, ['_POP_DEVICE_POWER_IRP']]],
        },
    ],
    '_OBJECT_DUMP_CONTROL': [
        0x10,
        {
            'Stream': [0x0, ['pointer64', ['void']]],
            'Detail': [0x8, ['unsigned long']],
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
    '_HEAP_STOP_ON_TAG': [
        0x4,
        {
            'HeapAndTagIndex': [0x0, ['unsigned long']],
            'TagIndex': [0x0, ['unsigned short']],
            'HeapIndex': [0x2, ['unsigned short']],
        },
    ],
    '_MMWSLE_HASH': [
        0x10,
        {
            'Key': [0x0, ['pointer64', ['void']]],
            'Index': [0x8, ['unsigned long']],
        },
    ],
    '_CM_NAME_CONTROL_BLOCK': [
        0x20,
        {
            'Compressed': [0x0, ['unsigned char']],
            'RefCount': [0x2, ['unsigned short']],
            'NameHash': [0x8, ['_CM_NAME_HASH']],
            'ConvKey': [0x8, ['unsigned long']],
            'NextHash': [0x10, ['pointer64', ['_CM_KEY_HASH']]],
            'NameLength': [0x18, ['unsigned short']],
            'Name': [0x1A, ['array', 1, ['unsigned short']]],
        },
    ],
    '_CM_KEY_BODY': [
        0x30,
        {
            'Type': [0x0, ['unsigned long']],
            'KeyControlBlock': [0x8, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'NotifyBlock': [0x10, ['pointer64', ['_CM_NOTIFY_BLOCK']]],
            'ProcessID': [0x18, ['pointer64', ['void']]],
            'KeyBodyList': [0x20, ['_LIST_ENTRY']],
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
            'NextFreeTableEntry': [0x8, ['long']],
        },
    ],
    '_HEAP_USERDATA_HEADER': [
        0x20,
        {
            'SFreeListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'SubSegment': [0x0, ['pointer64', ['_HEAP_SUBSEGMENT']]],
            'HeapHandle': [0x8, ['pointer64', ['void']]],
            'SizeIndex': [0x10, ['unsigned long long']],
            'Signature': [0x18, ['unsigned long long']],
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
    'PCI_POWER_STATE': [
        0x50,
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
            'WaitWakeIrp': [0x30, ['pointer64', ['_IRP']]],
            'SavedCancelRoutine': [0x38, ['pointer64', ['void']]],
            'Paging': [0x40, ['long']],
            'Hibernate': [0x44, ['long']],
            'CrashDump': [0x48, ['long']],
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
    '_POOL_HACKER': [
        0x30,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'Contents': [0x10, ['array', 8, ['unsigned long']]],
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
    '__unnamed_1930': [
        0x20,
        {
            'SecurityContext': [0x0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x8, ['unsigned long']],
            'FileAttributes': [0x10, ['unsigned short']],
            'ShareAccess': [0x12, ['unsigned short']],
            'EaLength': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1934': [
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
    '__unnamed_1938': [
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
    '__unnamed_193a': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Key': [0x8, ['unsigned long']],
            'ByteOffset': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_193e': [
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
                            42: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileIndex': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1940': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'CompletionFilter': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1942': [
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
                            42: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1944': [
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
                            42: 'FileMaximumInformation',
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
    '__unnamed_1946': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'EaList': [0x8, ['pointer64', ['void']]],
            'EaListLength': [0x10, ['unsigned long']],
            'EaIndex': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1948': [
        0x4,
        {
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_194c': [
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
                            10: 'FileFsMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_194e': [
        0x20,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x8, ['unsigned long']],
            'FsControlCode': [0x10, ['unsigned long']],
            'Type3InputBuffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1950': [
        0x18,
        {
            'Length': [0x0, ['pointer64', ['_LARGE_INTEGER']]],
            'Key': [0x8, ['unsigned long']],
            'ByteOffset': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1952': [
        0x20,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x8, ['unsigned long']],
            'IoControlCode': [0x10, ['unsigned long']],
            'Type3InputBuffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1954': [
        0x10,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1956': [
        0x10,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'SecurityDescriptor': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1958': [
        0x10,
        {
            'Vpb': [0x0, ['pointer64', ['_VPB']]],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_195c': [
        0x8,
        {
            'Srb': [0x0, ['pointer64', ['_SCSI_REQUEST_BLOCK']]],
        },
    ],
    '__unnamed_1960': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'StartSid': [0x8, ['pointer64', ['void']]],
            'SidList': [0x10, ['pointer64', ['_FILE_GET_QUOTA_INFORMATION']]],
            'SidListLength': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1964': [
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
    '__unnamed_1966': [
        0x20,
        {
            'InterfaceType': [0x0, ['pointer64', ['_GUID']]],
            'Size': [0x8, ['unsigned short']],
            'Version': [0xA, ['unsigned short']],
            'Interface': [0x10, ['pointer64', ['_INTERFACE']]],
            'InterfaceSpecificData': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_196a': [
        0x8,
        {
            'Capabilities': [0x0, ['pointer64', ['_DEVICE_CAPABILITIES']]],
        },
    ],
    '__unnamed_196c': [
        0x8,
        {
            'IoResourceRequirementList': [
                0x0,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
        },
    ],
    '__unnamed_196e': [
        0x20,
        {
            'WhichSpace': [0x0, ['unsigned long']],
            'Buffer': [0x8, ['pointer64', ['void']]],
            'Offset': [0x10, ['unsigned long']],
            'Length': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1970': [
        0x1,
        {
            'Lock': [0x0, ['unsigned char']],
        },
    ],
    '__unnamed_1974': [
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
    '__unnamed_1978': [
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
    '__unnamed_197c': [
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
    '__unnamed_197e': [
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
    '__unnamed_1982': [
        0x8,
        {
            'PowerSequence': [0x0, ['pointer64', ['_POWER_SEQUENCE']]],
        },
    ],
    '__unnamed_1986': [
        0x20,
        {
            'SystemContext': [0x0, ['unsigned long']],
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
    '__unnamed_1988': [
        0x10,
        {
            'AllocatedResources': [0x0, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'AllocatedResourcesTranslated': [
                0x8,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
        },
    ],
    '__unnamed_198a': [
        0x20,
        {
            'ProviderId': [0x0, ['unsigned long long']],
            'DataPath': [0x8, ['pointer64', ['void']]],
            'BufferSize': [0x10, ['unsigned long']],
            'Buffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_198c': [
        0x20,
        {
            'Argument1': [0x0, ['pointer64', ['void']]],
            'Argument2': [0x8, ['pointer64', ['void']]],
            'Argument3': [0x10, ['pointer64', ['void']]],
            'Argument4': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_198e': [
        0x20,
        {
            'Create': [0x0, ['__unnamed_1930']],
            'CreatePipe': [0x0, ['__unnamed_1934']],
            'CreateMailslot': [0x0, ['__unnamed_1938']],
            'Read': [0x0, ['__unnamed_193a']],
            'Write': [0x0, ['__unnamed_193a']],
            'QueryDirectory': [0x0, ['__unnamed_193e']],
            'NotifyDirectory': [0x0, ['__unnamed_1940']],
            'QueryFile': [0x0, ['__unnamed_1942']],
            'SetFile': [0x0, ['__unnamed_1944']],
            'QueryEa': [0x0, ['__unnamed_1946']],
            'SetEa': [0x0, ['__unnamed_1948']],
            'QueryVolume': [0x0, ['__unnamed_194c']],
            'SetVolume': [0x0, ['__unnamed_194c']],
            'FileSystemControl': [0x0, ['__unnamed_194e']],
            'LockControl': [0x0, ['__unnamed_1950']],
            'DeviceIoControl': [0x0, ['__unnamed_1952']],
            'QuerySecurity': [0x0, ['__unnamed_1954']],
            'SetSecurity': [0x0, ['__unnamed_1956']],
            'MountVolume': [0x0, ['__unnamed_1958']],
            'VerifyVolume': [0x0, ['__unnamed_1958']],
            'Scsi': [0x0, ['__unnamed_195c']],
            'QueryQuota': [0x0, ['__unnamed_1960']],
            'SetQuota': [0x0, ['__unnamed_1948']],
            'QueryDeviceRelations': [0x0, ['__unnamed_1964']],
            'QueryInterface': [0x0, ['__unnamed_1966']],
            'DeviceCapabilities': [0x0, ['__unnamed_196a']],
            'FilterResourceRequirements': [0x0, ['__unnamed_196c']],
            'ReadWriteConfig': [0x0, ['__unnamed_196e']],
            'SetLock': [0x0, ['__unnamed_1970']],
            'QueryId': [0x0, ['__unnamed_1974']],
            'QueryDeviceText': [0x0, ['__unnamed_1978']],
            'UsageNotification': [0x0, ['__unnamed_197c']],
            'WaitWake': [0x0, ['__unnamed_197e']],
            'PowerSequence': [0x0, ['__unnamed_1982']],
            'Power': [0x0, ['__unnamed_1986']],
            'StartDevice': [0x0, ['__unnamed_1988']],
            'WMI': [0x0, ['__unnamed_198a']],
            'Others': [0x0, ['__unnamed_198c']],
        },
    ],
    '_IO_STACK_LOCATION': [
        0x48,
        {
            'MajorFunction': [0x0, ['unsigned char']],
            'MinorFunction': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned char']],
            'Control': [0x3, ['unsigned char']],
            'Parameters': [0x8, ['__unnamed_198e']],
            'DeviceObject': [0x28, ['pointer64', ['_DEVICE_OBJECT']]],
            'FileObject': [0x30, ['pointer64', ['_FILE_OBJECT']]],
            'CompletionRoutine': [0x38, ['pointer64', ['void']]],
            'Context': [0x40, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1995': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Alignment': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1997': [
        0x8,
        {
            'MinimumVector': [0x0, ['unsigned long']],
            'MaximumVector': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1999': [
        0x8,
        {
            'MinimumChannel': [0x0, ['unsigned long']],
            'MaximumChannel': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_199b': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'MinBusNumber': [0x4, ['unsigned long']],
            'MaxBusNumber': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_199d': [
        0xC,
        {
            'Priority': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_199f': [
        0x18,
        {
            'Port': [0x0, ['__unnamed_1995']],
            'Memory': [0x0, ['__unnamed_1995']],
            'Interrupt': [0x0, ['__unnamed_1997']],
            'Dma': [0x0, ['__unnamed_1999']],
            'Generic': [0x0, ['__unnamed_1995']],
            'DevicePrivate': [0x0, ['__unnamed_16dc']],
            'BusNumber': [0x0, ['__unnamed_199b']],
            'ConfigData': [0x0, ['__unnamed_199d']],
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
            'u': [0x8, ['__unnamed_199f']],
        },
    ],
    '_MI_VERIFIER_POOL_HEADER': [
        0x8,
        {
            'VerifierPoolEntry': [0x0, ['pointer64', ['_VI_POOL_ENTRY']]],
        },
    ],
    '__unnamed_19a8': [
        0x4,
        {
            'DataLength': [0x0, ['short']],
            'TotalLength': [0x2, ['short']],
        },
    ],
    '__unnamed_19aa': [
        0x4,
        {
            's1': [0x0, ['__unnamed_19a8']],
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_19ac': [
        0x4,
        {
            'Type': [0x0, ['short']],
            'DataInfoOffset': [0x2, ['short']],
        },
    ],
    '__unnamed_19ae': [
        0x4,
        {
            's2': [0x0, ['__unnamed_19ac']],
            'ZeroInit': [0x0, ['unsigned long']],
        },
    ],
    '_PORT_MESSAGE': [
        0x28,
        {
            'u1': [0x0, ['__unnamed_19aa']],
            'u2': [0x4, ['__unnamed_19ae']],
            'ClientId': [0x8, ['_CLIENT_ID']],
            'DoNotUseThisField': [0x8, ['double']],
            'MessageId': [0x18, ['unsigned long']],
            'ClientViewSize': [0x20, ['unsigned long long']],
            'CallbackId': [0x20, ['unsigned long']],
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
        0x10,
        {
            'Count': [0x0, ['unsigned short']],
            'Maximum': [0x2, ['unsigned short']],
            'Orderings': [0x8, ['pointer64', ['_ARBITER_ORDERING']]],
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
    '_VI_POOL_ENTRY': [
        0x20,
        {
            'PageHeader': [0x0, ['_VI_POOL_PAGE_HEADER']],
            'InUse': [0x0, ['_VI_POOL_ENTRY_INUSE']],
            'NextFree': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
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
    '_INITIAL_PRIVILEGE_SET': [
        0x2C,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Control': [0x4, ['unsigned long']],
            'Privilege': [0x8, ['array', 3, ['_LUID_AND_ATTRIBUTES']]],
        },
    ],
    '_POP_HIBER_CONTEXT': [
        0x150,
        {
            'WriteToFile': [0x0, ['unsigned char']],
            'ReserveLoaderMemory': [0x1, ['unsigned char']],
            'ReserveFreeMemory': [0x2, ['unsigned char']],
            'VerifyOnWake': [0x3, ['unsigned char']],
            'Reset': [0x4, ['unsigned char']],
            'HiberFlags': [0x5, ['unsigned char']],
            'LinkFile': [0x6, ['unsigned char']],
            'LinkFileHandle': [0x8, ['pointer64', ['void']]],
            'Lock': [0x10, ['unsigned long long']],
            'MapFrozen': [0x18, ['unsigned char']],
            'MemoryMap': [0x20, ['_RTL_BITMAP']],
            'ClonedRanges': [0x30, ['_LIST_ENTRY']],
            'ClonedRangeCount': [0x40, ['unsigned long']],
            'NextCloneRange': [0x48, ['pointer64', ['_LIST_ENTRY']]],
            'NextPreserve': [0x50, ['unsigned long long']],
            'LoaderMdl': [0x58, ['pointer64', ['_MDL']]],
            'Clones': [0x60, ['pointer64', ['_MDL']]],
            'NextClone': [0x68, ['pointer64', ['unsigned char']]],
            'NoClones': [0x70, ['unsigned long long']],
            'Spares': [0x78, ['pointer64', ['_MDL']]],
            'PagesOut': [0x80, ['unsigned long long']],
            'IoPage': [0x88, ['pointer64', ['void']]],
            'CurrentMcb': [0x90, ['pointer64', ['void']]],
            'DumpStack': [0x98, ['pointer64', ['_DUMP_STACK_CONTEXT']]],
            'WakeState': [0xA0, ['pointer64', ['_KPROCESSOR_STATE']]],
            'NoRanges': [0xA8, ['unsigned long']],
            'HiberVa': [0xB0, ['unsigned long long']],
            'HiberPte': [0xB8, ['_LARGE_INTEGER']],
            'Status': [0xC0, ['long']],
            'MemoryImage': [0xC8, ['pointer64', ['PO_MEMORY_IMAGE']]],
            'TableHead': [0xD0, ['pointer64', ['_PO_MEMORY_RANGE_ARRAY']]],
            'CompressionWorkspace': [0xD8, ['pointer64', ['unsigned char']]],
            'CompressedWriteBuffer': [0xE0, ['pointer64', ['unsigned char']]],
            'PerformanceStats': [0xE8, ['pointer64', ['unsigned long']]],
            'CompressionBlock': [0xF0, ['pointer64', ['void']]],
            'DmaIO': [0xF8, ['pointer64', ['void']]],
            'TemporaryHeap': [0x100, ['pointer64', ['void']]],
            'PerfInfo': [0x108, ['_PO_HIBER_PERF']],
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
        0x10,
        {
            'StartVpn': [0x0, ['unsigned long long']],
            'EndVpn': [0x8, ['unsigned long long']],
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
    '_POP_SHUTDOWN_BUG_CHECK': [
        0x28,
        {
            'Code': [0x0, ['unsigned long']],
            'Parameter1': [0x8, ['unsigned long long']],
            'Parameter2': [0x10, ['unsigned long long']],
            'Parameter3': [0x18, ['unsigned long long']],
            'Parameter4': [0x20, ['unsigned long long']],
        },
    ],
    '__unnamed_19e9': [
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
    '__unnamed_19eb': [
        0x4,
        {
            'bits': [0x0, ['__unnamed_19e9']],
            'AsULONG': [0x0, ['unsigned long']],
        },
    ],
    '_PCI_SLOT_NUMBER': [
        0x4,
        {
            'u': [0x0, ['__unnamed_19eb']],
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
        0x8,
        {
            'Flags': [0x0, ['unsigned long']],
            'NextFree': [0x0, ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']]],
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
    '_SUPPORTED_RANGES': [
        0xC0,
        {
            'Version': [0x0, ['unsigned short']],
            'Sorted': [0x2, ['unsigned char']],
            'Reserved': [0x3, ['unsigned char']],
            'NoIO': [0x4, ['unsigned long']],
            'IO': [0x8, ['_SUPPORTED_RANGE']],
            'NoMemory': [0x30, ['unsigned long']],
            'Memory': [0x38, ['_SUPPORTED_RANGE']],
            'NoPrefetchMemory': [0x60, ['unsigned long']],
            'PrefetchMemory': [0x68, ['_SUPPORTED_RANGE']],
            'NoDma': [0x90, ['unsigned long']],
            'Dma': [0x98, ['_SUPPORTED_RANGE']],
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
    '__unnamed_1a1a': [
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
    '__unnamed_1a1c': [
        0x8,
        {
            'ArbitrationList': [0x0, ['pointer64', ['_LIST_ENTRY']]],
        },
    ],
    '__unnamed_1a20': [
        0x8,
        {
            'AllocatedResources': [
                0x0,
                ['pointer64', ['pointer64', ['_CM_PARTIAL_RESOURCE_LIST']]],
            ],
        },
    ],
    '__unnamed_1a22': [
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
    '__unnamed_1a24': [
        0x8,
        {
            'ReserveDevice': [0x0, ['pointer64', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_1a26': [
        0x20,
        {
            'TestAllocation': [0x0, ['__unnamed_1a1a']],
            'RetestAllocation': [0x0, ['__unnamed_1a1a']],
            'BootAllocation': [0x0, ['__unnamed_1a1c']],
            'QueryAllocatedResources': [0x0, ['__unnamed_1a20']],
            'QueryConflict': [0x0, ['__unnamed_1a22']],
            'QueryArbitrate': [0x0, ['__unnamed_1a1c']],
            'AddReserved': [0x0, ['__unnamed_1a24']],
        },
    ],
    '_ARBITER_PARAMETERS': [
        0x20,
        {
            'Parameters': [0x0, ['__unnamed_1a26']],
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
    'PO_MEMORY_IMAGE': [
        0xC0,
        {
            'Signature': [0x0, ['unsigned long']],
            'Version': [0x4, ['unsigned long']],
            'CheckSum': [0x8, ['unsigned long']],
            'LengthSelf': [0xC, ['unsigned long']],
            'PageSelf': [0x10, ['unsigned long long']],
            'PageSize': [0x18, ['unsigned long']],
            'ImageType': [0x1C, ['unsigned long']],
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
            'TotalPages': [0x60, ['unsigned long long']],
            'FirstTablePage': [0x68, ['unsigned long long']],
            'LastFilePage': [0x70, ['unsigned long long']],
            'PerfInfo': [0x78, ['_PO_HIBER_PERF']],
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
    '_FREE_DISPLAY': [
        0x18,
        {
            'RealVectorSize': [0x0, ['unsigned long']],
            'Display': [0x8, ['_RTL_BITMAP']],
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
    '_VI_POOL_PAGE_HEADER': [
        0x18,
        {
            'NextPage': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
            'VerifierEntry': [0x8, ['pointer64', ['void']]],
            'Signature': [0x10, ['unsigned long long']],
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
    '_RTL_CRITICAL_SECTION_DEBUG': [
        0x30,
        {
            'Type': [0x0, ['unsigned short']],
            'CreatorBackTraceIndex': [0x2, ['unsigned short']],
            'CriticalSection': [0x8, ['pointer64', ['_RTL_CRITICAL_SECTION']]],
            'ProcessLocksList': [0x10, ['_LIST_ENTRY']],
            'EntryCount': [0x20, ['unsigned long']],
            'ContentionCount': [0x24, ['unsigned long']],
            'Spare': [0x28, ['array', 2, ['unsigned long']]],
        },
    ],
    '__unnamed_1a48': [
        0x14,
        {
            'ClassGuid': [0x0, ['_GUID']],
            'SymbolicLinkName': [0x10, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1a4a': [
        0x2,
        {
            'DeviceIds': [0x0, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1a4c': [
        0x2,
        {
            'DeviceId': [0x0, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1a4e': [
        0x10,
        {
            'NotificationStructure': [0x0, ['pointer64', ['void']]],
            'DeviceIds': [0x8, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1a50': [
        0x8,
        {
            'Notification': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1a52': [
        0x8,
        {
            'NotificationCode': [0x0, ['unsigned long']],
            'NotificationData': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1a54': [
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
    '__unnamed_1a56': [
        0x10,
        {
            'BlockedDriverGuid': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_1a58': [
        0x2,
        {
            'ParentId': [0x0, ['array', 1, ['unsigned short']]],
        },
    ],
    '__unnamed_1a5a': [
        0x18,
        {
            'DeviceClass': [0x0, ['__unnamed_1a48']],
            'TargetDevice': [0x0, ['__unnamed_1a4a']],
            'InstallDevice': [0x0, ['__unnamed_1a4c']],
            'CustomNotification': [0x0, ['__unnamed_1a4e']],
            'ProfileNotification': [0x0, ['__unnamed_1a50']],
            'PowerNotification': [0x0, ['__unnamed_1a52']],
            'VetoNotification': [0x0, ['__unnamed_1a54']],
            'BlockedDriverNotification': [0x0, ['__unnamed_1a56']],
            'InvalidIDNotification': [0x0, ['__unnamed_1a58']],
        },
    ],
    '_PLUGPLAY_EVENT_BLOCK': [
        0x48,
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
                            9: 'InvalidIDEvent',
                            10: 'MaxPlugEventCategory',
                        },
                    ),
                ],
            ],
            'Result': [0x18, ['pointer64', ['unsigned long']]],
            'Flags': [0x20, ['unsigned long']],
            'TotalSize': [0x24, ['unsigned long']],
            'DeviceObject': [0x28, ['pointer64', ['void']]],
            'u': [0x30, ['__unnamed_1a5a']],
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
    '_PO_MEMORY_RANGE_ARRAY': [
        0x20,
        {
            'Range': [0x0, ['_PO_MEMORY_RANGE_ARRAY_RANGE']],
            'Link': [0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
        },
    ],
    '__unnamed_1a71': [
        0x8,
        {
            'Signature': [0x0, ['unsigned long']],
            'CheckSum': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1a73': [
        0x10,
        {
            'DiskId': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_1a75': [
        0x10,
        {
            'Mbr': [0x0, ['__unnamed_1a71']],
            'Gpt': [0x0, ['__unnamed_1a73']],
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
            'DiskInfo': [0x8C, ['__unnamed_1a75']],
        },
    ],
    '_IO_CLIENT_EXTENSION': [
        0x10,
        {
            'NextExtension': [0x0, ['pointer64', ['_IO_CLIENT_EXTENSION']]],
            'ClientIdentificationAddress': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_CM_NAME_HASH': [
        0x18,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x8, ['pointer64', ['_CM_NAME_HASH']]],
            'NameLength': [0x10, ['unsigned short']],
            'Name': [0x12, ['array', 1, ['unsigned short']]],
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
        0x410,
        {
            'DevNodeSequence': [0x0, ['unsigned long']],
            'WarmEjectPdoPointer': [
                0x8,
                ['pointer64', ['pointer64', ['_DEVICE_OBJECT']]],
            ],
            'OrderLevel': [0x10, ['array', 8, ['_PO_NOTIFY_ORDER_LEVEL']]],
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
    '_IA64_DBGKD_CONTROL_SET': [
        0x14,
        {
            'Continue': [0x0, ['unsigned long']],
            'CurrentSymbolStart': [0x4, ['unsigned long long']],
            'CurrentSymbolEnd': [0xC, ['unsigned long long']],
        },
    ],
    '_PO_MEMORY_RANGE_ARRAY_RANGE': [
        0x20,
        {
            'PageNo': [0x0, ['unsigned long long']],
            'StartPage': [0x8, ['unsigned long long']],
            'EndPage': [0x10, ['unsigned long long']],
            'CheckSum': [0x18, ['unsigned long']],
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
            'OwningObject': [0x0, ['pointer64', ['_DEVICE_OBJECT']]],
            'Start': [0x8, ['unsigned long long']],
            'End': [0x10, ['unsigned long long']],
        },
    ],
    '_PO_NOTIFY_ORDER_LEVEL': [
        0x80,
        {
            'LevelReady': [0x0, ['_KEVENT']],
            'DeviceCount': [0x18, ['unsigned long']],
            'ActiveCount': [0x1C, ['unsigned long']],
            'WaitSleep': [0x20, ['_LIST_ENTRY']],
            'ReadySleep': [0x30, ['_LIST_ENTRY']],
            'Pending': [0x40, ['_LIST_ENTRY']],
            'Complete': [0x50, ['_LIST_ENTRY']],
            'ReadyS0': [0x60, ['_LIST_ENTRY']],
            'WaitS0': [0x70, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1aa5': [
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
            'Range': [0xC, ['array', 4, ['__unnamed_1aa5']]],
            'InterruptLine': [0x2C, ['unsigned char']],
            'InterruptPin': [0x2D, ['unsigned char']],
            'BridgeControl': [0x2E, ['unsigned short']],
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
    '_PO_MEMORY_RANGE_ARRAY_LINK': [
        0x18,
        {
            'Next': [0x0, ['pointer64', ['_PO_MEMORY_RANGE_ARRAY']]],
            'NextTable': [0x8, ['unsigned long long']],
            'CheckSum': [0x10, ['unsigned long']],
            'EntryCount': [0x14, ['unsigned long']],
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
    '_OBJECT_DIRECTORY_ENTRY': [
        0x18,
        {
            'ChainLink': [0x0, ['pointer64', ['_OBJECT_DIRECTORY_ENTRY']]],
            'Object': [0x8, ['pointer64', ['void']]],
            'HashValue': [0x10, ['unsigned long']],
        },
    ],
    '_POP_DEVICE_POWER_IRP': [
        0x58,
        {
            'Free': [0x0, ['_SINGLE_LIST_ENTRY']],
            'Irp': [0x8, ['pointer64', ['_IRP']]],
            'Notify': [0x10, ['pointer64', ['_PO_DEVICE_NOTIFY']]],
            'Pending': [0x18, ['_LIST_ENTRY']],
            'Complete': [0x28, ['_LIST_ENTRY']],
            'Abort': [0x38, ['_LIST_ENTRY']],
            'Failed': [0x48, ['_LIST_ENTRY']],
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
    '_X86_DBGKD_CONTROL_SET': [
        0x10,
        {
            'TraceFlag': [0x0, ['unsigned long']],
            'Dr7': [0x4, ['unsigned long']],
            'CurrentSymbolStart': [0x8, ['unsigned long']],
            'CurrentSymbolEnd': [0xC, ['unsigned long']],
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
        0x28,
        {
            'Next': [0x0, ['pointer64', ['_SUPPORTED_RANGE']]],
            'SystemAddressSpace': [0x8, ['unsigned long']],
            'SystemBase': [0x10, ['long long']],
            'Base': [0x18, ['long long']],
            'Limit': [0x20, ['long long']],
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
                            16: 'MaximumInterfaceType',
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
    '_LPCP_NONPAGED_PORT_QUEUE': [
        0x28,
        {
            'Semaphore': [0x0, ['_KSEMAPHORE']],
            'BackPointer': [0x20, ['pointer64', ['_LPCP_PORT_OBJECT']]],
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
    '_CM_KEY_REFERENCE': [
        0x10,
        {
            'KeyCell': [0x0, ['unsigned long']],
            'KeyHive': [0x8, ['pointer64', ['_HHIVE']]],
        },
    ],
    '_ARBITER_ALTERNATIVE': [
        0x38,
        {
            'Minimum': [0x0, ['unsigned long long']],
            'Maximum': [0x8, ['unsigned long long']],
            'Length': [0x10, ['unsigned long']],
            'Alignment': [0x14, ['unsigned long']],
            'Priority': [0x18, ['long']],
            'Flags': [0x1C, ['unsigned long']],
            'Descriptor': [0x20, ['pointer64', ['_IO_RESOURCE_DESCRIPTOR']]],
            'Reserved': [0x28, ['array', 3, ['unsigned long']]],
        },
    ],
    '__unnamed_1b2b': [
        0x10,
        {
            'EndingOffset': [0x0, ['pointer64', ['_LARGE_INTEGER']]],
            'ResourceToRelease': [
                0x8,
                ['pointer64', ['pointer64', ['_ERESOURCE']]],
            ],
        },
    ],
    '__unnamed_1b2d': [
        0x8,
        {
            'ResourceToRelease': [0x0, ['pointer64', ['_ERESOURCE']]],
        },
    ],
    '__unnamed_1b31': [
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
    '__unnamed_1b33': [
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
            'AcquireForModifiedPageWriter': [0x0, ['__unnamed_1b2b']],
            'ReleaseForModifiedPageWriter': [0x0, ['__unnamed_1b2d']],
            'AcquireForSectionSynchronization': [0x0, ['__unnamed_1b31']],
            'Others': [0x0, ['__unnamed_1b33']],
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
