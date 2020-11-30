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
    '__unnamed_101f': [
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
            'u': [0x0, ['__unnamed_101f']],
            'QuadPart': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_1024': [
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
            'u': [0x0, ['__unnamed_1024']],
            'QuadPart': [0x0, ['long long']],
        },
    ],
    '__unnamed_103d': [
        0x4,
        {
            'LongFunction': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Private': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    '__unnamed_103f': [
        0x4,
        {
            'Flags': [0x0, ['unsigned long']],
            's': [0x0, ['__unnamed_103d']],
        },
    ],
    '_TP_CALLBACK_ENVIRON': [
        0x40,
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
            'u': [0x38, ['__unnamed_103f']],
        },
    ],
    '_TP_TASK_CALLBACKS': [
        0x10,
        {
            'ExecuteCallback': [0x0, ['pointer64', ['void']]],
            'Unposted': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_TP_TASK': [
        0x8,
        {
            'Callbacks': [0x0, ['pointer64', ['_TP_TASK_CALLBACKS']]],
        },
    ],
    '_TP_DIRECT': [
        0x8,
        {
            'Callback': [0x0, ['pointer64', ['void']]],
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
    '_KPRCB': [
        0x3A20,
        {
            'MxCsr': [0x0, ['unsigned long']],
            'Number': [0x4, ['unsigned short']],
            'InterruptRequest': [0x6, ['unsigned char']],
            'IdleHalt': [0x7, ['unsigned char']],
            'CurrentThread': [0x8, ['pointer64', ['_KTHREAD']]],
            'NextThread': [0x10, ['pointer64', ['_KTHREAD']]],
            'IdleThread': [0x18, ['pointer64', ['_KTHREAD']]],
            'NestingLevel': [0x20, ['unsigned char']],
            'Group': [0x21, ['unsigned char']],
            'PrcbPad00': [0x22, ['array', 6, ['unsigned char']]],
            'RspBase': [0x28, ['unsigned long long']],
            'PrcbLock': [0x30, ['unsigned long long']],
            'SetMember': [0x38, ['unsigned long long']],
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
            'PrcbPad01': [0x658, ['array', 3, ['unsigned long long']]],
            'LockQueue': [0x670, ['array', 33, ['_KSPIN_LOCK_QUEUE']]],
            'PPLookasideList': [0x880, ['array', 16, ['_PP_LOOKASIDE_LIST']]],
            'PPNPagedLookasideList': [
                0x980,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PPPagedLookasideList': [
                0x1580,
                ['array', 32, ['_GENERAL_LOOKASIDE_POOL']],
            ],
            'PacketBarrier': [0x2180, ['unsigned long long']],
            'DeferredReadyListHead': [0x2188, ['_SINGLE_LIST_ENTRY']],
            'MmPageFaultCount': [0x2190, ['long']],
            'MmCopyOnWriteCount': [0x2194, ['long']],
            'MmTransitionCount': [0x2198, ['long']],
            'MmDemandZeroCount': [0x219C, ['long']],
            'MmPageReadCount': [0x21A0, ['long']],
            'MmPageReadIoCount': [0x21A4, ['long']],
            'MmDirtyPagesWriteCount': [0x21A8, ['long']],
            'MmDirtyWriteIoCount': [0x21AC, ['long']],
            'MmMappedPagesWriteCount': [0x21B0, ['long']],
            'MmMappedWriteIoCount': [0x21B4, ['long']],
            'KeSystemCalls': [0x21B8, ['unsigned long']],
            'KeContextSwitches': [0x21BC, ['unsigned long']],
            'CcFastReadNoWait': [0x21C0, ['unsigned long']],
            'CcFastReadWait': [0x21C4, ['unsigned long']],
            'CcFastReadNotPossible': [0x21C8, ['unsigned long']],
            'CcCopyReadNoWait': [0x21CC, ['unsigned long']],
            'CcCopyReadWait': [0x21D0, ['unsigned long']],
            'CcCopyReadNoWaitMiss': [0x21D4, ['unsigned long']],
            'LookasideIrpFloat': [0x21D8, ['long']],
            'IoReadOperationCount': [0x21DC, ['long']],
            'IoWriteOperationCount': [0x21E0, ['long']],
            'IoOtherOperationCount': [0x21E4, ['long']],
            'IoReadTransferCount': [0x21E8, ['_LARGE_INTEGER']],
            'IoWriteTransferCount': [0x21F0, ['_LARGE_INTEGER']],
            'IoOtherTransferCount': [0x21F8, ['_LARGE_INTEGER']],
            'TargetSet': [0x2200, ['unsigned long long']],
            'IpiFrozen': [0x2208, ['unsigned long']],
            'PrcbPad3': [0x220C, ['array', 116, ['unsigned char']]],
            'RequestMailbox': [0x2280, ['array', 64, ['_REQUEST_MAILBOX']]],
            'SenderSummary': [0x3280, ['unsigned long long']],
            'PrcbPad4': [0x3288, ['array', 120, ['unsigned char']]],
            'DpcData': [0x3300, ['array', 2, ['_KDPC_DATA']]],
            'DpcStack': [0x3340, ['pointer64', ['void']]],
            'SavedRsp': [0x3348, ['pointer64', ['void']]],
            'MaximumDpcQueueDepth': [0x3350, ['long']],
            'DpcRequestRate': [0x3354, ['unsigned long']],
            'MinimumDpcRate': [0x3358, ['unsigned long']],
            'DpcInterruptRequested': [0x335C, ['unsigned char']],
            'DpcThreadRequested': [0x335D, ['unsigned char']],
            'DpcRoutineActive': [0x335E, ['unsigned char']],
            'DpcThreadActive': [0x335F, ['unsigned char']],
            'TimerHand': [0x3360, ['unsigned long long']],
            'TimerRequest': [0x3360, ['unsigned long long']],
            'TickOffset': [0x3368, ['long']],
            'MasterOffset': [0x336C, ['long']],
            'DpcLastCount': [0x3370, ['unsigned long']],
            'ThreadDpcEnable': [0x3374, ['unsigned char']],
            'QuantumEnd': [0x3375, ['unsigned char']],
            'PrcbPad50': [0x3376, ['unsigned char']],
            'IdleSchedule': [0x3377, ['unsigned char']],
            'DpcSetEventRequest': [0x3378, ['long']],
            'KeExceptionDispatchCount': [0x337C, ['unsigned long']],
            'DpcEvent': [0x3380, ['_KEVENT']],
            'PrcbPad51': [0x3398, ['pointer64', ['void']]],
            'CallDpc': [0x33A0, ['_KDPC']],
            'ClockKeepAlive': [0x33E0, ['long']],
            'ClockCheckSlot': [0x33E4, ['unsigned char']],
            'ClockPollCycle': [0x33E5, ['unsigned char']],
            'PrcbPad6': [0x33E6, ['array', 2, ['unsigned char']]],
            'DpcWatchdogPeriod': [0x33E8, ['long']],
            'DpcWatchdogCount': [0x33EC, ['long']],
            'PrcbPad70': [0x33F0, ['array', 2, ['unsigned long long']]],
            'WaitListHead': [0x3400, ['_LIST_ENTRY']],
            'WaitLock': [0x3410, ['unsigned long long']],
            'ReadySummary': [0x3418, ['unsigned long']],
            'QueueIndex': [0x341C, ['unsigned long']],
            'PrcbPad71': [0x3420, ['array', 12, ['unsigned long long']]],
            'DispatcherReadyListHead': [
                0x3480,
                ['array', 32, ['_LIST_ENTRY']],
            ],
            'InterruptCount': [0x3680, ['unsigned long']],
            'KernelTime': [0x3684, ['unsigned long']],
            'UserTime': [0x3688, ['unsigned long']],
            'DpcTime': [0x368C, ['unsigned long']],
            'InterruptTime': [0x3690, ['unsigned long']],
            'AdjustDpcThreshold': [0x3694, ['unsigned long']],
            'SkipTick': [0x3698, ['unsigned char']],
            'DebuggerSavedIRQL': [0x3699, ['unsigned char']],
            'PollSlot': [0x369A, ['unsigned char']],
            'PrcbPad80': [0x369B, ['array', 5, ['unsigned char']]],
            'DpcTimeCount': [0x36A0, ['unsigned long']],
            'DpcTimeLimit': [0x36A4, ['unsigned long']],
            'PeriodicCount': [0x36A8, ['unsigned long']],
            'PeriodicBias': [0x36AC, ['unsigned long']],
            'PrcbPad81': [0x36B0, ['array', 2, ['unsigned long long']]],
            'ParentNode': [0x36C0, ['pointer64', ['_KNODE']]],
            'MultiThreadProcessorSet': [0x36C8, ['unsigned long long']],
            'MultiThreadSetMaster': [0x36D0, ['pointer64', ['_KPRCB']]],
            'StartCycles': [0x36D8, ['unsigned long long']],
            'MmSpinLockOrdering': [0x36E0, ['long']],
            'PageColor': [0x36E4, ['unsigned long']],
            'NodeColor': [0x36E8, ['unsigned long']],
            'NodeShiftedColor': [0x36EC, ['unsigned long']],
            'SecondaryColorMask': [0x36F0, ['unsigned long']],
            'Sleeping': [0x36F4, ['long']],
            'CycleTime': [0x36F8, ['unsigned long long']],
            'CcFastMdlReadNoWait': [0x3700, ['unsigned long']],
            'CcFastMdlReadWait': [0x3704, ['unsigned long']],
            'CcFastMdlReadNotPossible': [0x3708, ['unsigned long']],
            'CcMapDataNoWait': [0x370C, ['unsigned long']],
            'CcMapDataWait': [0x3710, ['unsigned long']],
            'CcPinMappedDataCount': [0x3714, ['unsigned long']],
            'CcPinReadNoWait': [0x3718, ['unsigned long']],
            'CcPinReadWait': [0x371C, ['unsigned long']],
            'CcMdlReadNoWait': [0x3720, ['unsigned long']],
            'CcMdlReadWait': [0x3724, ['unsigned long']],
            'CcLazyWriteHotSpots': [0x3728, ['unsigned long']],
            'CcLazyWriteIos': [0x372C, ['unsigned long']],
            'CcLazyWritePages': [0x3730, ['unsigned long']],
            'CcDataFlushes': [0x3734, ['unsigned long']],
            'CcDataPages': [0x3738, ['unsigned long']],
            'CcLostDelayedWrites': [0x373C, ['unsigned long']],
            'CcFastReadResourceMiss': [0x3740, ['unsigned long']],
            'CcCopyReadWaitMiss': [0x3744, ['unsigned long']],
            'CcFastMdlReadResourceMiss': [0x3748, ['unsigned long']],
            'CcMapDataNoWaitMiss': [0x374C, ['unsigned long']],
            'CcMapDataWaitMiss': [0x3750, ['unsigned long']],
            'CcPinReadNoWaitMiss': [0x3754, ['unsigned long']],
            'CcPinReadWaitMiss': [0x3758, ['unsigned long']],
            'CcMdlReadNoWaitMiss': [0x375C, ['unsigned long']],
            'CcMdlReadWaitMiss': [0x3760, ['unsigned long']],
            'CcReadAheadIos': [0x3764, ['unsigned long']],
            'MmCacheTransitionCount': [0x3768, ['long']],
            'MmCacheReadCount': [0x376C, ['long']],
            'MmCacheIoCount': [0x3770, ['long']],
            'PrcbPad91': [0x3774, ['array', 3, ['unsigned long']]],
            'PowerState': [0x3780, ['_PROCESSOR_POWER_STATE']],
            'KeAlignmentFixupCount': [0x38B8, ['unsigned long']],
            'VendorString': [0x38BC, ['array', 13, ['unsigned char']]],
            'PrcbPad10': [0x38C9, ['array', 3, ['unsigned char']]],
            'FeatureBits': [0x38CC, ['unsigned long']],
            'UpdateSignature': [0x38D0, ['_LARGE_INTEGER']],
            'DpcWatchdogDpc': [0x38D8, ['_KDPC']],
            'DpcWatchdogTimer': [0x3918, ['_KTIMER']],
            'Cache': [0x3958, ['array', 5, ['_CACHE_DESCRIPTOR']]],
            'CacheCount': [0x3994, ['unsigned long']],
            'CachedCommit': [0x3998, ['unsigned long']],
            'CachedResidentAvailable': [0x399C, ['unsigned long']],
            'HyperPte': [0x39A0, ['pointer64', ['void']]],
            'WheaInfo': [0x39A8, ['pointer64', ['void']]],
            'EtwSupport': [0x39B0, ['pointer64', ['void']]],
            'InterruptObjectPool': [0x39C0, ['_SLIST_HEADER']],
            'HypercallPagePhysical': [0x39D0, ['_LARGE_INTEGER']],
            'HypercallPageVirtual': [0x39D8, ['pointer64', ['void']]],
            'RateControl': [0x39E0, ['pointer64', ['void']]],
            'CacheProcessorMask': [
                0x39E8,
                ['array', 5, ['unsigned long long']],
            ],
            'PackageProcessorSet': [0x3A10, ['unsigned long long']],
            'CoreProcessorSet': [0x3A18, ['unsigned long long']],
        },
    ],
    '_KTHREAD': [
        0x330,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'CycleTime': [0x18, ['unsigned long long']],
            'QuantumTarget': [0x20, ['unsigned long long']],
            'InitialStack': [0x28, ['pointer64', ['void']]],
            'StackLimit': [0x30, ['pointer64', ['void']]],
            'KernelStack': [0x38, ['pointer64', ['void']]],
            'ThreadLock': [0x40, ['unsigned long long']],
            'ApcState': [0x48, ['_KAPC_STATE']],
            'ApcStateFill': [0x48, ['array', 43, ['unsigned char']]],
            'Priority': [0x73, ['unsigned char']],
            'NextProcessor': [0x74, ['unsigned short']],
            'DeferredProcessor': [0x76, ['unsigned short']],
            'ApcQueueLock': [0x78, ['unsigned long long']],
            'WaitStatus': [0x80, ['long long']],
            'WaitBlockList': [0x88, ['pointer64', ['_KWAIT_BLOCK']]],
            'GateObject': [0x88, ['pointer64', ['_KGATE']]],
            'KernelStackResident': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ReadyTransition': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessReadyQueue': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'WaitNext': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SystemAffinityActive': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'Alertable': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'GdiFlushActive': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x90,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'MiscFlags': [0x90, ['long']],
            'WaitReason': [0x94, ['unsigned char']],
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
            'EtwStackTraceApc1Inserted': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'EtwStackTraceApc2Inserted': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'CycleChargePending': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'CalloutActive': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'ApcQueueable': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'EnableStackSwap': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'GuiThread': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'ReservedFlags': [
                0xF4,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'ThreadFlags': [0xF4, ['long']],
            'WaitBlock': [0xF8, ['array', 4, ['_KWAIT_BLOCK']]],
            'WaitBlockFill0': [0xF8, ['array', 43, ['unsigned char']]],
            'IdealProcessor': [0x123, ['unsigned char']],
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
            'FirstArgument': [0x1D0, ['pointer64', ['void']]],
            'CallbackStack': [0x1D8, ['pointer64', ['void']]],
            'CallbackDepth': [0x1D8, ['unsigned long long']],
            'ApcStateIndex': [0x1E0, ['unsigned char']],
            'BasePriority': [0x1E1, ['unsigned char']],
            'PriorityDecrement': [0x1E2, ['unsigned char']],
            'Preempted': [0x1E3, ['unsigned char']],
            'AdjustReason': [0x1E4, ['unsigned char']],
            'AdjustIncrement': [0x1E5, ['unsigned char']],
            'Spare01': [0x1E6, ['unsigned char']],
            'Saturation': [0x1E7, ['unsigned char']],
            'SystemCallNumber': [0x1E8, ['unsigned long']],
            'Spare02': [0x1EC, ['unsigned long']],
            'UserAffinity': [0x1F0, ['unsigned long long']],
            'Process': [0x1F8, ['pointer64', ['_KPROCESS']]],
            'Affinity': [0x200, ['unsigned long long']],
            'ApcStatePointer': [
                0x208,
                ['array', 2, ['pointer64', ['_KAPC_STATE']]],
            ],
            'SavedApcState': [0x218, ['_KAPC_STATE']],
            'SavedApcStateFill': [0x218, ['array', 43, ['unsigned char']]],
            'FreezeCount': [0x243, ['unsigned char']],
            'SuspendCount': [0x244, ['unsigned char']],
            'UserIdealProcessor': [0x245, ['unsigned char']],
            'Spare03': [0x246, ['unsigned char']],
            'CodePatchInProgress': [0x247, ['unsigned char']],
            'Win32Thread': [0x248, ['pointer64', ['void']]],
            'StackBase': [0x250, ['pointer64', ['void']]],
            'SuspendApc': [0x258, ['_KAPC']],
            'SuspendApcFill0': [0x258, ['array', 1, ['unsigned char']]],
            'Spare04': [0x259, ['unsigned char']],
            'SuspendApcFill1': [0x258, ['array', 3, ['unsigned char']]],
            'QuantumReset': [0x25B, ['unsigned char']],
            'SuspendApcFill2': [0x258, ['array', 4, ['unsigned char']]],
            'KernelTime': [0x25C, ['unsigned long']],
            'SuspendApcFill3': [0x258, ['array', 64, ['unsigned char']]],
            'WaitPrcb': [0x298, ['pointer64', ['_KPRCB']]],
            'SuspendApcFill4': [0x258, ['array', 72, ['unsigned char']]],
            'LegoData': [0x2A0, ['pointer64', ['void']]],
            'SuspendApcFill5': [0x258, ['array', 83, ['unsigned char']]],
            'PowerState': [0x2AB, ['unsigned char']],
            'UserTime': [0x2AC, ['unsigned long']],
            'SuspendSemaphore': [0x2B0, ['_KSEMAPHORE']],
            'SuspendSemaphorefill': [0x2B0, ['array', 28, ['unsigned char']]],
            'SListFaultCount': [0x2CC, ['unsigned long']],
            'ThreadListEntry': [0x2D0, ['_LIST_ENTRY']],
            'MutantListHead': [0x2E0, ['_LIST_ENTRY']],
            'SListFaultAddress': [0x2F0, ['pointer64', ['void']]],
            'ReadOperationCount': [0x2F8, ['long long']],
            'WriteOperationCount': [0x300, ['long long']],
            'OtherOperationCount': [0x308, ['long long']],
            'ReadTransferCount': [0x310, ['long long']],
            'WriteTransferCount': [0x318, ['long long']],
            'OtherTransferCount': [0x320, ['long long']],
            'MdlForLockedTeb': [0x328, ['pointer64', ['void']]],
        },
    ],
    '_KERNEL_STACK_CONTROL': [
        0x250,
        {
            'XmmSaveArea': [0x0, ['_XMM_SAVE_AREA32']],
            'Current': [0x200, ['_KERNEL_STACK_SEGMENT']],
            'Previous': [0x228, ['_KERNEL_STACK_SEGMENT']],
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
    '__unnamed_1115': [
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
    '__unnamed_111a': [
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
    '_SLIST_HEADER': [
        0x10,
        {
            'Alignment': [0x0, ['unsigned long long']],
            'Region': [0x8, ['unsigned long long']],
            'Header8': [0x0, ['__unnamed_1115']],
            'Header16': [0x0, ['__unnamed_111a']],
        },
    ],
    '_SLIST_ENTRY': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_SLIST_ENTRY']]],
        },
    ],
    '_LOOKASIDE_LIST_EX': [
        0x60,
        {
            'L': [0x0, ['_GENERAL_LOOKASIDE_POOL']],
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
    '_EX_PUSH_LOCK_CACHE_AWARE': [
        0x100,
        {
            'Locks': [0x0, ['array', 32, ['pointer64', ['_EX_PUSH_LOCK']]]],
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
    '_ETHREAD': [
        0x450,
        {
            'Tcb': [0x0, ['_KTHREAD']],
            'CreateTime': [0x330, ['_LARGE_INTEGER']],
            'ExitTime': [0x338, ['_LARGE_INTEGER']],
            'KeyedWaitChain': [0x338, ['_LIST_ENTRY']],
            'ExitStatus': [0x348, ['long']],
            'OfsChain': [0x348, ['pointer64', ['void']]],
            'PostBlockList': [0x350, ['_LIST_ENTRY']],
            'ForwardLinkShadow': [0x350, ['pointer64', ['void']]],
            'StartAddress': [0x358, ['pointer64', ['void']]],
            'TerminationPort': [0x360, ['pointer64', ['_TERMINATION_PORT']]],
            'ReaperLink': [0x360, ['pointer64', ['_ETHREAD']]],
            'KeyedWaitValue': [0x360, ['pointer64', ['void']]],
            'Win32StartParameter': [0x360, ['pointer64', ['void']]],
            'ActiveTimerListLock': [0x368, ['unsigned long long']],
            'ActiveTimerListHead': [0x370, ['_LIST_ENTRY']],
            'Cid': [0x380, ['_CLIENT_ID']],
            'KeyedWaitSemaphore': [0x390, ['_KSEMAPHORE']],
            'AlpcWaitSemaphore': [0x390, ['_KSEMAPHORE']],
            'ClientSecurity': [0x3B0, ['_PS_CLIENT_SECURITY_CONTEXT']],
            'IrpList': [0x3B8, ['_LIST_ENTRY']],
            'TopLevelIrp': [0x3C8, ['unsigned long long']],
            'DeviceToVerify': [0x3D0, ['pointer64', ['_DEVICE_OBJECT']]],
            'RateControlApc': [0x3D8, ['pointer64', ['_PSP_RATE_APC']]],
            'Win32StartAddress': [0x3E0, ['pointer64', ['void']]],
            'SparePtr0': [0x3E8, ['pointer64', ['void']]],
            'ThreadListEntry': [0x3F0, ['_LIST_ENTRY']],
            'RundownProtect': [0x400, ['_EX_RUNDOWN_REF']],
            'ThreadLock': [0x408, ['_EX_PUSH_LOCK']],
            'ReadClusterSize': [0x410, ['unsigned long']],
            'MmLockOrdering': [0x414, ['long']],
            'CrossThreadFlags': [0x418, ['unsigned long']],
            'Terminated': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ThreadInserted': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'HideFromDebugger': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ActiveImpersonationInfo': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'SystemThread': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'HardErrorsAreDisabled': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'BreakOnTermination': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SkipCreationMsg': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SkipTerminationMsg': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'CopyTokenOnOpen': [
                0x418,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'ThreadIoPriority': [
                0x418,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'ThreadPagePriority': [
                0x418,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'RundownFail': [
                0x418,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'SameThreadPassiveFlags': [0x41C, ['unsigned long']],
            'ActiveExWorker': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'ExWorkerCanWaitUser': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'MemoryMaker': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ClonedThread': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'KeyedEventInUse': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'RateApcState': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'SelfTerminate': [
                0x41C,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'SameThreadApcFlags': [0x420, ['unsigned long']],
            'Spare': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'StartAddressInvalid': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'EtwPageFaultCalloutActive': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetExclusive': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessWorkingSetShared': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemWorkingSetExclusive': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsSystemWorkingSetShared': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetExclusive': [
                0x420,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'OwnsSessionWorkingSetShared': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessAddressSpaceExclusive': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'OwnsProcessAddressSpaceShared': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'SuppressSymbolLoad': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'Prefetching': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'OwnsDynamicMemoryShared': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'OwnsChangeControlAreaExclusive': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'OwnsChangeControlAreaShared': [
                0x421,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'PriorityRegionActive': [
                0x422,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'CacheManagerActive': [0x424, ['unsigned char']],
            'DisablePageFaultClustering': [0x425, ['unsigned char']],
            'ActiveFaultCount': [0x426, ['unsigned char']],
            'AlpcMessageId': [0x428, ['unsigned long long']],
            'AlpcMessage': [0x430, ['pointer64', ['void']]],
            'AlpcReceiveAttributeSet': [0x430, ['unsigned long']],
            'AlpcWaitListEntry': [0x438, ['_LIST_ENTRY']],
            'CacheManagerCount': [0x448, ['unsigned long']],
        },
    ],
    '_EPROCESS': [
        0x3E8,
        {
            'Pcb': [0x0, ['_KPROCESS']],
            'ProcessLock': [0xC0, ['_EX_PUSH_LOCK']],
            'CreateTime': [0xC8, ['_LARGE_INTEGER']],
            'ExitTime': [0xD0, ['_LARGE_INTEGER']],
            'RundownProtect': [0xD8, ['_EX_RUNDOWN_REF']],
            'UniqueProcessId': [0xE0, ['pointer64', ['void']]],
            'ActiveProcessLinks': [0xE8, ['_LIST_ENTRY']],
            'QuotaUsage': [0xF8, ['array', 3, ['unsigned long long']]],
            'QuotaPeak': [0x110, ['array', 3, ['unsigned long long']]],
            'CommitCharge': [0x128, ['unsigned long long']],
            'PeakVirtualSize': [0x130, ['unsigned long long']],
            'VirtualSize': [0x138, ['unsigned long long']],
            'SessionProcessLinks': [0x140, ['_LIST_ENTRY']],
            'DebugPort': [0x150, ['pointer64', ['void']]],
            'ExceptionPortData': [0x158, ['pointer64', ['void']]],
            'ExceptionPortValue': [0x158, ['unsigned long long']],
            'ExceptionPortState': [
                0x158,
                [
                    'BitField',
                    dict(
                        start_bit=0,
                        end_bit=3,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ObjectTable': [0x160, ['pointer64', ['_HANDLE_TABLE']]],
            'Token': [0x168, ['_EX_FAST_REF']],
            'WorkingSetPage': [0x170, ['unsigned long long']],
            'AddressCreationLock': [0x178, ['_EX_PUSH_LOCK']],
            'RotateInProgress': [0x180, ['pointer64', ['_ETHREAD']]],
            'ForkInProgress': [0x188, ['pointer64', ['_ETHREAD']]],
            'HardwareTrigger': [0x190, ['unsigned long long']],
            'PhysicalVadRoot': [0x198, ['pointer64', ['_MM_AVL_TABLE']]],
            'CloneRoot': [0x1A0, ['pointer64', ['void']]],
            'NumberOfPrivatePages': [0x1A8, ['unsigned long long']],
            'NumberOfLockedPages': [0x1B0, ['unsigned long long']],
            'Win32Process': [0x1B8, ['pointer64', ['void']]],
            'Job': [0x1C0, ['pointer64', ['_EJOB']]],
            'SectionObject': [0x1C8, ['pointer64', ['void']]],
            'SectionBaseAddress': [0x1D0, ['pointer64', ['void']]],
            'QuotaBlock': [0x1D8, ['pointer64', ['_EPROCESS_QUOTA_BLOCK']]],
            'WorkingSetWatch': [0x1E0, ['pointer64', ['_PAGEFAULT_HISTORY']]],
            'Win32WindowStation': [0x1E8, ['pointer64', ['void']]],
            'InheritedFromUniqueProcessId': [0x1F0, ['pointer64', ['void']]],
            'LdtInformation': [0x1F8, ['pointer64', ['void']]],
            'VadFreeHint': [0x200, ['pointer64', ['void']]],
            'VdmObjects': [0x208, ['pointer64', ['void']]],
            'DeviceMap': [0x210, ['pointer64', ['void']]],
            'EtwDataSource': [0x218, ['pointer64', ['void']]],
            'FreeTebHint': [0x220, ['pointer64', ['void']]],
            'PageDirectoryPte': [0x228, ['_HARDWARE_PTE']],
            'Filler': [0x228, ['unsigned long long']],
            'Session': [0x230, ['pointer64', ['void']]],
            'ImageFileName': [0x238, ['array', 16, ['unsigned char']]],
            'JobLinks': [0x248, ['_LIST_ENTRY']],
            'LockedPagesList': [0x258, ['pointer64', ['void']]],
            'ThreadListHead': [0x260, ['_LIST_ENTRY']],
            'SecurityPort': [0x270, ['pointer64', ['void']]],
            'Wow64Process': [0x278, ['pointer64', ['_WOW64_PROCESS']]],
            'ActiveThreads': [0x280, ['unsigned long']],
            'ImagePathHash': [0x284, ['unsigned long']],
            'DefaultHardErrorProcessing': [0x288, ['unsigned long']],
            'LastThreadExitStatus': [0x28C, ['long']],
            'Peb': [0x290, ['pointer64', ['_PEB']]],
            'PrefetchTrace': [0x298, ['_EX_FAST_REF']],
            'ReadOperationCount': [0x2A0, ['_LARGE_INTEGER']],
            'WriteOperationCount': [0x2A8, ['_LARGE_INTEGER']],
            'OtherOperationCount': [0x2B0, ['_LARGE_INTEGER']],
            'ReadTransferCount': [0x2B8, ['_LARGE_INTEGER']],
            'WriteTransferCount': [0x2C0, ['_LARGE_INTEGER']],
            'OtherTransferCount': [0x2C8, ['_LARGE_INTEGER']],
            'CommitChargeLimit': [0x2D0, ['unsigned long long']],
            'CommitChargePeak': [0x2D8, ['unsigned long long']],
            'AweInfo': [0x2E0, ['pointer64', ['void']]],
            'SeAuditProcessCreationInfo': [
                0x2E8,
                ['_SE_AUDIT_PROCESS_CREATION_INFO'],
            ],
            'Vm': [0x2F0, ['_MMSUPPORT']],
            'MmProcessLinks': [0x358, ['_LIST_ENTRY']],
            'ModifiedPageCount': [0x368, ['unsigned long']],
            'Flags2': [0x36C, ['unsigned long']],
            'JobNotReallyActive': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AccountingFolded': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'NewProcessReported': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ExitProcessReported': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'ReportCommitChanges': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'LastReportMemory': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'ReportPhysicalPageChanges': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'HandleTableRundown': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'NeedsHandleRundown': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'RefTraceEnabled': [
                0x36C,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'NumaAware': [
                0x36C,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=11, native_type='unsigned long'
                    ),
                ],
            ],
            'ProtectedProcess': [
                0x36C,
                [
                    'BitField',
                    dict(
                        start_bit=11, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultPagePriority': [
                0x36C,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'PrimaryTokenFrozen': [
                0x36C,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessVerifierTarget': [
                0x36C,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'StackRandomizationDisabled': [
                0x36C,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'Flags': [0x370, ['unsigned long']],
            'CreateReported': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoDebugInherit': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'ProcessExiting': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'ProcessDelete': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow64SplitPages': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'VmDeleted': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'OutswapEnabled': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'Outswapped': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'ForkFailed': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=9, native_type='unsigned long'),
                ],
            ],
            'Wow64VaSpace4Gb': [
                0x370,
                [
                    'BitField',
                    dict(start_bit=9, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'AddressSpaceInitialized': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=12, native_type='unsigned long'
                    ),
                ],
            ],
            'SetTimerResolution': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=12, end_bit=13, native_type='unsigned long'
                    ),
                ],
            ],
            'BreakOnTermination': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=13, end_bit=14, native_type='unsigned long'
                    ),
                ],
            ],
            'DeprioritizeViews': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=14, end_bit=15, native_type='unsigned long'
                    ),
                ],
            ],
            'WriteWatch': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=15, end_bit=16, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInSession': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=16, end_bit=17, native_type='unsigned long'
                    ),
                ],
            ],
            'OverrideAddressSpace': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=17, end_bit=18, native_type='unsigned long'
                    ),
                ],
            ],
            'HasAddressSpace': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=18, end_bit=19, native_type='unsigned long'
                    ),
                ],
            ],
            'LaunchPrefetched': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=19, end_bit=20, native_type='unsigned long'
                    ),
                ],
            ],
            'InjectInpageErrors': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=20, end_bit=21, native_type='unsigned long'
                    ),
                ],
            ],
            'VmTopDown': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=22, native_type='unsigned long'
                    ),
                ],
            ],
            'ImageNotifyDone': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=22, end_bit=23, native_type='unsigned long'
                    ),
                ],
            ],
            'PdeUpdateNeeded': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=23, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'VdmAllowed': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=25, native_type='unsigned long'
                    ),
                ],
            ],
            'SmapAllowed': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=25, end_bit=26, native_type='unsigned long'
                    ),
                ],
            ],
            'ProcessInserted': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=26, end_bit=27, native_type='unsigned long'
                    ),
                ],
            ],
            'DefaultIoPriority': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=27, end_bit=30, native_type='unsigned long'
                    ),
                ],
            ],
            'SparePsFlags1': [
                0x370,
                [
                    'BitField',
                    dict(
                        start_bit=30, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ExitStatus': [0x374, ['long']],
            'Spare7': [0x378, ['unsigned short']],
            'SubSystemMinorVersion': [0x37A, ['unsigned char']],
            'SubSystemMajorVersion': [0x37B, ['unsigned char']],
            'SubSystemVersion': [0x37A, ['unsigned short']],
            'PriorityClass': [0x37C, ['unsigned char']],
            'VadRoot': [0x380, ['_MM_AVL_TABLE']],
            'Cookie': [0x3C0, ['unsigned long']],
            'AlpcContext': [0x3C8, ['_ALPC_PROCESS_CONTEXT']],
        },
    ],
    '__unnamed_1202': [
        0x8,
        {
            'MasterIrp': [0x0, ['pointer64', ['_IRP']]],
            'IrpCount': [0x0, ['long']],
            'SystemBuffer': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1207': [
        0x10,
        {
            'UserApcRoutine': [0x0, ['pointer64', ['void']]],
            'IssuingProcess': [0x0, ['pointer64', ['void']]],
            'UserApcContext': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1209': [
        0x10,
        {
            'AsynchronousParameters': [0x0, ['__unnamed_1207']],
            'AllocationSize': [0x0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1214': [
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
    '__unnamed_1216': [
        0x58,
        {
            'Overlay': [0x0, ['__unnamed_1214']],
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
            'AssociatedIrp': [0x18, ['__unnamed_1202']],
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
            'Overlay': [0x58, ['__unnamed_1209']],
            'CancelRoutine': [0x68, ['pointer64', ['void']]],
            'UserBuffer': [0x70, ['pointer64', ['void']]],
            'Tail': [0x78, ['__unnamed_1216']],
        },
    ],
    '__unnamed_121c': [
        0x20,
        {
            'SecurityContext': [0x0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [0x8, ['unsigned long']],
            'FileAttributes': [0x10, ['unsigned short']],
            'ShareAccess': [0x12, ['unsigned short']],
            'EaLength': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1220': [
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
    '__unnamed_1224': [
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
    '__unnamed_1226': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Key': [0x8, ['unsigned long']],
            'ByteOffset': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_122a': [
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
                            50: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
            'FileIndex': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_122c': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'CompletionFilter': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_122e': [
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
                            50: 'FileMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_1230': [
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
                            50: 'FileMaximumInformation',
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
    '__unnamed_1232': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'EaList': [0x8, ['pointer64', ['void']]],
            'EaListLength': [0x10, ['unsigned long']],
            'EaIndex': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1234': [
        0x4,
        {
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1238': [
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
                            11: 'FileFsMaximumInformation',
                        },
                    ),
                ],
            ],
        },
    ],
    '__unnamed_123a': [
        0x20,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x8, ['unsigned long']],
            'FsControlCode': [0x10, ['unsigned long']],
            'Type3InputBuffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_123c': [
        0x18,
        {
            'Length': [0x0, ['pointer64', ['_LARGE_INTEGER']]],
            'Key': [0x8, ['unsigned long']],
            'ByteOffset': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_123e': [
        0x20,
        {
            'OutputBufferLength': [0x0, ['unsigned long']],
            'InputBufferLength': [0x8, ['unsigned long']],
            'IoControlCode': [0x10, ['unsigned long']],
            'Type3InputBuffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1240': [
        0x10,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1242': [
        0x10,
        {
            'SecurityInformation': [0x0, ['unsigned long']],
            'SecurityDescriptor': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1246': [
        0x10,
        {
            'Vpb': [0x0, ['pointer64', ['_VPB']]],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
        },
    ],
    '__unnamed_124a': [
        0x8,
        {
            'Srb': [0x0, ['pointer64', ['_SCSI_REQUEST_BLOCK']]],
        },
    ],
    '__unnamed_124e': [
        0x20,
        {
            'Length': [0x0, ['unsigned long']],
            'StartSid': [0x8, ['pointer64', ['void']]],
            'SidList': [0x10, ['pointer64', ['_FILE_GET_QUOTA_INFORMATION']]],
            'SidListLength': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1252': [
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
    '__unnamed_1259': [
        0x20,
        {
            'InterfaceType': [0x0, ['pointer64', ['_GUID']]],
            'Size': [0x8, ['unsigned short']],
            'Version': [0xA, ['unsigned short']],
            'Interface': [0x10, ['pointer64', ['_INTERFACE']]],
            'InterfaceSpecificData': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_125d': [
        0x8,
        {
            'Capabilities': [0x0, ['pointer64', ['_DEVICE_CAPABILITIES']]],
        },
    ],
    '__unnamed_1261': [
        0x8,
        {
            'IoResourceRequirementList': [
                0x0,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
        },
    ],
    '__unnamed_1263': [
        0x20,
        {
            'WhichSpace': [0x0, ['unsigned long']],
            'Buffer': [0x8, ['pointer64', ['void']]],
            'Offset': [0x10, ['unsigned long']],
            'Length': [0x18, ['unsigned long']],
        },
    ],
    '__unnamed_1265': [
        0x1,
        {
            'Lock': [0x0, ['unsigned char']],
        },
    ],
    '__unnamed_1269': [
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
    '__unnamed_126d': [
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
    '__unnamed_1271': [
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
    '__unnamed_1275': [
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
    '__unnamed_1279': [
        0x8,
        {
            'PowerSequence': [0x0, ['pointer64', ['_POWER_SEQUENCE']]],
        },
    ],
    '__unnamed_1281': [
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
    '__unnamed_1285': [
        0x10,
        {
            'AllocatedResources': [0x0, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'AllocatedResourcesTranslated': [
                0x8,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
        },
    ],
    '__unnamed_1287': [
        0x20,
        {
            'ProviderId': [0x0, ['unsigned long long']],
            'DataPath': [0x8, ['pointer64', ['void']]],
            'BufferSize': [0x10, ['unsigned long']],
            'Buffer': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1289': [
        0x20,
        {
            'Argument1': [0x0, ['pointer64', ['void']]],
            'Argument2': [0x8, ['pointer64', ['void']]],
            'Argument3': [0x10, ['pointer64', ['void']]],
            'Argument4': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_128b': [
        0x20,
        {
            'Create': [0x0, ['__unnamed_121c']],
            'CreatePipe': [0x0, ['__unnamed_1220']],
            'CreateMailslot': [0x0, ['__unnamed_1224']],
            'Read': [0x0, ['__unnamed_1226']],
            'Write': [0x0, ['__unnamed_1226']],
            'QueryDirectory': [0x0, ['__unnamed_122a']],
            'NotifyDirectory': [0x0, ['__unnamed_122c']],
            'QueryFile': [0x0, ['__unnamed_122e']],
            'SetFile': [0x0, ['__unnamed_1230']],
            'QueryEa': [0x0, ['__unnamed_1232']],
            'SetEa': [0x0, ['__unnamed_1234']],
            'QueryVolume': [0x0, ['__unnamed_1238']],
            'SetVolume': [0x0, ['__unnamed_1238']],
            'FileSystemControl': [0x0, ['__unnamed_123a']],
            'LockControl': [0x0, ['__unnamed_123c']],
            'DeviceIoControl': [0x0, ['__unnamed_123e']],
            'QuerySecurity': [0x0, ['__unnamed_1240']],
            'SetSecurity': [0x0, ['__unnamed_1242']],
            'MountVolume': [0x0, ['__unnamed_1246']],
            'VerifyVolume': [0x0, ['__unnamed_1246']],
            'Scsi': [0x0, ['__unnamed_124a']],
            'QueryQuota': [0x0, ['__unnamed_124e']],
            'SetQuota': [0x0, ['__unnamed_1234']],
            'QueryDeviceRelations': [0x0, ['__unnamed_1252']],
            'QueryInterface': [0x0, ['__unnamed_1259']],
            'DeviceCapabilities': [0x0, ['__unnamed_125d']],
            'FilterResourceRequirements': [0x0, ['__unnamed_1261']],
            'ReadWriteConfig': [0x0, ['__unnamed_1263']],
            'SetLock': [0x0, ['__unnamed_1265']],
            'QueryId': [0x0, ['__unnamed_1269']],
            'QueryDeviceText': [0x0, ['__unnamed_126d']],
            'UsageNotification': [0x0, ['__unnamed_1271']],
            'WaitWake': [0x0, ['__unnamed_1275']],
            'PowerSequence': [0x0, ['__unnamed_1279']],
            'Power': [0x0, ['__unnamed_1281']],
            'StartDevice': [0x0, ['__unnamed_1285']],
            'WMI': [0x0, ['__unnamed_1287']],
            'Others': [0x0, ['__unnamed_1289']],
        },
    ],
    '_IO_STACK_LOCATION': [
        0x48,
        {
            'MajorFunction': [0x0, ['unsigned char']],
            'MinorFunction': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned char']],
            'Control': [0x3, ['unsigned char']],
            'Parameters': [0x8, ['__unnamed_128b']],
            'DeviceObject': [0x28, ['pointer64', ['_DEVICE_OBJECT']]],
            'FileObject': [0x30, ['pointer64', ['_FILE_OBJECT']]],
            'CompletionRoutine': [0x38, ['pointer64', ['void']]],
            'Context': [0x40, ['pointer64', ['void']]],
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
    '_PF_HARD_FAULT_INFO': [
        0x38,
        {
            'KernelTimeStamp': [0x0, ['_ETW_KERNEL_TRACE_TIMESTAMP']],
            'HardFaultEvent': [0x10, ['_PERFINFO_HARDPAGEFAULT_INFORMATION']],
            'IoTimeInTicks': [0x30, ['_LARGE_INTEGER']],
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
    '_WHEA_ERROR_RECORD': [
        0xD0,
        {
            'Header': [0x0, ['_WHEA_ERROR_RECORD_HEADER']],
            'SectionDescriptor': [
                0x88,
                ['array', 1, ['_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR']],
            ],
        },
    ],
    '_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR': [
        0x48,
        {
            'SectionOffset': [0x0, ['unsigned long']],
            'SectionLength': [0x4, ['unsigned long']],
            'Revision': [0x8, ['unsigned short']],
            'ValidationBits': [0xA, ['unsigned char']],
            'Reserved': [0xB, ['unsigned char']],
            'Flags': [0xC, ['unsigned long']],
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
                            3: 'WheaErrSevNone',
                        },
                    ),
                ],
            ],
            'FRUText': [0x34, ['array', 20, ['unsigned char']]],
        },
    ],
    '__unnamed_1339': [
        0xD0,
        {
            'ProcessorError': [0x0, ['_WHEA_GENERIC_PROCESSOR_ERROR']],
            'MemoryError': [0x0, ['_WHEA_MEMORY_ERROR']],
            'NmiError': [0x0, ['_WHEA_NMI_ERROR']],
            'PciExpressError': [0x0, ['_WHEA_PCIEXPRESS_ERROR']],
            'PciXBusError': [0x0, ['_WHEA_PCIX_BUS_ERROR']],
            'PciXDeviceError': [0x0, ['_WHEA_PCIX_DEVICE_ERROR']],
        },
    ],
    '_WHEA_ERROR_PACKET': [
        0x119,
        {
            'Signature': [0x0, ['unsigned long']],
            'Flags': [0x4, ['unsigned long']],
            'Size': [0x8, ['unsigned long long']],
            'RawDataLength': [0x10, ['unsigned long long']],
            'Context': [0x18, ['unsigned long long']],
            'ErrorType': [
                0x20,
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
                        },
                    ),
                ],
            ],
            'ErrorSeverity': [
                0x24,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrSevRecoverable',
                            1: 'WheaErrSevFatal',
                            2: 'WheaErrSevCorrected',
                            3: 'WheaErrSevNone',
                        },
                    ),
                ],
            ],
            'ErrorSourceId': [0x28, ['unsigned long']],
            'ErrorSourceType': [
                0x2C,
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
                            5: 'WheaErrSrcTypeOther',
                            6: 'WheaErrSrcTypeMax',
                        },
                    ),
                ],
            ],
            'Reserved1': [0x30, ['unsigned long']],
            'Version': [0x34, ['unsigned long']],
            'Cpu': [0x38, ['unsigned long long']],
            'u': [0x40, ['__unnamed_1339']],
            'RawDataFormat': [
                0x110,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'WheaErrorStatusFormatIPFSalRecord',
                            1: 'WheaErrorStatusFormatIA32MCA',
                            2: 'WheaErrorStatusFormatEM64TMCA',
                            3: 'WheaErrorStatusFormatAMD64MCA',
                            4: 'WheaErrorStatusFormatPCIExpress',
                            5: 'WheaErrorStatusFormatNMIPort',
                            6: 'WheaErrorStatusFormatOther',
                            7: 'WheaErrorStatusFormatMax',
                        },
                    ),
                ],
            ],
            'Reserved2': [0x114, ['unsigned long']],
            'RawData': [0x118, ['array', 1, ['unsigned char']]],
        },
    ],
    '_KPROCESS': [
        0xC0,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'ProfileListHead': [0x18, ['_LIST_ENTRY']],
            'DirectoryTableBase': [0x28, ['unsigned long long']],
            'Unused0': [0x30, ['unsigned long long']],
            'IopmOffset': [0x38, ['unsigned short']],
            'ActiveProcessors': [0x40, ['unsigned long long']],
            'KernelTime': [0x48, ['unsigned long']],
            'UserTime': [0x4C, ['unsigned long']],
            'ReadyListHead': [0x50, ['_LIST_ENTRY']],
            'SwapListEntry': [0x60, ['_SINGLE_LIST_ENTRY']],
            'InstrumentationCallback': [0x68, ['pointer64', ['void']]],
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
            'CycleTime': [0xB8, ['unsigned long long']],
        },
    ],
    '__unnamed_13f3': [
        0x8,
        {
            'Long': [0x0, ['unsigned long long']],
            'VolatileLong': [0x0, ['unsigned long long']],
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
            'u': [0x0, ['__unnamed_13f3']],
        },
    ],
    '_PTE_QUEUE_POINTER': [
        0x8,
        {
            'PointerPte': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=48, native_type='long long'),
                ],
            ],
            'TimeStamp': [
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
            'Data': [0x0, ['long long']],
        },
    ],
    '__unnamed_140c': [
        0x10,
        {
            'I386': [0x0, ['_I386_LOADER_BLOCK']],
            'Alpha': [0x0, ['_ALPHA_LOADER_BLOCK']],
            'Ia64': [0x0, ['_IA64_LOADER_BLOCK']],
        },
    ],
    '_LOADER_PARAMETER_BLOCK': [
        0xE8,
        {
            'LoadOrderListHead': [0x0, ['_LIST_ENTRY']],
            'MemoryDescriptorListHead': [0x10, ['_LIST_ENTRY']],
            'BootDriverListHead': [0x20, ['_LIST_ENTRY']],
            'KernelStack': [0x30, ['unsigned long long']],
            'Prcb': [0x38, ['unsigned long long']],
            'Process': [0x40, ['unsigned long long']],
            'Thread': [0x48, ['unsigned long long']],
            'RegistryLength': [0x50, ['unsigned long']],
            'RegistryBase': [0x58, ['pointer64', ['void']]],
            'ConfigurationRoot': [
                0x60,
                ['pointer64', ['_CONFIGURATION_COMPONENT_DATA']],
            ],
            'ArcBootDeviceName': [0x68, ['pointer64', ['unsigned char']]],
            'ArcHalDeviceName': [0x70, ['pointer64', ['unsigned char']]],
            'NtBootPathName': [0x78, ['pointer64', ['unsigned char']]],
            'NtHalPathName': [0x80, ['pointer64', ['unsigned char']]],
            'LoadOptions': [0x88, ['pointer64', ['unsigned char']]],
            'NlsData': [0x90, ['pointer64', ['_NLS_DATA_BLOCK']]],
            'ArcDiskInformation': [
                0x98,
                ['pointer64', ['_ARC_DISK_INFORMATION']],
            ],
            'OemFontFile': [0xA0, ['pointer64', ['void']]],
            'SetupLoaderBlock': [0xA8, ['pointer64', ['_SETUP_LOADER_BLOCK']]],
            'Extension': [
                0xB0,
                ['pointer64', ['_LOADER_PARAMETER_EXTENSION']],
            ],
            'u': [0xB8, ['__unnamed_140c']],
            'FirmwareInformation': [
                0xC8,
                ['_FIRMWARE_INFORMATION_LOADER_BLOCK'],
            ],
        },
    ],
    '__unnamed_1428': [
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
    '__unnamed_142a': [
        0x8,
        {
            'Blink': [0x0, ['unsigned long long']],
            'ImageProtoPte': [0x0, ['pointer64', ['_MMPTE']]],
            'ShareCount': [0x0, ['unsigned long long']],
        },
    ],
    '__unnamed_142e': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'VolatileReferenceCount': [0x0, ['short']],
            'ShortFlags': [0x2, ['unsigned short']],
        },
    ],
    '__unnamed_1430': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'ByteFlags': [0x2, ['unsigned char']],
            'InterlockedByteFlags': [0x3, ['unsigned char']],
        },
    ],
    '__unnamed_1432': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned short']],
            'e1': [0x2, ['_MMPFNENTRY']],
            'e2': [0x0, ['__unnamed_142e']],
            'e3': [0x0, ['__unnamed_1430']],
        },
    ],
    '__unnamed_143a': [
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
            'u1': [0x0, ['__unnamed_1428']],
            'u2': [0x8, ['__unnamed_142a']],
            'PteAddress': [0x10, ['pointer64', ['_MMPTE']]],
            'VolatilePteAddress': [0x10, ['pointer64', ['void']]],
            'u3': [0x18, ['__unnamed_1432']],
            'UsedPageTableEntries': [0x1C, ['unsigned short']],
            'VaType': [0x1E, ['unsigned char']],
            'ViewCount': [0x1F, ['unsigned char']],
            'OriginalPte': [0x20, ['_MMPTE']],
            'AweReferenceCount': [0x20, ['long']],
            'u4': [0x28, ['__unnamed_143a']],
        },
    ],
    '__unnamed_1446': [
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
            'u1': [0x0, ['__unnamed_1446']],
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
            'NextEstimationSlot': [0x24, ['unsigned long']],
            'NextAgingSlot': [0x28, ['unsigned long']],
            'EstimatedAvailable': [0x2C, ['unsigned long']],
            'GrowthSinceLastEstimate': [0x30, ['unsigned long']],
            'NumberOfCommittedPageTables': [0x34, ['unsigned long']],
            'VadBitMapHint': [0x38, ['unsigned long']],
            'NonDirectCount': [0x3C, ['unsigned long']],
            'NonDirectHash': [0x40, ['pointer64', ['_MMWSLE_NONDIRECT_HASH']]],
            'HashTableStart': [0x48, ['pointer64', ['_MMWSLE_HASH']]],
            'HighestPermittedHashAddress': [
                0x50,
                ['pointer64', ['_MMWSLE_HASH']],
            ],
            'HighestUserAddress': [0x58, ['pointer64', ['void']]],
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
    '_MMSUPPORT': [
        0x68,
        {
            'WorkingSetExpansionLinks': [0x0, ['_LIST_ENTRY']],
            'LastTrimStamp': [0x10, ['unsigned short']],
            'NextPageColor': [0x12, ['unsigned short']],
            'Flags': [0x14, ['_MMSUPPORT_FLAGS']],
            'PageFaultCount': [0x18, ['unsigned long']],
            'PeakWorkingSetSize': [0x1C, ['unsigned long']],
            'Spare0': [0x20, ['unsigned long']],
            'MinimumWorkingSetSize': [0x24, ['unsigned long']],
            'MaximumWorkingSetSize': [0x28, ['unsigned long']],
            'VmWorkingSetList': [0x30, ['pointer64', ['_MMWSL']]],
            'Claim': [0x38, ['unsigned long']],
            'Spare': [0x3C, ['array', 1, ['unsigned long']]],
            'WorkingSetPrivateSize': [0x40, ['unsigned long']],
            'WorkingSetSizeOverhead': [0x44, ['unsigned long']],
            'WorkingSetSize': [0x48, ['unsigned long']],
            'ExitEvent': [0x50, ['pointer64', ['_KEVENT']]],
            'WorkingSetMutex': [0x58, ['_EX_PUSH_LOCK']],
            'AccessLog': [0x60, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_146a': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MMSECTION_FLAGS']],
        },
    ],
    '__unnamed_146c': [
        0x4,
        {
            'ModifiedWriteCount': [0x0, ['unsigned short']],
            'FlushInProgressCount': [0x2, ['unsigned short']],
        },
    ],
    '__unnamed_146e': [
        0x4,
        {
            'e2': [0x0, ['__unnamed_146c']],
        },
    ],
    '__unnamed_147a': [
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
    '__unnamed_147c': [
        0x10,
        {
            'e2': [0x0, ['__unnamed_147a']],
        },
    ],
    '_CONTROL_AREA': [
        0x60,
        {
            'Segment': [0x0, ['pointer64', ['_SEGMENT']]],
            'DereferenceList': [0x8, ['_LIST_ENTRY']],
            'NumberOfSectionReferences': [0x18, ['unsigned long']],
            'NumberOfPfnReferences': [0x1C, ['unsigned long']],
            'NumberOfMappedViews': [0x20, ['unsigned long']],
            'NumberOfUserReferences': [0x24, ['unsigned long']],
            'u': [0x28, ['__unnamed_146a']],
            'u1': [0x2C, ['__unnamed_146e']],
            'FilePointer': [0x30, ['_EX_FAST_REF']],
            'ControlAreaLock': [0x38, ['long']],
            'StartingFrame': [0x3C, ['unsigned long']],
            'WaitingForDeletion': [
                0x40,
                ['pointer64', ['_MI_SECTION_CREATION_EVENT']],
            ],
            'u2': [0x48, ['__unnamed_147c']],
            'LockedPages': [0x58, ['long long']],
        },
    ],
    '_MMPAGING_FILE': [
        0xA0,
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
            'BitmapHint': [0x60, ['unsigned long']],
            'LastAllocationSize': [0x64, ['unsigned long']],
            'PageFileNumber': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'BootPartition': [
                0x68,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'Spare0': [
                0x68,
                [
                    'BitField',
                    dict(
                        start_bit=5, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'AdriftMdls': [
                0x6A,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'Spare1': [
                0x6A,
                [
                    'BitField',
                    dict(
                        start_bit=1, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'FileHandle': [0x70, ['pointer64', ['void']]],
            'AvailableList': [0x80, ['_SLIST_HEADER']],
            'NeedProcessingList': [0x90, ['_SLIST_HEADER']],
        },
    ],
    '_MMPAGING_FILE_FREE_ENTRY': [
        0x10,
        {
            'ListEntry': [0x0, ['_SINGLE_LIST_ENTRY']],
            'FreeBit': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_14ae': [
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
    '__unnamed_14b1': [
        0x8,
        {
            'LongFlags': [0x0, ['unsigned long long']],
            'VadFlags': [0x0, ['_MMVAD_FLAGS']],
        },
    ],
    '__unnamed_14b4': [
        0x8,
        {
            'LongFlags3': [0x0, ['unsigned long long']],
            'VadFlags3': [0x0, ['_MMVAD_FLAGS3']],
        },
    ],
    '_MMVAD_SHORT': [
        0x40,
        {
            'u1': [0x0, ['__unnamed_14ae']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_14b1']],
            'PushLock': [0x30, ['_EX_PUSH_LOCK']],
            'u5': [0x38, ['__unnamed_14b4']],
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
    '__unnamed_14be': [
        0x4,
        {
            'LongFlags2': [0x0, ['unsigned long']],
            'VadFlags2': [0x0, ['_MMVAD_FLAGS2']],
        },
    ],
    '_MMVAD': [
        0x60,
        {
            'u1': [0x0, ['__unnamed_14ae']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_14b1']],
            'PushLock': [0x30, ['_EX_PUSH_LOCK']],
            'u5': [0x38, ['__unnamed_14b4']],
            'u2': [0x40, ['__unnamed_14be']],
            'Subsection': [0x48, ['pointer64', ['_SUBSECTION']]],
            'MappedSubsection': [0x48, ['pointer64', ['_MSUBSECTION']]],
            'FirstPrototypePte': [0x50, ['pointer64', ['_MMPTE']]],
            'LastContiguousPte': [0x58, ['pointer64', ['_MMPTE']]],
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
    '__unnamed_14d0': [
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
            'u1': [0x0, ['__unnamed_14d0']],
            'LeftChild': [0x8, ['pointer64', ['_MMADDRESS_NODE']]],
            'RightChild': [0x10, ['pointer64', ['_MMADDRESS_NODE']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
        },
    ],
    '__unnamed_14d5': [
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
            'u': [0x28, ['__unnamed_14d5']],
            'StartingSector': [0x2C, ['unsigned long']],
            'NumberOfFullSectors': [0x30, ['unsigned long']],
        },
    ],
    '__unnamed_14db': [
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
            'NextToFree': [0x0, ['pointer64', ['_MI_PER_SESSION_PROTOS']]],
        },
    ],
    '__unnamed_14dd': [
        0x4,
        {
            'ReferenceCount': [0x0, ['unsigned long']],
            'NumberOfPtesToFree': [0x0, ['unsigned long']],
        },
    ],
    '_MI_PER_SESSION_PROTOS': [
        0x38,
        {
            'u1': [0x0, ['__unnamed_14db']],
            'LeftChild': [0x8, ['pointer64', ['_MMADDRESS_NODE']]],
            'RightChild': [0x10, ['pointer64', ['_MMADDRESS_NODE']]],
            'SessionId': [0x18, ['unsigned long']],
            'StartingVpn': [0x18, ['unsigned long long']],
            'Subsection': [0x18, ['pointer64', ['_SUBSECTION']]],
            'EndingVpn': [0x20, ['unsigned long long']],
            'SubsectionBase': [0x28, ['pointer64', ['_MMPTE']]],
            'u2': [0x30, ['__unnamed_14dd']],
        },
    ],
    '__unnamed_14e6': [
        0x10,
        {
            'IoStatus': [0x0, ['_IO_STATUS_BLOCK']],
        },
    ],
    '__unnamed_14e8': [
        0x8,
        {
            'LastPageToWrite': [0x0, ['unsigned long long']],
            'KeepForever': [0x0, ['unsigned long long']],
        },
    ],
    '_MMMOD_WRITER_MDL_ENTRY': [
        0xA0,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'u': [0x10, ['__unnamed_14e6']],
            'Irp': [0x20, ['pointer64', ['_IRP']]],
            'u1': [0x28, ['__unnamed_14e8']],
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
    '__unnamed_14f0': [
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
            'MdlHack': [0x30, ['__unnamed_14f0']],
        },
    ],
    '_HHIVE': [
        0x590,
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
            'DirtyFlag': [0x72, ['unsigned char']],
            'HvBinHeadersUse': [0x74, ['unsigned long']],
            'HvFreeCellsUse': [0x78, ['unsigned long']],
            'HvUsedCellsUse': [0x7C, ['unsigned long']],
            'CmUsedCellsUse': [0x80, ['unsigned long']],
            'HiveFlags': [0x84, ['unsigned long']],
            'CurrentLog': [0x88, ['unsigned long']],
            'LogSize': [0x8C, ['array', 2, ['unsigned long']]],
            'RefreshCount': [0x94, ['unsigned long']],
            'StorageTypeCount': [0x98, ['unsigned long']],
            'Version': [0x9C, ['unsigned long']],
            'Storage': [0xA0, ['array', 2, ['_DUAL']]],
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
    '_TEB': [
        0x1828,
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
            'SpareBytes1': [0x2D0, ['array', 24, ['unsigned char']]],
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
            'SpareBool0': [0x1744, ['unsigned char']],
            'SpareBool1': [0x1745, ['unsigned char']],
            'SpareBool2': [0x1746, ['unsigned char']],
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
            'ImpersonationLocale': [0x1798, ['unsigned long']],
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
            'DbgSafeThunkCall': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'DbgInDebugPrint': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'DbgHasFiberData': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'DbgSkipThreadAttach': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'DbgWerInShipAssertCode': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'DbgRanProcessInit': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'DbgClonedThread': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'DbgSuppressDebugMsg': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'SpareSameTebBits': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=8, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0x17F0, ['pointer64', ['void']]],
            'TxnScopeExitCallback': [0x17F8, ['pointer64', ['void']]],
            'TxnScopeContext': [0x1800, ['pointer64', ['void']]],
            'LockCount': [0x1808, ['unsigned long']],
            'ProcessRundown': [0x180C, ['unsigned long']],
            'LastSwitchTime': [0x1810, ['unsigned long long']],
            'TotalSwitchOutTime': [0x1818, ['unsigned long long']],
            'WaitReasonBitMap': [0x1820, ['_LARGE_INTEGER']],
        },
    ],
    '_CONTEXT32_UPDATE': [
        0x4,
        {
            'NumberEntries': [0x0, ['unsigned long']],
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
    '__unnamed_15c8': [
        0x2,
        {
            'AsUSHORT': [0x0, ['unsigned short']],
            'PStateDomain': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'PStateDomainIdleAccounting': [
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
    '_PROCESSOR_POWER_STATE': [
        0x138,
        {
            'IdleFunction': [0x0, ['pointer64', ['void']]],
            'IdleStates': [0x8, ['pointer64', ['PPM_IDLE_STATES']]],
            'LastTimeCheck': [0x10, ['unsigned long long']],
            'LastIdleTime': [0x18, ['unsigned long long']],
            'IdleTimes': [0x20, ['PROCESSOR_IDLE_TIMES']],
            'IdleAccounting': [0x40, ['pointer64', ['PPM_IDLE_ACCOUNTING']]],
            'PerfStates': [0x48, ['pointer64', ['PPM_PERF_STATES']]],
            'LastKernelUserTime': [0x50, ['unsigned long']],
            'LastIdleThreadKTime': [0x54, ['unsigned long']],
            'LastGlobalTimeHv': [0x58, ['unsigned long long']],
            'LastProcessorTimeHv': [0x60, ['unsigned long long']],
            'ThermalConstraint': [0x68, ['unsigned char']],
            'LastBusyPercentage': [0x69, ['unsigned char']],
            'Flags': [0x6A, ['__unnamed_15c8']],
            'PerfTimer': [0x70, ['_KTIMER']],
            'PerfDpc': [0xB0, ['_KDPC']],
            'LastSysTime': [0xF0, ['unsigned long']],
            'PStateMaster': [0xF8, ['pointer64', ['_KPRCB']]],
            'PStateSet': [0x100, ['unsigned long long']],
            'CurrentPState': [0x108, ['unsigned long']],
            'Reserved0': [0x10C, ['unsigned long']],
            'DesiredPState': [0x110, ['unsigned long']],
            'Reserved1': [0x114, ['unsigned long']],
            'PStateIdleStartTime': [0x118, ['unsigned long']],
            'PStateIdleTime': [0x11C, ['unsigned long']],
            'LastPStateIdleTime': [0x120, ['unsigned long']],
            'PStateStartTime': [0x124, ['unsigned long']],
            'WmiDispatchPtr': [0x128, ['unsigned long long']],
            'WmiInterfaceEnabled': [0x130, ['long']],
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
    '_PNP_DEVICE_COMPLETION_QUEUE': [
        0x50,
        {
            'SpinLock': [0x0, ['unsigned long long']],
            'DispatchedCount': [0x8, ['unsigned long']],
            'DispatchedList': [0x10, ['_LIST_ENTRY']],
            'CompletedSemaphore': [0x20, ['_KSEMAPHORE']],
            'CompletedList': [0x40, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_15f9': [
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
            'Queue': [0x50, ['__unnamed_15f9']],
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
    '__unnamed_160b': [
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
    '__unnamed_160d': [
        0x8,
        {
            'NextResourceDeviceNode': [0x0, ['pointer64', ['_DEVICE_NODE']]],
        },
    ],
    '__unnamed_1611': [
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
        0x220,
        {
            'Sibling': [0x0, ['pointer64', ['_DEVICE_NODE']]],
            'Child': [0x8, ['pointer64', ['_DEVICE_NODE']]],
            'Parent': [0x10, ['pointer64', ['_DEVICE_NODE']]],
            'LastChild': [0x18, ['pointer64', ['_DEVICE_NODE']]],
            'Level': [0x20, ['unsigned long']],
            'Notify': [0x28, ['_PO_DEVICE_NOTIFY']],
            'PoIrpManager': [0x68, ['_PO_IRP_MANAGER']],
            'State': [
                0x88,
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
                0x8C,
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
                0x90,
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
            'StateHistoryEntry': [0xE0, ['unsigned long']],
            'CompletionStatus': [0xE4, ['long']],
            'PendingIrp': [0xE8, ['pointer64', ['_IRP']]],
            'Flags': [0xF0, ['unsigned long']],
            'UserFlags': [0xF4, ['unsigned long']],
            'Problem': [0xF8, ['unsigned long']],
            'PhysicalDeviceObject': [0x100, ['pointer64', ['_DEVICE_OBJECT']]],
            'ResourceList': [0x108, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'ResourceListTranslated': [
                0x110,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
            'InstancePath': [0x118, ['_UNICODE_STRING']],
            'ServiceName': [0x128, ['_UNICODE_STRING']],
            'DuplicatePDO': [0x138, ['pointer64', ['_DEVICE_OBJECT']]],
            'ResourceRequirements': [
                0x140,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
            'InterfaceType': [
                0x148,
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
            'BusNumber': [0x14C, ['unsigned long']],
            'ChildInterfaceType': [
                0x150,
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
            'ChildBusNumber': [0x154, ['unsigned long']],
            'ChildBusTypeIndex': [0x158, ['unsigned short']],
            'RemovalPolicy': [0x15A, ['unsigned char']],
            'HardwareRemovalPolicy': [0x15B, ['unsigned char']],
            'TargetDeviceNotify': [0x160, ['_LIST_ENTRY']],
            'DeviceArbiterList': [0x170, ['_LIST_ENTRY']],
            'DeviceTranslatorList': [0x180, ['_LIST_ENTRY']],
            'NoTranslatorMask': [0x190, ['unsigned short']],
            'QueryTranslatorMask': [0x192, ['unsigned short']],
            'NoArbiterMask': [0x194, ['unsigned short']],
            'QueryArbiterMask': [0x196, ['unsigned short']],
            'OverUsed1': [0x198, ['__unnamed_160b']],
            'OverUsed2': [0x1A0, ['__unnamed_160d']],
            'BootResources': [0x1A8, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'BootResourcesTranslated': [
                0x1B0,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
            'CapabilityFlags': [0x1B8, ['unsigned long']],
            'DockInfo': [0x1C0, ['__unnamed_1611']],
            'DisableableDepends': [0x1E0, ['unsigned long']],
            'PendedSetInterfaceState': [0x1E8, ['_LIST_ENTRY']],
            'LegacyBusListEntry': [0x1F8, ['_LIST_ENTRY']],
            'DriverUnloadRetryCount': [0x208, ['unsigned long']],
            'PreviousParent': [0x210, ['pointer64', ['_DEVICE_NODE']]],
            'DeletedChildren': [0x218, ['unsigned long']],
            'NumaNodeIndex': [0x21C, ['unsigned long']],
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
    '__unnamed_16b1': [
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
            'u': [0x10, ['__unnamed_16b1']],
        },
    ],
    '__unnamed_16b8': [
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
            'u': [0xC, ['__unnamed_16b8']],
        },
    ],
    '_VOLUME_CACHE_MAP': [
        0x28,
        {
            'NodeTypeCode': [0x0, ['short']],
            'NodeByteCode': [0x2, ['short']],
            'UseCount': [0x4, ['unsigned long']],
            'DeviceObject': [0x8, ['pointer64', ['_DEVICE_OBJECT']]],
            'VolumeCacheMapLinks': [0x10, ['_LIST_ENTRY']],
            'Flags': [0x20, ['unsigned long']],
        },
    ],
    '_SHARED_CACHE_MAP': [
        0x1C8,
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
            'HighWaterMappingOffset': [0x148, ['_LARGE_INTEGER']],
            'PrivateCacheMap': [0x150, ['_PRIVATE_CACHE_MAP']],
            'WriteBehindWorkQueueEntry': [0x1B0, ['pointer64', ['void']]],
            'VolumeCacheMap': [0x1B8, ['pointer64', ['_VOLUME_CACHE_MAP']]],
            'ProcImagePathHash': [0x1C0, ['unsigned long']],
            'MappedWritesInProgress': [0x1C4, ['unsigned long']],
        },
    ],
    '__unnamed_16f3': [
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
            'Overlay': [0x10, ['__unnamed_16f3']],
            'LruList': [0x18, ['_LIST_ENTRY']],
            'ArrayHead': [0x28, ['pointer64', ['_VACB_ARRAY_HEADER']]],
        },
    ],
    '__unnamed_1701': [
        0x8,
        {
            'FileObject': [0x0, ['pointer64', ['_FILE_OBJECT']]],
        },
    ],
    '__unnamed_1703': [
        0x8,
        {
            'SharedCacheMap': [0x0, ['pointer64', ['_SHARED_CACHE_MAP']]],
        },
    ],
    '__unnamed_1705': [
        0x8,
        {
            'Event': [0x0, ['pointer64', ['_KEVENT']]],
        },
    ],
    '__unnamed_1707': [
        0x4,
        {
            'Reason': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1709': [
        0x8,
        {
            'Read': [0x0, ['__unnamed_1701']],
            'Write': [0x0, ['__unnamed_1703']],
            'Event': [0x0, ['__unnamed_1705']],
            'Notification': [0x0, ['__unnamed_1707']],
        },
    ],
    '_WORK_QUEUE_ENTRY': [
        0x30,
        {
            'WorkQueueLinks': [0x0, ['_LIST_ENTRY']],
            'CoalescedWorkQueueLinks': [0x10, ['_LIST_ENTRY']],
            'Parameters': [0x20, ['__unnamed_1709']],
            'Function': [0x28, ['unsigned char']],
        },
    ],
    '_VACB_LEVEL_REFERENCE': [
        0x8,
        {
            'Reference': [0x0, ['long']],
            'SpecialReference': [0x4, ['long']],
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
        0x1F8,
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
            'TuningParameters': [0x1E8, ['_HEAP_TUNING_PARAMETERS']],
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
    '_LDR_DATA_TABLE_ENTRY': [
        0xC8,
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
    '_WMI_LOGGER_CONTEXT': [
        0x350,
        {
            'StartTime': [0x0, ['_LARGE_INTEGER']],
            'LogFileHandle': [0x8, ['pointer64', ['void']]],
            'LoggerThread': [0x10, ['pointer64', ['_ETHREAD']]],
            'LoggerStatus': [0x18, ['long']],
            'LoggerId': [0x1C, ['unsigned long']],
            'NBQHead': [0x20, ['pointer64', ['void']]],
            'OverflowNBQHead': [0x28, ['pointer64', ['void']]],
            'QueueBlockFreeList': [0x30, ['_SLIST_HEADER']],
            'GlobalList': [0x40, ['_SLIST_HEADER']],
            'LoggerName': [0x50, ['_UNICODE_STRING']],
            'LogFileName': [0x60, ['_UNICODE_STRING']],
            'LogFilePattern': [0x70, ['_UNICODE_STRING']],
            'NewLogFileName': [0x80, ['_UNICODE_STRING']],
            'ClockType': [0x90, ['unsigned long']],
            'CollectionOn': [0x94, ['long']],
            'MaximumFileSize': [0x98, ['unsigned long']],
            'LoggerMode': [0x9C, ['unsigned long']],
            'LastFlushedBuffer': [0xA0, ['unsigned long']],
            'FlushTimer': [0xA4, ['unsigned long']],
            'ByteOffset': [0xA8, ['_LARGE_INTEGER']],
            'FlushTimeStamp': [0xB0, ['_LARGE_INTEGER']],
            'MinimumBuffers': [0xB8, ['unsigned long']],
            'BuffersAvailable': [0xBC, ['long']],
            'NumberOfBuffers': [0xC0, ['long']],
            'MaximumBuffers': [0xC4, ['unsigned long']],
            'EventsLost': [0xC8, ['unsigned long']],
            'BuffersWritten': [0xCC, ['unsigned long']],
            'LogBuffersLost': [0xD0, ['unsigned long']],
            'RealTimeBuffersDelivered': [0xD4, ['unsigned long']],
            'RealTimeBuffersLost': [0xD8, ['unsigned long']],
            'BufferSize': [0xDC, ['unsigned long']],
            'MaximumEventSize': [0xE0, ['unsigned long']],
            'SequencePtr': [0xE8, ['pointer64', ['long']]],
            'LocalSequence': [0xF0, ['unsigned long']],
            'InstanceGuid': [0xF4, ['_GUID']],
            'GetCpuClock': [0x108, ['pointer64', ['void']]],
            'FileCounter': [0x110, ['long']],
            'BufferCallback': [0x118, ['pointer64', ['void']]],
            'PoolType': [
                0x120,
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
            'ReferenceTime': [0x128, ['_ETW_REF_CLOCK']],
            'RealtimeLoggerContextFreed': [0x138, ['unsigned char']],
            'Consumers': [0x140, ['_LIST_ENTRY']],
            'NumConsumers': [0x150, ['unsigned long']],
            'Connecting': [0x158, ['_LIST_ENTRY']],
            'NewConsumer': [0x168, ['unsigned char']],
            'RealtimeLogfileHandle': [0x170, ['pointer64', ['void']]],
            'RealtimeLogfileName': [0x178, ['_UNICODE_STRING']],
            'RealtimeWriteOffset': [0x188, ['_LARGE_INTEGER']],
            'RealtimeReadOffset': [0x190, ['_LARGE_INTEGER']],
            'RealtimeLogfileSize': [0x198, ['_LARGE_INTEGER']],
            'RealtimeLogfileUsage': [0x1A0, ['unsigned long long']],
            'RealtimeBuffersSaved': [0x1A8, ['unsigned long']],
            'RealtimeReferenceTime': [0x1B0, ['_ETW_REF_CLOCK']],
            'RealtimeDisconnectProcessId': [0x1C0, ['unsigned long']],
            'RealtimeDisconnectConsumerId': [0x1C4, ['unsigned long']],
            'NewRTEventsLost': [
                0x1C8,
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
            'LoggerEvent': [0x1D0, ['_KEVENT']],
            'FlushEvent': [0x1E8, ['_KEVENT']],
            'FlushDpc': [0x200, ['_KDPC']],
            'LoggerMutex': [0x240, ['_KMUTANT']],
            'ClientSecurityContext': [0x278, ['_SECURITY_CLIENT_CONTEXT']],
            'SecurityDescriptor': [0x2C0, ['_EX_FAST_REF']],
            'DummyBufferForMarker': [0x2C8, ['_WMI_BUFFER_HEADER']],
            'BufferSequenceNumber': [0x310, ['long long']],
            'AcceptNewEvents': [0x318, ['long']],
            'Flags': [0x31C, ['unsigned long']],
            'Persistent': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'AutoLogger': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'FsReady': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'RealTime': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'Wow': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'KernelTrace': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned long'),
                ],
            ],
            'NoMoreEnable': [
                0x31C,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned long'),
                ],
            ],
            'RequestFlag': [0x320, ['unsigned long']],
            'RequestNewFie': [
                0x320,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'RequestUpdateFile': [
                0x320,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'RequestFlush': [
                0x320,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned long'),
                ],
            ],
            'RequestDisableRealtime': [
                0x320,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'RequestDisconnectConsumer': [
                0x320,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'StackTraceFilterHookCount': [0x324, ['unsigned short']],
            'StackTraceFilter': [0x326, ['array', 16, ['unsigned short']]],
        },
    ],
    '_WMI_BUFFER_HEADER': [
        0x48,
        {
            'Wnode': [0x0, ['_WNODE_HEADER']],
            'BufferSize': [0x0, ['unsigned long']],
            'SavedOffset': [0x4, ['unsigned long']],
            'CurrentOffset': [0x8, ['unsigned long']],
            'ReferenceCount': [0xC, ['long']],
            'TimeStamp': [0x10, ['_LARGE_INTEGER']],
            'StartPerfClock': [0x10, ['_LARGE_INTEGER']],
            'SequenceNumber': [0x18, ['long long']],
            'Spare0': [0x20, ['unsigned long']],
            'Spare1': [0x24, ['unsigned long']],
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
            'Flags': [0x2C, ['unsigned long']],
            'Offset': [0x30, ['unsigned long']],
            'BufferFlag': [0x34, ['unsigned short']],
            'BufferType': [0x36, ['unsigned short']],
            'Padding1': [0x38, ['array', 4, ['unsigned long']]],
            'StartTime': [0x38, ['_LARGE_INTEGER']],
            'Entry': [0x38, ['_LIST_ENTRY']],
            'SlistEntry': [0x38, ['_SINGLE_LIST_ENTRY']],
            'NextBuffer': [0x38, ['pointer64', ['_WMI_BUFFER_HEADER']]],
            'GlobalEntry': [0x40, ['_SINGLE_LIST_ENTRY']],
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
    '_ETW_GUID_ENTRY': [
        0x170,
        {
            'GuidList': [0x0, ['_LIST_ENTRY']],
            'RefCount': [0x10, ['long']],
            'Guid': [0x14, ['_GUID']],
            'RegListHead': [0x28, ['_LIST_ENTRY']],
            'SecurityDescriptor': [0x38, ['pointer64', ['void']]],
            'LegacyEnableContext': [0x40, ['_TRACE_ENABLE_CONTEXT']],
            'LegacyProviderEnabled': [0x48, ['unsigned long']],
            'ProviderEnableInfo': [0x50, ['_TRACE_ENABLE_INFO']],
            'EnableInfo': [0x70, ['array', 8, ['_TRACE_ENABLE_INFO']]],
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
        0x318,
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
            'ProxyData': [0xD0, ['pointer64', ['_SECURITY_TOKEN_PROXY_DATA']]],
            'AuditData': [0xD8, ['pointer64', ['_SECURITY_TOKEN_AUDIT_DATA']]],
            'LogonSession': [
                0xE0,
                ['pointer64', ['_SEP_LOGON_SESSION_REFERENCES']],
            ],
            'OriginatingLogonSession': [0xE8, ['_LUID']],
            'SidHash': [0xF0, ['_SID_AND_ATTRIBUTES_HASH']],
            'RestrictedSidHash': [0x200, ['_SID_AND_ATTRIBUTES_HASH']],
            'VariablePart': [0x310, ['unsigned long long']],
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
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=6,
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
    '_GUID': [
        0x10,
        {
            'Data1': [0x0, ['unsigned long']],
            'Data2': [0x4, ['unsigned short']],
            'Data3': [0x6, ['unsigned short']],
            'Data4': [0x8, ['array', 8, ['unsigned char']]],
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
    '_DISPATCHER_HEADER': [
        0x18,
        {
            'Type': [0x0, ['unsigned char']],
            'Abandoned': [0x1, ['unsigned char']],
            'Absolute': [0x1, ['unsigned char']],
            'NpxIrql': [0x1, ['unsigned char']],
            'Signalling': [0x1, ['unsigned char']],
            'Size': [0x2, ['unsigned char']],
            'Hand': [0x2, ['unsigned char']],
            'Inserted': [0x3, ['unsigned char']],
            'DebugActive': [0x3, ['unsigned char']],
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
    '_HEAP_COUNTERS': [
        0x60,
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
            'InBlockDeccommits': [0x50, ['unsigned long']],
            'InBlockDeccomitSize': [0x58, ['unsigned long long']],
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
    '_PERFINFO_HARDPAGEFAULT_INFORMATION': [
        0x20,
        {
            'ReadOffset': [0x0, ['_LARGE_INTEGER']],
            'VirtualAddress': [0x8, ['pointer64', ['void']]],
            'FileObject': [0x10, ['pointer64', ['void']]],
            'ThreadId': [0x18, ['unsigned long']],
            'ByteCount': [0x1C, ['unsigned long']],
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
    '_DBGKD_SEARCH_MEMORY': [
        0x18,
        {
            'SearchAddress': [0x0, ['unsigned long long']],
            'FoundAddress': [0x0, ['unsigned long long']],
            'SearchLength': [0x8, ['unsigned long long']],
            'PatternLength': [0x10, ['unsigned long']],
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
    '_WHEA_NMI_ERROR': [
        0x8,
        {
            'Data': [0x0, ['array', 8, ['unsigned char']]],
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
        0x60,
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
            'FirstFreeHandle': [0x48, ['long']],
            'LastFreeHandleEntry': [
                0x50,
                ['pointer64', ['_HANDLE_TABLE_ENTRY']],
            ],
            'HandleCount': [0x58, ['long']],
            'NextHandleNeedingPool': [0x5C, ['unsigned long']],
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
    '_VI_CANCEL_GLOBALS': [
        0x78,
        {
            'CancelLock': [0x0, ['unsigned long long']],
            'IssueLock': [0x8, ['unsigned long long']],
            'Counters': [0x10, ['array', 25, ['long']]],
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
    '_TRACE_ENABLE_CONTEXT': [
        0x8,
        {
            'LoggerId': [0x0, ['unsigned short']],
            'Level': [0x2, ['unsigned char']],
            'InternalFlag': [0x3, ['unsigned char']],
            'EnableFlags': [0x4, ['unsigned long']],
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
    '_CM_KEY_BODY': [
        0x60,
        {
            'Type': [0x0, ['unsigned long']],
            'KeyControlBlock': [0x8, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'NotifyBlock': [0x10, ['pointer64', ['_CM_NOTIFY_BLOCK']]],
            'ProcessID': [0x18, ['pointer64', ['void']]],
            'KeyBodyList': [0x20, ['_LIST_ENTRY']],
            'Flags': [0x30, ['unsigned long']],
            'KtmTrans': [0x38, ['pointer64', ['void']]],
            'KtmUow': [0x40, ['pointer64', ['_GUID']]],
            'KeyBodyLock': [0x48, ['_EX_PUSH_LOCK']],
            'ContextListHead': [0x50, ['_LIST_ENTRY']],
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
    '_THERMAL_INFORMATION_EX': [
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
            'S4TransitionTripPoint': [0x54, ['unsigned long']],
        },
    ],
    '__unnamed_18ac': [
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
    '__unnamed_18ae': [
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
            'File': [0x0, ['__unnamed_18ac']],
            'Private': [0x0, ['__unnamed_18ae']],
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
    '_CMHIVE': [
        0xB38,
        {
            'Hive': [0x0, ['_HHIVE']],
            'FileHandles': [0x590, ['array', 6, ['pointer64', ['void']]]],
            'NotifyList': [0x5C0, ['_LIST_ENTRY']],
            'HiveList': [0x5D0, ['_LIST_ENTRY']],
            'HiveLock': [0x5E0, ['pointer64', ['_FAST_MUTEX']]],
            'ViewLock': [0x5E8, ['pointer64', ['_FAST_MUTEX']]],
            'WriterLock': [0x5F0, ['pointer64', ['_FAST_MUTEX']]],
            'FlusherLock': [0x5F8, ['_EX_PUSH_LOCK']],
            'SecurityLock': [0x600, ['_EX_PUSH_LOCK']],
            'MappedViewList': [0x608, ['_LIST_ENTRY']],
            'PinnedViewList': [0x618, ['_LIST_ENTRY']],
            'FlushedViewList': [0x628, ['_LIST_ENTRY']],
            'MappedViewCount': [0x638, ['unsigned short']],
            'PinnedViewCount': [0x63A, ['unsigned short']],
            'UseCount': [0x63C, ['unsigned long']],
            'ViewsPerHive': [0x640, ['unsigned long']],
            'FileObject': [0x648, ['pointer64', ['_FILE_OBJECT']]],
            'LastShrinkHiveSize': [0x650, ['unsigned long']],
            'ActualFileSize': [0x658, ['_LARGE_INTEGER']],
            'FileFullPath': [0x660, ['_UNICODE_STRING']],
            'FileUserName': [0x670, ['_UNICODE_STRING']],
            'HiveRootPath': [0x680, ['_UNICODE_STRING']],
            'SecurityCount': [0x690, ['unsigned long']],
            'SecurityCacheSize': [0x694, ['unsigned long']],
            'SecurityHitHint': [0x698, ['long']],
            'SecurityCache': [
                0x6A0,
                ['pointer64', ['_CM_KEY_SECURITY_CACHE_ENTRY']],
            ],
            'SecurityHash': [0x6A8, ['array', 64, ['_LIST_ENTRY']]],
            'UnloadEventCount': [0xAA8, ['unsigned long']],
            'UnloadEventArray': [
                0xAB0,
                ['pointer64', ['pointer64', ['_KEVENT']]],
            ],
            'RootKcb': [0xAB8, ['pointer64', ['_CM_KEY_CONTROL_BLOCK']]],
            'Frozen': [0xAC0, ['unsigned char']],
            'UnloadWorkItem': [0xAC8, ['pointer64', ['_CM_WORKITEM']]],
            'GrowOnlyMode': [0xAD0, ['unsigned char']],
            'GrowOffset': [0xAD4, ['unsigned long']],
            'KcbConvertListHead': [0xAD8, ['_LIST_ENTRY']],
            'KnodeConvertListHead': [0xAE8, ['_LIST_ENTRY']],
            'CellRemapArray': [0xAF8, ['pointer64', ['_CM_CELL_REMAP_BLOCK']]],
            'Flags': [0xB00, ['unsigned long']],
            'TrustClassEntry': [0xB08, ['_LIST_ENTRY']],
            'FlushCount': [0xB18, ['unsigned long']],
            'CmRm': [0xB20, ['pointer64', ['_CM_RM']]],
            'CmRmInitFailPoint': [0xB28, ['unsigned long']],
            'CmRmInitFailStatus': [0xB2C, ['long']],
            'CreatorOwner': [0xB30, ['pointer64', ['_KTHREAD']]],
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
    '__unnamed_18d6': [
        0x10,
        {
            'List': [0x0, ['_LIST_ENTRY']],
            'Secured': [0x0, ['_MMADDRESS_LIST']],
        },
    ],
    '__unnamed_18dc': [
        0x8,
        {
            'Banked': [0x0, ['pointer64', ['_MMBANKED_SECTION']]],
            'ExtendedInfo': [0x0, ['pointer64', ['_MMEXTEND_INFO']]],
        },
    ],
    '_MMVAD_LONG': [
        0x78,
        {
            'u1': [0x0, ['__unnamed_14ae']],
            'LeftChild': [0x8, ['pointer64', ['_MMVAD']]],
            'RightChild': [0x10, ['pointer64', ['_MMVAD']]],
            'StartingVpn': [0x18, ['unsigned long long']],
            'EndingVpn': [0x20, ['unsigned long long']],
            'u': [0x28, ['__unnamed_14b1']],
            'PushLock': [0x30, ['_EX_PUSH_LOCK']],
            'u5': [0x38, ['__unnamed_14b4']],
            'u2': [0x40, ['__unnamed_14be']],
            'Subsection': [0x48, ['pointer64', ['_SUBSECTION']]],
            'FirstPrototypePte': [0x50, ['pointer64', ['_MMPTE']]],
            'LastContiguousPte': [0x58, ['pointer64', ['_MMPTE']]],
            'u3': [0x60, ['__unnamed_18d6']],
            'u4': [0x70, ['__unnamed_18dc']],
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
    '_EJOB': [
        0x1B0,
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
            'AccessState': [0x110, ['pointer64', ['_JOB_ACCESS_STATE']]],
            'UIRestrictionsClass': [0x118, ['unsigned long']],
            'EndOfJobTimeAction': [0x11C, ['unsigned long']],
            'CompletionPort': [0x120, ['pointer64', ['void']]],
            'CompletionKey': [0x128, ['pointer64', ['void']]],
            'SessionId': [0x130, ['unsigned long']],
            'SchedulingClass': [0x134, ['unsigned long']],
            'ReadOperationCount': [0x138, ['unsigned long long']],
            'WriteOperationCount': [0x140, ['unsigned long long']],
            'OtherOperationCount': [0x148, ['unsigned long long']],
            'ReadTransferCount': [0x150, ['unsigned long long']],
            'WriteTransferCount': [0x158, ['unsigned long long']],
            'OtherTransferCount': [0x160, ['unsigned long long']],
            'ProcessMemoryLimit': [0x168, ['unsigned long long']],
            'JobMemoryLimit': [0x170, ['unsigned long long']],
            'PeakProcessMemoryUsed': [0x178, ['unsigned long long']],
            'PeakJobMemoryUsed': [0x180, ['unsigned long long']],
            'CurrentJobMemoryUsed': [0x188, ['unsigned long long']],
            'MemoryLimitsLock': [0x190, ['_EX_PUSH_LOCK']],
            'JobSetLinks': [0x198, ['_LIST_ENTRY']],
            'MemberLevel': [0x1A8, ['unsigned long']],
            'JobFlags': [0x1AC, ['unsigned long']],
        },
    ],
    '__unnamed_18ee': [
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
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
        },
    ],
    'PPM_IDLE_STATES': [
        0x48,
        {
            'Type': [0x0, ['unsigned long']],
            'Count': [0x4, ['unsigned long']],
            'Flags': [0x8, ['__unnamed_18ee']],
            'TargetState': [0xC, ['unsigned long']],
            'ActualState': [0x10, ['unsigned long']],
            'OldState': [0x14, ['unsigned long']],
            'TargetProcessors': [0x18, ['unsigned long long']],
            'State': [0x20, ['array', 1, ['PPM_IDLE_STATE']]],
        },
    ],
    '_PEB': [
        0x368,
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
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
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
            'ReservedBits0': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'KernelCallbackTable': [0x58, ['pointer64', ['void']]],
            'UserSharedInfoPtr': [0x58, ['pointer64', ['void']]],
            'SystemReserved': [0x60, ['array', 1, ['unsigned long']]],
            'SpareUlong': [0x64, ['unsigned long']],
            'FreeList': [0x68, ['pointer64', ['_PEB_FREE_BLOCK']]],
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
            'FlsCallback': [0x320, ['pointer64', ['_FLS_CALLBACK_INFO']]],
            'FlsListHead': [0x328, ['_LIST_ENTRY']],
            'FlsBitmap': [0x338, ['pointer64', ['void']]],
            'FlsBitmapBits': [0x340, ['array', 4, ['unsigned long']]],
            'FlsHighIndex': [0x350, ['unsigned long']],
            'WerRegistrationData': [0x358, ['pointer64', ['void']]],
            'WerShipAssertPtr': [0x360, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1908': [
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
            'u': [0x8, ['__unnamed_1908']],
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
            'RunningAllocs': [0x8, ['long']],
            'RunningDeAllocs': [0xC, ['long']],
            'TotalPages': [0x10, ['long']],
            'TotalBigPages': [0x14, ['long']],
            'Threshold': [0x18, ['unsigned long']],
            'LockAddress': [0x20, ['pointer64', ['void']]],
            'PendingFrees': [0x28, ['pointer64', ['pointer64', ['void']]]],
            'ThreadsProcessingDeferrals': [0x30, ['long']],
            'PendingFreeDepth': [0x34, ['long']],
            'TotalBytes': [0x38, ['unsigned long long']],
            'Spare0': [0x40, ['unsigned long long']],
            'ListHeads': [0x48, ['array', 256, ['_LIST_ENTRY']]],
        },
    ],
    '_KGATE': [
        0x18,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
        },
    ],
    '_WHEA_ERROR_RECORD_HEADER': [
        0x88,
        {
            'Signature': [0x0, ['unsigned long']],
            'Revision': [0x4, ['unsigned short']],
            'Reserved1': [0x6, ['unsigned short']],
            'Reserved2': [0x8, ['unsigned short']],
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
                            3: 'WheaErrSevNone',
                        },
                    ),
                ],
            ],
            'ValidationBits': [0x10, ['unsigned long']],
            'Length': [0x14, ['unsigned long']],
            'Timestamp': [0x18, ['_LARGE_INTEGER']],
            'PlatformId': [0x20, ['_GUID']],
            'PartitionId': [0x30, ['_GUID']],
            'CreatorId': [0x40, ['_GUID']],
            'NotifyType': [0x50, ['_GUID']],
            'RecordId': [0x60, ['unsigned long long']],
            'Flags': [0x68, ['unsigned long']],
            'PersistenceInfo': [0x70, ['_WHEA_PERSISTENCE_INFO']],
            'Reserved3': [0x78, ['array', 12, ['unsigned char']]],
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
            'Number': [0x60, ['unsigned char']],
            'ShareVector': [0x61, ['unsigned char']],
            'Mode': [
                0x64,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={0: 'LevelSensitive', 1: 'Latched'},
                    ),
                ],
            ],
            'Polarity': [
                0x68,
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
            'ServiceCount': [0x6C, ['unsigned long']],
            'DispatchCount': [0x70, ['unsigned long']],
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
            'NextFreeTableEntry': [0x8, ['long']],
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
        0x38,
        {
            'FileName': [0x0, ['pointer64', ['unsigned short']]],
            'BaseName': [0x8, ['pointer64', ['unsigned short']]],
            'RegRootName': [0x10, ['pointer64', ['unsigned short']]],
            'CmHive': [0x18, ['pointer64', ['_CMHIVE']]],
            'HHiveFlags': [0x20, ['unsigned long']],
            'CmHiveFlags': [0x24, ['unsigned long']],
            'CmHive2': [0x28, ['pointer64', ['_CMHIVE']]],
            'ThreadFinished': [0x30, ['unsigned char']],
            'ThreadStarted': [0x31, ['unsigned char']],
            'Allocate': [0x32, ['unsigned char']],
            'WinPERequired': [0x33, ['unsigned char']],
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
    '_IOV_FORCED_PENDING_TRACE': [
        0x200,
        {
            'Irp': [0x0, ['pointer64', ['_IRP']]],
            'StackTrace': [0x8, ['array', 63, ['pointer64', ['void']]]],
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
    '_WHEA_PCIX_BUS_ERROR': [
        0x48,
        {
            'ValidationBits': [0x0, ['_WHEA_PCIX_BUS_VALIDATION_BITS']],
            'ErrorStatus': [0x8, ['_WHEA_ERROR_STATUS']],
            'ErrorType': [0x10, ['unsigned short']],
            'BusId': [0x12, ['unsigned short']],
            'Reserved': [0x14, ['unsigned long']],
            'BusAddress': [0x18, ['unsigned long long']],
            'BusData': [0x20, ['unsigned long long']],
            'BusCommand': [0x28, ['unsigned long long']],
            'BusRequestorId': [0x30, ['unsigned long long']],
            'BusCompleterId': [0x38, ['unsigned long long']],
            'TargetId': [0x40, ['unsigned long long']],
        },
    ],
    '_PEB_FREE_BLOCK': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_PEB_FREE_BLOCK']]],
            'Size': [0x8, ['unsigned long']],
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
    '__unnamed_1981': [
        0x28,
        {
            'CriticalSection': [0x0, ['_RTL_CRITICAL_SECTION']],
        },
    ],
    '_HEAP_LOCK': [
        0x28,
        {
            'Lock': [0x0, ['__unnamed_1981']],
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
    '_PP_LOOKASIDE_LIST': [
        0x10,
        {
            'P': [0x0, ['pointer64', ['_GENERAL_LOOKASIDE']]],
            'L': [0x8, ['pointer64', ['_GENERAL_LOOKASIDE']]],
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
            'Processor': [0xA, ['unsigned char']],
            'TickCount': [0xC, ['unsigned long']],
            'StackTrace': [0x10, ['array', 5, ['pointer64', ['void']]]],
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
    '_CM_KEY_CONTROL_BLOCK': [
        0x100,
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
            'KCBUoWListHead': [0xB0, ['_LIST_ENTRY']],
            'TransKCBOwner': [0xC0, ['pointer64', ['_CM_TRANS']]],
            'KCBLock': [0xC8, ['_CM_INTENT_LOCK']],
            'KeyLock': [0xD8, ['_CM_INTENT_LOCK']],
            'TransValueCache': [0xE8, ['_CHILD_LIST']],
            'TransValueListOwner': [0xF0, ['pointer64', ['_CM_TRANS']]],
            'FullKCBName': [0xF8, ['pointer64', ['_UNICODE_STRING']]],
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
    '_POWER_SEQUENCE': [
        0xC,
        {
            'SequenceD1': [0x0, ['unsigned long']],
            'SequenceD2': [0x4, ['unsigned long']],
            'SequenceD3': [0x8, ['unsigned long']],
        },
    ],
    '_KSEMAPHORE': [
        0x20,
        {
            'Header': [0x0, ['_DISPATCHER_HEADER']],
            'Limit': [0x18, ['long']],
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
            'SessionSpace': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'ModwriterAttached': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned char'),
                ],
            ],
            'TrimHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned char'),
                ],
            ],
            'MaximumWorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned char'),
                ],
            ],
            'ForceTrim': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned char'),
                ],
            ],
            'MinimumWorkingSetHard': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned char'),
                ],
            ],
            'SessionMaster': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned char'),
                ],
            ],
            'TrimmerAttached': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'TrimmerDetaching': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned char'),
                ],
            ],
            'Reserved': [
                0x1,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=8, native_type='unsigned char'),
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
            'Available': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=8, native_type='unsigned char'),
                ],
            ],
        },
    ],
    '__unnamed_1a07': [
        0x4,
        {
            'AsULONG': [0x0, ['unsigned long']],
            'UsingHypervisor': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'NoDomainAccounting': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned long'),
                ],
            ],
            'IncreasePolicy': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=4, native_type='unsigned long'),
                ],
            ],
            'DecreasePolicy': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=6, native_type='unsigned long'),
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
    'PPM_PERF_STATES': [
        0x80,
        {
            'Count': [0x0, ['unsigned long']],
            'MaxFrequency': [0x4, ['unsigned long']],
            'MaxPerfState': [0x8, ['unsigned long']],
            'MinPerfState': [0xC, ['unsigned long']],
            'LowestPState': [0x10, ['unsigned long']],
            'IncreaseTime': [0x14, ['unsigned long']],
            'DecreaseTime': [0x18, ['unsigned long']],
            'BusyAdjThreshold': [0x1C, ['unsigned char']],
            'Reserved': [0x1D, ['unsigned char']],
            'ThrottleStatesOnly': [0x1E, ['unsigned char']],
            'PolicyType': [0x1F, ['unsigned char']],
            'TimerInterval': [0x20, ['unsigned long']],
            'Flags': [0x24, ['__unnamed_1a07']],
            'TargetProcessors': [0x28, ['unsigned long long']],
            'PStateHandler': [0x30, ['pointer64', ['void']]],
            'PStateContext': [0x38, ['unsigned long long']],
            'TStateHandler': [0x40, ['pointer64', ['void']]],
            'TStateContext': [0x48, ['unsigned long long']],
            'FeedbackHandler': [0x50, ['pointer64', ['void']]],
            'State': [0x58, ['array', 1, ['PPM_PERF_STATE']]],
        },
    ],
    'PPM_PERF_STATE': [
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
    'PPM_IDLE_STATE': [
        0x28,
        {
            'IdleHandler': [0x0, ['pointer64', ['void']]],
            'Context': [0x8, ['unsigned long long']],
            'Latency': [0x10, ['unsigned long']],
            'Power': [0x14, ['unsigned long']],
            'TimeCheck': [0x18, ['unsigned long']],
            'StateFlags': [0x1C, ['unsigned long']],
            'PromotePercent': [0x20, ['unsigned char']],
            'DemotePercent': [0x21, ['unsigned char']],
            'PromotePercentBase': [0x22, ['unsigned char']],
            'DemotePercentBase': [0x23, ['unsigned char']],
            'StateType': [0x24, ['unsigned char']],
        },
    ],
    'PPM_IDLE_ACCOUNTING': [
        0x48,
        {
            'StateCount': [0x0, ['unsigned long']],
            'TotalTransitions': [0x4, ['unsigned long']],
            'ResetCount': [0x8, ['unsigned long']],
            'StartTime': [0x10, ['unsigned long long']],
            'State': [0x18, ['array', 1, ['PPM_IDLE_STATE_ACCOUNTING']]],
        },
    ],
    'PPM_IDLE_STATE_ACCOUNTING': [
        0x30,
        {
            'IdleTransitions': [0x0, ['unsigned long']],
            'FailedTransitions': [0x4, ['unsigned long']],
            'InvalidBucketIndex': [0x8, ['unsigned long']],
            'TotalTime': [0x10, ['unsigned long long']],
            'IdleTimeBuckets': [0x18, ['array', 6, ['unsigned long']]],
        },
    ],
    'PROCESSOR_IDLE_TIMES': [
        0x20,
        {
            'StartTime': [0x0, ['unsigned long long']],
            'EndTime': [0x8, ['unsigned long long']],
            'Reserved': [0x10, ['array', 4, ['unsigned long']]],
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
    '_TERMINATION_PORT': [
        0x10,
        {
            'Next': [0x0, ['pointer64', ['_TERMINATION_PORT']]],
            'Port': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_MEMORY_ALLOCATION_DESCRIPTOR': [
        0x20,
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
                            28: 'LoaderMaximum',
                        },
                    ),
                ],
            ],
            'BasePage': [0x14, ['unsigned long']],
            'PageCount': [0x18, ['unsigned long']],
        },
    ],
    '_WHEA_PCIX_DEVICE_ERROR': [
        0x68,
        {
            'ValidationBits': [0x0, ['_WHEA_PCIX_DEV_VALIDATION_BITS']],
            'ErrorStatus': [0x8, ['_WHEA_ERROR_STATUS']],
            'IdInfo': [0x10, ['array', 16, ['unsigned char']]],
            'MemoryNumber': [0x20, ['unsigned long']],
            'IoNumber': [0x24, ['unsigned long']],
            'RegisterDataPairs': [0x28, ['array', 64, ['unsigned char']]],
        },
    ],
    '_CM_INTENT_LOCK': [
        0x10,
        {
            'OwnerCount': [0x0, ['unsigned long']],
            'OwnerTable': [0x8, ['pointer64', ['pointer64', ['_CM_KCB_UOW']]]],
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
        0x40,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'NonExtendedPtes': [0xC, ['unsigned long']],
            'NumberOfCommittedPages': [0x10, ['unsigned long long']],
            'SizeOfSegment': [0x18, ['unsigned long long']],
            'ExtendInfo': [0x20, ['pointer64', ['_MMEXTEND_INFO']]],
            'BasedAddress': [0x20, ['pointer64', ['void']]],
            'SegmentLock': [0x28, ['_EX_PUSH_LOCK']],
            'SegmentFlags': [0x30, ['_SEGMENT_FLAGS']],
            'LastSubsectionHint': [0x38, ['pointer64', ['_MSUBSECTION']]],
        },
    ],
    '_TEB64': [
        0x1828,
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
            'SpareBytes1': [0x2D0, ['array', 24, ['unsigned char']]],
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
            'SpareBool0': [0x1744, ['unsigned char']],
            'SpareBool1': [0x1745, ['unsigned char']],
            'SpareBool2': [0x1746, ['unsigned char']],
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
            'ImpersonationLocale': [0x1798, ['unsigned long']],
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
            'DbgSafeThunkCall': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'DbgInDebugPrint': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'DbgHasFiberData': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'DbgSkipThreadAttach': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'DbgWerInShipAssertCode': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'DbgRanProcessInit': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'DbgClonedThread': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'DbgSuppressDebugMsg': [
                0x17EE,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'SpareSameTebBits': [
                0x17EE,
                [
                    'BitField',
                    dict(
                        start_bit=8, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0x17F0, ['unsigned long long']],
            'TxnScopeExitCallback': [0x17F8, ['unsigned long long']],
            'TxnScopeContext': [0x1800, ['unsigned long long']],
            'LockCount': [0x1808, ['unsigned long']],
            'ProcessRundown': [0x180C, ['unsigned long']],
            'LastSwitchTime': [0x1810, ['unsigned long long']],
            'TotalSwitchOutTime': [0x1818, ['unsigned long long']],
            'WaitReasonBitMap': [0x1820, ['_LARGE_INTEGER']],
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
            'OwnerCount': [0x8, ['long']],
            'TableSize': [0x8, ['unsigned long']],
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
    '__unnamed_1a66': [
        0x8,
        {
            'Flags': [0x0, ['_MMSECURE_FLAGS']],
            'StartVa': [0x0, ['pointer64', ['void']]],
        },
    ],
    '_MMADDRESS_LIST': [
        0x10,
        {
            'u1': [0x0, ['__unnamed_1a66']],
            'EndVa': [0x8, ['pointer64', ['void']]],
        },
    ],
    '_ARBITER_INSTANCE': [
        0x690,
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
            'Extension': [0x128, ['pointer64', ['void']]],
            'BusDeviceObject': [0x130, ['pointer64', ['_DEVICE_OBJECT']]],
            'ConflictCallbackContext': [0x138, ['pointer64', ['void']]],
            'ConflictCallback': [0x140, ['pointer64', ['void']]],
            'PdoDescriptionString': [0x148, ['array', 336, ['wchar']]],
            'PdoSymbolicNameString': [
                0x3E8,
                ['array', 672, ['unsigned char']],
            ],
            'PdoAddressString': [0x688, ['array', 1, ['wchar']]],
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
    '_HMAP_TABLE': [
        0x4000,
        {
            'Table': [0x0, ['array', 512, ['_HMAP_ENTRY']]],
        },
    ],
    '_WHEA_MEMORY_ERROR': [
        0x50,
        {
            'ValidationBits': [0x0, ['unsigned long long']],
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
            'RequestorId': [0x30, ['unsigned long long']],
            'ResponderId': [0x38, ['unsigned long long']],
            'TargetId': [0x40, ['unsigned long long']],
            'ErrorType': [0x48, ['unsigned char']],
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
    '_ALPHA_LOADER_BLOCK': [
        0x4,
        {
            'PlaceHolder': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1acc': [
        0x18,
        {
            'Length': [0x0, ['unsigned long']],
            'Alignment': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1ad2': [
        0x18,
        {
            'MinimumVector': [0x0, ['unsigned long']],
            'MaximumVector': [0x4, ['unsigned long']],
            'AffinityPolicy': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'IrqPolicyMachineDefault',
                            1: 'IrqPolicyAllCloseProcessors',
                            2: 'IrqPolicyOneCloseProcessor',
                            3: 'IrqPolicyAllProcessorsInMachine',
                            4: 'IrqPolicySpecifiedProcessors',
                            5: 'IrqPolicySpreadMessagesAcrossAllProcessors',
                        },
                    ),
                ],
            ],
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
    '__unnamed_1ad4': [
        0x8,
        {
            'MinimumChannel': [0x0, ['unsigned long']],
            'MaximumChannel': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1ad6': [
        0xC,
        {
            'Data': [0x0, ['array', 3, ['unsigned long']]],
        },
    ],
    '__unnamed_1ad8': [
        0x10,
        {
            'Length': [0x0, ['unsigned long']],
            'MinBusNumber': [0x4, ['unsigned long']],
            'MaxBusNumber': [0x8, ['unsigned long']],
            'Reserved': [0xC, ['unsigned long']],
        },
    ],
    '__unnamed_1ada': [
        0xC,
        {
            'Priority': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1adc': [
        0x18,
        {
            'Length40': [0x0, ['unsigned long']],
            'Alignment40': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1ade': [
        0x18,
        {
            'Length48': [0x0, ['unsigned long']],
            'Alignment48': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1ae0': [
        0x18,
        {
            'Length64': [0x0, ['unsigned long']],
            'Alignment64': [0x4, ['unsigned long']],
            'MinimumAddress': [0x8, ['_LARGE_INTEGER']],
            'MaximumAddress': [0x10, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1ae2': [
        0x18,
        {
            'Port': [0x0, ['__unnamed_1acc']],
            'Memory': [0x0, ['__unnamed_1acc']],
            'Interrupt': [0x0, ['__unnamed_1ad2']],
            'Dma': [0x0, ['__unnamed_1ad4']],
            'Generic': [0x0, ['__unnamed_1acc']],
            'DevicePrivate': [0x0, ['__unnamed_1ad6']],
            'BusNumber': [0x0, ['__unnamed_1ad8']],
            'ConfigData': [0x0, ['__unnamed_1ada']],
            'Memory40': [0x0, ['__unnamed_1adc']],
            'Memory48': [0x0, ['__unnamed_1ade']],
            'Memory64': [0x0, ['__unnamed_1ae0']],
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
            'u': [0x8, ['__unnamed_1ae2']],
        },
    ],
    '_POP_THERMAL_ZONE': [
        0x128,
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
    '_CM_TRANS': [
        0xB0,
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
            'HiveArray': [0x70, ['array', 8, ['pointer64', ['_CMHIVE']]]],
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
    '_POOL_HACKER': [
        0x30,
        {
            'Header': [0x0, ['_POOL_HEADER']],
            'Contents': [0x10, ['array', 8, ['unsigned long']]],
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
        0x1B,
        {
            'AdtTokenPolicy': [0x0, ['_TOKEN_AUDIT_POLICY']],
            'PolicySetStatus': [0x1A, ['unsigned char']],
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
    '__unnamed_1b1e': [
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
            'Flags': [0x7, ['__unnamed_1b1e']],
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
            'Reserved2': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=21, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'ContextAsUlong': [0x0, ['unsigned long']],
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
    '_ETW_BUFFER_CONTEXT': [
        0x4,
        {
            'ProcessorNumber': [0x0, ['unsigned char']],
            'Alignment': [0x1, ['unsigned char']],
            'LoggerId': [0x2, ['unsigned short']],
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
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=8, native_type='unsigned char'),
                ],
            ],
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
        0x18,
        {
            'Links': [0x0, ['_LIST_ENTRY']],
            'MappingCount': [0x10, ['unsigned long']],
            'Reserved': [0x14, ['unsigned long']],
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
    '_WOW64_PROCESS': [
        0x8,
        {
            'Wow64': [0x0, ['pointer64', ['void']]],
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
    '_MI_SECTION_CREATION_EVENT': [
        0x20,
        {
            'Next': [0x0, ['pointer64', ['_MI_SECTION_CREATION_EVENT']]],
            'Event': [0x8, ['_KEVENT']],
        },
    ],
    '_PEB32': [
        0x238,
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
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
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
            'ReservedBits0': [
                0x28,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'KernelCallbackTable': [0x2C, ['unsigned long']],
            'UserSharedInfoPtr': [0x2C, ['unsigned long']],
            'SystemReserved': [0x30, ['array', 1, ['unsigned long']]],
            'SpareUlong': [0x34, ['unsigned long']],
            'FreeList': [0x38, ['unsigned long']],
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
            'WerRegistrationData': [0x230, ['unsigned long']],
            'WerShipAssertPtr': [0x234, ['unsigned long']],
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
    '__unnamed_1b63': [
        0x4,
        {
            'DataLength': [0x0, ['short']],
            'TotalLength': [0x2, ['short']],
        },
    ],
    '__unnamed_1b65': [
        0x4,
        {
            's1': [0x0, ['__unnamed_1b63']],
            'Length': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1b67': [
        0x4,
        {
            'Type': [0x0, ['short']],
            'DataInfoOffset': [0x2, ['short']],
        },
    ],
    '__unnamed_1b69': [
        0x4,
        {
            's2': [0x0, ['__unnamed_1b67']],
            'ZeroInit': [0x0, ['unsigned long']],
        },
    ],
    '_PORT_MESSAGE': [
        0x28,
        {
            'u1': [0x0, ['__unnamed_1b65']],
            'u2': [0x4, ['__unnamed_1b69']],
            'ClientId': [0x8, ['_CLIENT_ID']],
            'DoNotUseThisField': [0x8, ['double']],
            'MessageId': [0x18, ['unsigned long']],
            'ClientViewSize': [0x20, ['unsigned long long']],
            'CallbackId': [0x20, ['unsigned long']],
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
    '_DBGKD_RESTORE_BREAKPOINT': [
        0x4,
        {
            'BreakPointHandle': [0x0, ['unsigned long']],
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
    '_ETW_REF_CLOCK': [
        0x10,
        {
            'StartTime': [0x0, ['_LARGE_INTEGER']],
            'StartPerfClock': [0x8, ['_LARGE_INTEGER']],
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
    '__unnamed_1b90': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1b92': [
        0x10,
        {
            'Level': [0x0, ['unsigned long']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_1b94': [
        0x10,
        {
            'Reserved': [0x0, ['unsigned short']],
            'MessageCount': [0x2, ['unsigned short']],
            'Vector': [0x4, ['unsigned long']],
            'Affinity': [0x8, ['unsigned long long']],
        },
    ],
    '__unnamed_1b96': [
        0x10,
        {
            'Raw': [0x0, ['__unnamed_1b94']],
            'Translated': [0x0, ['__unnamed_1b92']],
        },
    ],
    '__unnamed_1b98': [
        0xC,
        {
            'Channel': [0x0, ['unsigned long']],
            'Port': [0x4, ['unsigned long']],
            'Reserved1': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1b9a': [
        0xC,
        {
            'Start': [0x0, ['unsigned long']],
            'Length': [0x4, ['unsigned long']],
            'Reserved': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1b9c': [
        0xC,
        {
            'DataSize': [0x0, ['unsigned long']],
            'Reserved1': [0x4, ['unsigned long']],
            'Reserved2': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1b9e': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length40': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1ba0': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length48': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1ba2': [
        0xC,
        {
            'Start': [0x0, ['_LARGE_INTEGER']],
            'Length64': [0x8, ['unsigned long']],
        },
    ],
    '__unnamed_1ba4': [
        0x10,
        {
            'Generic': [0x0, ['__unnamed_1b90']],
            'Port': [0x0, ['__unnamed_1b90']],
            'Interrupt': [0x0, ['__unnamed_1b92']],
            'MessageInterrupt': [0x0, ['__unnamed_1b96']],
            'Memory': [0x0, ['__unnamed_1b90']],
            'Dma': [0x0, ['__unnamed_1b98']],
            'DevicePrivate': [0x0, ['__unnamed_1ad6']],
            'BusNumber': [0x0, ['__unnamed_1b9a']],
            'DeviceSpecificData': [0x0, ['__unnamed_1b9c']],
            'Memory40': [0x0, ['__unnamed_1b9e']],
            'Memory48': [0x0, ['__unnamed_1ba0']],
            'Memory64': [0x0, ['__unnamed_1ba2']],
        },
    ],
    '_CM_PARTIAL_RESOURCE_DESCRIPTOR': [
        0x14,
        {
            'Type': [0x0, ['unsigned char']],
            'ShareDisposition': [0x1, ['unsigned char']],
            'Flags': [0x2, ['unsigned short']],
            'u': [0x4, ['__unnamed_1ba4']],
        },
    ],
    '__unnamed_1ba9': [
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
            'Misc': [0x8, ['__unnamed_1ba9']],
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
    '_KUSER_SHARED_DATA': [
        0x3B8,
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
            'SystemDllRelocated': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned long'),
                ],
            ],
            'SpareBits': [
                0x2F0,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'TestRetInstruction': [0x2F8, ['unsigned long long']],
            'SystemCall': [0x300, ['unsigned long']],
            'SystemCallReturn': [0x304, ['unsigned long']],
            'SystemCallPad': [0x308, ['array', 3, ['unsigned long long']]],
            'TickCount': [0x320, ['_KSYSTEM_TIME']],
            'TickCountQuad': [0x320, ['unsigned long long']],
            'Cookie': [0x330, ['unsigned long']],
            'ConsoleSessionForegroundProcessId': [0x338, ['long long']],
            'Wow64SharedInformation': [
                0x340,
                ['array', 16, ['unsigned long']],
            ],
            'UserModeGlobalLogger': [0x380, ['array', 8, ['unsigned short']]],
            'HeapTracingPid': [0x390, ['array', 2, ['unsigned long']]],
            'CritSecTracingPid': [0x398, ['array', 2, ['unsigned long']]],
            'ImageFileExecutionOptions': [0x3A0, ['unsigned long']],
            'AffinityPad': [0x3A8, ['unsigned long long']],
            'ActiveProcessorAffinity': [0x3A8, ['unsigned long long']],
            'InterruptTimeBias': [0x3B0, ['unsigned long long']],
        },
    ],
    '__unnamed_1bc6': [
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
            'Data': [0x8, ['__unnamed_1bc6']],
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
    '__unnamed_1bd0': [
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
            'u': [0x0, ['__unnamed_14d5']],
            'StartingSector': [0x4, ['unsigned long']],
            'NumberOfFullSectors': [0x8, ['unsigned long']],
            'u1': [0x10, ['__unnamed_1bd0']],
            'LeftChild': [0x18, ['pointer64', ['_MMSUBSECTION_NODE']]],
            'RightChild': [0x20, ['pointer64', ['_MMSUBSECTION_NODE']]],
        },
    ],
    '_DEVICE_OBJECT_POWER_EXTENSION': [
        0x88,
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
            'PreviousIdleCount': [0x80, ['unsigned long']],
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
    '_WHEA_ERROR_STATUS': [
        0x8,
        {
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
                            269: 'KEnlistmentSavepointing',
                            270: 'KEnlistmentAborting',
                            271: 'KEnlistmentReadOnly',
                            272: 'KEnlistmentOutcomeUnavailable',
                            273: 'KEnlistmentOffline',
                            274: 'KEnlistmentPrePrepared',
                            275: 'KEnlistmentInitialized',
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
    '_CHILD_LIST': [
        0x8,
        {
            'Count': [0x0, ['unsigned long']],
            'List': [0x4, ['unsigned long']],
        },
    ],
    '_ETW_KERNEL_TRACE_TIMESTAMP': [
        0x10,
        {
            'KernelTraceTimeStamp': [0x0, ['array', 2, ['_LARGE_INTEGER']]],
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
    '_WHEA_PCIEXPRESS_ERROR': [
        0xD0,
        {
            'ValidationBits': [0x0, ['unsigned long long']],
            'PortType': [
                0x8,
                [
                    'Enumeration',
                    dict(
                        target='long',
                        choices={
                            0: 'PciExpressEndpoint',
                            1: 'PciExpressLegacyEndpoint',
                            4: 'PciExpressRootPort',
                            5: 'PciExpressUpstreamSwitchPort',
                            6: 'PciExpressDownstreamSwitchPort',
                            7: 'PciExpressToPciXBridge',
                            8: 'PciXToExpressBridge',
                            9: 'PciExpressRootComplexIntegratedEndpoint',
                            10: 'PciExpressRootComplexEventCollector',
                        },
                    ),
                ],
            ],
            'Version': [0xC, ['unsigned long']],
            'CommandStatus': [0x10, ['unsigned long']],
            'Reserved': [0x14, ['unsigned long']],
            'DeviceId': [0x18, ['_PCIE_DEVICE_ID']],
            'DeviceSN': [0x28, ['unsigned long long']],
            'BridgeCtrlSts': [0x30, ['unsigned long']],
            'ExpressCapability': [0x34, ['array', 60, ['unsigned char']]],
            'AerInfo': [0x70, ['array', 96, ['unsigned char']]],
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
    '_OBJECT_TYPE': [
        0x220,
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
            'ObjectLocks': [0x120, ['array', 32, ['_EX_PUSH_LOCK']]],
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
            'ObjectTypeCode': [0x4, ['unsigned long']],
            'InvalidAttributes': [0x8, ['unsigned long']],
            'GenericMapping': [0xC, ['_GENERIC_MAPPING']],
            'ValidAccessMask': [0x1C, ['unsigned long']],
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
            'Compressed': [0x0, ['unsigned char']],
            'RefCount': [0x2, ['unsigned short']],
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
    '_REQUEST_MAILBOX': [
        0x40,
        {
            'RequestSummary': [0x0, ['long long']],
            'RequestPacket': [0x8, ['_KREQUEST_PACKET']],
            'Virtual': [0x8, ['array', 7, ['pointer64', ['void']]]],
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
        0xB0,
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
            'DisplayResumeContext': [
                0x40,
                ['pointer64', ['_POP_DISPLAY_RESUME_CONTEXT']],
            ],
            'HiberContext': [0x48, ['pointer64', ['_POP_HIBER_CONTEXT']]],
            'WakeTime': [0x50, ['unsigned long long']],
            'SleepTime': [0x58, ['unsigned long long']],
            'SystemContext': [0x60, ['_SYSTEM_POWER_STATE_CONTEXT']],
            'FilteredCapabilities': [0x64, ['SYSTEM_POWER_CAPABILITIES']],
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
        0x20,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x8, ['pointer64', ['_CM_KEY_HASH']]],
            'KeyHive': [0x10, ['pointer64', ['_HHIVE']]],
            'KeyCell': [0x18, ['unsigned long']],
        },
    ],
    '_PO_DEVICE_NOTIFY': [
        0x40,
        {
            'Link': [0x0, ['_LIST_ENTRY']],
            'TargetDevice': [0x10, ['pointer64', ['_DEVICE_OBJECT']]],
            'OrderLevel': [0x18, ['unsigned char']],
            'DeviceObject': [0x20, ['pointer64', ['_DEVICE_OBJECT']]],
            'DeviceName': [0x28, ['pointer64', ['unsigned short']]],
            'DriverName': [0x30, ['pointer64', ['unsigned short']]],
            'ChildCount': [0x38, ['unsigned long']],
            'ActiveChild': [0x3C, ['unsigned long']],
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
    '__unnamed_1cb0': [
        0x4,
        {
            'Level': [0x0, ['unsigned long']],
        },
    ],
    '__unnamed_1cb2': [
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
            'Battery': [0x10, ['__unnamed_1cb0']],
            'Button': [0x10, ['__unnamed_1cb2']],
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
                            269: 'KEnlistmentSavepointing',
                            270: 'KEnlistmentAborting',
                            271: 'KEnlistmentReadOnly',
                            272: 'KEnlistmentOutcomeUnavailable',
                            273: 'KEnlistmentOffline',
                            274: 'KEnlistmentPrePrepared',
                            275: 'KEnlistmentInitialized',
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
    '_LOADER_PARAMETER_EXTENSION': [
        0xB8,
        {
            'Size': [0x0, ['unsigned long']],
            'Profile': [0x4, ['_PROFILE_PARAMETER_BLOCK']],
            'MajorVersion': [0x14, ['unsigned long']],
            'MinorVersion': [0x18, ['unsigned long']],
            'EmInfFileImage': [0x20, ['pointer64', ['void']]],
            'EmInfFileSize': [0x28, ['unsigned long']],
            'TriageDumpBlock': [0x30, ['pointer64', ['void']]],
            'LoaderPagesSpanned': [0x38, ['unsigned long']],
            'HeadlessLoaderBlock': [
                0x40,
                ['pointer64', ['_HEADLESS_LOADER_BLOCK']],
            ],
            'SMBiosEPSHeader': [0x48, ['pointer64', ['_SMBIOS_TABLE_HEADER']]],
            'DrvDBImage': [0x50, ['pointer64', ['void']]],
            'DrvDBSize': [0x58, ['unsigned long']],
            'NetworkLoaderBlock': [
                0x60,
                ['pointer64', ['_NETWORK_LOADER_BLOCK']],
            ],
            'FirmwareDescriptorListHead': [0x68, ['_LIST_ENTRY']],
            'AcpiTable': [0x78, ['pointer64', ['void']]],
            'AcpiTableSize': [0x80, ['unsigned long']],
            'BootViaWinload': [
                0x84,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned long'),
                ],
            ],
            'Reserved': [
                0x84,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'LoaderPerformanceData': [
                0x88,
                ['pointer64', ['_LOADER_PERFORMANCE_DATA']],
            ],
            'BootApplicationPersistentData': [0x90, ['_LIST_ENTRY']],
            'WmdTestResult': [0xA0, ['pointer64', ['void']]],
            'BootIdentifier': [0xA8, ['_GUID']],
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
    '_DBGKD_CONTINUE': [
        0x4,
        {
            'ContinueStatus': [0x0, ['long']],
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
    '_RTL_USER_PROCESS_PARAMETERS': [
        0x3F8,
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
        },
    ],
    '_PHYSICAL_MEMORY_RUN': [
        0x10,
        {
            'BasePage': [0x0, ['unsigned long long']],
            'PageCount': [0x8, ['unsigned long long']],
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
        0x368,
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
            'SpareBits': [
                0x3,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=8, native_type='unsigned char'),
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
            'ReservedBits0': [
                0x50,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=32, native_type='unsigned long'),
                ],
            ],
            'KernelCallbackTable': [0x58, ['unsigned long long']],
            'UserSharedInfoPtr': [0x58, ['unsigned long long']],
            'SystemReserved': [0x60, ['array', 1, ['unsigned long']]],
            'SpareUlong': [0x64, ['unsigned long']],
            'FreeList': [0x68, ['unsigned long long']],
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
            'WerRegistrationData': [0x358, ['unsigned long long']],
            'WerShipAssertPtr': [0x360, ['unsigned long long']],
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
    '__unnamed_1d51': [
        0x4,
        {
            'LongFlags': [0x0, ['unsigned long']],
            'Flags': [0x0, ['_MM_SESSION_SPACE_FLAGS']],
        },
    ],
    '_MM_SESSION_SPACE': [
        0x1E00,
        {
            'ReferenceCount': [0x0, ['long']],
            'u': [0x4, ['__unnamed_1d51']],
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
            'ImageLoadingCount': [0x64, ['long']],
            'SessionPoolAllocationFailures': [
                0x68,
                ['array', 4, ['unsigned long']],
            ],
            'ImageList': [0x78, ['_LIST_ENTRY']],
            'LocaleId': [0x88, ['unsigned long']],
            'AttachCount': [0x8C, ['unsigned long']],
            'AttachEvent': [0x90, ['_KEVENT']],
            'WsListEntry': [0xA8, ['_LIST_ENTRY']],
            'Lookaside': [0xC0, ['array', 21, ['_GENERAL_LOOKASIDE']]],
            'Session': [0xB40, ['_MMSESSION']],
            'PagedPoolInfo': [0xB98, ['_MM_PAGED_POOL_INFO']],
            'Vm': [0xC00, ['_MMSUPPORT']],
            'Wsle': [0xC68, ['pointer64', ['_MMWSLE']]],
            'DriverUnload': [0xC70, ['pointer64', ['void']]],
            'PagedPool': [0xC78, ['_POOL_DESCRIPTOR']],
            'PageDirectory': [0x1CC0, ['_MMPTE']],
            'SessionVaLock': [0x1CC8, ['_KGUARDED_MUTEX']],
            'DynamicVaBitMap': [0x1D00, ['_RTL_BITMAP']],
            'DynamicVaHint': [0x1D10, ['unsigned long']],
            'SpecialPool': [0x1D18, ['_MI_SPECIAL_POOL']],
            'SessionPteLock': [0x1D48, ['_KGUARDED_MUTEX']],
            'PoolBigEntriesInUse': [0x1D80, ['long']],
            'PagedPoolPdeCount': [0x1D84, ['unsigned long']],
            'SpecialPoolPdeCount': [0x1D88, ['unsigned long']],
            'DynamicSessionPdeCount': [0x1D8C, ['unsigned long']],
            'SessionPteFreeHead': [0x1D90, ['_MMPTE']],
            'SystemPteInfo': [0x1D98, ['_MI_SYSTEM_PTE_TYPE']],
            'PoolTrackTableExpansion': [0x1DB8, ['pointer64', ['void']]],
            'PoolTrackTableExpansionSize': [0x1DC0, ['unsigned long long']],
            'PoolTrackBigPages': [0x1DC8, ['pointer64', ['void']]],
            'PoolTrackBigPagesSize': [0x1DD0, ['unsigned long long']],
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
    '_GENERIC_MAPPING': [
        0x10,
        {
            'GenericRead': [0x0, ['unsigned long']],
            'GenericWrite': [0x4, ['unsigned long']],
            'GenericExecute': [0x8, ['unsigned long']],
            'GenericAll': [0xC, ['unsigned long']],
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
            'Accessed': [
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
            'Spare': [
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
    '_WHEA_GENERIC_PROCESSOR_ERROR': [
        0xC0,
        {
            'ValidBits': [0x0, ['unsigned long long']],
            'ProcessorType': [0x8, ['unsigned char']],
            'InstructionSet': [0x9, ['unsigned char']],
            'ErrorType': [0xA, ['unsigned char']],
            'Operation': [0xB, ['unsigned char']],
            'Flags': [0xC, ['unsigned char']],
            'Level': [0xD, ['unsigned char']],
            'Reserved': [0xE, ['unsigned short']],
            'CPUVersion': [0x10, ['unsigned long long']],
            'CPUBrandString': [0x18, ['array', 128, ['unsigned char']]],
            'ProcessorId': [0x98, ['unsigned long long']],
            'TargetAddress': [0xA0, ['unsigned long long']],
            'RequestorId': [0xA8, ['unsigned long long']],
            'ResponderId': [0xB0, ['unsigned long long']],
            'InstructionPointer': [0xB8, ['unsigned long long']],
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
        0x30,
        {
            'PteBase': [0x0, ['pointer64', ['_MMPTE']]],
            'FreePteHead': [0x8, ['_MMPTE']],
            'FreePteTail': [0x10, ['_MMPTE']],
            'PagesInUse': [0x18, ['long long']],
            'SpecialPoolPdes': [0x20, ['_RTL_BITMAP']],
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
    '_PNP_DEVICE_EVENT_LIST': [
        0x88,
        {
            'Status': [0x0, ['long']],
            'EventQueueMutex': [0x8, ['_KMUTANT']],
            'Lock': [0x40, ['_KGUARDED_MUTEX']],
            'List': [0x78, ['_LIST_ENTRY']],
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
    '_CM_WORKITEM': [
        0x20,
        {
            'ListEntry': [0x0, ['_LIST_ENTRY']],
            'WorkerRoutine': [0x10, ['pointer64', ['void']]],
            'Parameter': [0x18, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1dca': [
        0x10,
        {
            'UserData': [0x0, ['pointer64', ['void']]],
            'Owner': [0x8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1dcc': [
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
            'Allocated': [0x10, ['__unnamed_1dca']],
            'Merged': [0x10, ['__unnamed_1dcc']],
            'Attributes': [0x20, ['unsigned char']],
            'PublicFlags': [0x21, ['unsigned char']],
            'PrivateFlags': [0x22, ['unsigned short']],
            'ListEntry': [0x28, ['_LIST_ENTRY']],
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
    '__unnamed_1dd3': [
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
            'Flags': [0x2, ['__unnamed_1dd3']],
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
        0x68,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'SubsectionBase': [0x8, ['pointer64', ['_MMPTE']]],
            'NextSubsection': [0x10, ['pointer64', ['_SUBSECTION']]],
            'NextMappedSubsection': [0x10, ['pointer64', ['_MSUBSECTION']]],
            'PtesInSubsection': [0x18, ['unsigned long']],
            'UnusedPtes': [0x20, ['unsigned long']],
            'GlobalPerSessionHead': [0x20, ['pointer64', ['_MM_AVL_TABLE']]],
            'u': [0x28, ['__unnamed_14d5']],
            'StartingSector': [0x2C, ['unsigned long']],
            'NumberOfFullSectors': [0x30, ['unsigned long']],
            'u1': [0x38, ['__unnamed_1bd0']],
            'LeftChild': [0x40, ['pointer64', ['_MMSUBSECTION_NODE']]],
            'RightChild': [0x48, ['pointer64', ['_MMSUBSECTION_NODE']]],
            'DereferenceList': [0x50, ['_LIST_ENTRY']],
            'NumberOfMappedViews': [0x60, ['unsigned long long']],
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
        0x58,
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
    '__unnamed_1de9': [
        0x8,
        {
            'ImageCommitment': [0x0, ['unsigned long long']],
            'CreatingProcess': [0x0, ['pointer64', ['_EPROCESS']]],
        },
    ],
    '__unnamed_1ded': [
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
        0x58,
        {
            'ControlArea': [0x0, ['pointer64', ['_CONTROL_AREA']]],
            'TotalNumberOfPtes': [0x8, ['unsigned long']],
            'NonExtendedPtes': [0xC, ['unsigned long']],
            'NumberOfCommittedPages': [0x10, ['unsigned long long']],
            'SizeOfSegment': [0x18, ['unsigned long long']],
            'ExtendInfo': [0x20, ['pointer64', ['_MMEXTEND_INFO']]],
            'BasedAddress': [0x20, ['pointer64', ['void']]],
            'SegmentLock': [0x28, ['_EX_PUSH_LOCK']],
            'SegmentFlags': [0x30, ['_SEGMENT_FLAGS']],
            'u1': [0x38, ['__unnamed_1de9']],
            'u2': [0x40, ['__unnamed_1ded']],
            'PrototypePte': [0x48, ['pointer64', ['_MMPTE']]],
            'ThePtes': [0x50, ['array', 1, ['_MMPTE']]],
        },
    ],
    '_PCAT_FIRMWARE_INFORMATION': [
        0x4,
        {
            'PlaceHolder': [0x0, ['unsigned long']],
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
    '_WHEA_PCIX_BUS_VALIDATION_BITS': [
        0x8,
        {
            'ErrorStatusValid': [
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
            'ErrorTypeValid': [
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
            'BusIdValid': [
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
            'BusAddressValid': [
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
            'BusDataValid': [
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
            'CommandValid': [
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
            'RequestorIdValid': [
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
            'CompleterIdValid': [
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
            'TargetIdValid': [
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
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=9,
                        end_bit=64,
                        native_type='unsigned long long',
                    ),
                ],
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
        0x50,
        {
            'RegList': [0x0, ['_LIST_ENTRY']],
            'GuidEntry': [0x10, ['pointer64', ['_ETW_GUID_ENTRY']]],
            'Index': [0x18, ['unsigned short']],
            'Flags': [0x1A, ['unsigned short']],
            'EnableMask': [0x1C, ['unsigned char']],
            'ReplyQueue': [0x20, ['pointer64', ['_ETW_REPLY_QUEUE']]],
            'ReplySlot': [
                0x20,
                ['array', 4, ['pointer64', ['_ETW_REG_ENTRY']]],
            ],
            'Process': [0x40, ['pointer64', ['_EPROCESS']]],
            'Callback': [0x40, ['pointer64', ['void']]],
            'CallbackContext': [0x48, ['pointer64', ['void']]],
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
    '_KNODE': [
        0xC0,
        {
            'PagedPoolSListHead': [0x0, ['_SLIST_HEADER']],
            'NonPagedPoolSListHead': [0x10, ['array', 3, ['_SLIST_HEADER']]],
            'PfnDereferenceSListHead': [0x40, ['_SLIST_HEADER']],
            'ProcessorMask': [0x50, ['unsigned long long']],
            'Color': [0x58, ['unsigned char']],
            'Seed': [0x59, ['unsigned char']],
            'NodeNumber': [0x5A, ['unsigned char']],
            'Flags': [0x5B, ['_flags']],
            'MmShiftedColor': [0x5C, ['unsigned long']],
            'FreeCount': [0x60, ['array', 2, ['unsigned long long']]],
            'PfnDeferredList': [0x70, ['pointer64', ['_SLIST_ENTRY']]],
            'Right': [0x78, ['unsigned long']],
            'Left': [0x7C, ['unsigned long']],
            'CachedKernelStacks': [0x80, ['_CACHED_KSTACK_LIST']],
        },
    ],
    '_CACHED_KSTACK_LIST': [
        0x20,
        {
            'SListHead': [0x0, ['_SLIST_HEADER']],
            'MinimumFree': [0x10, ['long']],
            'Misses': [0x14, ['unsigned long']],
            'MissesLast': [0x18, ['unsigned long']],
        },
    ],
    '_POP_DEVICE_SYS_STATE': [
        0x2B8,
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
            'NotifyGdiLevelForPowerOn': [0x288, ['long']],
            'NotifyGdiLevelForResumeUI': [0x28C, ['long']],
            'Pending': [0x290, ['_LIST_ENTRY']],
            'Status': [0x2A0, ['long']],
            'FailedDevice': [0x2A8, ['pointer64', ['_DEVICE_OBJECT']]],
            'Waking': [0x2B0, ['unsigned char']],
            'Cancelled': [0x2B1, ['unsigned char']],
            'IgnoreErrors': [0x2B2, ['unsigned char']],
            'IgnoreNotImplemented': [0x2B3, ['unsigned char']],
            'TimeRefreshLockAcquired': [0x2B4, ['unsigned char']],
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
            'WatchProto': [
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
            'DebugSymbolsLoaded': [
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
            'WriteCombined': [
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
            'NoCache': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=15,
                        end_bit=16,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'FloppyMedia': [
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
            'DefaultProtectionMask': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=17,
                        end_bit=22,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'ContainsPxeSubsection': [
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
            'Spare': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=23,
                        end_bit=63,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Binary32': [
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
    '_SHARED_CACHE_MAP_LIST_CURSOR': [
        0x18,
        {
            'SharedCacheMapLinks': [0x0, ['_LIST_ENTRY']],
            'Flags': [0x10, ['unsigned long']],
        },
    ],
    '_TEB32': [
        0xFF8,
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
            'SpareBytes1': [0x1AC, ['array', 36, ['unsigned char']]],
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
            'SpareBool0': [0xF74, ['unsigned char']],
            'SpareBool1': [0xF75, ['unsigned char']],
            'SpareBool2': [0xF76, ['unsigned char']],
            'IdealProcessor': [0xF77, ['unsigned char']],
            'GuaranteedStackBytes': [0xF78, ['unsigned long']],
            'ReservedForPerf': [0xF7C, ['unsigned long']],
            'ReservedForOle': [0xF80, ['unsigned long']],
            'WaitingOnLoaderLock': [0xF84, ['unsigned long']],
            'SavedPriorityState': [0xF88, ['unsigned long']],
            'SoftPatchPtr1': [0xF8C, ['unsigned long']],
            'ThreadPoolData': [0xF90, ['unsigned long']],
            'TlsExpansionSlots': [0xF94, ['unsigned long']],
            'ImpersonationLocale': [0xF98, ['unsigned long']],
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
            'DbgSafeThunkCall': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=1, native_type='unsigned short'),
                ],
            ],
            'DbgInDebugPrint': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=1, end_bit=2, native_type='unsigned short'),
                ],
            ],
            'DbgHasFiberData': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=2, end_bit=3, native_type='unsigned short'),
                ],
            ],
            'DbgSkipThreadAttach': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=4, native_type='unsigned short'),
                ],
            ],
            'DbgWerInShipAssertCode': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=4, end_bit=5, native_type='unsigned short'),
                ],
            ],
            'DbgRanProcessInit': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=5, end_bit=6, native_type='unsigned short'),
                ],
            ],
            'DbgClonedThread': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=6, end_bit=7, native_type='unsigned short'),
                ],
            ],
            'DbgSuppressDebugMsg': [
                0xFCA,
                [
                    'BitField',
                    dict(start_bit=7, end_bit=8, native_type='unsigned short'),
                ],
            ],
            'SpareSameTebBits': [
                0xFCA,
                [
                    'BitField',
                    dict(
                        start_bit=8, end_bit=16, native_type='unsigned short'
                    ),
                ],
            ],
            'TxnScopeEnterCallback': [0xFCC, ['unsigned long']],
            'TxnScopeExitCallback': [0xFD0, ['unsigned long']],
            'TxnScopeContext': [0xFD4, ['unsigned long']],
            'LockCount': [0xFD8, ['unsigned long']],
            'ProcessRundown': [0xFDC, ['unsigned long']],
            'LastSwitchTime': [0xFE0, ['unsigned long long']],
            'TotalSwitchOutTime': [0xFE8, ['unsigned long long']],
            'WaitReasonBitMap': [0xFF0, ['_LARGE_INTEGER']],
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
            'OptionChanges': [0x78, ['unsigned long']],
            'VerifyMode': [0x7C, ['unsigned long']],
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
                ['array', 1023, ['_VI_DEADLOCK_ADDRESS_RANGE']],
            ],
            'ThreadDatabase': [0x4010, ['pointer64', ['_LIST_ENTRY']]],
            'ThreadDatabaseCount': [0x4018, ['unsigned long long']],
            'ThreadAddressRange': [
                0x4020,
                ['array', 1023, ['_VI_DEADLOCK_ADDRESS_RANGE']],
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
            'CacheReductionInProgress': [0x8160, ['unsigned long']],
        },
    ],
    '_POP_DISPLAY_RESUME_CONTEXT': [
        0x80,
        {
            'WorkItem': [0x0, ['_WORK_QUEUE_ITEM']],
            'WorkerThread': [0x20, ['pointer64', ['_ETHREAD']]],
            'PrepareUIEvent': [0x28, ['_KEVENT']],
            'PowerOnEvent': [0x40, ['_KEVENT']],
            'DoneEvent': [0x58, ['_KEVENT']],
            'WorkerQueued': [0x70, ['unsigned long']],
            'WorkerAbort': [0x74, ['unsigned long']],
            'NoResumeUI': [0x78, ['unsigned long']],
        },
    ],
    '_KPCR': [
        0x3BA0,
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
    '_KTM': [
        0x380,
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
            'TmRmHandle': [0x298, ['pointer64', ['void']]],
            'TmRm': [0x2A0, ['pointer64', ['_KRESOURCEMANAGER']]],
            'LogFullNotifyEvent': [0x2A8, ['_KEVENT']],
            'CheckpointWorkItem': [0x2C0, ['_WORK_QUEUE_ITEM']],
            'CheckpointTargetLsn': [0x2E0, ['_CLS_LSN']],
            'LogFullCompletedWorkItem': [0x2E8, ['_WORK_QUEUE_ITEM']],
            'LogWriteResource': [0x308, ['_ERESOURCE']],
            'LogFlags': [0x370, ['unsigned long']],
            'LogFullStatus': [0x374, ['long']],
            'RecoveryStatus': [0x378, ['long']],
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
    '__unnamed_1e94': [
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
            'Privileges': [0x50, ['__unnamed_1e94']],
            'AuditPrivileges': [0x7C, ['unsigned char']],
            'ObjectName': [0x80, ['_UNICODE_STRING']],
            'ObjectTypeName': [0x90, ['_UNICODE_STRING']],
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
            'ConfigurationDataLength': [0x18, ['unsigned long']],
            'IdentifierLength': [0x1C, ['unsigned long']],
            'Identifier': [0x20, ['pointer64', ['unsigned char']]],
        },
    ],
    '_KTRANSACTION': [
        0x268,
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
                            11: 'KTransactionSavepointing',
                            12: 'KTransactionPrePrepared',
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
            'NextSavepoint': [0x1FC, ['unsigned long']],
            'Tm': [0x200, ['pointer64', ['_KTM']]],
            'CommitReservation': [0x208, ['long long']],
            'TransactionHistory': [
                0x210,
                ['array', 10, ['_KTRANSACTION_HISTORY']],
            ],
            'TransactionHistoryCount': [0x260, ['unsigned long']],
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
    '_CM_NAME_HASH': [
        0x18,
        {
            'ConvKey': [0x0, ['unsigned long']],
            'NextHash': [0x8, ['pointer64', ['_CM_NAME_HASH']]],
            'NameLength': [0x10, ['unsigned short']],
            'Name': [0x12, ['array', 1, ['wchar']]],
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
    '__unnamed_1ecb': [
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
            'u1': [0x48, ['__unnamed_1ecb']],
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
    '_CLIENT_ID32': [
        0x8,
        {
            'UniqueProcess': [0x0, ['unsigned long']],
            'UniqueThread': [0x4, ['unsigned long']],
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
    '_WHEA_PERSISTENCE_INFO': [
        0x8,
        {
            'Identifier': [
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
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=40,
                        end_bit=46,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Attributes': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=46,
                        end_bit=48,
                        native_type='unsigned long long',
                    ),
                ],
            ],
            'Signature': [
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
    '_PCIE_DEVICE_ID': [
        0x10,
        {
            'VendorID': [0x0, ['unsigned short']],
            'DeviceID': [0x2, ['unsigned short']],
            'ClassCode': [
                0x4,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'FunctionNumber': [
                0x4,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'DeviceNumber': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Segment': [
                0x8,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=24, native_type='unsigned long'),
                ],
            ],
            'PrimaryBusNumber': [
                0x8,
                [
                    'BitField',
                    dict(
                        start_bit=24, end_bit=32, native_type='unsigned long'
                    ),
                ],
            ],
            'SecondaryBusNumber': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=0, end_bit=8, native_type='unsigned long'),
                ],
            ],
            'Reserved1': [
                0xC,
                [
                    'BitField',
                    dict(start_bit=8, end_bit=10, native_type='unsigned long'),
                ],
            ],
            'SlotNumber': [
                0xC,
                [
                    'BitField',
                    dict(
                        start_bit=10, end_bit=24, native_type='unsigned long'
                    ),
                ],
            ],
            'Reserved2': [
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
    '_WHEA_PCIX_DEV_VALIDATION_BITS': [
        0x8,
        {
            'ErrorStatusValid': [
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
            'IdInfoValid': [
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
            'MemoryNumberValid': [
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
            'IoNumberValid': [
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
            'RegisterDataPairValid': [
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
            'Reserved': [
                0x0,
                [
                    'BitField',
                    dict(
                        start_bit=5,
                        end_bit=64,
                        native_type='unsigned long long',
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
    '_DBGKD_ANY_CONTROL_SET': [
        0x1C,
        {
            'X86ControlSet': [0x0, ['_X86_DBGKD_CONTROL_SET']],
            'AlphaControlSet': [0x0, ['unsigned long']],
            'IA64ControlSet': [0x0, ['_IA64_DBGKD_CONTROL_SET']],
            'Amd64ControlSet': [0x0, ['_AMD64_DBGKD_CONTROL_SET']],
            'ArmControlSet': [0x0, ['_ARM_DBGKD_CONTROL_SET']],
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
            'Reserved': [
                0x33,
                [
                    'BitField',
                    dict(start_bit=3, end_bit=8, native_type='unsigned char'),
                ],
            ],
            'LoaderFlags': [0x34, ['unsigned long']],
            'ImageFileSize': [0x38, ['unsigned long']],
            'CheckSum': [0x3C, ['unsigned long']],
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
    '_TOKEN_AUDIT_POLICY': [
        0x1A,
        {
            'PerUserPolicy': [0x0, ['array', 26, ['unsigned char']]],
        },
    ],
    '__unnamed_1f1d': [
        0x10,
        {
            'EndingOffset': [0x0, ['pointer64', ['_LARGE_INTEGER']]],
            'ResourceToRelease': [
                0x8,
                ['pointer64', ['pointer64', ['_ERESOURCE']]],
            ],
        },
    ],
    '__unnamed_1f1f': [
        0x8,
        {
            'ResourceToRelease': [0x0, ['pointer64', ['_ERESOURCE']]],
        },
    ],
    '__unnamed_1f23': [
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
    '__unnamed_1f27': [
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
    '__unnamed_1f29': [
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
            'AcquireForModifiedPageWriter': [0x0, ['__unnamed_1f1d']],
            'ReleaseForModifiedPageWriter': [0x0, ['__unnamed_1f1f']],
            'AcquireForSectionSynchronization': [0x0, ['__unnamed_1f23']],
            'NotifyStreamFileObject': [0x0, ['__unnamed_1f27']],
            'Others': [0x0, ['__unnamed_1f29']],
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
    '_INITIAL_PRIVILEGE_SET': [
        0x2C,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Control': [0x4, ['unsigned long']],
            'Privilege': [0x8, ['array', 3, ['_LUID_AND_ATTRIBUTES']]],
        },
    ],
    '_POP_HIBER_CONTEXT': [
        0x158,
        {
            'WriteToFile': [0x0, ['unsigned char']],
            'ReserveLoaderMemory': [0x1, ['unsigned char']],
            'ReserveFreeMemory': [0x2, ['unsigned char']],
            'VerifyOnWake': [0x3, ['unsigned char']],
            'Reset': [0x4, ['unsigned char']],
            'HiberFlags': [0x5, ['unsigned char']],
            'WroteHiberFile': [0x6, ['unsigned char']],
            'Lock': [0x8, ['unsigned long long']],
            'MapFrozen': [0x10, ['unsigned char']],
            'MemoryMap': [0x18, ['_RTL_BITMAP']],
            'DiscardedMemoryPages': [0x28, ['_RTL_BITMAP']],
            'ClonedRanges': [0x38, ['_LIST_ENTRY']],
            'ClonedRangeCount': [0x48, ['unsigned long']],
            'NextCloneRange': [0x50, ['pointer64', ['_LIST_ENTRY']]],
            'NextPreserve': [0x58, ['unsigned long long']],
            'LoaderMdl': [0x60, ['pointer64', ['_MDL']]],
            'AllocatedMdl': [0x68, ['pointer64', ['_MDL']]],
            'PagesOut': [0x70, ['unsigned long long']],
            'IoPages': [0x78, ['pointer64', ['void']]],
            'CurrentMcb': [0x80, ['pointer64', ['void']]],
            'DumpStack': [0x88, ['pointer64', ['_DUMP_STACK_CONTEXT']]],
            'WakeState': [0x90, ['pointer64', ['_KPROCESSOR_STATE']]],
            'HiberVa': [0x98, ['unsigned long long']],
            'HiberPte': [0xA0, ['_LARGE_INTEGER']],
            'Status': [0xA8, ['long']],
            'MemoryImage': [0xB0, ['pointer64', ['PO_MEMORY_IMAGE']]],
            'TableHead': [0xB8, ['pointer64', ['_PO_MEMORY_RANGE_ARRAY']]],
            'CompressionWorkspace': [0xC0, ['pointer64', ['unsigned char']]],
            'CompressedWriteBuffer': [0xC8, ['pointer64', ['unsigned char']]],
            'PerformanceStats': [0xD0, ['pointer64', ['unsigned long']]],
            'CompressionBlock': [0xD8, ['pointer64', ['void']]],
            'DmaIO': [0xE0, ['pointer64', ['void']]],
            'TemporaryHeap': [0xE8, ['pointer64', ['void']]],
            'PerfInfo': [0xF0, ['_PO_HIBER_PERF']],
            'BootLoaderLogMdl': [0x150, ['pointer64', ['_MDL']]],
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
        0x28,
        {
            'Code': [0x0, ['unsigned long']],
            'Parameter1': [0x8, ['unsigned long long']],
            'Parameter2': [0x10, ['unsigned long long']],
            'Parameter3': [0x18, ['unsigned long long']],
            'Parameter4': [0x20, ['unsigned long long']],
        },
    ],
    '_MI_EXTRA_IMAGE_INFORMATION': [
        0x4,
        {
            'SizeOfHeaders': [0x0, ['unsigned long']],
        },
    ],
    '_RTL_HANDLE_TABLE_ENTRY': [
        0x8,
        {
            'Flags': [0x0, ['unsigned long']],
            'NextFree': [0x0, ['pointer64', ['_RTL_HANDLE_TABLE_ENTRY']]],
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
    '__unnamed_1f51': [
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
            'Parameters': [0x0, ['__unnamed_1f51']],
        },
    ],
    '__unnamed_1f55': [
        0x8,
        {
            'idxRecord': [0x0, ['unsigned long']],
            'cidContainer': [0x4, ['unsigned long']],
        },
    ],
    '_CLS_LSN': [
        0x8,
        {
            'offset': [0x0, ['__unnamed_1f55']],
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
            'TotalPages': [0x60, ['unsigned long long']],
            'FirstTablePage': [0x68, ['unsigned long long']],
            'LastFilePage': [0x70, ['unsigned long long']],
            'PerfInfo': [0x78, ['_PO_HIBER_PERF']],
            'NoBootLoaderLogPages': [0xD8, ['unsigned long']],
            'BootLoaderLogPages': [0xE0, ['array', 8, ['unsigned long long']]],
            'TotalPhysicalMemoryCount': [0x120, ['unsigned long']],
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
        0x60,
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
            'ResumeAppStartTime': [0x48, ['unsigned long long']],
            'ResumeAppEndTime': [0x50, ['unsigned long long']],
            'HiberFileResumeTime': [0x58, ['unsigned long long']],
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
        0x10,
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
    '__unnamed_1f74': [
        0x14,
        {
            'ClassGuid': [0x0, ['_GUID']],
            'SymbolicLinkName': [0x10, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f76': [
        0x2,
        {
            'DeviceIds': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f78': [
        0x2,
        {
            'DeviceId': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f7a': [
        0x10,
        {
            'NotificationStructure': [0x0, ['pointer64', ['void']]],
            'DeviceIds': [0x8, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f7c': [
        0x8,
        {
            'Notification': [0x0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1f7e': [
        0x8,
        {
            'NotificationCode': [0x0, ['unsigned long']],
            'NotificationData': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1f80': [
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
    '__unnamed_1f82': [
        0x10,
        {
            'BlockedDriverGuid': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_1f84': [
        0x2,
        {
            'ParentId': [0x0, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_1f86': [
        0x1C,
        {
            'PowerSettingGuid': [0x0, ['_GUID']],
            'PowerSettingChanged': [0x10, ['unsigned char']],
            'DataLength': [0x14, ['unsigned long']],
            'Data': [0x18, ['array', 1, ['unsigned char']]],
        },
    ],
    '__unnamed_1f88': [
        0x20,
        {
            'DeviceClass': [0x0, ['__unnamed_1f74']],
            'TargetDevice': [0x0, ['__unnamed_1f76']],
            'InstallDevice': [0x0, ['__unnamed_1f78']],
            'CustomNotification': [0x0, ['__unnamed_1f7a']],
            'ProfileNotification': [0x0, ['__unnamed_1f7c']],
            'PowerNotification': [0x0, ['__unnamed_1f7e']],
            'VetoNotification': [0x0, ['__unnamed_1f80']],
            'BlockedDriverNotification': [0x0, ['__unnamed_1f82']],
            'InvalidIDNotification': [0x0, ['__unnamed_1f84']],
            'PowerSettingNotification': [0x0, ['__unnamed_1f86']],
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
                            6: 'PowerEvent',
                            7: 'VetoEvent',
                            8: 'BlockedDriverEvent',
                            9: 'InvalidIDEvent',
                            10: 'PowerSettingChange',
                            11: 'MaxPlugEventCategory',
                        },
                    ),
                ],
            ],
            'Result': [0x18, ['pointer64', ['unsigned long']]],
            'Flags': [0x20, ['unsigned long']],
            'TotalSize': [0x24, ['unsigned long']],
            'DeviceObject': [0x28, ['pointer64', ['void']]],
            'u': [0x30, ['__unnamed_1f88']],
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
    '_POWER_CHANNEL_SUMMARY': [
        0x20,
        {
            'Signature': [0x0, ['unsigned long']],
            'TotalCount': [0x4, ['unsigned long']],
            'D0Count': [0x8, ['unsigned long']],
            'NotifyList': [0x10, ['_LIST_ENTRY']],
        },
    ],
    '_PO_MEMORY_RANGE_ARRAY': [
        0x20,
        {
            'Range': [0x0, ['_PO_MEMORY_RANGE_ARRAY_RANGE']],
            'Link': [0x0, ['_PO_MEMORY_RANGE_ARRAY_LINK']],
        },
    ],
    '__unnamed_1f9f': [
        0x8,
        {
            'Signature': [0x0, ['unsigned long']],
            'CheckSum': [0x4, ['unsigned long']],
        },
    ],
    '__unnamed_1fa1': [
        0x10,
        {
            'DiskId': [0x0, ['_GUID']],
        },
    ],
    '__unnamed_1fa3': [
        0x10,
        {
            'Mbr': [0x0, ['__unnamed_1f9f']],
            'Gpt': [0x0, ['__unnamed_1fa1']],
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
            'DiskInfo': [0x8C, ['__unnamed_1fa3']],
        },
    ],
    '_MI_SYSTEM_PTE_TYPE': [
        0x20,
        {
            'FirstFreePte': [0x0, ['pointer64', ['_MMPTE']]],
            'FailureCount': [0x8, ['pointer64', ['unsigned long']]],
            'GlobalMutex': [0x10, ['pointer64', ['_KGUARDED_MUTEX']]],
            'TbFlushTimeStamp': [0x18, ['unsigned long']],
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
        0x250,
        {
            'Locked': [0x0, ['unsigned char']],
            'WarmEjectPdoPointer': [
                0x8,
                ['pointer64', ['pointer64', ['_DEVICE_OBJECT']]],
            ],
            'OrderLevel': [0x10, ['array', 8, ['_PO_NOTIFY_ORDER_LEVEL']]],
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
    '_VI_DEADLOCK_ADDRESS_RANGE': [
        0x10,
        {
            'Start': [0x0, ['pointer64', ['unsigned char']]],
            'End': [0x8, ['pointer64', ['unsigned char']]],
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
    '_PO_MEMORY_RANGE_ARRAY_LINK': [
        0x18,
        {
            'Next': [0x0, ['pointer64', ['_PO_MEMORY_RANGE_ARRAY']]],
            'NextTable': [0x8, ['unsigned long long']],
            'CheckSum': [0x10, ['unsigned long']],
            'EntryCount': [0x14, ['unsigned long']],
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
    '_OBJECT_DIRECTORY_ENTRY': [
        0x18,
        {
            'ChainLink': [0x0, ['pointer64', ['_OBJECT_DIRECTORY_ENTRY']]],
            'Object': [0x8, ['pointer64', ['void']]],
            'HashValue': [0x10, ['unsigned long']],
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
    '_PRIVILEGE_SET': [
        0x14,
        {
            'PrivilegeCount': [0x0, ['unsigned long']],
            'Control': [0x4, ['unsigned long']],
            'Privilege': [0x8, ['array', 1, ['_LUID_AND_ATTRIBUTES']]],
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
    '__unnamed_1fda': [
        0x4,
        {
            'BaseMiddle': [0x0, ['unsigned char']],
            'Flags1': [0x1, ['unsigned char']],
            'Flags2': [0x2, ['unsigned char']],
            'BaseHigh': [0x3, ['unsigned char']],
        },
    ],
    '__unnamed_1fde': [
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
            'Bytes': [0x4, ['__unnamed_1fda']],
            'Bits': [0x4, ['__unnamed_1fde']],
            'BaseUpper': [0x8, ['unsigned long']],
            'MustBeZero': [0xC, ['unsigned long']],
            'Alignment': [0x0, ['unsigned long long']],
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
}
