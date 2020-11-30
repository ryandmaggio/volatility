win32k_types = {
    '_HANDLEENTRY': [
        0x18,
        {
            'pOwner': [8, ['pointer64', ['void']]],
            'phead': [0, ['pointer64', ['_HEAD']]],
            'bFlags': [17, ['unsigned char']],
            'wUniq': [18, ['unsigned short']],
            'bType': [16, ['unsigned char']],
        },
    ],
    'tagTOUCHINPUTINFO': [
        0x50,
        {
            'dwcInputs': [24, ['unsigned long']],
            'head': [0, ['_THROBJHEAD']],
            'uFlags': [28, ['unsigned long']],
            'TouchInput': [32, ['array', 1, ['tagTOUCHINPUT']]],
        },
    ],
    'tagHOOK': [
        0x60,
        {
            'head': [0, ['_THRDESKHEAD']],
            'offPfn': [56, ['unsigned long long']],
            'flags': [64, ['unsigned long']],
            'fLastHookHung': [
                88,
                [
                    'BitField',
                    {'end_bit': 8, 'start_bit': 7, 'native_type': 'long'},
                ],
            ],
            'nTimeout': [
                88,
                [
                    'BitField',
                    {
                        'end_bit': 7,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ihmod': [68, ['long']],
            'iHook': [48, ['long']],
            'ptiHooked': [72, ['pointer64', ['tagTHREADINFO']]],
            'phkNext': [40, ['pointer64', ['tagHOOK']]],
            'rpdesk': [80, ['pointer64', ['tagDESKTOP']]],
        },
    ],
    'DEADKEY': [
        0x8,
        {
            'wchComposed': [4, ['wchar']],
            'dwBoth': [0, ['unsigned long']],
            'uFlags': [6, ['unsigned short']],
        },
    ],
    '_W32THREAD': [
        0x150,
        {
            'pRBRecursionCount': [96, ['unsigned long']],
            'iVisRgnUniqueness': [328, ['unsigned long']],
            'RefCount': [8, ['unsigned long']],
            'pDevHTInfo': [280, ['pointer64', ['void']]],
            'pUMPDHeap': [48, ['pointer64', ['void']]],
            'pgdiBrushAttr': [32, ['pointer64', ['void']]],
            'ulWindowSystemRendering': [324, ['unsigned long']],
            'tlSpriteState': [104, ['_TLSPRITESTATE']],
            'pdcoRender': [304, ['pointer64', ['void']]],
            'bEnableEngUpdateDeviceSurface': [320, ['unsigned char']],
            'pdcoAA': [296, ['pointer64', ['void']]],
            'pNonRBRecursionCount': [100, ['unsigned long']],
            'ptlW32': [16, ['pointer64', ['_TL']]],
            'GdiTmpTgoList': [80, ['_LIST_ENTRY']],
            'pUMPDObjs': [40, ['pointer64', ['void']]],
            'pgdiDcattr': [24, ['pointer64', ['void']]],
            'bIncludeSprites': [321, ['unsigned char']],
            'pEThread': [0, ['pointer64', ['_ETHREAD']]],
            'pSpriteState': [272, ['pointer64', ['void']]],
            'pProxyPort': [64, ['pointer64', ['void']]],
            'ulDevHTInfoUniqueness': [288, ['unsigned long']],
            'pdcoSrc': [312, ['pointer64', ['void']]],
            'pUMPDObj': [56, ['pointer64', ['void']]],
            'pClientID': [72, ['pointer64', ['void']]],
        },
    ],
    'tagPROPLIST': [
        0x18,
        {
            'aprop': [8, ['array', 1, ['tagPROP']]],
            'cEntries': [0, ['unsigned long']],
            'iFirstFree': [4, ['unsigned long']],
        },
    ],
    'tagSVR_INSTANCE_INFO': [
        0x40,
        {
            'head': [0, ['_THROBJHEAD']],
            'next': [24, ['pointer64', ['tagSVR_INSTANCE_INFO']]],
            'nextInThisThread': [32, ['pointer64', ['tagSVR_INSTANCE_INFO']]],
            'spwndEvent': [48, ['pointer64', ['tagWND']]],
            'afCmd': [40, ['unsigned long']],
            'pcii': [56, ['pointer64', ['void']]],
        },
    ],
    'tagDESKTOPINFO': [
        0xF0,
        {
            'spwndProgman': [192, ['pointer64', ['tagWND']]],
            'pvwplMessagePPHandler': [224, ['pointer64', ['VWPL']]],
            'pvDesktopLimit': [8, ['pointer64', ['void']]],
            'fComposited': [
                232,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwndGestureEngine': [216, ['pointer64', ['tagWND']]],
            'pvDesktopBase': [0, ['pointer64', ['void']]],
            'spwndShell': [160, ['pointer64', ['tagWND']]],
            'ppiShellProcess': [168, ['pointer64', ['tagPROCESSINFO']]],
            'pvwplShellHook': [200, ['pointer64', ['VWPL']]],
            'fIsDwmDesktop': [
                232,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwndTaskman': [184, ['pointer64', ['tagWND']]],
            'aphkStart': [32, ['array', 16, ['pointer64', ['tagHOOK']]]],
            'fsHooks': [24, ['unsigned long']],
            'cntMBox': [208, ['long']],
            'spwndBkGnd': [176, ['pointer64', ['tagWND']]],
            'spwnd': [16, ['pointer64', ['tagWND']]],
        },
    ],
    'tagDISPLAYINFO': [
        0xA8,
        {
            'hDev': [0, ['pointer64', ['void']]],
            'SpatialListHead': [144, ['_KLIST_ENTRY']],
            'BitCountMax': [130, ['unsigned short']],
            'cyGray': [60, ['long']],
            'hdcBits': [32, ['pointer64', ['HDC__']]],
            'fDesktopIsRect': [
                132,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'hbmGray': [48, ['pointer64', ['HBITMAP__']]],
            'pmdev': [8, ['pointer64', ['void']]],
            'cFullScreen': [160, ['short']],
            'cxGray': [56, ['long']],
            'dmLogPixels': [128, ['unsigned short']],
            'hDevInfo': [16, ['pointer64', ['void']]],
            'fAnyPalette': [
                132,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'pspbFirst': [72, ['pointer64', ['tagSPB']]],
            'pMonitorPrimary': [88, ['pointer64', ['tagMONITOR']]],
            'Spare0': [162, ['short']],
            'pMonitorFirst': [96, ['pointer64', ['tagMONITOR']]],
            'hdcGray': [40, ['pointer64', ['HDC__']]],
            'hrgnScreenReal': [120, ['pointer64', ['HRGN__']]],
            'cMonitors': [80, ['unsigned long']],
            'hdcScreen': [24, ['pointer64', ['HDC__']]],
            'DockThresholdMax': [136, ['unsigned long']],
            'rcScreenReal': [104, ['tagRECT']],
            'pdceFirst': [64, ['pointer64', ['tagDCE']]],
        },
    ],
    '__unnamed_1261': [
        0x20,
        {
            'Buffer': [24, ['pointer64', ['void']]],
            'ProviderId': [0, ['unsigned long long']],
            'BufferSize': [16, ['unsigned long']],
            'DataPath': [8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1263': [
        0x20,
        {
            'Argument4': [24, ['pointer64', ['void']]],
            'Argument2': [8, ['pointer64', ['void']]],
            'Argument3': [16, ['pointer64', ['void']]],
            'Argument1': [0, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1265': [
        0x20,
        {
            'DeviceIoControl': [0, ['__unnamed_121d']],
            'QuerySecurity': [0, ['__unnamed_121f']],
            'ReadWriteConfig': [0, ['__unnamed_123d']],
            'Create': [0, ['__unnamed_11ff']],
            'SetSecurity': [0, ['__unnamed_1221']],
            'Write': [0, ['__unnamed_1209']],
            'VerifyVolume': [0, ['__unnamed_1225']],
            'WMI': [0, ['__unnamed_1261']],
            'CreateMailslot': [0, ['__unnamed_1207']],
            'FilterResourceRequirements': [0, ['__unnamed_123b']],
            'SetFile': [0, ['__unnamed_1213']],
            'MountVolume': [0, ['__unnamed_1225']],
            'FileSystemControl': [0, ['__unnamed_1219']],
            'UsageNotification': [0, ['__unnamed_124b']],
            'Scsi': [0, ['__unnamed_1229']],
            'WaitWake': [0, ['__unnamed_124f']],
            'QueryFile': [0, ['__unnamed_1211']],
            'QueryDeviceText': [0, ['__unnamed_1247']],
            'CreatePipe': [0, ['__unnamed_1203']],
            'Power': [0, ['__unnamed_125b']],
            'QueryDeviceRelations': [0, ['__unnamed_122d']],
            'Read': [0, ['__unnamed_1209']],
            'StartDevice': [0, ['__unnamed_125f']],
            'QueryDirectory': [0, ['__unnamed_120d']],
            'PowerSequence': [0, ['__unnamed_1253']],
            'QueryId': [0, ['__unnamed_1243']],
            'LockControl': [0, ['__unnamed_121b']],
            'NotifyDirectory': [0, ['__unnamed_120f']],
            'QueryInterface': [0, ['__unnamed_1233']],
            'Others': [0, ['__unnamed_1263']],
            'QueryVolume': [0, ['__unnamed_1217']],
            'SetLock': [0, ['__unnamed_123f']],
            'DeviceCapabilities': [0, ['__unnamed_1237']],
        },
    ],
    '_D3DKMDT_2DREGION': [
        0x8,
        {
            'cy': [4, ['unsigned long']],
            'cx': [0, ['unsigned long']],
        },
    ],
    'tagMONITOR': [
        0x90,
        {
            'hDev': [80, ['pointer64', ['void']]],
            'head': [0, ['_HEAD']],
            'hDevReal': [88, ['pointer64', ['void']]],
            'rcWorkReal': [44, ['tagRECT']],
            'dwMONFlags': [24, ['unsigned long']],
            'Spare0': [72, ['short']],
            'rcMonitorReal': [28, ['tagRECT']],
            'pMonitorNext': [16, ['pointer64', ['tagMONITOR']]],
            'Flink': [128, ['pointer64', ['tagMONITOR']]],
            'Blink': [136, ['pointer64', ['tagMONITOR']]],
            'hrgnMonitorReal': [64, ['pointer64', ['HRGN__']]],
            'cWndStack': [74, ['short']],
            'DockTargets': [96, ['array', 7, ['array', 4, ['unsigned char']]]],
        },
    ],
    '__unnamed_123b': [
        0x8,
        {
            'IoResourceRequirementList': [
                0,
                ['pointer64', ['_IO_RESOURCE_REQUIREMENTS_LIST']],
            ],
        },
    ],
    '_D3DKMDT_VIDPN_PRESENT_PATH_COPYPROTECTION': [
        0x10C,
        {
            'APSTriggerBits': [4, ['unsigned long']],
            'CopyProtectionType': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_VPPMT_UNINITIALIZED',
                            1: 'D3DKMDT_VPPMT_NOPROTECTION',
                            2: 'D3DKMDT_VPPMT_MACROVISION_APSTRIGGER',
                            3: 'D3DKMDT_VPPMT_MACROVISION_FULLSUPPORT',
                            255: 'D3DKMDT_VPPMT_NOTSPECIFIED',
                        },
                    },
                ],
            ],
            'CopyProtectionSupport': [
                264,
                ['_D3DKMDT_VIDPN_PRESENT_PATH_COPYPROTECTION_SUPPORT'],
            ],
            'OEMCopyProtection': [8, ['array', 256, ['unsigned char']]],
        },
    ],
    'tagHID_TLC_INFO': [
        0x28,
        {
            'cExcludeRequest': [32, ['unsigned long']],
            'link': [0, ['_LIST_ENTRY']],
            'cExcludeOrphaned': [36, ['unsigned long']],
            'cUsagePageRequest': [28, ['unsigned long']],
            'usUsagePage': [16, ['unsigned short']],
            'cDevices': [20, ['unsigned long']],
            'cDirectRequest': [24, ['unsigned long']],
            'usUsage': [18, ['unsigned short']],
        },
    ],
    'HWND__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '_DMM_VIDPNPATHANDTARGETMODE_SERIALIZATION': [
        0x1B0,
        {
            'TargetMode': [360, ['_D3DKMDT_VIDPN_TARGET_MODE']],
            'PathInfo': [0, ['_D3DKMDT_VIDPN_PRESENT_PATH']],
        },
    ],
    'tagQ': [
        0x158,
        {
            'hwndDblClk': [112, ['pointer64', ['HWND__']]],
            'timeDblClk': [108, ['unsigned long']],
            'spwndFocus': [72, ['pointer64', ['tagWND']]],
            'ExtraInfo': [328, ['long long']],
            'cLockCount': [322, ['unsigned short']],
            'iCursorLevel': [312, ['long']],
            'ptiSysLock': [24, ['pointer64', ['tagTHREADINFO']]],
            'caret': [232, ['tagCARET']],
            'ptiMouse': [48, ['pointer64', ['tagTHREADINFO']]],
            'spwndActivePrev': [88, ['pointer64', ['tagWND']]],
            'ptMouseMove': [128, ['tagPOINT']],
            'msgDblClk': [100, ['unsigned long']],
            'msgJournal': [324, ['unsigned long']],
            'ptiKeyboard': [56, ['pointer64', ['tagTHREADINFO']]],
            'cThreads': [320, ['unsigned short']],
            'QF_flags': [316, ['unsigned long']],
            'mlInput': [0, ['tagMLIST']],
            'spwndActive': [80, ['pointer64', ['tagWND']]],
            'codeCapture': [96, ['unsigned long']],
            'idSysLock': [32, ['unsigned long long']],
            'spcurCurrent': [304, ['pointer64', ['tagCURSOR']]],
            'ulEtwReserved1': [336, ['unsigned long']],
            'ptDblClk': [120, ['tagPOINT']],
            'xbtnDblClk': [104, ['unsigned short']],
            'afKeyRecentDown': [136, ['array', 32, ['unsigned char']]],
            'afKeyState': [168, ['array', 64, ['unsigned char']]],
            'spwndCapture': [64, ['pointer64', ['tagWND']]],
            'idSysPeek': [40, ['unsigned long long']],
        },
    ],
    'tagUSERSTARTUPINFO': [
        0x1C,
        {
            'wShowWindow': [24, ['unsigned short']],
            'dwYSize': [16, ['unsigned long']],
            'dwXSize': [12, ['unsigned long']],
            'cbReserved2': [26, ['unsigned short']],
            'cb': [0, ['unsigned long']],
            'dwX': [4, ['unsigned long']],
            'dwY': [8, ['unsigned long']],
            'dwFlags': [20, ['unsigned long']],
        },
    ],
    '_DMM_COMMITVIDPNREQUESTSET_SERIALIZATION': [
        0x8,
        {
            'CommitVidPnRequestOffset': [4, ['array', 1, ['unsigned long']]],
            'NumCommitVidPnRequests': [0, ['unsigned char']],
        },
    ],
    '__unnamed_1805': [
        0xC,
        {
            'Start': [0, ['_LARGE_INTEGER']],
            'Length': [8, ['unsigned long']],
        },
    ],
    '_DMM_MONITORDESCRIPTORSET_SERIALIZATION': [
        0x90,
        {
            'NumDescriptors': [0, ['unsigned char']],
            'DescriptorSerialization': [
                4,
                ['array', 1, ['_DMM_MONITORDESCRIPTOR_SERIALIZATION']],
            ],
        },
    ],
    '_DMM_MONITORSOURCEMODESET_SERIALIZATION': [
        0x70,
        {
            'NumModes': [0, ['unsigned char']],
            'ModeSerialization': [
                8,
                ['array', 1, ['_DMM_MONITOR_SOURCE_MODE_SERIALIZATION']],
            ],
        },
    ],
    '_VK_FUNCTION_PARAM': [
        0x8,
        {
            'NLSFEProcIndex': [0, ['unsigned char']],
            'NLSFEProcParam': [4, ['unsigned long']],
        },
    ],
    '_D3DKMDT_COLOR_COEFF_DYNAMIC_RANGES': [
        0x10,
        {
            'SecondChannel': [4, ['unsigned long']],
            'FourthChannel': [12, ['unsigned long']],
            'ThirdChannel': [8, ['unsigned long']],
            'FirstChannel': [0, ['unsigned long']],
        },
    ],
    'tagMLIST': [
        0x18,
        {
            'cMsgs': [16, ['unsigned long']],
            'pqmsgRead': [0, ['pointer64', ['tagQMSG']]],
            'pqmsgWriteLast': [8, ['pointer64', ['tagQMSG']]],
        },
    ],
    '__unnamed_122d': [
        0x4,
        {
            'Type': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'BusRelations',
                            1: 'EjectionRelations',
                            2: 'PowerRelations',
                            3: 'RemovalRelations',
                            4: 'TargetDeviceRelation',
                            5: 'SingleBusRelations',
                            6: 'TransportRelations',
                        },
                    },
                ],
            ],
        },
    ],
    'tagMENUSTATE': [
        0x90,
        {
            'fDragAndDrop': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 11,
                        'start_bit': 10,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fInsideMenuLoop': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'cxAni': [116, ['long']],
            'pGlobalPopupMenu': [0, ['pointer64', ['tagPOPUPMENU']]],
            'uDraggingIndex': [88, ['unsigned long']],
            'uDraggingHitArea': [80, ['unsigned long long']],
            'fNotifyByPos': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 18,
                        'start_bit': 17,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fButtonDown': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ixAni': [108, ['long']],
            'fInCallHandleMenuMessages': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 10,
                        'start_bit': 9,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'mnFocus': [20, ['long']],
            'iyAni': [112, ['long']],
            'dwLockCount': [40, ['unsigned long']],
            'fAutoDismiss': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 12,
                        'start_bit': 11,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fIsSysMenu': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'dwAniStartTime': [104, ['unsigned long']],
            'pmnsPrev': [48, ['pointer64', ['tagMENUSTATE']]],
            'fInEndMenu': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 5,
                        'start_bit': 4,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'hbmAni': [128, ['pointer64', ['HBITMAP__']]],
            'fIgnoreButtonUp': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 14,
                        'start_bit': 13,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptButtonDown': [56, ['tagPOINT']],
            'hdcWndAni': [96, ['pointer64', ['HDC__']]],
            'fAboutToAutoDismiss': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 13,
                        'start_bit': 12,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fMenuStarted': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'uDraggingFlags': [92, ['unsigned long']],
            'fUnderline': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 6,
                        'start_bit': 5,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fInDoDragDrop': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 15,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptiMenuStateOwner': [32, ['pointer64', ['tagTHREADINFO']]],
            'uButtonDownIndex': [72, ['unsigned long']],
            'fModelessMenu': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 9,
                        'start_bit': 8,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'cyAni': [120, ['long']],
            'uButtonDownHitArea': [64, ['unsigned long long']],
            'fButtonAlwaysDown': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 7,
                        'start_bit': 6,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'iAniDropDir': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 24,
                        'start_bit': 19,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptMouseLast': [12, ['tagPOINT']],
            'hdcAni': [136, ['pointer64', ['HDC__']]],
            'vkButtonDown': [76, ['long']],
            'fSetCapture': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 19,
                        'start_bit': 18,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fDragging': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 8,
                        'start_bit': 7,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fActiveNoForeground': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 17,
                        'start_bit': 16,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fMouseOffMenu': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 15,
                        'start_bit': 14,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'cmdLast': [24, ['long']],
        },
    ],
    'tagMSGPPINFO': [
        0x4,
        {
            'dwIndexMsgPP': [0, ['unsigned long']],
        },
    ],
    'VWPLELEMENT': [
        0x10,
        {
            'DataOrTag': [0, ['unsigned long long']],
            'pwnd': [8, ['pointer64', ['tagWND']]],
        },
    ],
    '_WM_VALUES_STRINGS': [
        0x10,
        {
            'pszName': [0, ['pointer64', ['unsigned char']]],
            'fInternal': [8, ['unsigned char']],
            'fDefined': [9, ['unsigned char']],
        },
    ],
    'tagCLIP': [
        0x18,
        {
            'fmt': [0, ['unsigned long']],
            'fGlobalHandle': [16, ['long']],
            'hData': [8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_1229': [
        0x8,
        {
            'Srb': [0, ['pointer64', ['_SCSI_REQUEST_BLOCK']]],
        },
    ],
    '_HEAD': [
        0x10,
        {
            'h': [0, ['pointer64', ['void']]],
            'cLockObj': [8, ['unsigned long']],
        },
    ],
    '__unnamed_1221': [
        0x10,
        {
            'SecurityInformation': [0, ['unsigned long']],
            'SecurityDescriptor': [8, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_11e6': [
        0x10,
        {
            'AsynchronousParameters': [0, ['__unnamed_11e4']],
            'AllocationSize': [0, ['_LARGE_INTEGER']],
        },
    ],
    'tagQMSG': [
        0x68,
        {
            'FromPen': [
                84,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'pti': [88, ['pointer64', ['tagTHREADINFO']]],
            'ExtraInfo': [64, ['long long']],
            'Wow64Message': [
                84,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'pqmsgPrev': [8, ['pointer64', ['tagQMSG']]],
            'NoCoalesce': [
                84,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'Padding': [
                80,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 30,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptMouseReal': [72, ['tagPOINT']],
            'pqmsgNext': [0, ['pointer64', ['tagQMSG']]],
            'dwQEvent': [
                80,
                [
                    'BitField',
                    {
                        'end_bit': 30,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'MsgPPInfo': [96, ['tagMSGPPINFO']],
            'FromTouch': [
                84,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'msg': [16, ['tagMSG']],
        },
    ],
    'HWINSTA__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    'tagWin32PoolHead': [
        0x20,
        {
            'pPrev': [8, ['pointer64', ['tagWin32PoolHead']]],
            'pTrace': [24, ['pointer64', ['pointer64', ['void']]]],
            'pNext': [16, ['pointer64', ['tagWin32PoolHead']]],
            'size': [0, ['unsigned long long']],
        },
    ],
    'tagTOUCHINPUT': [
        0x30,
        {
            'hSource': [8, ['pointer64', ['void']]],
            'dwExtraInfo': [32, ['unsigned long long']],
            'cxContact': [40, ['unsigned long']],
            'dwMask': [24, ['unsigned long']],
            'y': [4, ['long']],
            'x': [0, ['long']],
            'dwID': [16, ['unsigned long']],
            'cyContact': [44, ['unsigned long']],
            'dwTime': [28, ['unsigned long']],
            'dwFlags': [20, ['unsigned long']],
        },
    ],
    '_CALLBACKWND': [
        0x18,
        {
            'hwnd': [0, ['pointer64', ['HWND__']]],
            'pActCtx': [16, ['pointer64', ['_ACTIVATION_CONTEXT']]],
            'pwnd': [8, ['pointer64', ['tagWND']]],
        },
    ],
    'HMONITOR__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '_D3DKMDT_GRAPHICS_RENDERING_FORMAT': [
        0x20,
        {
            'VisibleRegionSize': [8, ['_D3DKMDT_2DREGION']],
            'Stride': [16, ['unsigned long']],
            'PixelFormat': [
                20,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DDDIFMT_UNKNOWN',
                            20: 'D3DDDIFMT_R8G8B8',
                            21: 'D3DDDIFMT_A8R8G8B8',
                            22: 'D3DDDIFMT_X8R8G8B8',
                            23: 'D3DDDIFMT_R5G6B5',
                            24: 'D3DDDIFMT_X1R5G5B5',
                            25: 'D3DDDIFMT_A1R5G5B5',
                            26: 'D3DDDIFMT_A4R4G4B4',
                            27: 'D3DDDIFMT_R3G3B2',
                            28: 'D3DDDIFMT_A8',
                            29: 'D3DDDIFMT_A8R3G3B2',
                            30: 'D3DDDIFMT_X4R4G4B4',
                            31: 'D3DDDIFMT_A2B10G10R10',
                            32: 'D3DDDIFMT_A8B8G8R8',
                            33: 'D3DDDIFMT_X8B8G8R8',
                            34: 'D3DDDIFMT_G16R16',
                            35: 'D3DDDIFMT_A2R10G10B10',
                            36: 'D3DDDIFMT_A16B16G16R16',
                            40: 'D3DDDIFMT_A8P8',
                            41: 'D3DDDIFMT_P8',
                            50: 'D3DDDIFMT_L8',
                            51: 'D3DDDIFMT_A8L8',
                            52: 'D3DDDIFMT_A4L4',
                            60: 'D3DDDIFMT_V8U8',
                            61: 'D3DDDIFMT_L6V5U5',
                            62: 'D3DDDIFMT_X8L8V8U8',
                            63: 'D3DDDIFMT_Q8W8V8U8',
                            64: 'D3DDDIFMT_V16U16',
                            65: 'D3DDDIFMT_W11V11U10',
                            67: 'D3DDDIFMT_A2W10V10U10',
                            877942852: 'D3DDDIFMT_DXT4',
                            70: 'D3DDDIFMT_D16_LOCKABLE',
                            71: 'D3DDDIFMT_D32',
                            72: 'D3DDDIFMT_S1D15',
                            73: 'D3DDDIFMT_D15S1',
                            74: 'D3DDDIFMT_S8D24',
                            75: 'D3DDDIFMT_D24S8',
                            76: 'D3DDDIFMT_X8D24',
                            77: 'D3DDDIFMT_D24X8',
                            78: 'D3DDDIFMT_X4S4D24',
                            79: 'D3DDDIFMT_D24X4S4',
                            80: 'D3DDDIFMT_D16',
                            81: 'D3DDDIFMT_L16',
                            82: 'D3DDDIFMT_D32F_LOCKABLE',
                            83: 'D3DDDIFMT_D24FS8',
                            84: 'D3DDDIFMT_D32_LOCKABLE',
                            85: 'D3DDDIFMT_S8_LOCKABLE',
                            100: 'D3DDDIFMT_VERTEXDATA',
                            101: 'D3DDDIFMT_INDEX16',
                            102: 'D3DDDIFMT_INDEX32',
                            110: 'D3DDDIFMT_Q16W16V16U16',
                            111: 'D3DDDIFMT_R16F',
                            112: 'D3DDDIFMT_G16R16F',
                            113: 'D3DDDIFMT_A16B16G16R16F',
                            114: 'D3DDDIFMT_R32F',
                            115: 'D3DDDIFMT_G32R32F',
                            116: 'D3DDDIFMT_A32B32G32R32F',
                            117: 'D3DDDIFMT_CxV8U8',
                            118: 'D3DDDIFMT_A1',
                            119: 'D3DDDIFMT_A2B10G10R10_XR_BIAS',
                            150: 'D3DDDIFMT_PICTUREPARAMSDATA',
                            151: 'D3DDDIFMT_MACROBLOCKDATA',
                            152: 'D3DDDIFMT_RESIDUALDIFFERENCEDATA',
                            153: 'D3DDDIFMT_DEBLOCKINGDATA',
                            154: 'D3DDDIFMT_INVERSEQUANTIZATIONDATA',
                            155: 'D3DDDIFMT_SLICECONTROLDATA',
                            156: 'D3DDDIFMT_BITSTREAMDATA',
                            157: 'D3DDDIFMT_MOTIONVECTORBUFFER',
                            158: 'D3DDDIFMT_FILMGRAINBUFFER',
                            159: 'D3DDDIFMT_DXVA_RESERVED9',
                            160: 'D3DDDIFMT_DXVA_RESERVED10',
                            161: 'D3DDDIFMT_DXVA_RESERVED11',
                            162: 'D3DDDIFMT_DXVA_RESERVED12',
                            163: 'D3DDDIFMT_DXVA_RESERVED13',
                            164: 'D3DDDIFMT_DXVA_RESERVED14',
                            165: 'D3DDDIFMT_DXVA_RESERVED15',
                            166: 'D3DDDIFMT_DXVA_RESERVED16',
                            167: 'D3DDDIFMT_DXVA_RESERVED17',
                            168: 'D3DDDIFMT_DXVA_RESERVED18',
                            169: 'D3DDDIFMT_DXVA_RESERVED19',
                            170: 'D3DDDIFMT_DXVA_RESERVED20',
                            171: 'D3DDDIFMT_DXVA_RESERVED21',
                            172: 'D3DDDIFMT_DXVA_RESERVED22',
                            173: 'D3DDDIFMT_DXVA_RESERVED23',
                            174: 'D3DDDIFMT_DXVA_RESERVED24',
                            175: 'D3DDDIFMT_DXVA_RESERVED25',
                            176: 'D3DDDIFMT_DXVA_RESERVED26',
                            177: 'D3DDDIFMT_DXVA_RESERVED27',
                            178: 'D3DDDIFMT_DXVA_RESERVED28',
                            179: 'D3DDDIFMT_DXVA_RESERVED29',
                            180: 'D3DDDIFMT_DXVA_RESERVED30',
                            181: 'D3DDDIFMT_DXVACOMPBUFFER_MAX',
                            844388420: 'D3DDDIFMT_DXT2',
                            199: 'D3DDDIFMT_BINARYBUFFER',
                            861165636: 'D3DDDIFMT_DXT3',
                            827611204: 'D3DDDIFMT_DXT1',
                            827606349: 'D3DDDIFMT_MULTI2_ARGB8',
                            1195525970: 'D3DDDIFMT_R8G8_B8G8',
                            1498831189: 'D3DDDIFMT_UYVY',
                            844715353: 'D3DDDIFMT_YUY2',
                            894720068: 'D3DDDIFMT_DXT5',
                            1111970375: 'D3DDDIFMT_G8R8_G8B8',
                            2147483647: 'D3DDDIFMT_FORCE_UINT',
                        },
                    },
                ],
            ],
            'PixelValueAccessMode': [
                28,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_PVAM_UNINITIALIZED',
                            1: 'D3DKMDT_PVAM_DIRECT',
                            2: 'D3DKMDT_PVAM_PRESETPALETTE',
                            3: 'D3DKMDT_PVAM_MAXVALID',
                        },
                    },
                ],
            ],
            'PrimSurfSize': [0, ['_D3DKMDT_2DREGION']],
            'ColorBasis': [
                24,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_CB_UNINITIALIZED',
                            1: 'D3DKMDT_CB_INTENSITY',
                            2: 'D3DKMDT_CB_SRGB',
                            3: 'D3DKMDT_CB_SCRGB',
                            4: 'D3DKMDT_CB_YCBCR',
                            5: 'D3DKMDT_CB_MAXVALID',
                        },
                    },
                ],
            ],
        },
    ],
    '_VK_TO_WCHAR_TABLE': [
        0x10,
        {
            'pVkToWchars': [0, ['pointer64', ['_VK_TO_WCHARS1']]],
            'cbSize': [9, ['unsigned char']],
            'nModifications': [8, ['unsigned char']],
        },
    ],
    '__unnamed_1153': [
        0x10,
        {
            'Reserved': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 61,
                        'start_bit': 2,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'HeaderType': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Sequence': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 25,
                        'start_bit': 16,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Region': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 61,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Init': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Depth': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'NextEntry': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 25,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
        },
    ],
    '__unnamed_1158': [
        0x10,
        {
            'Reserved': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 2,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'HeaderType': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Sequence': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 16,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Init': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Depth': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'NextEntry': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 4,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
        },
    ],
    '_TL': [
        0x18,
        {
            'pfnFree': [16, ['pointer64', ['void']]],
            'pobj': [8, ['pointer64', ['void']]],
            'next': [0, ['pointer64', ['_TL']]],
        },
    ],
    'tagTHREADINFO': [
        0x3A8,
        {
            'pstrAppName': [416, ['pointer64', ['_UNICODE_STRING']]],
            'ForceLegacyResizeNCMetr': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 30,
                        'start_bit': 29,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'ptl': [336, ['pointer64', ['_TL']]],
            'timeLast': [448, ['long']],
            'DontJournalAttach': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 29,
                        'start_bit': 28,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ppi': [344, ['pointer64', ['tagPROCESSINFO']]],
            'SendMnuDblClk': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 19,
                        'start_bit': 18,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'DDENoSync': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 19,
                        'start_bit': 18,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'EditNoMouseHide': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 9,
                        'start_bit': 8,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'pDevHTInfo': [280, ['pointer64', ['void']]],
            'OpenGLEMF': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 27,
                        'start_bit': 26,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'dwCompatFlags': [516, ['unsigned long']],
            'hTouchInputCurrent': [888, ['pointer64', ['HTOUCHINPUT__']]],
            'psmsSent': [424, ['pointer64', ['tagSMS']]],
            'cVisWindows': [728, ['unsigned long']],
            'hPrevHidData': [880, ['pointer64', ['void']]],
            'fsHooks': [552, ['unsigned long']],
            'qwCompatFlags2': [520, ['unsigned long long']],
            'NoPaddedBorder': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 29,
                        'start_bit': 28,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'NoDrawPatRect': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'ForceTTGrapchis': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 15,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'GetDeviceCaps': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 21,
                        'start_bit': 20,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pgdiBrushAttr': [32, ['pointer64', ['void']]],
            'pq': [352, ['pointer64', ['tagQ']]],
            'ulWindowSystemRendering': [324, ['unsigned long']],
            'dwExpWinVer': [512, ['unsigned long']],
            'NoSoftCursOnMoveSize': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 31,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'psmsReceiveList': [440, ['pointer64', ['tagSMS']]],
            'sphkCurrent': [560, ['pointer64', ['tagHOOK']]],
            'No50ExStyles': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'IgnoreFaults': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 26,
                        'start_bit': 25,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pClientInfo': [400, ['pointer64', ['tagCLIENTINFO']]],
            'pdcoSrc': [312, ['pointer64', ['void']]],
            'pEventQueueServer': [600, ['pointer64', ['_KEVENT']]],
            'DealyHwndShakeChk': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 12,
                        'start_bit': 11,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'amdesk': [720, ['unsigned long']],
            'fsChangeBitsRemoved': [704, ['unsigned short']],
            'psmsCurrent': [432, ['pointer64', ['tagSMS']]],
            'NoBatching': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 10,
                        'start_bit': 9,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'StrictLLHook': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 22,
                        'start_bit': 21,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'pdcoRender': [304, ['pointer64', ['void']]],
            'NoShadow': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 23,
                        'start_bit': 22,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'EnumHelv': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 13,
                        'start_bit': 12,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fPack': [
                928,
                [
                    'BitField',
                    {
                        'end_bit': 28,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'CallTTDevice': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 5,
                        'start_bit': 4,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fsReserveKeys': [708, ['unsigned long']],
            'Winver31': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 22,
                        'start_bit': 21,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'DisableDBCSProp': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 30,
                        'start_bit': 29,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Win30AvgWidth': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 20,
                        'start_bit': 19,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptlW32': [16, ['pointer64', ['_TL']]],
            'AlwaysSendSyncPaint': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 7,
                        'start_bit': 6,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'IgnoreNoDiscard': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'NoTimeCbProtect': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 25,
                        'start_bit': 24,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'MsShellDlg': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 5,
                        'start_bit': 4,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'hEventQueueClient': [592, ['pointer64', ['void']]],
            'cPaintsReady': [480, ['long']],
            'SubtractClips': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 15,
                        'start_bit': 14,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'PtiLink': [608, ['_LIST_ENTRY']],
            'DpiAware': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 26,
                        'start_bit': 25,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'spklActive': [360, ['pointer64', ['tagKL']]],
            'bIncludeSprites': [321, ['unsigned char']],
            'mlPost': [680, ['tagMLIST']],
            'ptLastReal': [636, ['tagPOINT']],
            'fThreadCleanupFinished': [
                928,
                [
                    'BitField',
                    {
                        'end_bit': 29,
                        'start_bit': 28,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'MultipleBands': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 6,
                        'start_bit': 5,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Random31Ux': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 28,
                        'start_bit': 27,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'HackWinFlags': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 11,
                        'start_bit': 10,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pProxyPort': [64, ['pointer64', ['void']]],
            'KCOff': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'wParamHkCurrent': [576, ['unsigned long long']],
            'readyHead': [912, ['_LIST_ENTRY']],
            'UsePrintingEscape': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'NoInitFlagsOnFocus': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 18,
                        'start_bit': 17,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'ForceTextBand': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pEThread': [0, ['pointer64', ['_ETHREAD']]],
            'ptdb': [496, ['pointer64', ['tagTDB']]],
            'SpareCompatFlags2': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 33,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'cWindows': [724, ['unsigned long']],
            'cEnterCount': [672, ['long']],
            'fETWReserved': [
                928,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 29,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'dwCompatFlags2': [520, ['unsigned long']],
            'NoEMFSpooling': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 27,
                        'start_bit': 26,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pMenuState': [488, ['pointer64', ['tagMENUSTATE']]],
            'pRBRecursionCount': [96, ['unsigned long']],
            'SmoothScrolling': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 31,
                        'start_bit': 30,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'iVisRgnUniqueness': [328, ['unsigned long']],
            'RefCount': [8, ['unsigned long']],
            'Win31DevModeSize': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 24,
                        'start_bit': 23,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pwinsta': [496, ['pointer64', ['tagWINDOWSTATION']]],
            'pSBTrack': [584, ['pointer64', ['tagSBTRACK']]],
            'ActiveMenus': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 8,
                        'start_bit': 7,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'spwndDefaultIme': [648, ['pointer64', ['tagWND']]],
            'NoCustomPaperSize': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 13,
                        'start_bit': 12,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'wchInjected': [706, ['wchar']],
            'cTimersReady': [484, ['unsigned long']],
            'EditSetTextMunge': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 8,
                        'start_bit': 7,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pUMPDHeap': [48, ['pointer64', ['void']]],
            'fgfSwitchInProgressSetter': [
                928,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'iCursorLevel': [624, ['long']],
            'NoScrollBarCtxMenu': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 31,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ulClientDelta': [392, ['unsigned long long']],
            'pdcoAA': [296, ['pointer64', ['void']]],
            'cNestedStableVisRgn': [908, ['unsigned long']],
            'TryExceptCallWndProc': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 17,
                        'start_bit': 16,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'cti': [864, ['tagCLIENTTHREADINFO']],
            'NcCalcSizeOnMove': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 18,
                        'start_bit': 17,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'DisableFontAssoc': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 25,
                        'start_bit': 24,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pcti': [368, ['pointer64', ['tagCLIENTTHREADINFO']]],
            'MsgPPInfo': [904, ['tagMSGPPINFO']],
            'DDE': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 14,
                        'start_bit': 13,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'ulThreadFlags2': [928, ['unsigned long']],
            'tlSpriteState': [104, ['_TLSPRITESTATE']],
            'NoCharDeadKey': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 15,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'pqAttach': [528, ['pointer64', ['tagQ']]],
            'TTIgnoreRasterDupe': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 10,
                        'start_bit': 9,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'aphkStart': [736, ['array', 16, ['pointer64', ['tagHOOK']]]],
            'DefaultCharset': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 15,
                        'start_bit': 14,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'idLast': [456, ['unsigned long long']],
            'rpdesk': [376, ['pointer64', ['tagDESKTOP']]],
            'NoWindowArrangement': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 33,
                        'start_bit': 32,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'AnimationOff': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'No50ExStyleBits': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 12,
                        'start_bit': 11,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'TransparentBltMirror': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 28,
                        'start_bit': 27,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'DDENoAsyncReg': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 21,
                        'start_bit': 20,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'bEnableEngUpdateDeviceSurface': [320, ['unsigned char']],
            'pDeskInfo': [384, ['pointer64', ['tagDESKTOPINFO']]],
            'hdesk': [472, ['pointer64', ['HDESK__']]],
            'pNonRBRecursionCount': [100, ['unsigned long']],
            'MoreExtraWndWords': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 9,
                        'start_bit': 8,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'hklPrev': [664, ['pointer64', ['HKL__']]],
            'NoGhost': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 20,
                        'start_bit': 19,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'IgnoreTopMost': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pmsd': [544, ['pointer64', ['_MOVESIZEDATA']]],
            'NoHRGN1': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 17,
                        'start_bit': 16,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'exitCode': [464, ['long']],
            'NoDDETrackDying': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 6,
                        'start_bit': 5,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'ptLast': [628, ['tagPOINT']],
            'hGestureInfoCurrent': [896, ['pointer64', ['HGESTUREINFO__']]],
            'GdiTmpTgoList': [80, ['_LIST_ENTRY']],
            'pUMPDObjs': [40, ['pointer64', ['void']]],
            'FontSubs': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 11,
                        'start_bit': 10,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'GiveUpForegound': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 7,
                        'start_bit': 6,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'spDefaultImc': [656, ['pointer64', ['tagIMC']]],
            'pgdiDcattr': [24, ['pointer64', ['void']]],
            'TIF_flags': [408, ['unsigned long']],
            'apEvent': [712, ['pointer64', ['pointer64', ['_KEVENT']]]],
            'HardwareMixer': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 31,
                        'start_bit': 30,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'pUMPDObj': [56, ['pointer64', ['void']]],
            'pSpriteState': [272, ['pointer64', ['void']]],
            'EnumTTNotDevice': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 14,
                        'start_bit': 13,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'lParamHkCurrent': [568, ['long long']],
            'ulDevHTInfoUniqueness': [288, ['unsigned long']],
            'ptiSibling': [536, ['pointer64', ['tagTHREADINFO']]],
            'psiiList': [504, ['pointer64', ['tagSVR_INSTANCE_INFO']]],
            'ForceFusion': [
                520,
                [
                    'BitField',
                    {
                        'end_bit': 24,
                        'start_bit': 23,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'fSpecialInitialization': [
                928,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'IncreaseStack': [
                516,
                [
                    'BitField',
                    {
                        'end_bit': 23,
                        'start_bit': 22,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pClientID': [72, ['pointer64', ['void']]],
        },
    ],
    '_MOVESIZEDATA': [
        0xF0,
        {
            'fmsKbd': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fMoveFromMax': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 8,
                        'start_bit': 7,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fSnapMoving': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 12,
                        'start_bit': 11,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptRestore': [156, ['tagPOINT']],
            'fUsePreviewRect': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 27,
                        'start_bit': 26,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptStartHitWindowRelative': [208, ['tagPOINT']],
            'CurrentHitTarget': [
                192,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'ThresholdMarginTop',
                            1: 'ThresholdMarginLeft',
                            2: 'ThresholdMarginRight',
                            3: 'ThresholdMarginBottom',
                            4: 'ThresholdMarginMax',
                        },
                    },
                ],
            ],
            'fHasSoftwareCursor': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 28,
                        'start_bit': 27,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fCheckPtForcefullyRestored': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 19,
                        'start_bit': 18,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fSnapMovingTemporaryAllowed': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 24,
                        'start_bit': 23,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Unused': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 28,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fOffScreen': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 7,
                        'start_bit': 6,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fWindowWasSuperMaximized': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 13,
                        'start_bit': 12,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'StartCurrentHitTarget': [
                176,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'ThresholdMarginTop',
                            1: 'ThresholdMarginLeft',
                            2: 'ThresholdMarginRight',
                            3: 'ThresholdMarginBottom',
                            4: 'ThresholdMarginMax',
                        },
                    },
                ],
            ],
            'fSnapSizing': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 11,
                        'start_bit': 10,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fIsMoveSizeLoop': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 21,
                        'start_bit': 20,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'rcPreviewCursor': [56, ['tagRECT']],
            'dyMouse': [140, ['long']],
            'fVerticallyMaximizedRight': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 10,
                        'start_bit': 9,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fTrackCancelled': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'impx': [148, ['long']],
            'impy': [152, ['long']],
            'fLockWindowUpdate': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fStartVerticallyMaximizedLeft': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 14,
                        'start_bit': 13,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ptMinTrack': [88, ['tagPOINT']],
            'pMonitorCurrentHitTarget': [184, ['pointer64', ['tagMONITOR']]],
            'rcWindow': [104, ['tagRECT']],
            'pStartMonitorCurrentHitTarget': [
                168,
                ['pointer64', ['tagMONITOR']],
            ],
            'cmd': [144, ['long']],
            'ptMaxTrack': [96, ['tagPOINT']],
            'fForceSizing': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 20,
                        'start_bit': 19,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fThresholdSelector': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 18,
                        'start_bit': 15,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'MoveRectStyle': [
                196,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'MoveRectKeepPositionAtCursor',
                            1: 'MoveRectMidTopAtCursor',
                            2: 'MoveRectKeepAspectRatioAtCursor',
                            3: 'MoveRectSidewiseKeepPositionAtCursor',
                        },
                    },
                ],
            ],
            'fDragFullWindows': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 6,
                        'start_bit': 5,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fForeground': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 5,
                        'start_bit': 4,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ulCountDragOutOfLeftRightTarget': [228, ['unsigned long']],
            'ptLastTrack': [216, ['tagPOINT']],
            'frcNormalCheckPtValid': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 25,
                        'start_bit': 24,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fIsHitPtOffScreen': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 22,
                        'start_bit': 21,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fSnapSizingTemporaryAllowed': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 23,
                        'start_bit': 22,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fInitSize': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'dxMouse': [136, ['long']],
            'fStartVerticallyMaximizedRight': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 15,
                        'start_bit': 14,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ulCountDragOutOfTopTarget': [224, ['unsigned long']],
            'fVerticallyMaximizedLeft': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 9,
                        'start_bit': 8,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwnd': [0, ['pointer64', ['tagWND']]],
            'fHasPreviewRect': [
                164,
                [
                    'BitField',
                    {
                        'end_bit': 26,
                        'start_bit': 25,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'rcPreview': [40, ['tagRECT']],
            'rcDragCursor': [24, ['tagRECT']],
            'Flags': [164, ['unsigned long']],
            'ptHitWindowRelative': [200, ['tagPOINT']],
            'rcParent': [72, ['tagRECT']],
            'ulCountSizeOutOfTopBottomTarget': [232, ['unsigned long']],
            'rcNormalStartCheckPt': [120, ['tagRECT']],
            'rcDrag': [8, ['tagRECT']],
        },
    ],
    '_LARGE_UNICODE_STRING': [
        0x10,
        {
            'Buffer': [8, ['pointer64', ['unsigned short']]],
            'Length': [0, ['unsigned long']],
            'MaximumLength': [
                4,
                [
                    'BitField',
                    {
                        'end_bit': 31,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'bAnsi': [
                4,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 31,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
        },
    ],
    'VSC_LPWSTR': [
        0x10,
        {
            'vsc': [0, ['unsigned char']],
            'pwsz': [8, ['pointer64', ['unsigned short']]],
        },
    ],
    '_D3DKMDT_VIDPN_PRESENT_PATH_TRANSFORMATION': [
        0x10,
        {
            'Scaling': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_VPPS_UNINITIALIZED',
                            1: 'D3DKMDT_VPPS_IDENTITY',
                            2: 'D3DKMDT_VPPS_CENTERED',
                            3: 'D3DKMDT_VPPS_STRETCHED',
                            4: 'D3DKMDT_VPPS_ASPECTRATIOCENTEREDMAX',
                            5: 'D3DKMDT_VPPS_CUSTOM',
                            253: 'D3DKMDT_VPPS_RESERVED1',
                            254: 'D3DKMDT_VPPS_UNPINNED',
                            255: 'D3DKMDT_VPPS_NOTSPECIFIED',
                        },
                    },
                ],
            ],
            'RotationSupport': [
                12,
                ['_D3DKMDT_VIDPN_PRESENT_PATH_ROTATION_SUPPORT'],
            ],
            'Rotation': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_VPPR_UNINITIALIZED',
                            1: 'D3DKMDT_VPPR_IDENTITY',
                            2: 'D3DKMDT_VPPR_ROTATE90',
                            3: 'D3DKMDT_VPPR_ROTATE180',
                            4: 'D3DKMDT_VPPR_ROTATE270',
                            254: 'D3DKMDT_VPPR_UNPINNED',
                            255: 'D3DKMDT_VPPR_NOTSPECIFIED',
                        },
                    },
                ],
            ],
            'ScalingSupport': [
                4,
                ['_D3DKMDT_VIDPN_PRESENT_PATH_SCALING_SUPPORT'],
            ],
        },
    ],
    'tagUAHMENUPOPUPMETRICS': [
        0x14,
        {
            'rgcx': [0, ['array', 4, ['long']]],
            'fUpdateMaxWidths': [
                16,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
        },
    ],
    '__unnamed_115b': [
        0x10,
        {
            'NextEntry': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 4,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Depth': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Reserved': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 1,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'HeaderType': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
            'Sequence': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 64,
                        'start_bit': 16,
                        'native_type': 'unsigned long long',
                    },
                ],
            ],
        },
    ],
    '_THROBJHEAD': [
        0x18,
        {
            'h': [0, ['pointer64', ['void']]],
            'pti': [16, ['pointer64', ['tagTHREADINFO']]],
            'cLockObj': [8, ['unsigned long']],
        },
    ],
    '_DMM_COFUNCPATHSMODALITY_SERIALIZATION': [
        0x8,
        {
            'NumPathsFromSource': [0, ['unsigned char']],
            'PathAndTargetModeSetOffset': [4, ['array', 1, ['unsigned long']]],
        },
    ],
    'tagSBTRACK': [
        0x68,
        {
            'spwndSBNotify': [24, ['pointer64', ['tagWND']]],
            'hTimerSB': [64, ['unsigned long long']],
            'cmdSB': [56, ['unsigned long']],
            'xxxpfnSB': [48, ['pointer64', ['void']]],
            'fTrackVert': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'posNew': [84, ['long']],
            'posOld': [80, ['long']],
            'fCtlSB': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'rcTrack': [32, ['tagRECT']],
            'fTrackRecalc': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwndSB': [16, ['pointer64', ['tagWND']]],
            'spwndTrack': [8, ['pointer64', ['tagWND']]],
            'dpxThumb': [72, ['long']],
            'pxOld': [76, ['long']],
            'fHitOld': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'pSBCalc': [96, ['pointer64', ['tagSBCALC']]],
            'nBar': [88, ['long']],
        },
    ],
    '_DMA_ADAPTER': [
        0x10,
        {
            'Version': [0, ['unsigned short']],
            'DmaOperations': [8, ['pointer64', ['_DMA_OPERATIONS']]],
            'Size': [2, ['unsigned short']],
        },
    ],
    '__unnamed_1217': [
        0x10,
        {
            'FsInformationClass': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
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
                    },
                ],
            ],
            'Length': [0, ['unsigned long']],
        },
    ],
    'tagDPISERVERINFO': [
        0x28,
        {
            'hMsgFont': [16, ['pointer64', ['HFONT__']]],
            'hCaptionFont': [8, ['pointer64', ['HFONT__']]],
            'gclBorder': [0, ['long']],
            'cxMsgFontChar': [24, ['long']],
            'wMaxBtnSize': [32, ['unsigned long']],
            'cyMsgFontChar': [28, ['long']],
        },
    ],
    'HICON__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '_DMM_VIDPNTARGETMODESET_SERIALIZATION': [
        0x50,
        {
            'NumModes': [0, ['unsigned char']],
            'ModeSerialization': [
                8,
                ['array', 1, ['_D3DKMDT_VIDPN_TARGET_MODE']],
            ],
        },
    ],
    '__unnamed_16c1': [
        0x8,
        {
            'ActiveSize': [0, ['_D3DKMDT_2DREGION']],
            'MaxPixelRate': [0, ['unsigned long long']],
        },
    ],
    '__unnamed_127c': [
        0x48,
        {
            'Wcb': [0, ['_WAIT_CONTEXT_BLOCK']],
            'ListEntry': [0, ['_LIST_ENTRY']],
        },
    ],
    '_D3DMATRIX': [
        0x40,
        {
            '_33': [40, ['float']],
            '_42': [52, ['float']],
            '_43': [56, ['float']],
            '_44': [60, ['float']],
            '_34': [44, ['float']],
            '_14': [12, ['float']],
            '_13': [8, ['float']],
            '_12': [4, ['float']],
            '_11': [0, ['float']],
            '_41': [48, ['float']],
            '_31': [32, ['float']],
            '_24': [28, ['float']],
            '_32': [36, ['float']],
            '_22': [20, ['float']],
            '_23': [24, ['float']],
            '_21': [16, ['float']],
        },
    ],
    '__unnamed_18a1': [
        0x20,
        {
            'Text': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {0: 'D3DKMDT_TRF_UNINITIALIZED'},
                    },
                ],
            ],
            'Graphics': [0, ['_D3DKMDT_GRAPHICS_RENDERING_FORMAT']],
        },
    ],
    'HGESTUREINFO__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '_VK_TO_FUNCTION_TABLE': [
        0x84,
        {
            'NLSFEProcType': [1, ['unsigned char']],
            'NLSFEProcSwitch': [3, ['unsigned char']],
            'Vk': [0, ['unsigned char']],
            'NLSFEProcCurrent': [2, ['unsigned char']],
            'NLSFEProcAlt': [68, ['array', 8, ['_VK_FUNCTION_PARAM']]],
            'NLSFEProc': [4, ['array', 8, ['_VK_FUNCTION_PARAM']]],
        },
    ],
    #'__unnamed_16ca': [0x10, {
    #    'Attrib': [0, ['Enumeration', {'target': 'long', 'choices': {0: 'WCA_UNDEFINED', 1: 'WCA_NCRENDERING_ENABLED', 2: 'WCA_NCRENDERING_POLICY', 3: 'WCA_TRANSITIONS_FORCEDISABLED', 4: 'WCA_ALLOW_NCPAINT', 5: 'WCA_CAPTION_BUTTON_BOUNDS', 6: 'WCA_NONCLIENT_RTL_LAYOUT', 7: 'WCA_FORCE_ICONIC_REPRESENTATION', 8: 'WCA_FLIP3D_POLICY', 9: 'WCA_EXTENDED_FRAME_BOUNDS', 10: 'WCA_HAS_ICONIC_BITMAP', 11: 'WCA_THEME_ATTRIBUTES', 12: 'WCA_NCRENDERING_EXILED', 13: 'WCA_NCADORNMENTINFO', 14: 'WCA_EXCLUDED_FROM_LIVEPREVIEW', 15: 'WCA_VIDEO_OVERLAY_ACTIVE', 16: 'WCA_FORCE_ACTIVEWINDOW_APPEARANCE', 17: 'WCA_DISALLOW_PEEK', 18: 'WCA_LAST'}}]],
    #    'cbData': [8, ['unsigned long long']],
    #    }],
    '_DMM_VIDPNPATHANDTARGETMODESET_SERIALIZATION': [
        0x1B8,
        {
            'PathInfo': [0, ['_D3DKMDT_VIDPN_PRESENT_PATH']],
            'TargetModeSet': [360, ['_DMM_VIDPNTARGETMODESET_SERIALIZATION']],
        },
    ],
    'HDESK__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    'VK_TO_BIT': [
        0x2,
        {
            'Vk': [0, ['unsigned char']],
            'ModBits': [1, ['unsigned char']],
        },
    ],
    'tagIMEINFOEX': [
        0x160,
        {
            'fSysWow64Only': [
                348,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'wszImeFile': [188, ['array', 80, ['wchar']]],
            'fLoadFlag': [76, ['long']],
            'hkl': [0, ['pointer64', ['HKL__']]],
            'dwImeWinVersion': [84, ['unsigned long']],
            'dwProdVersion': [80, ['unsigned long']],
            'wszImeDescription': [88, ['array', 50, ['wchar']]],
            'fCUASLayer': [
                348,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'ImeInfo': [8, ['tagIMEINFO']],
            'wszUIClass': [36, ['array', 16, ['wchar']]],
            'fInitOpen': [72, ['long']],
            'fdwInitConvMode': [68, ['unsigned long']],
        },
    ],
    '__unnamed_12e0': [
        0x2C,
        {
            'InitialPrivilegeSet': [0, ['_INITIAL_PRIVILEGE_SET']],
            'PrivilegeSet': [0, ['_PRIVILEGE_SET']],
        },
    ],
    '_D3DKMDT_VIDPN_PRESENT_PATH_COPYPROTECTION_SUPPORT': [
        0x4,
        {
            'MacroVisionFull': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'MacroVisionApsTrigger': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'NoProtection': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Reserved': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
        },
    ],
    '_SCATTER_GATHER_ELEMENT': [
        0x18,
        {
            'Length': [8, ['unsigned long']],
            'Reserved': [16, ['unsigned long long']],
            'Address': [0, ['_LARGE_INTEGER']],
        },
    ],
    'tagWND': [
        0x128,
        {
            'bEraseBackground': [
                40,
                [
                    'BitField',
                    {'end_bit': 11, 'start_bit': 10, 'native_type': 'long'},
                ],
            ],
            'spwndOwner': [104, ['pointer64', ['tagWND']]],
            'bWS_EX_LAYERED': [
                48,
                [
                    'BitField',
                    {'end_bit': 20, 'start_bit': 19, 'native_type': 'long'},
                ],
            ],
            'bWS_CLIPCHILDREN': [
                52,
                [
                    'BitField',
                    {'end_bit': 26, 'start_bit': 25, 'native_type': 'long'},
                ],
            ],
            'bMaximizeButtonDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 14, 'start_bit': 13, 'native_type': 'long'},
                ],
            ],
            'cbwndExtra': [232, ['long']],
            'bMakeVisibleWhenUnghosted': [
                48,
                [
                    'BitField',
                    {'end_bit': 12, 'start_bit': 11, 'native_type': 'long'},
                ],
            ],
            'bUIStateActive': [
                48,
                [
                    'BitField',
                    {'end_bit': 27, 'start_bit': 26, 'native_type': 'long'},
                ],
            ],
            'hMod16': [64, ['unsigned short']],
            'bWS_TABSTOP': [
                52,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bUnused8': [
                52,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_NOPARENTNOTIFY': [
                48,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'bForceFullNCPaintClipRgn': [
                44,
                [
                    'BitField',
                    {'end_bit': 24, 'start_bit': 23, 'native_type': 'long'},
                ],
            ],
            'bDialogWindow': [
                40,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'lpfnWndProc': [144, ['pointer64', ['void']]],
            'bWS_EX_RTLREADING': [
                48,
                [
                    'BitField',
                    {'end_bit': 14, 'start_bit': 13, 'native_type': 'long'},
                ],
            ],
            'bMinimizeButtonDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 15, 'start_bit': 14, 'native_type': 'long'},
                ],
            ],
            'bUnused2': [
                48,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 15, 'native_type': 'long'},
                ],
            ],
            'bUnused3': [
                48,
                [
                    'BitField',
                    {'end_bit': 22, 'start_bit': 21, 'native_type': 'long'},
                ],
            ],
            'bUnused4': [
                48,
                [
                    'BitField',
                    {'end_bit': 25, 'start_bit': 24, 'native_type': 'long'},
                ],
            ],
            'bHasMeun': [
                40,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bUnused6': [
                52,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bUnused7': [
                52,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bWS_SIZEBOX': [
                52,
                [
                    'BitField',
                    {'end_bit': 19, 'start_bit': 18, 'native_type': 'long'},
                ],
            ],
            'style': [52, ['unsigned long']],
            'ppropList': [168, ['pointer64', ['tagPROPLIST']]],
            'hrgnNewFrame': [208, ['pointer64', ['HRGN__']]],
            'bHasOverlay': [
                288,
                [
                    'BitField',
                    {'end_bit': 10, 'start_bit': 9, 'native_type': 'long'},
                ],
            ],
            'bUnused9': [
                52,
                [
                    'BitField',
                    {'end_bit': 19, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bClipboardListener': [
                288,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bScrollBarLineDownBtnDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 20, 'start_bit': 19, 'native_type': 'long'},
                ],
            ],
            'bReserved3': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bRedirectedForPrint': [
                288,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_RIGHT': [
                48,
                [
                    'BitField',
                    {'end_bit': 13, 'start_bit': 12, 'native_type': 'long'},
                ],
            ],
            'bStartPaint': [
                44,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'bHasCreatestructName': [
                40,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 17, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_COMPOSITED': [
                48,
                [
                    'BitField',
                    {'end_bit': 26, 'start_bit': 25, 'native_type': 'long'},
                ],
            ],
            'bFullScreen': [
                44,
                [
                    'BitField',
                    {'end_bit': 7, 'start_bit': 6, 'native_type': 'long'},
                ],
            ],
            'spwndLastActive': [240, ['pointer64', ['tagWND']]],
            'hrgnUpdate': [160, ['pointer64', ['HRGN__']]],
            'head': [0, ['_THRDESKHEAD']],
            'bConsoleWindow': [
                288,
                [
                    'BitField',
                    {'end_bit': 11, 'start_bit': 10, 'native_type': 'long'},
                ],
            ],
            'bHiddenPopup': [
                40,
                [
                    'BitField',
                    {'end_bit': 15, 'start_bit': 14, 'native_type': 'long'},
                ],
            ],
            'hrgnClip': [200, ['pointer64', ['HRGN__']]],
            'bWS_EX_CONTROLPARENT': [
                48,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_TOPMOST': [
                48,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'bSendEraseBackground': [
                40,
                [
                    'BitField',
                    {'end_bit': 10, 'start_bit': 9, 'native_type': 'long'},
                ],
            ],
            'bScrollBarLineUpBtnDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bWin50Compat': [
                44,
                [
                    'BitField',
                    {'end_bit': 11, 'start_bit': 10, 'native_type': 'long'},
                ],
            ],
            'bRecievedQuerySuspendMsg': [
                40,
                [
                    'BitField',
                    {'end_bit': 25, 'start_bit': 24, 'native_type': 'long'},
                ],
            ],
            'bMaximizeMonitorRegion': [
                44,
                [
                    'BitField',
                    {'end_bit': 12, 'start_bit': 11, 'native_type': 'long'},
                ],
            ],
            'bLayeredLimbo': [
                288,
                [
                    'BitField',
                    {'end_bit': 6, 'start_bit': 5, 'native_type': 'long'},
                ],
            ],
            'bRedrawIfHung': [
                40,
                [
                    'BitField',
                    {'end_bit': 28, 'start_bit': 27, 'native_type': 'long'},
                ],
            ],
            'FullScreenMode': [
                44,
                [
                    'BitField',
                    {'end_bit': 27, 'start_bit': 24, 'native_type': 'long'},
                ],
            ],
            'bLayeredInvalidate': [
                288,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'bVerticallyMaximizedLeft': [
                288,
                [
                    'BitField',
                    {'end_bit': 8, 'start_bit': 7, 'native_type': 'long'},
                ],
            ],
            'bWS_POPUP': [
                52,
                [
                    'BitField',
                    {'end_bit': 32, 'start_bit': 31, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_CONTEXTHELP': [
                48,
                [
                    'BitField',
                    {'end_bit': 11, 'start_bit': 10, 'native_type': 'long'},
                ],
            ],
            'dwUserData': [256, ['unsigned long long']],
            'bDisabled': [
                52,
                [
                    'BitField',
                    {'end_bit': 28, 'start_bit': 27, 'native_type': 'long'},
                ],
            ],
            'bAnsiWindowProc': [
                40,
                [
                    'BitField',
                    {'end_bit': 20, 'start_bit': 19, 'native_type': 'long'},
                ],
            ],
            'bWin40Compat': [
                44,
                [
                    'BitField',
                    {'end_bit': 10, 'start_bit': 9, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_NOINHERITLAYOUT': [
                48,
                [
                    'BitField',
                    {'end_bit': 21, 'start_bit': 20, 'native_type': 'long'},
                ],
            ],
            'rcClient': [128, ['tagRECT']],
            'bAnsiCreator': [
                40,
                [
                    'BitField',
                    {'end_bit': 30, 'start_bit': 29, 'native_type': 'long'},
                ],
            ],
            'bAnyScrollButtonDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 21, 'start_bit': 20, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_LAYOUTRTL': [
                48,
                [
                    'BitField',
                    {'end_bit': 23, 'start_bit': 22, 'native_type': 'long'},
                ],
            ],
            'bUIStateKbdAccelHidden': [
                48,
                [
                    'BitField',
                    {'end_bit': 31, 'start_bit': 30, 'native_type': 'long'},
                ],
            ],
            'bSendSizeMoveMsgs': [
                40,
                [
                    'BitField',
                    {'end_bit': 5, 'start_bit': 4, 'native_type': 'long'},
                ],
            ],
            'spwndParent': [88, ['pointer64', ['tagWND']]],
            'bLinked': [
                288,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'bSendNCPaint': [
                40,
                [
                    'BitField',
                    {'end_bit': 12, 'start_bit': 11, 'native_type': 'long'},
                ],
            ],
            'bToggleTopmost': [
                40,
                [
                    'BitField',
                    {'end_bit': 27, 'start_bit': 26, 'native_type': 'long'},
                ],
            ],
            'bInternalPaint': [
                40,
                [
                    'BitField',
                    {'end_bit': 13, 'start_bit': 12, 'native_type': 'long'},
                ],
            ],
            'bDestroyed': [
                40,
                [
                    'BitField',
                    {'end_bit': 32, 'start_bit': 31, 'native_type': 'long'},
                ],
            ],
            'bHasClientEdge': [
                44,
                [
                    'BitField',
                    {'end_bit': 5, 'start_bit': 4, 'native_type': 'long'},
                ],
            ],
            'bServerSideWindowProc': [
                40,
                [
                    'BitField',
                    {'end_bit': 19, 'start_bit': 18, 'native_type': 'long'},
                ],
            ],
            'bCaptionTextTruncated': [
                44,
                [
                    'BitField',
                    {'end_bit': 28, 'start_bit': 27, 'native_type': 'long'},
                ],
            ],
            'rcWindow': [112, ['tagRECT']],
            'bEndPaintInvalidate': [
                44,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'bHasPalette': [
                40,
                [
                    'BitField',
                    {'end_bit': 22, 'start_bit': 21, 'native_type': 'long'},
                ],
            ],
            'bHasHorizontalScrollbar': [
                40,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'bUIStateFocusRectHidden': [
                48,
                [
                    'BitField',
                    {'end_bit': 32, 'start_bit': 31, 'native_type': 'long'},
                ],
            ],
            'bReserved1': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_COMPOSITEDCompositing': [
                48,
                [
                    'BitField',
                    {'end_bit': 29, 'start_bit': 28, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_MDICHILD': [
                48,
                [
                    'BitField',
                    {'end_bit': 7, 'start_bit': 6, 'native_type': 'long'},
                ],
            ],
            'bHasVerticalScrollbar': [
                40,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'bReserved2': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bWMCreateMsgProcessed': [
                44,
                [
                    'BitField',
                    {'end_bit': 32, 'start_bit': 31, 'native_type': 'long'},
                ],
            ],
            'bMinimized': [
                52,
                [
                    'BitField',
                    {'end_bit': 30, 'start_bit': 29, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_NOACTIVATE': [
                48,
                [
                    'BitField',
                    {'end_bit': 28, 'start_bit': 27, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_APPWINDOW': [
                48,
                [
                    'BitField',
                    {'end_bit': 19, 'start_bit': 18, 'native_type': 'long'},
                ],
            ],
            'pSBInfo': [176, ['pointer64', ['tagSBINFO']]],
            'bSmallIconFromWMQueryDrag': [
                44,
                [
                    'BitField',
                    {'end_bit': 30, 'start_bit': 29, 'native_type': 'long'},
                ],
            ],
            'bNoNCPaint': [
                40,
                [
                    'BitField',
                    {'end_bit': 9, 'start_bit': 8, 'native_type': 'long'},
                ],
            ],
            'bCloseButtonDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 13, 'start_bit': 12, 'native_type': 'long'},
                ],
            ],
            'bUnused1': [
                48,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'bHasSPB': [
                40,
                [
                    'BitField',
                    {'end_bit': 8, 'start_bit': 7, 'native_type': 'long'},
                ],
            ],
            'bWS_MINIMIZEBOX': [
                52,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 17, 'native_type': 'long'},
                ],
            ],
            'bMaximized': [
                52,
                [
                    'BitField',
                    {'end_bit': 25, 'start_bit': 24, 'native_type': 'long'},
                ],
            ],
            'bScrollBarVerticalTracking': [
                44,
                [
                    'BitField',
                    {'end_bit': 22, 'start_bit': 21, 'native_type': 'long'},
                ],
            ],
            'bWS_CHILD': [
                52,
                [
                    'BitField',
                    {'end_bit': 31, 'start_bit': 30, 'native_type': 'long'},
                ],
            ],
            'bReserved5': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_DLGMODALFRAME': [
                48,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_TRANSPARENT': [
                48,
                [
                    'BitField',
                    {'end_bit': 6, 'start_bit': 5, 'native_type': 'long'},
                ],
            ],
            'spmenu': [192, ['pointer64', ['tagMENU']]],
            'bWS_THICKFRAME': [
                52,
                [
                    'BitField',
                    {'end_bit': 19, 'start_bit': 18, 'native_type': 'long'},
                ],
            ],
            'bPaintNotProcessed': [
                40,
                [
                    'BitField',
                    {'end_bit': 23, 'start_bit': 22, 'native_type': 'long'},
                ],
            ],
            'bSyncPaintPending': [
                40,
                [
                    'BitField',
                    {'end_bit': 24, 'start_bit': 23, 'native_type': 'long'},
                ],
            ],
            'pcls': [152, ['pointer64', ['tagCLS']]],
            'bLayeredForDWM': [
                288,
                [
                    'BitField',
                    {'end_bit': 5, 'start_bit': 4, 'native_type': 'long'},
                ],
            ],
            'bMsgBox': [
                40,
                [
                    'BitField',
                    {'end_bit': 6, 'start_bit': 5, 'native_type': 'long'},
                ],
            ],
            'bShellHookRegistered': [
                44,
                [
                    'BitField',
                    {'end_bit': 31, 'start_bit': 30, 'native_type': 'long'},
                ],
            ],
            'spwndChild': [96, ['pointer64', ['tagWND']]],
            'bUnused5': [
                52,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bHelpButtonDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 15, 'native_type': 'long'},
                ],
            ],
            'bInDestroy': [
                44,
                [
                    'BitField',
                    {'end_bit': 8, 'start_bit': 7, 'native_type': 'long'},
                ],
            ],
            'state': [40, ['unsigned long']],
            'strName': [216, ['_LARGE_UNICODE_STRING']],
            'spwndPrev': [80, ['pointer64', ['tagWND']]],
            'bRedrawFrameIfHung': [
                40,
                [
                    'BitField',
                    {'end_bit': 29, 'start_bit': 28, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_LEFTSCROLLBAR': [
                48,
                [
                    'BitField',
                    {'end_bit': 15, 'start_bit': 14, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_TOOLWINDOW': [
                48,
                [
                    'BitField',
                    {'end_bit': 8, 'start_bit': 7, 'native_type': 'long'},
                ],
            ],
            'bWS_VSCROLL': [
                52,
                [
                    'BitField',
                    {'end_bit': 22, 'start_bit': 21, 'native_type': 'long'},
                ],
            ],
            'bMaximizesToMonitor': [
                40,
                [
                    'BitField',
                    {'end_bit': 31, 'start_bit': 30, 'native_type': 'long'},
                ],
            ],
            'bNoMinmaxAnimatedRects': [
                44,
                [
                    'BitField',
                    {'end_bit': 29, 'start_bit': 28, 'native_type': 'long'},
                ],
            ],
            'fnid': [66, ['unsigned short']],
            'ExStyle': [48, ['unsigned long']],
            'bRedirected': [
                48,
                [
                    'BitField',
                    {'end_bit': 30, 'start_bit': 29, 'native_type': 'long'},
                ],
            ],
            'bActiveFrame': [
                40,
                [
                    'BitField',
                    {'end_bit': 7, 'start_bit': 6, 'native_type': 'long'},
                ],
            ],
            'bReserved4': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_WINDOWEDGE': [
                48,
                [
                    'BitField',
                    {'end_bit': 9, 'start_bit': 8, 'native_type': 'long'},
                ],
            ],
            'bReserved6': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bReserved7': [
                52,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bWS_CLIPSIBLINGS': [
                52,
                [
                    'BitField',
                    {'end_bit': 27, 'start_bit': 26, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_ACCEPTFILE': [
                48,
                [
                    'BitField',
                    {'end_bit': 5, 'start_bit': 4, 'native_type': 'long'},
                ],
            ],
            'bWS_HSCROLL': [
                52,
                [
                    'BitField',
                    {'end_bit': 21, 'start_bit': 20, 'native_type': 'long'},
                ],
            ],
            'bUpdateDirty': [
                40,
                [
                    'BitField',
                    {'end_bit': 14, 'start_bit': 13, 'native_type': 'long'},
                ],
            ],
            'bBeingActivated': [
                40,
                [
                    'BitField',
                    {'end_bit': 21, 'start_bit': 20, 'native_type': 'long'},
                ],
            ],
            'state2': [44, ['unsigned long']],
            'spwndNext': [72, ['pointer64', ['tagWND']]],
            'bScrollBarPageDownBtnDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 19, 'start_bit': 18, 'native_type': 'long'},
                ],
            ],
            'bWS_BORDER': [
                52,
                [
                    'BitField',
                    {'end_bit': 24, 'start_bit': 23, 'native_type': 'long'},
                ],
            ],
            'bWMPaintSent': [
                44,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'bScrollBarPageUpBtnDown': [
                44,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 17, 'native_type': 'long'},
                ],
            ],
            'pTransform': [272, ['pointer64', ['_D3DMATRIX']]],
            'bWS_MAXIMIZEBOX': [
                52,
                [
                    'BitField',
                    {'end_bit': 17, 'start_bit': 16, 'native_type': 'long'},
                ],
            ],
            'bVisible': [
                52,
                [
                    'BitField',
                    {'end_bit': 29, 'start_bit': 28, 'native_type': 'long'},
                ],
            ],
            'bVerticallyMaximizedRight': [
                288,
                [
                    'BitField',
                    {'end_bit': 9, 'start_bit': 8, 'native_type': 'long'},
                ],
            ],
            'bWin31Compat': [
                44,
                [
                    'BitField',
                    {'end_bit': 9, 'start_bit': 8, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_STATICEDGE': [
                48,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 17, 'native_type': 'long'},
                ],
            ],
            'bForceMenuDraw': [
                40,
                [
                    'BitField',
                    {'end_bit': 16, 'start_bit': 15, 'native_type': 'long'},
                ],
            ],
            'bForceNCPaint': [
                44,
                [
                    'BitField',
                    {'end_bit': 23, 'start_bit': 22, 'native_type': 'long'},
                ],
            ],
            'ExStyle2': [288, ['unsigned long']],
            'bOldUI': [
                44,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'bWS_DLGFRAME': [
                52,
                [
                    'BitField',
                    {'end_bit': 23, 'start_bit': 22, 'native_type': 'long'},
                ],
            ],
            'bHIGHDPI_UNAWARE_Unused': [
                288,
                [
                    'BitField',
                    {'end_bit': 7, 'start_bit': 6, 'native_type': 'long'},
                ],
            ],
            'bWS_SYSMENU': [
                52,
                [
                    'BitField',
                    {'end_bit': 20, 'start_bit': 19, 'native_type': 'long'},
                ],
            ],
            'spwndClipboardListenerNext': [280, ['pointer64', ['tagWND']]],
            'hModule': [56, ['pointer64', ['void']]],
            'bWS_EX_NOPADDEDBORDER': [
                48,
                [
                    'BitField',
                    {'end_bit': 24, 'start_bit': 23, 'native_type': 'long'},
                ],
            ],
            'pActCtx': [264, ['pointer64', ['_ACTIVATION_CONTEXT']]],
            'bBottomMost': [
                44,
                [
                    'BitField',
                    {'end_bit': 6, 'start_bit': 5, 'native_type': 'long'},
                ],
            ],
            'spmenuSys': [184, ['pointer64', ['tagMENU']]],
            'bRecievedSuspendMsg': [
                40,
                [
                    'BitField',
                    {'end_bit': 26, 'start_bit': 25, 'native_type': 'long'},
                ],
            ],
            'bWS_EX_CLIENTEDGE': [
                48,
                [
                    'BitField',
                    {'end_bit': 10, 'start_bit': 9, 'native_type': 'long'},
                ],
            ],
            'bHasCaption': [
                40,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'hImc': [248, ['pointer64', ['HIMC__']]],
            'bChildNoActivate': [
                288,
                [
                    'BitField',
                    {'end_bit': 12, 'start_bit': 11, 'native_type': 'long'},
                ],
            ],
            'bWS_GROUP': [
                52,
                [
                    'BitField',
                    {'end_bit': 18, 'start_bit': 17, 'native_type': 'long'},
                ],
            ],
        },
    ],
    'tagUAHMENUITEMMETRICS': [
        0x20,
        {
            'rgsizeBar': [0, ['array', 2, ['tagSIZE']]],
            'rgsizePopup': [0, ['array', 4, ['tagSIZE']]],
        },
    ],
    '_DXGK_DIAG_CODE_POINT_PACKET': [
        0x40,
        {
            'Header': [0, ['_DXGK_DIAG_HEADER']],
            'Param3': [60, ['unsigned long']],
            'Param1': [52, ['unsigned long']],
            'CodePointType': [
                48,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'DXGK_DIAG_CODE_POINT_TYPE_NONE',
                            1: 'DXGK_DIAG_CODE_POINT_TYPE_RECOMMEND_FUNC_VIDPN',
                            2: 'DXGK_DIAG_CODE_POINT_TYPE_OS_RECOMMENDED_VIDPN',
                            3: 'DXGK_DIAG_CODE_POINT_TYPE_SDC_LOG_FAILURE',
                            4: 'DXGK_DIAG_CODE_POINT_TYPE_SDC_INVALIDATE_ERROR',
                            5: 'DXGK_DIAG_CODE_POINT_TYPE_CDS_LOG_FAILURE',
                            7: 'DXGK_DIAG_CODE_POINT_TYPE_CDS_FAILURE_DB',
                            8: 'DXGK_DIAG_CODE_POINT_TYPE_RETRIEVE_BTL',
                            9: 'DXGK_DIAG_CODE_POINT_TYPE_RETRIEVE_DB',
                            10: 'DXGK_DIAG_CODE_POINT_TYPE_QDC_LOG_FAILURE',
                            11: 'DXGK_DIAG_CODE_POINT_TYPE_POWER_ON_GDI',
                            12: 'DXGK_DIAG_CODE_POINT_TYPE_POWER_OFF_GDI',
                            13: 'DXGK_DIAG_CODE_POINT_TYPE_POWER_ON_MONITOR',
                            14: 'DXGK_DIAG_CODE_POINT_TYPE_POWER_OFF_MONITOR',
                            15: 'DXGK_DIAG_CODE_POINT_TYPE_POWER_DIM_MONITOR',
                            16: 'DXGK_DIAG_CODE_POINT_TYPE_POWER_UNDIM_MONITOR',
                            17: 'DXGK_DIAG_CODE_POINT_TYPE_BML_BACKTRACK',
                            18: 'DXGK_DIAG_CODE_POINT_TYPE_BML_CLOSEST_TARGET_MODE',
                            19: 'DXGK_DIAG_CODE_POINT_TYPE_BML_NO_EXACT_SOURCE_MODE',
                            20: 'DXGK_DIAG_CODE_POINT_TYPE_BML_NO_EXACT_TARGET_MODE',
                            21: 'DXGK_DIAG_CODE_POINT_TYPE_BML_SOURCE_MODE_NOT_PINNED',
                            22: 'DXGK_DIAG_CODE_POINT_TYPE_BML_TARGET_MODE_NOT_PINNED',
                            23: 'DXGK_DIAG_CODE_POINT_TYPE_BML_RESTARTED',
                            24: 'DXGK_DIAG_CODE_POINT_TYPE_TDR',
                            25: 'DXGK_DIAG_CODE_POINT_TYPE_ACPI_EVENT_NOTIFICATION',
                            26: 'DXGK_DIAG_CODE_POINT_TYPE_CREATEMDEV_USE_DEFAULT_MODE',
                            27: 'DXGK_DIAG_CODE_POINT_TYPE_CONNECTED_SET_LOG_FAILURE',
                            28: 'DXGK_DIAG_CODE_POINT_TYPE_INVALIDATE_DXGK_MODE_CACHE',
                            29: 'DXGK_DIAG_CODE_POINT_TYPE_REBUILD_DXGK_MODE_CACHE',
                            30: 'DXGK_DIAG_CODE_POINT_TYPE_CREATEFUNVIDPN_RELAX_REFRESH_MATCH',
                            31: 'DXGK_DIAG_CODE_POINT_TYPE_CREATEFUNVIDPN_CCDBML_FAIL_VISTABML_SUCCESSED',
                            32: 'DXGK_DIAG_CODE_POINT_TYPE_BML_BEST_SOURCE_MODE',
                            33: 'DXGK_DIAG_CODE_POINT_TYPE_BML_BEST_TARGET_MODE',
                            34: 'DXGK_DIAG_CODE_POINT_TYPE_ADD_DEVICE',
                            35: 'DXGK_DIAG_CODE_POINT_TYPE_START_ADAPTER',
                            36: 'DXGK_DIAG_CODE_POINT_TYPE_STOP_ADAPTER',
                            37: 'DXGK_DIAG_CODE_POINT_TYPE_CHILD_POLLING',
                            38: 'DXGK_DIAG_CODE_POINT_TYPE_CHILD_POLLING_TARGET',
                            39: 'DXGK_DIAG_CODE_POINT_TYPE_INDICATE_CHILD_STATUS',
                            40: 'DXGK_DIAG_CODE_POINT_TYPE_HANDLE_IRP',
                            41: 'DXGK_DIAG_CODE_POINT_TYPE_CHANGE_UNSUPPORTED_MONITOR_MODE_FLAG',
                            42: 'DXGK_DIAG_CODE_POINT_TYPE_ACPI_NOTIFY_CALLBACK',
                            43: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_EXCLUDE_EVICTALL_DISABLEGDI',
                            44: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_EXCLUDE_EVICTALL_ENABLEGDI',
                            45: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_EXCLUDE_MODESWITCH',
                            46: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_SYNC_MONITOR_EVENT',
                            47: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_PNP_NOTIFY_GDI',
                            48: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_PNP_ENABLE_VGA',
                            49: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_TDR_SWITCH_GDI',
                            50: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_CDD_CREATE_DEVICE_FAILED',
                            51: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_CDD_DEVICE_REMOVED',
                            52: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_CDD_DRVASSERTMODE_TRUE_FAILED',
                            53: 'DXGK_DIAG_CODE_POINT_TYPE_VIDEOPORTCALLOUT_CDD_RECREATE_DEVICE_FAILED',
                            54: 'DXGK_DIAG_CODE_POINT_TYPE_CDD_MAPSHADOWBUFFER_FAILED',
                            55: 'DXGK_DIAG_CODE_POINT_TYPE_COMMIT_VIDPN_LOG_FAILURE',
                            56: 'DXGK_DIAG_CODE_POINT_TYPE_DRIVER_RECOMMEND_LOG_FAILURE',
                            57: 'DXGK_DIAG_CODE_POINT_TYPE_SDC_ENFORCED_CLONE_PATH_INVALID_SOURCE_IDX',
                            58: 'DXGK_DIAG_CODE_POINT_TYPE_DRVPROBEANDCAPTURE_FAILED',
                            59: 'DXGK_DIAG_CODE_POINT_TYPE_DXGKCDDENABLE_OPTIMIZED_MODE_CHANGE',
                            60: 'DXGK_DIAG_CODE_POINT_TYPE_DXGKSETDISPLAYMODE_OPTIMIZED_MODE_CHANGE',
                            61: 'DXGK_DIAG_CODE_POINT_TYPE_MON_DEPART_GETRECENTTOP_FAIL',
                            62: 'DXGK_DIAG_CODE_POINT_TYPE_MON_ARRIVE_INC_ADD_FAIL',
                            63: 'DXGK_DIAG_CODE_POINT_TYPE_CCD_DATABASE_PERSIST',
                            64: 'DXGK_DIAG_CODE_POINT_TYPE_MAX',
                            -1: 'DXGK_DIAG_CODE_POINT_TYPE_FORCE_UINT32',
                        },
                    },
                ],
            ],
            'Param2': [56, ['unsigned long']],
        },
    ],
    'tagW32JOB': [
        0x40,
        {
            'restrictions': [24, ['unsigned long']],
            'Job': [8, ['pointer64', ['_EJOB']]],
            'ughCrt': [48, ['unsigned long']],
            'pgh': [56, ['pointer64', ['unsigned long long']]],
            'ppiTable': [40, ['pointer64', ['pointer64', ['tagPROCESSINFO']]]],
            'ughMax': [52, ['unsigned long']],
            'pAtomTable': [16, ['pointer64', ['void']]],
            'uProcessCount': [28, ['unsigned long']],
            'uMaxProcesses': [32, ['unsigned long']],
            'pNext': [0, ['pointer64', ['tagW32JOB']]],
        },
    ],
    'tagMBSTRING': [
        0x28,
        {
            'szName': [0, ['array', 15, ['wchar']]],
            'uID': [32, ['unsigned long']],
            'uStr': [36, ['unsigned long']],
        },
    ],
    '_D3DKMDT_VIDPN_TARGET_MODE': [
        0x48,
        {
            'VideoSignalInfo': [8, ['_D3DKMDT_VIDEO_SIGNAL_INFO']],
            'Id': [0, ['unsigned long']],
            'Preference': [
                64,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MP_UNINITIALIZED',
                            1: 'D3DKMDT_MP_PREFERRED',
                            2: 'D3DKMDT_MP_MAXVALID',
                        },
                    },
                ],
            ],
        },
    ],
    '__unnamed_124f': [
        0x4,
        {
            'PowerState': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'PowerSystemUnspecified',
                            1: 'PowerSystemWorking',
                            2: 'PowerSystemSleeping1',
                            3: 'PowerSystemSleeping2',
                            4: 'PowerSystemSleeping3',
                            5: 'PowerSystemHibernate',
                            6: 'PowerSystemShutdown',
                            7: 'PowerSystemMaximum',
                        },
                    },
                ],
            ],
        },
    ],
    '__unnamed_124b': [
        0x10,
        {
            'Type': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'DeviceUsageTypeUndefined',
                            1: 'DeviceUsageTypePaging',
                            2: 'DeviceUsageTypeHibernation',
                            3: 'DeviceUsageTypeDumpFile',
                        },
                    },
                ],
            ],
            'Reserved': [1, ['array', 3, ['unsigned char']]],
            'InPath': [0, ['unsigned char']],
        },
    ],
    'tagDESKTOP': [
        0xE0,
        {
            'spmenuVScroll': [80, ['pointer64', ['tagMENU']]],
            'dwMouseHoverTime': [212, ['unsigned long']],
            'rpwinstaParent': [32, ['pointer64', ['tagWINDOWSTATION']]],
            'spmenuDialogSys': [64, ['pointer64', ['tagMENU']]],
            'spwndForeground': [88, ['pointer64', ['tagWND']]],
            'spmenuHScroll': [72, ['pointer64', ['tagMENU']]],
            'spwndTooltip': [112, ['pointer64', ['tagWND']]],
            'dwSessionId': [0, ['unsigned long']],
            'pDeskInfo': [8, ['pointer64', ['tagDESKTOPINFO']]],
            'spwndMessage': [104, ['pointer64', ['tagWND']]],
            'cciConsole': [144, ['_CONSOLE_CARET_INFO']],
            'PtiList': [168, ['_LIST_ENTRY']],
            'spwndTray': [96, ['pointer64', ['tagWND']]],
            'rpdeskNext': [24, ['pointer64', ['tagDESKTOP']]],
            'dwDTFlags': [40, ['unsigned long']],
            'pMagInputTransform': [
                216,
                ['pointer64', ['_MAGNIFICATION_INPUT_TRANSFORM']],
            ],
            'spwndTrack': [184, ['pointer64', ['tagWND']]],
            'htEx': [192, ['long']],
            'ulHeapSize': [136, ['unsigned long']],
            'pheapDesktop': [128, ['pointer64', ['tagWIN32HEAP']]],
            'hsectionDesktop': [120, ['pointer64', ['void']]],
            'rcMouseHover': [196, ['tagRECT']],
            'dwDesktopId': [48, ['unsigned long long']],
            'spmenuSys': [56, ['pointer64', ['tagMENU']]],
            'pDispInfo': [16, ['pointer64', ['tagDISPLAYINFO']]],
        },
    ],
    'tagPOOLRECORD': [
        0x40,
        {
            'ExtraData': [0, ['pointer64', ['void']]],
            'trace': [16, ['array', 6, ['pointer64', ['void']]]],
            'size': [8, ['unsigned long long']],
        },
    ],
    'tagSPB': [
        0x40,
        {
            'hbm': [16, ['pointer64', ['HBITMAP__']]],
            'hrgn': [40, ['pointer64', ['HRGN__']]],
            'ulSaveId': [56, ['unsigned long long']],
            'flags': [48, ['unsigned long']],
            'rc': [24, ['tagRECT']],
            'pspbNext': [0, ['pointer64', ['tagSPB']]],
            'spwnd': [8, ['pointer64', ['tagWND']]],
        },
    ],
    '_DMM_COMMITVIDPNREQUEST_DIAGINFO': [
        0xC,
        {
            'CleanupAfterFailedCommitVidPn': [
                4,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned char',
                    },
                ],
            ],
            'ModeChangeRequestId': [8, ['unsigned long']],
            'ReclaimClonedTarget': [
                4,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned char',
                    },
                ],
            ],
            'ForceAllActiveVidPnModeListInvalidation': [
                4,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned char',
                    },
                ],
            ],
        },
    ],
    'HFONT__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    'tagTEXTMETRICW': [
        0x3C,
        {
            'tmCharSet': [56, ['unsigned char']],
            'tmDigitizedAspectY': [40, ['long']],
            'tmStruckOut': [54, ['unsigned char']],
            'tmItalic': [52, ['unsigned char']],
            'tmDigitizedAspectX': [36, ['long']],
            'tmWeight': [28, ['long']],
            'tmFirstChar': [44, ['wchar']],
            'tmOverhang': [32, ['long']],
            'tmDescent': [8, ['long']],
            'tmPitchAndFamily': [55, ['unsigned char']],
            'tmDefaultChar': [48, ['wchar']],
            'tmLastChar': [46, ['wchar']],
            'tmBreakChar': [50, ['wchar']],
            'tmMaxCharWidth': [24, ['long']],
            'tmUnderlined': [53, ['unsigned char']],
            'tmInternalLeading': [12, ['long']],
            'tmAscent': [4, ['long']],
            'tmHeight': [0, ['long']],
            'tmAveCharWidth': [20, ['long']],
            'tmExternalLeading': [16, ['long']],
        },
    ],
    '_KLIST_ENTRY': [
        0x10,
        {
            'Flink': [0, ['pointer64', ['_KLIST_ENTRY']]],
            'Blink': [8, ['pointer64', ['_KLIST_ENTRY']]],
        },
    ],
    '__unnamed_1247': [
        0x10,
        {
            'DeviceTextType': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'DeviceTextDescription',
                            1: 'DeviceTextLocationInformation',
                        },
                    },
                ],
            ],
            'LocaleId': [8, ['unsigned long']],
        },
    ],
    'tagPROP': [
        0x10,
        {
            'fs': [10, ['unsigned short']],
            'hData': [0, ['pointer64', ['void']]],
            'atomKey': [8, ['unsigned short']],
        },
    ],
    '__unnamed_1243': [
        0x4,
        {
            'IdType': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'BusQueryDeviceID',
                            1: 'BusQueryHardwareIDs',
                            2: 'BusQueryCompatibleIDs',
                            3: 'BusQueryInstanceID',
                            4: 'BusQueryDeviceSerialNumber',
                            5: 'BusQueryContainerID',
                        },
                    },
                ],
            ],
        },
    ],
    '__unnamed_123d': [
        0x20,
        {
            'Buffer': [8, ['pointer64', ['void']]],
            'WhichSpace': [0, ['unsigned long']],
            'Length': [24, ['unsigned long']],
            'Offset': [16, ['unsigned long']],
        },
    ],
    'tagCLIENTTHREADINFO': [
        0x10,
        {
            'fsWakeMask': [10, ['unsigned short']],
            'CTIF_flags': [0, ['unsigned long']],
            'fsWakeBits': [6, ['unsigned short']],
            'fsWakeBitsJournal': [8, ['unsigned short']],
            'fsChangeBits': [4, ['unsigned short']],
            'tickLastMsgChecked': [12, ['unsigned long']],
        },
    ],
    'tagKbdNlsLayer': [
        0x20,
        {
            'OEMIdentifier': [0, ['unsigned short']],
            'NumOfVkToF': [4, ['unsigned long']],
            'pusMouseVKey': [24, ['pointer64', ['unsigned short']]],
            'NumOfMouseVKey': [16, ['long']],
            'pVkToF': [8, ['pointer64', ['_VK_TO_FUNCTION_TABLE']]],
            'LayoutInformation': [2, ['unsigned short']],
        },
    ],
    'HBITMAP__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '__unnamed_11ff': [
        0x20,
        {
            'ShareAccess': [18, ['unsigned short']],
            'EaLength': [24, ['unsigned long']],
            'SecurityContext': [0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [8, ['unsigned long']],
            'FileAttributes': [16, ['unsigned short']],
        },
    ],
    'tagPROCESS_HID_TABLE': [
        0x68,
        {
            'UsagePageLast': [96, ['unsigned short']],
            'fExclusiveMouseSink': [
                100,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'fRawKeyboardSink': [
                100,
                [
                    'BitField',
                    {'end_bit': 7, 'start_bit': 6, 'native_type': 'long'},
                ],
            ],
            'fAppKeys': [
                100,
                [
                    'BitField',
                    {'end_bit': 11, 'start_bit': 10, 'native_type': 'long'},
                ],
            ],
            'fCaptureMouse': [
                100,
                [
                    'BitField',
                    {'end_bit': 9, 'start_bit': 8, 'native_type': 'long'},
                ],
            ],
            'fNoLegacyMouse': [
                100,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'UsageLast': [98, ['unsigned short']],
            'fRawKeyboard': [
                100,
                [
                    'BitField',
                    {'end_bit': 5, 'start_bit': 4, 'native_type': 'long'},
                ],
            ],
            'fNoLegacyKeyboard': [
                100,
                [
                    'BitField',
                    {'end_bit': 6, 'start_bit': 5, 'native_type': 'long'},
                ],
            ],
            'nSinks': [80, ['long']],
            'fNoHotKeys': [
                100,
                [
                    'BitField',
                    {'end_bit': 10, 'start_bit': 9, 'native_type': 'long'},
                ],
            ],
            'spwndTargetMouse': [64, ['pointer64', ['tagWND']]],
            'spwndTargetKbd': [72, ['pointer64', ['tagWND']]],
            'UsagePageList': [32, ['_LIST_ENTRY']],
            'link': [0, ['_LIST_ENTRY']],
            'fExclusiveKeyboardSink': [
                100,
                [
                    'BitField',
                    {'end_bit': 8, 'start_bit': 7, 'native_type': 'long'},
                ],
            ],
            'pLastRequest': [88, ['pointer64', ['tagPROCESS_HID_REQUEST']]],
            'ExclusionList': [48, ['_LIST_ENTRY']],
            'fRawMouse': [
                100,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'fRawMouseSink': [
                100,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'InclusionList': [16, ['_LIST_ENTRY']],
        },
    ],
    '__unnamed_1809': [
        0x10,
        {
            'Affinity': [8, ['unsigned long long']],
            'Vector': [4, ['unsigned long']],
            'Group': [0, ['unsigned short']],
            'MessageCount': [2, ['unsigned short']],
        },
    ],
    '_KFLOATING_SAVE': [
        0x4,
        {
            'Dummy': [0, ['unsigned long']],
        },
    ],
    'tagRECT': [
        0x10,
        {
            'top': [4, ['long']],
            'right': [8, ['long']],
            'bottom': [12, ['long']],
            'left': [0, ['long']],
        },
    ],
    '__unnamed_1807': [
        0x10,
        {
            'Affinity': [8, ['unsigned long long']],
            'Vector': [4, ['unsigned long']],
            'Group': [2, ['unsigned short']],
            'Level': [0, ['unsigned short']],
        },
    ],
    'HBRUSH__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '_TLSPRITESTATE': [
        0xA8,
        {
            'flOriginalSurfFlags': [4, ['unsigned long']],
            'iSpriteType': [16, ['unsigned long']],
            'pfnSaveScreenBits': [144, ['pointer64', ['void']]],
            'bInsideDriverCall': [0, ['unsigned char']],
            'pfnStrokePath': [48, ['pointer64', ['void']]],
            'pfnTransparentBlt': [112, ['pointer64', ['void']]],
            'pfnPaint': [64, ['pointer64', ['void']]],
            'pfnFillPath': [56, ['pointer64', ['void']]],
            'pfnStretchBltROP': [152, ['pointer64', ['void']]],
            'iType': [24, ['unsigned long']],
            'pfnPlgBlt': [128, ['pointer64', ['void']]],
            'pfnCopyBits': [80, ['pointer64', ['void']]],
            'pState': [32, ['pointer64', ['void']]],
            'iOriginalType': [8, ['unsigned long']],
            'pfnTextOut': [96, ['pointer64', ['void']]],
            'pfnDrawStream': [160, ['pointer64', ['void']]],
            'pfnStrokeAndFillPath': [40, ['pointer64', ['void']]],
            'pfnLineTo': [104, ['pointer64', ['void']]],
            'pfnStretchBlt': [88, ['pointer64', ['void']]],
            'pfnGradientFill': [136, ['pointer64', ['void']]],
            'pfnAlphaBlend': [120, ['pointer64', ['void']]],
            'flags': [20, ['unsigned long']],
            'flSpriteSurfFlags': [12, ['unsigned long']],
            'pfnBitBlt': [72, ['pointer64', ['void']]],
        },
    ],
    'tagSMS': [
        0x70,
        {
            'wParam': [72, ['unsigned long long']],
            'lParam': [80, ['long long']],
            'lRet': [56, ['long long']],
            'psmsReceiveNext': [8, ['pointer64', ['tagSMS']]],
            'tSent': [64, ['unsigned long']],
            'psmsNext': [0, ['pointer64', ['tagSMS']]],
            'ptiCallBackSender': [48, ['pointer64', ['tagTHREADINFO']]],
            'ptiReceiver': [24, ['pointer64', ['tagTHREADINFO']]],
            'lpResultCallBack': [32, ['pointer64', ['void']]],
            'message': [88, ['unsigned long']],
            'dwData': [40, ['unsigned long long']],
            'ptiSender': [16, ['pointer64', ['tagTHREADINFO']]],
            'flags': [68, ['unsigned long']],
            'pvCapture': [104, ['pointer64', ['void']]],
            'spwnd': [96, ['pointer64', ['tagWND']]],
        },
    ],
    '_D3DKMDT_FREQUENCY_RANGE': [
        0x20,
        {
            'MinVSyncFreq': [0, ['_D3DDDI_RATIONAL']],
            'MaxVSyncFreq': [8, ['_D3DDDI_RATIONAL']],
            'MaxHSyncFreq': [24, ['_D3DDDI_RATIONAL']],
            'MinHSyncFreq': [16, ['_D3DDDI_RATIONAL']],
        },
    ],
    '__unnamed_11f8': [
        0x58,
        {
            'Apc': [0, ['_KAPC']],
            'CompletionKey': [0, ['pointer64', ['void']]],
            'Overlay': [0, ['__unnamed_11f5']],
        },
    ],
    '__unnamed_18bf': [
        0x4,
        {
            'BaseMiddle': [0, ['unsigned char']],
            'BaseHigh': [3, ['unsigned char']],
            'Flags1': [1, ['unsigned char']],
            'Flags2': [2, ['unsigned char']],
        },
    ],
    '__unnamed_11f5': [
        0x50,
        {
            'AuxiliaryBuffer': [40, ['pointer64', ['unsigned char']]],
            'Thread': [32, ['pointer64', ['_ETHREAD']]],
            'OriginalFileObject': [72, ['pointer64', ['_FILE_OBJECT']]],
            'DeviceQueueEntry': [0, ['_KDEVICE_QUEUE_ENTRY']],
            'PacketType': [64, ['unsigned long']],
            'CurrentStackLocation': [
                64,
                ['pointer64', ['_IO_STACK_LOCATION']],
            ],
            'ListEntry': [48, ['_LIST_ENTRY']],
            'DriverContext': [0, ['array', 4, ['pointer64', ['void']]]],
        },
    ],
    'HRGN__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    'tagSIZE': [
        0x8,
        {
            'cy': [4, ['long']],
            'cx': [0, ['long']],
        },
    ],
    'tagDESKTOPVIEW': [
        0x18,
        {
            'ulClientDelta': [16, ['unsigned long long']],
            'pdesk': [8, ['pointer64', ['tagDESKTOP']]],
            'pdvNext': [0, ['pointer64', ['tagDESKTOPVIEW']]],
        },
    ],
    '__unnamed_180b': [
        0x10,
        {
            'Translated': [0, ['__unnamed_1807']],
            'Raw': [0, ['__unnamed_1809']],
        },
    ],
    '__unnamed_180d': [
        0xC,
        {
            'Reserved1': [8, ['unsigned long']],
            'Port': [4, ['unsigned long']],
            'Channel': [0, ['unsigned long']],
        },
    ],
    'MODIFIERS': [
        0x10,
        {
            'wMaxModBits': [8, ['unsigned short']],
            'pVkToBit': [0, ['pointer64', ['VK_TO_BIT']]],
            'ModNumber': [10, ['array', 0, ['unsigned char']]],
        },
    ],
    '__unnamed_120f': [
        0x10,
        {
            'CompletionFilter': [8, ['unsigned long']],
            'Length': [0, ['unsigned long']],
        },
    ],
    '__unnamed_120d': [
        0x20,
        {
            'Length': [0, ['unsigned long']],
            'FileIndex': [24, ['unsigned long']],
            'FileInformationClass': [
                16,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
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
                    },
                ],
            ],
            'FileName': [8, ['pointer64', ['_UNICODE_STRING']]],
        },
    ],
    '_DMM_VIDPNPATHSFROMSOURCE_SERIALIZATION': [
        0x1E0,
        {
            'PathAndTargetModeSerialization': [
                48,
                ['array', 1, ['_DMM_VIDPNPATHANDTARGETMODE_SERIALIZATION']],
            ],
            'NumPathsFromSource': [40, ['unsigned char']],
            'SourceMode': [0, ['_D3DKMDT_VIDPN_SOURCE_MODE']],
        },
    ],
    '_D3DDDI_GAMMA_RAMP_RGB256x3x16': [
        0x600,
        {
            'Blue': [1024, ['array', 256, ['unsigned short']]],
            'Green': [512, ['array', 256, ['unsigned short']]],
            'Red': [0, ['array', 256, ['unsigned short']]],
        },
    ],
    '_CALLPROCDATA': [
        0x40,
        {
            'head': [0, ['_PROCDESKHEAD']],
            'pfnClientPrevious': [48, ['unsigned long long']],
            'wType': [56, ['unsigned short']],
            'spcpdNext': [40, ['pointer64', ['_CALLPROCDATA']]],
        },
    ],
    '_D3DDDI_RATIONAL': [
        0x8,
        {
            'Denominator': [4, ['unsigned long']],
            'Numerator': [0, ['unsigned long']],
        },
    ],
    '_PFNCLIENT': [
        0xB8,
        {
            'pfnDispatchDefWindowProc': [160, ['pointer64', ['void']]],
            'pfnStaticWndProc': [112, ['pointer64', ['void']]],
            'pfnDispatchHook': [152, ['pointer64', ['void']]],
            'pfnDesktopWndProc': [24, ['pointer64', ['void']]],
            'pfnImeWndProc': [120, ['pointer64', ['void']]],
            'pfnScrollBarWndProc': [0, ['pointer64', ['void']]],
            'pfnEditWndProc': [88, ['pointer64', ['void']]],
            'pfnGhostWndProc': [128, ['pointer64', ['void']]],
            'pfnMessageWindowProc': [40, ['pointer64', ['void']]],
            'pfnSwitchWindowProc': [48, ['pointer64', ['void']]],
            'pfnComboListBoxProc': [72, ['pointer64', ['void']]],
            'pfnComboBoxWndProc': [64, ['pointer64', ['void']]],
            'pfnMDIClientWndProc': [104, ['pointer64', ['void']]],
            'pfnDialogWndProc': [80, ['pointer64', ['void']]],
            'pfnHkINLPCWPSTRUCT': [136, ['pointer64', ['void']]],
            'pfnTitleWndProc': [8, ['pointer64', ['void']]],
            'pfnHkINLPCWPRETSTRUCT': [144, ['pointer64', ['void']]],
            'pfnButtonWndProc': [56, ['pointer64', ['void']]],
            'pfnMenuWndProc': [16, ['pointer64', ['void']]],
            'pfnListBoxWndProc': [96, ['pointer64', ['void']]],
            'pfnDispatchMessage': [168, ['pointer64', ['void']]],
            'pfnDefWindowProc': [32, ['pointer64', ['void']]],
            'pfnMDIActivateDlgProc': [176, ['pointer64', ['void']]],
        },
    ],
    '_THRDESKHEAD': [
        0x28,
        {
            'h': [0, ['pointer64', ['void']]],
            'pSelf': [32, ['pointer64', ['unsigned char']]],
            'rpdesk': [24, ['pointer64', ['tagDESKTOP']]],
            'pti': [16, ['pointer64', ['tagTHREADINFO']]],
            'cLockObj': [8, ['unsigned long']],
        },
    ],
    '_D3DKMDT_MONITOR_SOURCE_MODE': [
        0x60,
        {
            'Origin': [
                84,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MCO_UNINITIALIZED',
                            1: 'D3DKMDT_MCO_DEFAULTMONITORPROFILE',
                            2: 'D3DKMDT_MCO_MONITORDESCRIPTOR',
                            3: 'D3DKMDT_MCO_MONITORDESCRIPTOR_REGISTRYOVERRIDE',
                            4: 'D3DKMDT_MCO_SPECIFICCAP_REGISTRYOVERRIDE',
                            5: 'D3DKMDT_MCO_MAXVALID',
                        },
                    },
                ],
            ],
            'VideoSignalInfo': [8, ['_D3DKMDT_VIDEO_SIGNAL_INFO']],
            'ColorCoeffDynamicRanges': [
                68,
                ['_D3DKMDT_COLOR_COEFF_DYNAMIC_RANGES'],
            ],
            'Preference': [
                88,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MP_UNINITIALIZED',
                            1: 'D3DKMDT_MP_PREFERRED',
                            2: 'D3DKMDT_MP_MAXVALID',
                        },
                    },
                ],
            ],
            'Id': [0, ['unsigned long']],
            'ColorBasis': [
                64,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_CB_UNINITIALIZED',
                            1: 'D3DKMDT_CB_INTENSITY',
                            2: 'D3DKMDT_CB_SRGB',
                            3: 'D3DKMDT_CB_SCRGB',
                            4: 'D3DKMDT_CB_YCBCR',
                            5: 'D3DKMDT_CB_MAXVALID',
                        },
                    },
                ],
            ],
        },
    ],
    'VWPL': [
        0x10,
        {
            'fTagged': [12, ['long']],
            'cElem': [4, ['unsigned long']],
            'cThreshhold': [8, ['unsigned long']],
            'aElement': [16, ['array', 0, ['VWPLELEMENT']]],
            'cPwnd': [0, ['unsigned long']],
        },
    ],
    'tagCURSOR': [
        0x88,
        {
            'rt': [58, ['unsigned short']],
            'head': [0, ['_PROCMARKHEAD']],
            'hbmUserAlpha': [112, ['pointer64', ['HBITMAP__']]],
            'cx': [124, ['unsigned long']],
            'xHotspot': [68, ['short']],
            'hbmColor': [80, ['pointer64', ['HBITMAP__']]],
            'pcurNext': [32, ['pointer64', ['tagCURSOR']]],
            'CURSORF_flags': [64, ['unsigned long']],
            'hbmMask': [72, ['pointer64', ['HBITMAP__']]],
            'bpp': [120, ['unsigned long']],
            'cy': [128, ['unsigned long']],
            'strName': [40, ['_UNICODE_STRING']],
            'rcBounds': [96, ['tagRECT']],
            'atomModName': [56, ['unsigned short']],
            'hbmAlpha': [88, ['pointer64', ['HBITMAP__']]],
            'yHotspot': [70, ['short']],
        },
    ],
    '__unnamed_1203': [
        0x20,
        {
            'ShareAccess': [18, ['unsigned short']],
            'Reserved': [16, ['unsigned short']],
            'SecurityContext': [0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [8, ['unsigned long']],
            'Parameters': [
                24,
                ['pointer64', ['_NAMED_PIPE_CREATE_PARAMETERS']],
            ],
        },
    ],
    '__unnamed_1207': [
        0x20,
        {
            'ShareAccess': [18, ['unsigned short']],
            'Reserved': [16, ['unsigned short']],
            'SecurityContext': [0, ['pointer64', ['_IO_SECURITY_CONTEXT']]],
            'Options': [8, ['unsigned long']],
            'Parameters': [24, ['pointer64', ['_MAILSLOT_CREATE_PARAMETERS']]],
        },
    ],
    'HKL__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '__unnamed_1209': [
        0x18,
        {
            'Length': [0, ['unsigned long']],
            'ByteOffset': [16, ['_LARGE_INTEGER']],
            'Key': [8, ['unsigned long']],
        },
    ],
    'tagDCE': [
        0x60,
        {
            'hrgnClipPublic': [48, ['pointer64', ['HRGN__']]],
            'pdceNext': [0, ['pointer64', ['tagDCE']]],
            'hrgnSavedVis': [56, ['pointer64', ['HRGN__']]],
            'pwndRedirect': [32, ['pointer64', ['tagWND']]],
            'pMonitor': [88, ['pointer64', ['tagMONITOR']]],
            'ppiOwner': [80, ['pointer64', ['tagPROCESSINFO']]],
            'pwndOrg': [16, ['pointer64', ['tagWND']]],
            'hrgnClip': [40, ['pointer64', ['HRGN__']]],
            'hdc': [8, ['pointer64', ['HDC__']]],
            'ptiOwner': [72, ['pointer64', ['tagTHREADINFO']]],
            'DCX_flags': [64, ['unsigned long']],
            'pwndClip': [24, ['pointer64', ['tagWND']]],
        },
    ],
    'tagPROCESS_HID_REQUEST': [
        0x28,
        {
            'link': [0, ['_LIST_ENTRY']],
            'fExclusiveOrphaned': [
                20,
                [
                    'BitField',
                    {'end_bit': 4, 'start_bit': 3, 'native_type': 'long'},
                ],
            ],
            'spwndTarget': [32, ['pointer64', ['tagWND']]],
            'fSinkable': [
                20,
                [
                    'BitField',
                    {'end_bit': 1, 'start_bit': 0, 'native_type': 'long'},
                ],
            ],
            'pTLCInfo': [24, ['pointer64', ['tagHID_TLC_INFO']]],
            'fDevNotify': [
                20,
                [
                    'BitField',
                    {'end_bit': 3, 'start_bit': 2, 'native_type': 'long'},
                ],
            ],
            'fExSinkable': [
                20,
                [
                    'BitField',
                    {'end_bit': 2, 'start_bit': 1, 'native_type': 'long'},
                ],
            ],
            'usUsage': [18, ['unsigned short']],
            'ptr': [24, ['pointer64', ['void']]],
            'pPORequest': [24, ['pointer64', ['tagHID_PAGEONLY_REQUEST']]],
            'usUsagePage': [16, ['unsigned short']],
        },
    ],
    'tagWOWTHREADINFO': [
        0x28,
        {
            'idParentProcess': [24, ['unsigned long']],
            'pwtiNext': [0, ['pointer64', ['tagWOWTHREADINFO']]],
            'idTask': [8, ['unsigned long']],
            'pIdleEvent': [32, ['pointer64', ['_KEVENT']]],
            'idWaitObject': [16, ['unsigned long long']],
        },
    ],
    '__unnamed_1962': [
        0x18,
        {
            'Dma': [0, ['__unnamed_1956']],
            'Generic': [0, ['__unnamed_1950']],
            'Memory': [0, ['__unnamed_1950']],
            'BusNumber': [0, ['__unnamed_1958']],
            'Memory48': [0, ['__unnamed_195e']],
            'Memory40': [0, ['__unnamed_195c']],
            'DevicePrivate': [0, ['__unnamed_180f']],
            'ConfigData': [0, ['__unnamed_195a']],
            'Memory64': [0, ['__unnamed_1960']],
            'Interrupt': [0, ['__unnamed_1954']],
            'Port': [0, ['__unnamed_1950']],
        },
    ],
    '__unnamed_1960': [
        0x18,
        {
            'Length64': [0, ['unsigned long']],
            'MaximumAddress': [16, ['_LARGE_INTEGER']],
            'MinimumAddress': [8, ['_LARGE_INTEGER']],
            'Alignment64': [4, ['unsigned long']],
        },
    ],
    'tagSBDATA': [
        0x10,
        {
            'posMax': [4, ['long']],
            'posMin': [0, ['long']],
            'page': [8, ['long']],
            'pos': [12, ['long']],
        },
    ],
    '__unnamed_1233': [
        0x20,
        {
            'Interface': [16, ['pointer64', ['_INTERFACE']]],
            'InterfaceSpecificData': [24, ['pointer64', ['void']]],
            'Version': [10, ['unsigned short']],
            'InterfaceType': [0, ['pointer64', ['_GUID']]],
            'Size': [8, ['unsigned short']],
        },
    ],
    '__unnamed_1237': [
        0x8,
        {
            'Capabilities': [0, ['pointer64', ['_DEVICE_CAPABILITIES']]],
        },
    ],
    'tagIMEINFO': [
        0x1C,
        {
            'fdwProperty': [4, ['unsigned long']],
            'fdwSelectCaps': [24, ['unsigned long']],
            'fdwUICaps': [16, ['unsigned long']],
            'dwPrivateDataSize': [0, ['unsigned long']],
            'fdwSCSCaps': [20, ['unsigned long']],
            'fdwSentenceCaps': [12, ['unsigned long']],
            'fdwConversionCaps': [8, ['unsigned long']],
        },
    ],
    '_D3DKMDT_VIDPN_SOURCE_MODE': [
        0x28,
        {
            'Type': [
                4,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_RMT_UNINITIALIZED',
                            1: 'D3DKMDT_RMT_GRAPHICS',
                            2: 'D3DKMDT_RMT_TEXT',
                        },
                    },
                ],
            ],
            'Id': [0, ['unsigned long']],
            'Format': [8, ['__unnamed_18a1']],
        },
    ],
    '_PROCMARKHEAD': [
        0x20,
        {
            'h': [0, ['pointer64', ['void']]],
            'ppi': [24, ['pointer64', ['tagPROCESSINFO']]],
            'hTaskWow': [16, ['unsigned long']],
            'cLockObj': [8, ['unsigned long']],
        },
    ],
    'tagKBDFILE': [
        0x78,
        {
            'head': [0, ['_HEAD']],
            'awchDllName': [56, ['array', 32, ['wchar']]],
            'pKbdTbl': [32, ['pointer64', ['tagKbdLayer']]],
            'pkfNext': [16, ['pointer64', ['tagKBDFILE']]],
            'pKbdNlsTbl': [48, ['pointer64', ['tagKbdNlsLayer']]],
            'hBase': [24, ['pointer64', ['void']]],
            'Size': [40, ['unsigned long']],
        },
    ],
    'tagCLIENTINFO': [
        0xD8,
        {
            'msgDbcsCB': [160, ['tagMSG']],
            'dwCompatFlags': [20, ['unsigned long']],
            'achDbcsCF': [154, ['array', 2, ['unsigned char']]],
            'dwTIFlags': [28, ['unsigned long']],
            'pClientThreadInfo': [96, ['pointer64', ['tagCLIENTTHREADINFO']]],
            'CodePage': [152, ['unsigned short']],
            'dwKeyCache': [112, ['unsigned long']],
            'dwHookCurrent': [88, ['unsigned long']],
            'afAsyncKeyStateRecentDown': [
                136,
                ['array', 8, ['unsigned char']],
            ],
            'dwCompatFlags2': [24, ['unsigned long']],
            'fsHooks': [56, ['unsigned long']],
            'ulClientDelta': [40, ['unsigned long long']],
            'pDeskInfo': [32, ['pointer64', ['tagDESKTOPINFO']]],
            'dwExpWinVer': [16, ['unsigned long']],
            'dwHookData': [104, ['unsigned long long']],
            'afAsyncKeyState': [128, ['array', 8, ['unsigned char']]],
            'CallbackWnd': [64, ['_CALLBACKWND']],
            'lpdwRegisteredClasses': [208, ['pointer64', ['unsigned long']]],
            'cInDDEMLCallback': [92, ['long']],
            'cSpins': [8, ['unsigned long long']],
            'hKL': [144, ['pointer64', ['HKL__']]],
            'dwAsyncKeyCache': [124, ['unsigned long']],
            'afKeyState': [116, ['array', 8, ['unsigned char']]],
            'CI_flags': [0, ['unsigned long long']],
            'phkCurrent': [48, ['pointer64', ['tagHOOK']]],
        },
    ],
    'tagCLS': [
        0xA0,
        {
            'spcur': [120, ['pointer64', ['tagCURSOR']]],
            'cbwndExtra': [100, ['long']],
            'pclsClone': [72, ['pointer64', ['tagCLS']]],
            'lpszClientAnsiMenuName': [40, ['pointer64', ['unsigned char']]],
            'pclsBase': [64, ['pointer64', ['tagCLS']]],
            'atomNVClassName': [10, ['unsigned short']],
            'style': [84, ['unsigned long']],
            'pclsNext': [0, ['pointer64', ['tagCLS']]],
            'CSF_flags': [34, ['unsigned short']],
            'lpfnWndProc': [88, ['pointer64', ['void']]],
            'lpszAnsiClassName': [144, ['pointer64', ['unsigned char']]],
            'spcpdFirst': [56, ['pointer64', ['_CALLPROCDATA']]],
            'lpszClientUnicodeMenuName': [
                48,
                ['pointer64', ['unsigned short']],
            ],
            'cbclsExtra': [96, ['long']],
            'lpszMenuName': [136, ['pointer64', ['unsigned short']]],
            'spicnSm': [152, ['pointer64', ['tagCURSOR']]],
            'hTaskWow': [32, ['unsigned short']],
            'cWndReferenceCount': [80, ['long']],
            'hbrBackground': [128, ['pointer64', ['HBRUSH__']]],
            'spicn': [112, ['pointer64', ['tagCURSOR']]],
            'fnid': [12, ['unsigned short']],
            'pdce': [24, ['pointer64', ['tagDCE']]],
            'hModule': [104, ['pointer64', ['void']]],
            'rpdeskParent': [16, ['pointer64', ['tagDESKTOP']]],
            'atomClassName': [8, ['unsigned short']],
        },
    ],
    '_DMM_VIDPN_SERIALIZATION': [
        0xC,
        {
            'PathsFromSourceSerializationOffsets': [
                8,
                ['array', 1, ['unsigned long']],
            ],
            'NumActiveSources': [4, ['unsigned char']],
            'Size': [0, ['unsigned long']],
        },
    ],
    'tagHID_PAGEONLY_REQUEST': [
        0x18,
        {
            'usUsagePage': [16, ['unsigned short']],
            'link': [0, ['_LIST_ENTRY']],
            'cRefCount': [20, ['unsigned long']],
        },
    ],
    'tagWINDOWSTATION': [
        0x98,
        {
            'pClipBase': [88, ['pointer64', ['tagCLIP']]],
            'dwSessionId': [0, ['unsigned long']],
            'cNumClipFormats': [96, ['unsigned long']],
            'luidUser': [136, ['_LUID']],
            'pGlobalAtomTable': [120, ['pointer64', ['void']]],
            'ptiClipLock': [48, ['pointer64', ['tagTHREADINFO']]],
            'dwWSF_Flags': [32, ['unsigned long']],
            'rpdeskList': [16, ['pointer64', ['tagDESKTOP']]],
            'spklList': [40, ['pointer64', ['tagKL']]],
            'spwndClipOpen': [64, ['pointer64', ['tagWND']]],
            'luidEndSession': [128, ['_LUID']],
            'pTerm': [24, ['pointer64', ['tagTERMINAL']]],
            'rpwinstaNext': [8, ['pointer64', ['tagWINDOWSTATION']]],
            'spwndClipboardListener': [112, ['pointer64', ['tagWND']]],
            'spwndClipViewer': [72, ['pointer64', ['tagWND']]],
            'iClipSequenceNumber': [104, ['unsigned long']],
            'ptiDrawingClipboard': [56, ['pointer64', ['tagTHREADINFO']]],
            'spwndClipOwner': [80, ['pointer64', ['tagWND']]],
            'psidUser': [144, ['pointer64', ['void']]],
            'iClipSerialNumber': [100, ['unsigned long']],
        },
    ],
    '__unnamed_11e4': [
        0x10,
        {
            'UserApcContext': [8, ['pointer64', ['void']]],
            'UserApcRoutine': [0, ['pointer64', ['void']]],
            'IssuingProcess': [0, ['pointer64', ['void']]],
        },
    ],
    'tagPROFILEVALUEINFO': [
        0x10,
        {
            'dwValue': [0, ['unsigned long']],
            'uSection': [4, ['unsigned long']],
            'pwszKeyName': [8, ['pointer64', ['wchar']]],
        },
    ],
    'tagOEMBITMAPINFO': [
        0x10,
        {
            'y': [4, ['long']],
            'x': [0, ['long']],
            'cy': [12, ['long']],
            'cx': [8, ['long']],
        },
    ],
    '_DMM_COMMITVIDPNREQUEST_SERIALIZATION': [
        0x1C,
        {
            'RequestDiagInfo': [4, ['_DMM_COMMITVIDPNREQUEST_DIAGINFO']],
            'AffectedVidPnSourceId': [0, ['unsigned long']],
            'VidPnSerialization': [16, ['_DMM_VIDPN_SERIALIZATION']],
        },
    ],
    '_WNDMSG': [
        0x10,
        {
            'abMsgs': [8, ['pointer64', ['unsigned char']]],
            'maxMsgs': [0, ['unsigned long']],
        },
    ],
    'tagTDB': [
        0x28,
        {
            'pti': [16, ['pointer64', ['tagTHREADINFO']]],
            'TDB_Flags': [34, ['unsigned short']],
            'hTaskWow': [32, ['unsigned short']],
            'pwti': [24, ['pointer64', ['tagWOWTHREADINFO']]],
            'nEvents': [8, ['long']],
            'nPriority': [12, ['long']],
            'ptdbNext': [0, ['pointer64', ['tagTDB']]],
        },
    ],
    '_LIGATURE1': [
        0x6,
        {
            'wch': [4, ['array', 1, ['wchar']]],
            'VirtualKey': [0, ['unsigned char']],
            'ModificationNumber': [2, ['unsigned short']],
        },
    ],
    '_D3DKMDT_VIDPN_PRESENT_PATH': [
        0x168,
        {
            'GammaRamp': [336, ['_D3DKMDT_GAMMA_RAMP']],
            'VidPnSourceId': [0, ['unsigned long']],
            'Content': [
                64,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_VPPC_UNINITIALIZED',
                            1: 'D3DKMDT_VPPC_GRAPHICS',
                            2: 'D3DKMDT_VPPC_VIDEO',
                            255: 'D3DKMDT_VPPC_NOTSPECIFIED',
                        },
                    },
                ],
            ],
            'VisibleFromActiveBROffset': [36, ['_D3DKMDT_2DREGION']],
            'VidPnTargetColorBasis': [
                44,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_CB_UNINITIALIZED',
                            1: 'D3DKMDT_CB_INTENSITY',
                            2: 'D3DKMDT_CB_SRGB',
                            3: 'D3DKMDT_CB_SCRGB',
                            4: 'D3DKMDT_CB_YCBCR',
                            5: 'D3DKMDT_CB_MAXVALID',
                        },
                    },
                ],
            ],
            'ContentTransformation': [
                12,
                ['_D3DKMDT_VIDPN_PRESENT_PATH_TRANSFORMATION'],
            ],
            'VidPnTargetId': [4, ['unsigned long']],
            'VisibleFromActiveTLOffset': [28, ['_D3DKMDT_2DREGION']],
            'CopyProtection': [
                68,
                ['_D3DKMDT_VIDPN_PRESENT_PATH_COPYPROTECTION'],
            ],
            'VidPnTargetColorCoeffDynamicRanges': [
                48,
                ['_D3DKMDT_COLOR_COEFF_DYNAMIC_RANGES'],
            ],
            'ImportanceOrdinal': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_VPPI_UNINITIALIZED',
                            1: 'D3DKMDT_VPPI_PRIMARY',
                            2: 'D3DKMDT_VPPI_SECONDARY',
                            3: 'D3DKMDT_VPPI_TERTIARY',
                            4: 'D3DKMDT_VPPI_QUATERNARY',
                            5: 'D3DKMDT_VPPI_QUINARY',
                            6: 'D3DKMDT_VPPI_SENARY',
                            7: 'D3DKMDT_VPPI_SEPTENARY',
                            8: 'D3DKMDT_VPPI_OCTONARY',
                            9: 'D3DKMDT_VPPI_NONARY',
                            10: 'D3DKMDT_VPPI_DENARY',
                            32: 'D3DKMDT_VPPI_MAX',
                            255: 'D3DKMDT_VPPI_NOTSPECIFIED',
                        },
                    },
                ],
            ],
        },
    ],
    '__unnamed_1253': [
        0x8,
        {
            'PowerSequence': [0, ['pointer64', ['_POWER_SEQUENCE']]],
        },
    ],
    '_PROCDESKHEAD': [
        0x28,
        {
            'h': [0, ['pointer64', ['void']]],
            'pSelf': [32, ['pointer64', ['unsigned char']]],
            'rpdesk': [24, ['pointer64', ['tagDESKTOP']]],
            'hTaskWow': [16, ['unsigned long']],
            'cLockObj': [8, ['unsigned long']],
        },
    ],
    '_D3DKMDT_VIDPN_PRESENT_PATH_ROTATION_SUPPORT': [
        0x4,
        {
            'Rotate270': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Rotate90': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Identity': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Rotate180': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
        },
    ],
    '__unnamed_1958': [
        0x10,
        {
            'MinBusNumber': [4, ['unsigned long']],
            'Length': [0, ['unsigned long']],
            'Reserved': [12, ['unsigned long']],
            'MaxBusNumber': [8, ['unsigned long']],
        },
    ],
    '_CONSOLE_CARET_INFO': [
        0x18,
        {
            'hwnd': [0, ['pointer64', ['HWND__']]],
            'rc': [8, ['tagRECT']],
        },
    ],
    'tagPROCESSINFO': [
        0x300,
        {
            'fHasMagContext': [
                736,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'hwinsta': [608, ['pointer64', ['HWINSTA__']]],
            'ptiList': [256, ['pointer64', ['tagTHREADINFO']]],
            'pHidTable': [744, ['pointer64', ['tagPROCESS_HID_TABLE']]],
            'W32PF_Flags': [12, ['unsigned long']],
            'UserHandleCount': [68, ['long']],
            'dwhmodLibLoadedMask': [340, ['unsigned long']],
            'GDIBrushAttrFreeList': [208, ['_LIST_ENTRY']],
            'hdeskStartup': [328, ['pointer64', ['HDESK__']]],
            'dwImeCompatFlags': [696, ['unsigned long']],
            'dwRegisteredClasses': [752, ['unsigned long']],
            'pBrushAttrList': [48, ['pointer64', ['void']]],
            'usi': [708, ['tagUSERSTARTUPINFO']],
            'InputIdleEvent': [16, ['pointer64', ['_KEVENT']]],
            'W32Pid': [56, ['unsigned long']],
            'bmHandleFlags': [648, ['_RTL_BITMAP']],
            'UserHandleCountPeak': [72, ['unsigned long']],
            'GDIEngUserMemAllocTable': [88, ['_RTL_AVL_TABLE']],
            'cSysExpunge': [336, ['unsigned long']],
            'pdvList': [632, ['pointer64', ['tagDESKTOPVIEW']]],
            'pwpi': [296, ['pointer64', ['tagWOWPROCESSINFO']]],
            'ppiNextRunning': [312, ['pointer64', ['tagPROCESSINFO']]],
            'Process': [0, ['pointer64', ['_EPROCESS']]],
            'pCursorCache': [664, ['pointer64', ['tagCURSOR']]],
            'pClientBase': [672, ['pointer64', ['void']]],
            'dwLpkEntryPoints': [680, ['unsigned long']],
            'GDIDcAttrFreeList': [192, ['_LIST_ENTRY']],
            'DxProcess': [248, ['pointer64', ['void']]],
            'NextStart': [32, ['pointer64', ['_W32PROCESS']]],
            'RefCount': [8, ['unsigned long']],
            'dwLayout': [740, ['unsigned long']],
            'pclsPublicList': [288, ['pointer64', ['tagCLS']]],
            'Unused': [
                736,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'GDIPushLock': [80, ['_EX_PUSH_LOCK']],
            'hMonitor': [624, ['pointer64', ['HMONITOR__']]],
            'ptiMainThread': [264, ['pointer64', ['tagTHREADINFO']]],
            'pvwplWndGCList': [760, ['pointer64', ['VWPL']]],
            'pW32Job': [688, ['pointer64', ['tagW32JOB']]],
            'luidSession': [700, ['_LUID']],
            'GDIHandleCount': [60, ['long']],
            'cThreads': [320, ['unsigned long']],
            'rpdeskStartup': [272, ['pointer64', ['tagDESKTOP']]],
            'hSecureGdiSharedHandleTable': [240, ['pointer64', ['void']]],
            'pclsPrivateList': [280, ['pointer64', ['tagCLS']]],
            'GDIHandleCountPeak': [64, ['unsigned long']],
            'StartCursorHideTime': [24, ['unsigned long']],
            'ppiNext': [304, ['pointer64', ['tagPROCESSINFO']]],
            'Flags': [736, ['unsigned long']],
            'dwHotkey': [620, ['unsigned long']],
            'amwinsta': [616, ['unsigned long']],
            'rpwinsta': [600, ['pointer64', ['tagWINDOWSTATION']]],
            'ahmodLibLoaded': [344, ['array', 32, ['pointer64', ['void']]]],
            'iClipSerialNumber': [640, ['unsigned long']],
            'GDIW32PIDLockedBitmaps': [224, ['_LIST_ENTRY']],
            'pDCAttrList': [40, ['pointer64', ['void']]],
        },
    ],
    '__unnamed_181b': [
        0x10,
        {
            'Dma': [0, ['__unnamed_180d']],
            'MessageInterrupt': [0, ['__unnamed_180b']],
            'Generic': [0, ['__unnamed_1805']],
            'Memory': [0, ['__unnamed_1805']],
            'BusNumber': [0, ['__unnamed_1811']],
            'DeviceSpecificData': [0, ['__unnamed_1813']],
            'Memory48': [0, ['__unnamed_1817']],
            'Memory40': [0, ['__unnamed_1815']],
            'DevicePrivate': [0, ['__unnamed_180f']],
            'Memory64': [0, ['__unnamed_1819']],
            'Interrupt': [0, ['__unnamed_1807']],
            'Port': [0, ['__unnamed_1805']],
        },
    ],
    '__unnamed_195e': [
        0x18,
        {
            'Length48': [0, ['unsigned long']],
            'Alignment48': [4, ['unsigned long']],
            'MinimumAddress': [8, ['_LARGE_INTEGER']],
            'MaximumAddress': [16, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_195c': [
        0x18,
        {
            'Length40': [0, ['unsigned long']],
            'Alignment40': [4, ['unsigned long']],
            'MinimumAddress': [8, ['_LARGE_INTEGER']],
            'MaximumAddress': [16, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_195a': [
        0xC,
        {
            'Priority': [0, ['unsigned long']],
            'Reserved1': [4, ['unsigned long']],
            'Reserved2': [8, ['unsigned long']],
        },
    ],
    '__unnamed_125f': [
        0x10,
        {
            'AllocatedResources': [0, ['pointer64', ['_CM_RESOURCE_LIST']]],
            'AllocatedResourcesTranslated': [
                8,
                ['pointer64', ['_CM_RESOURCE_LIST']],
            ],
        },
    ],
    '__unnamed_125b': [
        0x20,
        {
            'State': [16, ['_POWER_STATE']],
            'Type': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'SystemPowerState',
                            1: 'DevicePowerState',
                        },
                    },
                ],
            ],
            'SystemContext': [0, ['unsigned long']],
            'ShutdownType': [
                24,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'PowerActionNone',
                            1: 'PowerActionReserved',
                            2: 'PowerActionSleep',
                            3: 'PowerActionHibernate',
                            4: 'PowerActionShutdown',
                            5: 'PowerActionShutdownReset',
                            6: 'PowerActionShutdownOff',
                            7: 'PowerActionWarmEject',
                        },
                    },
                ],
            ],
            'SystemPowerStateContext': [0, ['_SYSTEM_POWER_STATE_CONTEXT']],
        },
    ],
    'tagKbdLayer': [
        0x68,
        {
            'pVkToWcharTable': [8, ['pointer64', ['_VK_TO_WCHAR_TABLE']]],
            'pusVSCtoVK': [48, ['pointer64', ['unsigned short']]],
            'fLocaleFlags': [80, ['unsigned long']],
            'pKeyNamesExt': [32, ['pointer64', ['VSC_LPWSTR']]],
            'dwSubType': [100, ['unsigned long']],
            'pDeadKey': [16, ['pointer64', ['DEADKEY']]],
            'pCharModifiers': [0, ['pointer64', ['MODIFIERS']]],
            'pKeyNamesDead': [
                40,
                ['pointer64', ['pointer64', ['unsigned short']]],
            ],
            'bMaxVSCtoVK': [56, ['unsigned char']],
            'pKeyNames': [24, ['pointer64', ['VSC_LPWSTR']]],
            'dwType': [96, ['unsigned long']],
            'pLigature': [88, ['pointer64', ['_LIGATURE1']]],
            'nLgMax': [84, ['unsigned char']],
            'pVSCtoVK_E1': [72, ['pointer64', ['_VSC_VK']]],
            'pVSCtoVK_E0': [64, ['pointer64', ['_VSC_VK']]],
            'cbLgEntry': [85, ['unsigned char']],
        },
    ],
    'HDC__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    'tagWin32AllocStats': [
        0x20,
        {
            'dwMaxAlloc': [16, ['unsigned long']],
            'pHead': [24, ['pointer64', ['tagWin32PoolHead']]],
            'dwMaxMem': [0, ['unsigned long long']],
            'dwCrtMem': [8, ['unsigned long long']],
            'dwCrtAlloc': [20, ['unsigned long']],
        },
    ],
    '__unnamed_18c5': [
        0x4,
        {
            'DefaultBig': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 23,
                        'start_bit': 22,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'BaseMiddle': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 8,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Granularity': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 24,
                        'start_bit': 23,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'LimitHigh': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 20,
                        'start_bit': 16,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'BaseHigh': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 32,
                        'start_bit': 24,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Dpl': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 15,
                        'start_bit': 13,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Type': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 13,
                        'start_bit': 8,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'System': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 21,
                        'start_bit': 20,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Present': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 15,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'LongMode': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 22,
                        'start_bit': 21,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
        },
    ],
    '__unnamed_1817': [
        0xC,
        {
            'Length48': [8, ['unsigned long']],
            'Start': [0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1815': [
        0xC,
        {
            'Length40': [8, ['unsigned long']],
            'Start': [0, ['_LARGE_INTEGER']],
        },
    ],
    '__unnamed_1813': [
        0xC,
        {
            'DataSize': [0, ['unsigned long']],
            'Reserved1': [4, ['unsigned long']],
            'Reserved2': [8, ['unsigned long']],
        },
    ],
    '_D3DKMDT_VIDPN_PRESENT_PATH_SCALING_SUPPORT': [
        0x4,
        {
            'Centered': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'AspectRatioCenteredMax': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Stretched': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Identity': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'Custom': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 5,
                        'start_bit': 4,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
        },
    ],
    '__unnamed_1811': [
        0xC,
        {
            'Start': [0, ['unsigned long']],
            'Length': [4, ['unsigned long']],
            'Reserved': [8, ['unsigned long']],
        },
    ],
    '__unnamed_1956': [
        0x8,
        {
            'MinimumChannel': [0, ['unsigned long']],
            'MaximumChannel': [4, ['unsigned long']],
        },
    ],
    '__unnamed_1954': [
        0x18,
        {
            'AffinityPolicy': [8, ['unsigned short']],
            'Group': [10, ['unsigned short']],
            'PriorityPolicy': [
                12,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'IrqPriorityUndefined',
                            1: 'IrqPriorityLow',
                            2: 'IrqPriorityNormal',
                            3: 'IrqPriorityHigh',
                        },
                    },
                ],
            ],
            'MinimumVector': [0, ['unsigned long']],
            'MaximumVector': [4, ['unsigned long']],
            'TargetedProcessors': [16, ['unsigned long long']],
        },
    ],
    'tagMSG': [
        0x30,
        {
            'wParam': [16, ['unsigned long long']],
            'lParam': [24, ['long long']],
            'pt': [36, ['tagPOINT']],
            'hwnd': [0, ['pointer64', ['HWND__']]],
            'time': [32, ['unsigned long']],
            'message': [8, ['unsigned long']],
        },
    ],
    '__unnamed_1819': [
        0xC,
        {
            'Start': [0, ['_LARGE_INTEGER']],
            'Length64': [8, ['unsigned long']],
        },
    ],
    '_DMM_VIDPNSET_SERIALIZATION': [
        0x8,
        {
            'VidPnOffset': [4, ['array', 1, ['unsigned long']]],
            'NumVidPns': [0, ['unsigned char']],
        },
    ],
    'tagWOWPROCESSINFO': [
        0x48,
        {
            'ptdbHead': [16, ['pointer64', ['tagTDB']]],
            'lpfnWowExitTask': [24, ['pointer64', ['void']]],
            'CSOwningThread': [56, ['pointer64', ['tagTHREADINFO']]],
            'ptiScheduled': [8, ['pointer64', ['tagTHREADINFO']]],
            'nSendLock': [48, ['unsigned long']],
            'nRecvLock': [52, ['unsigned long']],
            'CSLockCount': [64, ['long']],
            'hEventWowExecClient': [40, ['pointer64', ['void']]],
            'pwpiNext': [0, ['pointer64', ['tagWOWPROCESSINFO']]],
            'pEventWowExec': [32, ['pointer64', ['_KEVENT']]],
        },
    ],
    'tagMENU': [
        0x98,
        {
            'iItem': [44, ['long']],
            'head': [0, ['_PROCDESKHEAD']],
            'umpm': [132, ['tagUAHMENUPOPUPMETRICS']],
            'cItems': [52, ['unsigned long']],
            'pParentMenus': [88, ['pointer64', ['tagMENULIST']]],
            'fFlags': [40, ['unsigned long']],
            'cxMenu': [56, ['unsigned long']],
            'dwContextHelpId': [96, ['unsigned long']],
            'hbrBack': [112, ['pointer64', ['HBRUSH__']]],
            'cxTextAlign': [64, ['unsigned long']],
            'cAlloced': [48, ['unsigned long']],
            'spwndNotify': [72, ['pointer64', ['tagWND']]],
            'dwArrowsOn': [
                128,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'iMaxTop': [124, ['long']],
            'dwMenuData': [104, ['unsigned long long']],
            'cyMenu': [60, ['unsigned long']],
            'rgItems': [80, ['pointer64', ['tagITEM']]],
            'iTop': [120, ['long']],
            'cyMax': [100, ['unsigned long']],
        },
    ],
    '_D3DDDI_GAMMA_RAMP_DXGI_1': [
        0x3024,
        {
            'GammaCurve': [24, ['array', 1025, ['D3DDDI_DXGI_RGB']]],
            'Scale': [0, ['D3DDDI_DXGI_RGB']],
            'Offset': [12, ['D3DDDI_DXGI_RGB']],
        },
    ],
    'tagPOPUPMENU': [
        0x58,
        {
            'fUseMonitorRect': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 29,
                        'start_bit': 28,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fDroppedLeft': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 5,
                        'start_bit': 4,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fHierarchyDropped': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 6,
                        'start_bit': 5,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'posDropped': [84, ['unsigned long']],
            'spwndNextPopup': [24, ['pointer64', ['tagWND']]],
            'fIsMenuBar': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwndPrevPopup': [32, ['pointer64', ['tagWND']]],
            'fHasMenuBar': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwndActivePopup': [56, ['pointer64', ['tagWND']]],
            'fTrackMouseEvent': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 21,
                        'start_bit': 20,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fNoNotify': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 12,
                        'start_bit': 11,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'posSelectedItem': [80, ['unsigned long']],
            'fIsSysMenu': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 3,
                        'start_bit': 2,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fFlushDelayedFree': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 18,
                        'start_bit': 17,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ppmDelayedFree': [72, ['pointer64', ['tagPOPUPMENU']]],
            'fFreed': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 19,
                        'start_bit': 18,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fSynchronous': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 9,
                        'start_bit': 8,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fDropNextPopup': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 11,
                        'start_bit': 10,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fRightButton': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 7,
                        'start_bit': 6,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spmenuAlternate': [48, ['pointer64', ['tagMENU']]],
            'spmenu': [40, ['pointer64', ['tagMENU']]],
            'spwndPopupMenu': [16, ['pointer64', ['tagWND']]],
            'fDestroyed': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 16,
                        'start_bit': 15,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'iDropDir': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 28,
                        'start_bit': 23,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'ppopupmenuRoot': [64, ['pointer64', ['tagPOPUPMENU']]],
            'fFirstClick': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 10,
                        'start_bit': 9,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'spwndNotify': [8, ['pointer64', ['tagWND']]],
            'fRtoL': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 23,
                        'start_bit': 22,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fIsTrackPopup': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 4,
                        'start_bit': 3,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fSendUninit': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 22,
                        'start_bit': 21,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fShowTimer': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 14,
                        'start_bit': 13,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fInCancel': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 20,
                        'start_bit': 19,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fToggle': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 8,
                        'start_bit': 7,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fDelayedFree': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 17,
                        'start_bit': 16,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fHideTimer': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 15,
                        'start_bit': 14,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'fAboutToHide': [
                0,
                [
                    'BitField',
                    {
                        'end_bit': 13,
                        'start_bit': 12,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
        },
    ],
    '_DMM_MONITORDESCRIPTOR_SERIALIZATION': [
        0x8C,
        {
            'Origin': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MCO_UNINITIALIZED',
                            1: 'D3DKMDT_MCO_DEFAULTMONITORPROFILE',
                            2: 'D3DKMDT_MCO_MONITORDESCRIPTOR',
                            3: 'D3DKMDT_MCO_MONITORDESCRIPTOR_REGISTRYOVERRIDE',
                            4: 'D3DKMDT_MCO_SPECIFICCAP_REGISTRYOVERRIDE',
                            5: 'D3DKMDT_MCO_MAXVALID',
                        },
                    },
                ],
            ],
            'Data': [12, ['array', 128, ['unsigned char']]],
            'Type': [
                4,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MDT_UNINITIALIZED',
                            1: 'D3DKMDT_MDT_VESA_EDID_V1_BASEBLOCK',
                            2: 'D3DKMDT_MDT_VESA_EDID_V1_BLOCKMAP',
                            255: 'D3DKMDT_MDT_OTHER',
                        },
                    },
                ],
            ],
            'Id': [0, ['unsigned long']],
        },
    ],
    'HTOUCHINPUT__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    '_VK_VALUES_STRINGS': [
        0x10,
        {
            'fReserved': [8, ['unsigned char']],
            'pszMultiNames': [0, ['pointer64', ['unsigned char']]],
        },
    ],
    '_DMM_MONITOR_SOURCE_MODE_SERIALIZATION': [
        0x68,
        {
            'Info': [0, ['_D3DKMDT_MONITOR_SOURCE_MODE']],
            'TimingType': [
                96,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MTT_UNINITIALIZED',
                            1: 'D3DKMDT_MTT_ESTABLISHED',
                            2: 'D3DKMDT_MTT_STANDARD',
                            3: 'D3DKMDT_MTT_EXTRASTANDARD',
                            4: 'D3DKMDT_MTT_DETAILED',
                            5: 'D3DKMDT_MTT_DEFAULTMONITORPROFILE',
                            6: 'D3DKMDT_MTT_MAXVALID',
                        },
                    },
                ],
            ],
        },
    ],
    'tagSBCALC': [
        0x40,
        {
            'posMax': [4, ['long']],
            'pxThumbTop': [52, ['long']],
            'pxThumbBottom': [48, ['long']],
            'cpxThumb': [32, ['long']],
            'pxMin': [60, ['long']],
            'pxStart': [44, ['long']],
            'pxDownArrow': [40, ['long']],
            'pos': [12, ['long']],
            'cpx': [56, ['long']],
            'pxBottom': [20, ['long']],
            'pxTop': [16, ['long']],
            'pxLeft': [24, ['long']],
            'pxRight': [28, ['long']],
            'pxUpArrow': [36, ['long']],
            'posMin': [0, ['long']],
            'page': [8, ['long']],
        },
    ],
    'HIMC__': [
        0x4,
        {
            'unused': [0, ['long']],
        },
    ],
    'tagSBINFO': [
        0x24,
        {
            'WSBflags': [0, ['long']],
            'Horz': [4, ['tagSBDATA']],
            'Vert': [20, ['tagSBDATA']],
        },
    ],
    '__unnamed_1211': [
        0x10,
        {
            'Length': [0, ['unsigned long']],
            'FileInformationClass': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
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
                    },
                ],
            ],
        },
    ],
    '__unnamed_1213': [
        0x20,
        {
            'FileInformationClass': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
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
                    },
                ],
            ],
            'AdvanceOnly': [25, ['unsigned char']],
            'ClusterCount': [24, ['unsigned long']],
            'Length': [0, ['unsigned long']],
            'DeleteHandle': [24, ['pointer64', ['void']]],
            'ReplaceIfExists': [24, ['unsigned char']],
            'FileObject': [16, ['pointer64', ['_FILE_OBJECT']]],
        },
    ],
    '__unnamed_1219': [
        0x20,
        {
            'Type3InputBuffer': [24, ['pointer64', ['void']]],
            'OutputBufferLength': [0, ['unsigned long']],
            'FsControlCode': [16, ['unsigned long']],
            'InputBufferLength': [8, ['unsigned long']],
        },
    ],
    '__unnamed_1950': [
        0x18,
        {
            'Length': [0, ['unsigned long']],
            'MaximumAddress': [16, ['_LARGE_INTEGER']],
            'MinimumAddress': [8, ['_LARGE_INTEGER']],
            'Alignment': [4, ['unsigned long']],
        },
    ],
    'tagITEM': [
        0x90,
        {
            'ulX': [84, ['unsigned long']],
            'wID': [8, ['unsigned long']],
            'dwItemData': [56, ['unsigned long long']],
            'cyItem': [76, ['unsigned long']],
            'hbmpChecked': [24, ['pointer64', ['void']]],
            'xItem': [64, ['unsigned long']],
            'spSubMenu': [16, ['pointer64', ['tagMENU']]],
            'hbmpUnchecked': [32, ['pointer64', ['void']]],
            'fState': [4, ['unsigned long']],
            'dxTab': [80, ['unsigned long']],
            'hbmp': [96, ['pointer64', ['HBITMAP__']]],
            'yItem': [68, ['unsigned long']],
            'fType': [0, ['unsigned long']],
            'umim': [112, ['tagUAHMENUITEMMETRICS']],
            'cch': [48, ['unsigned long']],
            'ulWidth': [88, ['unsigned long']],
            'cyBmp': [108, ['long']],
            'cxBmp': [104, ['long']],
            'lpstr': [40, ['pointer64', ['unsigned short']]],
            'cxItem': [72, ['unsigned long']],
        },
    ],
    '_VSC_VK': [
        0x4,
        {
            'Vsc': [0, ['unsigned char']],
            'Vk': [2, ['unsigned short']],
        },
    ],
    '__unnamed_123f': [
        0x1,
        {
            'Lock': [0, ['unsigned char']],
        },
    ],
    '_DMM_MONITOR_SERIALIZATION': [
        0x28,
        {
            'FrequencyRangeSetOffset': [28, ['unsigned long']],
            'ModePruningAlgorithm': [
                16,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'DMM_MPA_UNINITIALIZED',
                            1: 'DMM_MPA_GDI',
                            2: 'DMM_MPA_VISTA',
                            3: 'DMM_MPA_MAXVALID',
                        },
                    },
                ],
            ],
            'VideoPresentTargetId': [4, ['unsigned long']],
            'IsSimulatedMonitor': [12, ['unsigned char']],
            'SourceModeSetOffset': [24, ['unsigned long']],
            'Orientation': [
                8,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MO_UNINITIALIZED',
                            1: 'D3DKMDT_MO_0DEG',
                            2: 'D3DKMDT_MO_90DEG',
                            3: 'D3DKMDT_MO_180DEG',
                            4: 'D3DKMDT_MO_270DEG',
                        },
                    },
                ],
            ],
            'DescriptorSetOffset': [32, ['unsigned long']],
            'MonitorPowerState': [
                20,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'PowerDeviceUnspecified',
                            1: 'PowerDeviceD0',
                            2: 'PowerDeviceD1',
                            3: 'PowerDeviceD2',
                            4: 'PowerDeviceD3',
                            5: 'PowerDeviceMaximum',
                        },
                    },
                ],
            ],
            'IsUsingDefaultProfile': [13, ['unsigned char']],
            'MonitorType': [
                36,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'DMM_VMT_UNINITIALIZED',
                            1: 'DMM_VMT_PHYSICAL_MONITOR',
                            2: 'DMM_VMT_BOOT_PERSISTENT_MONITOR',
                            3: 'DMM_VMT_PERSISTENT_MONITOR',
                            4: 'DMM_VMT_TEMPORARY_MONITOR',
                            5: 'DMM_VMT_SIMULATED_MONITOR',
                        },
                    },
                ],
            ],
            'Size': [0, ['unsigned long']],
        },
    ],
    '_VK_TO_WCHARS1': [
        0x4,
        {
            'Attributes': [1, ['unsigned char']],
            'VirtualKey': [0, ['unsigned char']],
            'wch': [2, ['array', 1, ['wchar']]],
        },
    ],
    '__unnamed_121b': [
        0x18,
        {
            'Length': [0, ['pointer64', ['_LARGE_INTEGER']]],
            'ByteOffset': [16, ['_LARGE_INTEGER']],
            'Key': [8, ['unsigned long']],
        },
    ],
    '__unnamed_121d': [
        0x20,
        {
            'Type3InputBuffer': [24, ['pointer64', ['void']]],
            'OutputBufferLength': [0, ['unsigned long']],
            'IoControlCode': [16, ['unsigned long']],
            'InputBufferLength': [8, ['unsigned long']],
        },
    ],
    '__unnamed_121f': [
        0x10,
        {
            'Length': [8, ['unsigned long']],
            'SecurityInformation': [0, ['unsigned long']],
        },
    ],
    '_DMM_MONITORFREQUENCYRANGESET_SERIALIZATION': [
        0x38,
        {
            'NumFrequencyRanges': [0, ['unsigned char']],
            'FrequencyRangeSerialization': [
                8,
                ['array', 1, ['_D3DKMDT_MONITOR_FREQUENCY_RANGE']],
            ],
        },
    ],
    '_D3DKMDT_GAMMA_RAMP': [
        0x18,
        {
            'Data': [16, ['__unnamed_182e']],
            'DataSize': [8, ['unsigned long long']],
            'Type': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DDDI_GAMMARAMP_UNINITIALIZED',
                            1: 'D3DDDI_GAMMARAMP_DEFAULT',
                            2: 'D3DDDI_GAMMARAMP_RGB256x3x16',
                            3: 'D3DDDI_GAMMARAMP_DXGI_1',
                        },
                    },
                ],
            ],
        },
    ],
    '_W32PROCESS': [
        0x100,
        {
            'GDIPushLock': [80, ['_EX_PUSH_LOCK']],
            'DxProcess': [248, ['pointer64', ['void']]],
            'pBrushAttrList': [48, ['pointer64', ['void']]],
            'Process': [0, ['pointer64', ['_EPROCESS']]],
            'NextStart': [32, ['pointer64', ['_W32PROCESS']]],
            'GDIW32PIDLockedBitmaps': [224, ['_LIST_ENTRY']],
            'RefCount': [8, ['unsigned long']],
            'StartCursorHideTime': [24, ['unsigned long']],
            'GDIBrushAttrFreeList': [208, ['_LIST_ENTRY']],
            'InputIdleEvent': [16, ['pointer64', ['_KEVENT']]],
            'W32PF_Flags': [12, ['unsigned long']],
            'GDIHandleCount': [60, ['long']],
            'hSecureGdiSharedHandleTable': [240, ['pointer64', ['void']]],
            'UserHandleCountPeak': [72, ['unsigned long']],
            'W32Pid': [56, ['unsigned long']],
            'UserHandleCount': [68, ['long']],
            'pDCAttrList': [40, ['pointer64', ['void']]],
            'GDIEngUserMemAllocTable': [88, ['_RTL_AVL_TABLE']],
            'GDIHandleCountPeak': [64, ['unsigned long']],
            'GDIDcAttrFreeList': [192, ['_LIST_ENTRY']],
        },
    ],
    'tagSERVERINFO': [
        0x1220,
        {
            'uiShellMsg': [912, ['unsigned long']],
            'atomSysClass': [852, ['array', 25, ['unsigned short']]],
            'dtScroll': [2800, ['unsigned long']],
            'dwKeyCache': [2952, ['unsigned long']],
            'atomIconSmProp': [1356, ['unsigned short']],
            'argbSystemUnmatched': [2268, ['array', 31, ['unsigned long']]],
            'atomContextHelpIdProp': [1360, ['unsigned short']],
            'cySysFontChar': [2832, ['long']],
            'mpFnid_serverCBWndProc': [328, ['array', 31, ['unsigned short']]],
            'PUSIFlags': [4476, ['unsigned long']],
            'dtLBSearch': [2804, ['unsigned long']],
            'tmSysFont': [2836, ['tagTEXTMETRICW']],
            'ahbrSystem': [2520, ['array', 31, ['pointer64', ['HBRUSH__']]]],
            'dwDefaultHeapSize': [908, ['unsigned long']],
            'dwSRVIFlags': [0, ['unsigned long']],
            'BitsPixel': [4473, ['unsigned char']],
            'wMaxLeftOverlapChars': [2820, ['long']],
            'dwLastSystemRITEventTickCountUpdate': [4488, ['unsigned long']],
            'dpiSystem': [2896, ['tagDPISERVERINFO']],
            'hIcoWindows': [2944, ['pointer64', ['HICON__']]],
            'dwAsyncKeyCache': [2956, ['unsigned long']],
            'dwTagCount': [4632, ['unsigned long']],
            'adwDBGTAGFlags': [4492, ['array', 35, ['unsigned long']]],
            'aiSysMet': [1880, ['array', 97, ['long']]],
            'acAnsiToOem': [1620, ['array', 256, ['unsigned char']]],
            'aStoCidPfn': [272, ['array', 7, ['pointer64', ['void']]]],
            'dwLastRITEventTickCount': [2792, ['unsigned long']],
            'cbHandleTable': [848, ['unsigned long']],
            'atomFrostedWindowProp': [1362, ['unsigned short']],
            'ucWheelScrollLines': [2812, ['unsigned long']],
            'ptCursorReal': [2784, ['tagPOINT']],
            'ucWheelScrollChars': [2816, ['unsigned long']],
            'acOemToAnsi': [1364, ['array', 256, ['unsigned char']]],
            'hbrGray': [2768, ['pointer64', ['HBRUSH__']]],
            'BitCount': [4468, ['unsigned short']],
            'argbSystem': [2392, ['array', 31, ['unsigned long']]],
            'dtCaretBlink': [2808, ['unsigned long']],
            'dwInstalledEventHooks': [1876, ['unsigned long']],
            'cxSysFontChar': [2828, ['long']],
            'wMaxRightOverlapChars': [2824, ['long']],
            'oembmi': [2964, ['array', 93, ['tagOEMBITMAPINFO']]],
            'apfnClientWorker': [760, ['_PFNCLIENTWORKER']],
            'dwDefaultHeapBase': [904, ['unsigned long']],
            'apfnClientA': [392, ['_PFNCLIENT']],
            'dmLogPixels': [4470, ['unsigned short']],
            'nEvents': [2796, ['long']],
            'atomIconProp': [1358, ['unsigned short']],
            'Planes': [4472, ['unsigned char']],
            'apfnClientW': [576, ['_PFNCLIENT']],
            'MBStrings': [916, ['array', 11, ['tagMBSTRING']]],
            'UILangID': [4484, ['unsigned short']],
            'dwRIPFlags': [4636, ['unsigned long']],
            'uCaretWidth': [4480, ['unsigned long']],
            'cCaptures': [2960, ['unsigned long']],
            'cHandleEntries': [8, ['unsigned long long']],
            'ptCursor': [2776, ['tagPOINT']],
            'hIconSmWindows': [2936, ['pointer64', ['HICON__']]],
            'mpFnidPfn': [16, ['array', 32, ['pointer64', ['void']]]],
            'rcScreenReal': [4452, ['tagRECT']],
        },
    ],
    '_D3DKMDT_VIDEO_SIGNAL_INFO': [
        0x38,
        {
            'VSyncFreq': [20, ['_D3DDDI_RATIONAL']],
            'ActiveSize': [12, ['_D3DKMDT_2DREGION']],
            'PixelRate': [40, ['unsigned long long']],
            'TotalSize': [4, ['_D3DKMDT_2DREGION']],
            'VideoStandard': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_VSS_UNINITIALIZED',
                            1: 'D3DKMDT_VSS_VESA_DMT',
                            2: 'D3DKMDT_VSS_VESA_GTF',
                            3: 'D3DKMDT_VSS_VESA_CVT',
                            4: 'D3DKMDT_VSS_IBM',
                            5: 'D3DKMDT_VSS_APPLE',
                            6: 'D3DKMDT_VSS_NTSC_M',
                            7: 'D3DKMDT_VSS_NTSC_J',
                            8: 'D3DKMDT_VSS_NTSC_443',
                            9: 'D3DKMDT_VSS_PAL_B',
                            10: 'D3DKMDT_VSS_PAL_B1',
                            11: 'D3DKMDT_VSS_PAL_G',
                            12: 'D3DKMDT_VSS_PAL_H',
                            13: 'D3DKMDT_VSS_PAL_I',
                            14: 'D3DKMDT_VSS_PAL_D',
                            15: 'D3DKMDT_VSS_PAL_N',
                            16: 'D3DKMDT_VSS_PAL_NC',
                            17: 'D3DKMDT_VSS_SECAM_B',
                            18: 'D3DKMDT_VSS_SECAM_D',
                            19: 'D3DKMDT_VSS_SECAM_G',
                            20: 'D3DKMDT_VSS_SECAM_H',
                            21: 'D3DKMDT_VSS_SECAM_K',
                            22: 'D3DKMDT_VSS_SECAM_K1',
                            23: 'D3DKMDT_VSS_SECAM_L',
                            24: 'D3DKMDT_VSS_SECAM_L1',
                            25: 'D3DKMDT_VSS_EIA_861',
                            26: 'D3DKMDT_VSS_EIA_861A',
                            27: 'D3DKMDT_VSS_EIA_861B',
                            28: 'D3DKMDT_VSS_PAL_K',
                            29: 'D3DKMDT_VSS_PAL_K1',
                            30: 'D3DKMDT_VSS_PAL_L',
                            31: 'D3DKMDT_VSS_PAL_M',
                            255: 'D3DKMDT_VSS_OTHER',
                        },
                    },
                ],
            ],
            'ScanLineOrdering': [
                48,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DDDI_VSSLO_UNINITIALIZED',
                            1: 'D3DDDI_VSSLO_PROGRESSIVE',
                            2: 'D3DDDI_VSSLO_INTERLACED_UPPERFIELDFIRST',
                            3: 'D3DDDI_VSSLO_INTERLACED_LOWERFIELDFIRST',
                            255: 'D3DDDI_VSSLO_OTHER',
                        },
                    },
                ],
            ],
            'HSyncFreq': [28, ['_D3DDDI_RATIONAL']],
        },
    ],
    '__unnamed_11df': [
        0x8,
        {
            'IrpCount': [0, ['long']],
            'SystemBuffer': [0, ['pointer64', ['void']]],
            'MasterIrp': [0, ['pointer64', ['_IRP']]],
        },
    ],
    'D3DDDI_DXGI_RGB': [
        0xC,
        {
            'Blue': [8, ['float']],
            'Green': [4, ['float']],
            'Red': [0, ['float']],
        },
    ],
    '_MAGNIFICATION_INPUT_TRANSFORM': [
        0x30,
        {
            'rcScreen': [16, ['tagRECT']],
            'magFactorX': [40, ['long']],
            'magFactorY': [44, ['long']],
            'ptiMagThreadInfo': [32, ['pointer64', ['tagTHREADINFO']]],
            'rcSource': [0, ['tagRECT']],
        },
    ],
    '_D3DKMDT_MONITOR_FREQUENCY_RANGE': [
        0x30,
        {
            'Origin': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MCO_UNINITIALIZED',
                            1: 'D3DKMDT_MCO_DEFAULTMONITORPROFILE',
                            2: 'D3DKMDT_MCO_MONITORDESCRIPTOR',
                            3: 'D3DKMDT_MCO_MONITORDESCRIPTOR_REGISTRYOVERRIDE',
                            4: 'D3DKMDT_MCO_SPECIFICCAP_REGISTRYOVERRIDE',
                            5: 'D3DKMDT_MCO_MAXVALID',
                        },
                    },
                ],
            ],
            'ConstraintType': [
                36,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'D3DKMDT_MFRC_UNINITIALIZED',
                            1: 'D3DKMDT_MFRC_ACTIVESIZE',
                            2: 'D3DKMDT_MFRC_MAXPIXELRATE',
                        },
                    },
                ],
            ],
            'RangeLimits': [4, ['_D3DKMDT_FREQUENCY_RANGE']],
            'Constraint': [40, ['__unnamed_16c1']],
        },
    ],
    '_PFNCLIENTWORKER': [
        0x58,
        {
            'pfnComboBoxWndProc': [8, ['pointer64', ['void']]],
            'pfnMDIClientWndProc': [48, ['pointer64', ['void']]],
            'pfnDialogWndProc': [24, ['pointer64', ['void']]],
            'pfnStaticWndProc': [56, ['pointer64', ['void']]],
            'pfnCtfHookProc': [80, ['pointer64', ['void']]],
            'pfnButtonWndProc': [0, ['pointer64', ['void']]],
            'pfnImeWndProc': [64, ['pointer64', ['void']]],
            'pfnEditWndProc': [32, ['pointer64', ['void']]],
            'pfnListBoxWndProc': [40, ['pointer64', ['void']]],
            'pfnGhostWndProc': [72, ['pointer64', ['void']]],
            'pfnComboListBoxProc': [16, ['pointer64', ['void']]],
        },
    ],
    '_DMA_OPERATIONS': [
        0x80,
        {
            'PutDmaAdapter': [8, ['pointer64', ['void']]],
            'FreeMapRegisters': [56, ['pointer64', ['void']]],
            'MapTransfer': [64, ['pointer64', ['void']]],
            'FreeCommonBuffer': [24, ['pointer64', ['void']]],
            'ReadDmaCounter': [80, ['pointer64', ['void']]],
            'AllocateCommonBuffer': [16, ['pointer64', ['void']]],
            'PutScatterGatherList': [96, ['pointer64', ['void']]],
            'CalculateScatterGatherList': [104, ['pointer64', ['void']]],
            'BuildMdlFromScatterGatherList': [120, ['pointer64', ['void']]],
            'GetScatterGatherList': [88, ['pointer64', ['void']]],
            'AllocateAdapterChannel': [32, ['pointer64', ['void']]],
            'FreeAdapterChannel': [48, ['pointer64', ['void']]],
            'GetDmaAlignment': [72, ['pointer64', ['void']]],
            'FlushAdapterBuffers': [40, ['pointer64', ['void']]],
            'BuildScatterGatherList': [112, ['pointer64', ['void']]],
            'Size': [0, ['unsigned long']],
        },
    ],
    '_DXGK_DIAG_HEADER': [
        0x30,
        {
            'Index': [40, ['unsigned long']],
            'ProcessName': [16, ['array', 16, ['unsigned char']]],
            'LogTimestamp': [8, ['unsigned long long']],
            'ThreadId': [32, ['unsigned long long']],
            'Type': [
                0,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'DXGK_DIAG_TYPE_NONE',
                            1: 'DXGK_DIAG_TYPE_SDC',
                            2: 'DXGK_DIAG_TYPE_HPD',
                            3: 'DXGK_DIAG_TYPE_DC_ORIGIN',
                            4: 'DXGK_DIAG_TYPE_USER_CDS',
                            5: 'DXGK_DIAG_TYPE_DRV_CDS',
                            6: 'DXGK_DIAG_TYPE_CODE_POINT',
                            7: 'DXGK_DIAG_TYPE_QDC',
                            8: 'DXGK_DIAG_TYPE_MONITOR_MGR',
                            9: 'DXGK_DIAG_TYPE_CONNECTEDSET_NOT_FOUND',
                            10: 'DXGK_DIAG_TYPE_DISPDIAG_COLLECTED',
                            11: 'DXGK_DIAG_TYPE_BML_PACKET',
                            12: 'DXGK_DIAG_TYPE_BML_PACKET_EX',
                            13: 'DXGK_DIAG_TYPE_COMMIT_VIDPN_FAILED',
                            14: 'DXGK_DIAG_TYPE_MAX',
                            -1: 'DXGK_DIAG_TYPE_FORCE_UINT32',
                        },
                    },
                ],
            ],
            'WdLogIdx': [44, ['unsigned long']],
            'Size': [4, ['unsigned long']],
        },
    ],
    '__unnamed_1225': [
        0x10,
        {
            'DeviceObject': [8, ['pointer64', ['_DEVICE_OBJECT']]],
            'Vpb': [0, ['pointer64', ['_VPB']]],
        },
    ],
    '_SM_VALUES_STRINGS': [
        0x18,
        {
            'StorageType': [
                16,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'SmStorageActual',
                            1: 'SmStorageNonActual',
                        },
                    },
                ],
            ],
            'pszName': [0, ['pointer64', ['unsigned char']]],
            'ulValue': [8, ['unsigned long']],
            'RangeType': [
                12,
                [
                    'Enumeration',
                    {
                        'target': 'long',
                        'choices': {
                            0: 'SmRangeSharedInfo',
                            1: 'SmRangeNonSharedInfo',
                            2: 'SmRangeBool',
                        },
                    },
                ],
            ],
        },
    ],
    'tagTERMINAL': [
        0x40,
        {
            'spwndDesktopOwner': [8, ['pointer64', ['tagWND']]],
            'dwTERMF_Flags': [0, ['unsigned long']],
            'dwNestedLevel': [32, ['unsigned long']],
            'pqDesktop': [24, ['pointer64', ['tagQ']]],
            'pEventInputReady': [56, ['pointer64', ['_KEVENT']]],
            'rpdeskDestroy': [48, ['pointer64', ['tagDESKTOP']]],
            'ptiDesktop': [16, ['pointer64', ['tagTHREADINFO']]],
            'pEventTermInit': [40, ['pointer64', ['_KEVENT']]],
        },
    ],
    '_SCATTER_GATHER_LIST': [
        0x10,
        {
            'Elements': [16, ['array', 0, ['_SCATTER_GATHER_ELEMENT']]],
            'Reserved': [8, ['unsigned long long']],
            'NumberOfElements': [0, ['unsigned long']],
        },
    ],
    'tagMENULIST': [
        0x10,
        {
            'pMenu': [8, ['pointer64', ['tagMENU']]],
            'pNext': [0, ['pointer64', ['tagMENULIST']]],
        },
    ],
    'tagPOINT': [
        0x8,
        {
            'y': [4, ['long']],
            'x': [0, ['long']],
        },
    ],
    'tagSHAREDINFO': [
        0x238,
        {
            'psi': [0, ['pointer64', ['tagSERVERINFO']]],
            'DefWindowSpecMsgs': [552, ['_WNDMSG']],
            'awmControl': [40, ['array', 31, ['_WNDMSG']]],
            'ulSharedDelta': [32, ['unsigned long long']],
            'pDispInfo': [24, ['pointer64', ['tagDISPLAYINFO']]],
            'aheList': [8, ['pointer64', ['_HANDLEENTRY']]],
            'DefWindowMsgs': [536, ['_WNDMSG']],
            'HeEntrySize': [16, ['unsigned long']],
        },
    ],
    'tagIMC': [
        0x40,
        {
            'dwClientImcData': [48, ['unsigned long long']],
            'head': [0, ['_THRDESKHEAD']],
            'hImeWnd': [56, ['pointer64', ['HWND__']]],
            'pImcNext': [40, ['pointer64', ['tagIMC']]],
        },
    ],
    'tagKL': [
        0x78,
        {
            'uNumTbl': [88, ['unsigned long']],
            'pklPrev': [24, ['pointer64', ['tagKL']]],
            'head': [0, ['_HEAD']],
            'pklNext': [16, ['pointer64', ['tagKL']]],
            'spkfPrimary': [56, ['pointer64', ['tagKBDFILE']]],
            'dwFontSigs': [64, ['unsigned long']],
            'dwLastKbdType': [104, ['unsigned long']],
            'CodePage': [72, ['unsigned short']],
            'dwKL_Flags': [32, ['unsigned long']],
            'iBaseCharset': [68, ['unsigned long']],
            'dwKLID': [112, ['unsigned long']],
            'spkf': [48, ['pointer64', ['tagKBDFILE']]],
            'piiex': [80, ['pointer64', ['tagIMEINFOEX']]],
            'hkl': [40, ['pointer64', ['HKL__']]],
            'pspkfExtra': [96, ['pointer64', ['pointer64', ['tagKBDFILE']]]],
            'wchDiacritic': [74, ['wchar']],
            'dwLastKbdSubType': [108, ['unsigned long']],
        },
    ],
    '__unnamed_182e': [
        0x8,
        {
            'pRgb256x3x16': [
                0,
                ['pointer64', ['_D3DDDI_GAMMA_RAMP_RGB256x3x16']],
            ],
            'pRaw': [0, ['pointer64', ['void']]],
            'pDxgi1': [0, ['pointer64', ['_D3DDDI_GAMMA_RAMP_DXGI_1']]],
        },
    ],
    'tagCARET': [
        0x48,
        {
            'iHideLevel': [12, ['long']],
            'yOwnDc': [56, ['long']],
            'y': [20, ['long']],
            'cy': [24, ['long']],
            'cx': [28, ['long']],
            'hBitmap': [32, ['pointer64', ['HBITMAP__']]],
            'cyOwnDc': [64, ['long']],
            'fOn': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 2,
                        'start_bit': 1,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'hTimer': [40, ['unsigned long long']],
            'xOwnDc': [52, ['long']],
            'fVisible': [
                8,
                [
                    'BitField',
                    {
                        'end_bit': 1,
                        'start_bit': 0,
                        'native_type': 'unsigned long',
                    },
                ],
            ],
            'cxOwnDc': [60, ['long']],
            'tid': [48, ['unsigned long']],
            'x': [16, ['long']],
            'spwnd': [0, ['pointer64', ['tagWND']]],
        },
    ],
}
