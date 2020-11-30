# Volatility
# Copyright (c) 2008-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

crash_vtypes = {
    ## These types are for crash dumps
    '_DMP_HEADER': [
        0x1000,
        {
            'Signature': [0x0, ['array', 4, ['unsigned char']]],
            'ValidDump': [0x4, ['array', 4, ['unsigned char']]],
            'MajorVersion': [0x8, ['unsigned long']],
            'MinorVersion': [0xC, ['unsigned long']],
            'DirectoryTableBase': [0x10, ['unsigned long']],
            'PfnDataBase': [0x14, ['unsigned long']],
            'PsLoadedModuleList': [0x18, ['unsigned long']],
            'PsActiveProcessHead': [0x1C, ['unsigned long']],
            'MachineImageType': [0x20, ['unsigned long']],
            'NumberProcessors': [0x24, ['unsigned long']],
            'BugCheckCode': [0x28, ['unsigned long']],
            'BugCheckCodeParameter': [0x2C, ['array', 4, ['unsigned long']]],
            'VersionUser': [0x3C, ['array', 32, ['unsigned char']]],
            'PaeEnabled': [0x5C, ['unsigned char']],
            'KdSecondaryVersion': [0x5D, ['unsigned char']],
            'VersionUser2': [0x5E, ['array', 2, ['unsigned char']]],
            'KdDebuggerDataBlock': [0x60, ['unsigned long']],
            'PhysicalMemoryBlockBuffer': [
                0x64,
                ['_PHYSICAL_MEMORY_DESCRIPTOR'],
            ],
            'ContextRecord': [0x320, ['array', 1200, ['unsigned char']]],
            'Exception': [0x7D0, ['_EXCEPTION_RECORD32']],
            'Comment': [0x820, ['array', 128, ['unsigned char']]],
            'DumpType': [0xF88, ['unsigned long']],
            'MiniDumpFields': [0xF8C, ['unsigned long']],
            'SecondaryDataState': [0xF90, ['unsigned long']],
            'ProductType': [0xF94, ['unsigned long']],
            'SuiteMask': [0xF98, ['unsigned long']],
            'WriterStatus': [0xF9C, ['unsigned long']],
            'RequiredDumpSpace': [0xFA0, ['unsigned long long']],
            'SystemUpTime': [0xFB8, ['unsigned long long']],
            'SystemTime': [0xFC0, ['unsigned long long']],
            'reserved3': [0xFC8, ['array', 56, ['unsigned char']]],
        },
    ],
    '_DMP_HEADER64': [
        0x2000,
        {
            'Signature': [0x0, ['array', 4, ['unsigned char']]],
            'ValidDump': [0x4, ['array', 4, ['unsigned char']]],
            'MajorVersion': [0x8, ['unsigned long']],
            'MinorVersion': [0xC, ['unsigned long']],
            'DirectoryTableBase': [0x10, ['unsigned long long']],
            'PfnDataBase': [0x18, ['unsigned long long']],
            'PsLoadedModuleList': [0x20, ['unsigned long long']],
            'PsActiveProcessHead': [0x28, ['unsigned long long']],
            'MachineImageType': [0x30, ['unsigned long']],
            'NumberProcessors': [0x34, ['unsigned long']],
            'BugCheckCode': [0x38, ['unsigned long']],
            'BugCheckCodeParameter': [
                0x40,
                ['array', 4, ['unsigned long long']],
            ],
            'KdDebuggerDataBlock': [0x80, ['unsigned long long']],
            'PhysicalMemoryBlockBuffer': [
                0x88,
                ['_PHYSICAL_MEMORY_DESCRIPTOR'],
            ],
            'ContextRecord': [0x348, ['array', 3000, ['unsigned char']]],
            'Exception': [0xF00, ['_EXCEPTION_RECORD64']],
            'DumpType': [0xF98, ['unsigned long']],
            'RequiredDumpSpace': [0xFA0, ['unsigned long long']],
            'SystemTime': [0xFA8, ['unsigned long long']],
            'Comment': [0xFB0, ['array', 128, ['unsigned char']]],
            'SystemUpTime': [0x1030, ['unsigned long long']],
            'MiniDumpFields': [0x1038, ['unsigned long']],
            'SecondaryDataState': [0x103C, ['unsigned long']],
            'ProductType': [0x1040, ['unsigned long']],
            'SuiteMask': [0x1044, ['unsigned long']],
            'WriterStatus': [0x1048, ['unsigned long']],
            'Unused1': [0x104C, ['unsigned char']],
            'KdSecondaryVersion': [0x104D, ['unsigned char']],
            'Unused': [0x104E, ['array', 2, ['unsigned char']]],
            '_reserved0': [0x1050, ['array', 4016, ['unsigned char']]],
        },
    ],
}
