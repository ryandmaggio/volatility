# Volatility
# Copyright (C) 2009-2013 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.debug as debug
import volatility.obj as obj
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address
import datetime


class _DMP_HEADER(obj.CType):
    """A class for crash dumps"""

    @property
    def SystemUpTime(self):
        """Returns a string uptime"""

        # Some utilities write PAGEPAGE to this field when
        # creating the dump header.
        if self.m('SystemUpTime') == 0x4547415045474150:
            return obj.NoneObject("No uptime recorded")

        # 1 uptime is 100ns so convert that to microsec
        msec = self.m('SystemUpTime') // 10

        return datetime.timedelta(microseconds=msec)


class CrashInfoModification(obj.ProfileModification):
    """Applies overlays for crash dump headers"""

    conditions = {'os': lambda x: x == 'windows'}

    before = ["WindowsVTypes", "WindowsObjectClasses"]

    def modification(self, profile):
        profile.merge_overlay(
            {
                '_DMP_HEADER': [
                    None,
                    {
                        'Comment': [None, ['String', dict(length=128)]],
                        'DumpType': [
                            None,
                            [
                                'Enumeration',
                                dict(
                                    choices={
                                        0x1: "Full Dump",
                                        0x2: "Kernel Dump",
                                        0x5: "BitMap Dump",
                                    }
                                ),
                            ],
                        ],
                        'SystemTime': [
                            None,
                            ['WinTimeStamp', dict(is_utc=True)],
                        ],
                    },
                ],
                '_DMP_HEADER64': [
                    None,
                    {
                        'Comment': [None, ['String', dict(length=128)]],
                        'DumpType': [
                            None,
                            [
                                'Enumeration',
                                dict(
                                    choices={
                                        0x1: "Full Dump",
                                        0x2: "Kernel Dump",
                                        0x5: "BitMap Dump",
                                    }
                                ),
                            ],
                        ],
                        'SystemTime': [
                            None,
                            ['WinTimeStamp', dict(is_utc=True)],
                        ],
                    },
                ],
            }
        )

        ## Both x86 and x64 use the same structure for now, just
        ## so they can share the same SystemUpTime property.
        profile.object_classes.update(
            {'_DMP_HEADER': _DMP_HEADER, '_DMP_HEADER64': _DMP_HEADER}
        )


class CrashInfo(common.AbstractWindowsCommand):
    """Dump crash-dump information"""

    target_as = [
        'WindowsCrashDumpSpace32',
        'WindowsCrashDumpSpace64',
        'WindowsCrashDumpSpace64BitMap',
    ]

    @cache.CacheDecorator("tests/crashinfo")
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as(self._config, astype='physical')

        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ in self.target_as:
                result = adrs
            adrs = adrs.base

        if result is None:
            debug.error(
                f"Memory Image could not be identified as {self.target_as}"
            )

        return result

    def unified_output(self, data):
        return TreeGrid(
            [
                ("HeaderName", str),
                ("Majorversion", Address),
                ("Minorversion", Address),
                ("KdSecondaryVersion", Address),
                ("DirectoryTableBase", Address),
                ("PfnDataBase", Address),
                ("PsLoadedModuleList", Address),
                ("PsActiveProcessHead", Address),
                ("MachineImageType", Address),
                ("NumberProcessors", Address),
                ("BugCheckCode", Address),
                ("PaeEnabled", Address),
                ("KdDebuggerDataBlock", Address),
                ("ProductType", Address),
                ("SuiteMask", Address),
                ("WriterStatus", Address),
                ("Comment", str),
                ("DumpType", str),
                ("SystemTime", str),
                ("SystemUpTime", str),
                ("NumRuns", int),
            ],
            self.generator(data),
        )

    def generator(self, data):
        hdr = data.get_header()
        pae = -1
        if hdr.obj_name != "_DMP_HEADER64":
            pae = hdr.PaeEnabled
        yield (
            0,
            [
                str(hdr.obj_name),
                Address(hdr.MajorVersion),
                Address(hdr.MinorVersion),
                Address(hdr.KdSecondaryVersion),
                Address(hdr.DirectoryTableBase),
                Address(hdr.PfnDataBase),
                Address(hdr.PsLoadedModuleList),
                Address(hdr.PsActiveProcessHead),
                Address(hdr.MachineImageType),
                Address(hdr.NumberProcessors),
                Address(hdr.BugCheckCode),
                Address(pae),
                Address(hdr.KdDebuggerDataBlock),
                Address(hdr.ProductType),
                Address(hdr.SuiteMask),
                Address(hdr.WriterStatus),
                str(hdr.Comment),
                str(hdr.DumpType),
                str(hdr.SystemTime or ''),
                str(hdr.SystemUpTime or ''),
                len(data.get_runs()),
            ],
        )

    def render_text(self, outfd, data):
        """Renders the crashdump header as text"""

        hdr = data.get_header()
        runs = data.get_runs()

        outfd.write(f"{hdr.obj_name}:\n")
        outfd.write(
            f" Majorversion:         0x{hdr.MajorVersion:08x} ({hdr.MajorVersion})\n"
        )
        outfd.write(
            f" Minorversion:         0x{hdr.MinorVersion:08x} ({hdr.MinorVersion})\n"
        )
        outfd.write(f" KdSecondaryVersion    0x{hdr.KdSecondaryVersion:08x}\n")
        outfd.write(f" DirectoryTableBase    0x{hdr.DirectoryTableBase:08x}\n")
        outfd.write(f" PfnDataBase           0x{hdr.PfnDataBase:08x}\n")
        outfd.write(f" PsLoadedModuleList    0x{hdr.PsLoadedModuleList:08x}\n")
        outfd.write(
            f" PsActiveProcessHead   0x{hdr.PsActiveProcessHead:08x}\n"
        )
        outfd.write(f" MachineImageType      0x{hdr.MachineImageType:08x}\n")
        outfd.write(f" NumberProcessors      0x{hdr.NumberProcessors:08x}\n")
        outfd.write(f" BugCheckCode          0x{hdr.BugCheckCode:08x}\n")
        if hdr.obj_name != "_DMP_HEADER64":
            outfd.write(f" PaeEnabled            0x{hdr.PaeEnabled:08x}\n")
        outfd.write(
            f" KdDebuggerDataBlock   0x{hdr.KdDebuggerDataBlock:08x}\n"
        )
        outfd.write(f" ProductType           0x{hdr.ProductType:08x}\n")
        outfd.write(f" SuiteMask             0x{hdr.SuiteMask:08x}\n")
        outfd.write(f" WriterStatus          0x{hdr.WriterStatus:08x}\n")
        outfd.write(f" Comment               {hdr.Comment}\n")
        outfd.write(f" DumpType              {hdr.DumpType}\n")
        outfd.write(f" SystemTime            {hdr.SystemTime or ''}\n")
        outfd.write(f" SystemUpTime          {hdr.SystemUpTime or ''}\n")
        outfd.write("\nPhysical Memory Description:\n")
        outfd.write(f"Number of runs: {len(runs)}\n")
        outfd.write("FileOffset    Start Address    Length\n")
        foffset = 0x1000
        if hdr.obj_name == "_DMP_HEADER64":
            foffset = 0x2000
        run = []

        ## FIXME. These runs differ for x86 vs x64. This is a reminder
        ## for MHL or AW to fix it.

        for run in runs:
            outfd.write(
                f"{foffset:08x}      {run[0]:08x}         {run[2]:08x}\n"
            )
            foffset += run[2]
        outfd.write(
            f"{(foffset - 0x1000):08x}      {(run[0] + run[2] - 0x1000):08x}\n"
        )
