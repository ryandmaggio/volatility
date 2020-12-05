# Volatility
# Copyright (C) 2008-2013 Volatility Foundation
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0
@contact:      awalters@4tphi.net,bdolangavitt@wesleyan.edu
@organization: Volatility Foundation
"""

# pylint: disable-msg=C0111

import volatility.obj as obj
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.debug as debug
import volatility.utils as utils
import volatility.commands as commands
import volatility.plugins.common as common
import volatility.plugins.registry.hivelist as hivelist
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address, Bytes


def vol(k):
    return bool(k.obj_offset & 0x80000000)


class PrintKey(hivelist.HiveList):
    "Print a registry key, and its subkeys and values"
    # Declare meta information associated with this plugin

    meta_info = commands.Command.meta_info
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def __init__(self, config, *args, **kwargs):
        hivelist.HiveList.__init__(self, config, *args, **kwargs)
        config.add_option(
            'HIVE-OFFSET',
            short_option='o',
            help='Hive offset (virtual)',
            type='int',
        )
        config.add_option(
            'KEY', short_option='K', help='Registry Key', type='str'
        )

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.HIVE_OFFSET:
            hive_offsets = {
                h.obj_offset for h in hivelist.HiveList.calculate(self)
            }
        else:
            hive_offsets = {self._config.HIVE_OFFSET}

        for hoff in sorted(list(hive_offsets)):
            h = hivemod.HiveAddressSpace(addr_space, self._config, hoff)
            name = obj.Object("_CMHIVE", vm=addr_space, offset=hoff).get_name()
            root = rawreg.get_root(h)
            if not root:
                if self._config.HIVE_OFFSET:
                    debug.error(
                        "Unable to find root key. Is the hive offset correct?"
                    )
            else:
                if self._config.KEY:
                    opened_key = rawreg.open_key(
                        root, self._config.KEY.split('\\')
                    )
                    yield name, opened_key
                else:
                    yield name, root

    def voltext(self, key):
        return "(V)" if vol(key) else "(S)"

    def render_text(self, outfd, data):
        outfd.write("Legend: (S) = Stable   (V) = Volatile\n\n")
        keyfound = False
        for reg, key in data:
            if key:
                keyfound = True
                outfd.write("----------------------------\n")
                outfd.write(f"Registry: {reg}\n")
                outfd.write(f"Key name: {key.Name} {self.voltext(key):3s}\n")
                outfd.write(f"Last updated: {key.LastWriteTime}\n")
                outfd.write("\n")
                outfd.write("Subkeys:\n")
                for s in rawreg.subkeys(key):
                    if s.Name == None:
                        outfd.write(f"  Unknown subkey at {s.obj_offset:#x}\n")
                    else:
                        outfd.write(f"  {self.voltext(s):3s} {s.Name}\n")
                outfd.write("\n")
                outfd.write("Values:\n")
                for v in rawreg.values(key):
                    tp, dat = rawreg.value_data(v)
                    if tp == 'REG_BINARY' or tp == 'REG_NONE':
                        dat = "\n" + "\n".join(
                            [
                                f"{o:#010x}  {h:<48}  {''.join(c)}"
                                for o, h, c in utils.Hexdump(dat)
                            ]
                        )
                    if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                        dat = dat.encode("ascii", 'backslashreplace')
                    if tp == 'REG_MULTI_SZ':
                        for i in range(len(dat)):
                            dat[i] = dat[i].encode("ascii", 'backslashreplace')
                    outfd.write(
                        f"{tp:13} {v.Name:15} : {self.voltext(v):3s} {dat}\n"
                    )
        if not keyfound:
            outfd.write(
                "The requested key could not be found in the hive(s) searched\n"
            )

    def unified_output(self, data):
        return TreeGrid(
            [
                ("Registry", str),
                ("KeyName", str),
                ("KeyStability", str),
                ("LastWrite", str),
                ("Subkeys", str),
                ("SubkeyStability", str),
                ("ValType", str),
                ("ValName", str),
                ("ValStability", str),
                ("ValData", str),
            ],
            self.generator(data),
        )

    def generator(self, data):
        for reg, key in data:
            if key:
                subkeys = list(rawreg.subkeys(key))
                values = list(rawreg.values(key))
                yield (
                    0,
                    [
                        f"{reg}",
                        f"{key.Name}",
                        f"{self.voltext(key):3s}",
                        f"{key.LastWriteTime}",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                    ],
                )

                if subkeys:
                    for s in subkeys:
                        if s.Name == None:
                            yield (
                                0,
                                [
                                    f"{reg}",
                                    f"{key.Name}",
                                    f"{self.voltext(key):3s}",
                                    f"{key.LastWriteTime}",
                                    f"Unknown subkey: {s.Name.reason}",
                                    "-",
                                    "-",
                                    "-",
                                    "-",
                                    "-",
                                ],
                            )
                        else:
                            yield (
                                0,
                                [
                                    f"{reg}",
                                    f"{key.Name}",
                                    f"{self.voltext(key):3s}",
                                    f"{key.LastWriteTime}",
                                    f"{s.Name}",
                                    f"{self.voltext(s):3s}",
                                    "-",
                                    "-",
                                    "-",
                                    "-",
                                ],
                            )

                if values:
                    for v in values:
                        tp, dat = rawreg.value_data(v)
                        if tp == 'REG_BINARY' or tp == 'REG_NONE':
                            dat = Bytes(dat)
                        if tp in ['REG_SZ', 'REG_EXPAND_SZ', 'REG_LINK']:
                            dat = dat.encode("ascii", 'backslashreplace')
                        if tp == 'REG_MULTI_SZ':
                            for i in range(len(dat)):
                                dat[i] = dat[i].encode(
                                    "ascii", 'backslashreplace'
                                )
                        yield (
                            0,
                            [
                                f"{reg}",
                                f"{key.Name}",
                                f"{self.voltext(key):3s}",
                                f"{key.LastWriteTime}",
                                "-",
                                "-",
                                f"{tp}",
                                f"{v.Name}",
                                f"{self.voltext(v):3s}",
                                f"{dat}",
                            ],
                        )


class HiveDump(common.AbstractWindowsCommand):
    """Prints out a hive"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option(
            'HIVE-OFFSET',
            short_option='o',
            type='int',
            help='Hive offset (virtual)',
        )

    def calculate(self):
        addr_space = utils.load_as(self._config)

        if not self._config.hive_offset:
            debug.error("A Hive offset must be provided (--hive-offset)")

        h = hivemod.HiveAddressSpace(
            addr_space, self._config, self._config.hive_offset
        )
        return rawreg.get_root(h)

    def render_text(self, outfd, data):
        outfd.write(f"{'Last Written':20s} Key\n")
        self.print_key(outfd, '', data)

    def unified_output(self, data):
        return TreeGrid(
            [("LastWritten", str), ("Key", str)], self.generator(data)
        )

    def generator(self, data):
        path = str(data.Name)
        keys = [(data, path)]
        for key, path in keys:
            if key:
                yield (0, [f"{key.LastWriteTime}", str(path)])
                for s in rawreg.subkeys(key):
                    item = f"{path}\\{s.Name}"
                    keys.append((s, item))

    def print_key(self, outfd, keypath, key):
        if key.Name != None:
            kp = f"{keypath}\\{key.Name}"
            outfd.write(f"{key.LastWriteTime:20s} {kp}\n")
        for k in rawreg.subkeys(key):
            self.print_key(outfd, f"{keypath}\\{key.Name}", k)
