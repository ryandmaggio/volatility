# Volatility
#
# Authors:
# Adam Boileau <metlstorm@storm.net.nz>
# Mike Auty <mike.auty@gmail.com>
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
# *Heavily* based upon http://www.storm.net.nz/static/files/bioskbsnarf

import string
import struct
import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug
from volatility.renderers import TreeGrid
from volatility.renderers.basic import Address


class BiosKbd(common.AbstractWindowsCommand):
    """Reads the keyboard buffer from Real Mode memory"""

    BASE = 0x400
    OFFSET = 0x17
    BUFOFFSET = 0x1E
    LEN = 39
    FORMAT = "<BBBHH32s"

    def unified_output(self, data):
        return TreeGrid(
            [
                ("AsciiChar", str),
                ("AsciiCode", Address),
                ("Scancode", Address),
            ],
            self.generator(data),
        )

    def generator(self, data):
        """Displays the character codes"""
        for c, s in data:
            yield (0, [str(self.format_char(c)), Address(c), Address(s)])

    def render_text(self, outfd, data):
        """Displays the character codes"""
        outfd.write("Ascii     Scancode\n")
        for c, s in data:
            outfd.write(f"{self.format_char(c)} (0x{c:02x})   0x{s:02x}\n")

    def format_char(self, c):
        """Prints out an ascii printable character"""
        charset = string.digits + string.ascii_letters + string.punctuation
        if c in charset.encode('ascii'):
            return c
        return '.'

    def calculate(self):
        """Calculate returns the results of the bios keyboard reading"""
        addr_space = utils.load_as(self._config, astype='physical')
        data = addr_space.read(self.BASE + self.OFFSET, self.LEN)
        if not data or len(data) != self.LEN:
            debug.error(
                "Failed to read keyboard buffer, please check this is a physical memory image."
            )
        _shifta, _shiftb, _alt, readp, _writep, buf = struct.unpack(
            self.FORMAT, data
        )
        unringed = buf[readp - self.BUFOFFSET :]
        unringed += buf[: readp - self.BUFOFFSET]
        results = []
        for i in range(0, len(unringed) - 2, 2):
            if unringed[i] != 0:
                results.append((unringed[i], unringed[i + 1]))

        return results
