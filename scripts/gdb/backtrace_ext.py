# Copyright 2023 Adam Szaj <adam.szaj@gmail.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re
import gdb


def not_empty(s):
    return len(s) > 0


class MemoryMapping:
    def __init__(self, start_addr, end_addr, offset, perm, pathname):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.size = end_addr - start_addr
        self.offset = offset
        self.perm = perm
        self.pathname = pathname
        pass

    def __str__(self):
        pathname = self.pathname
        perm = self.perm
        if pathname is None:
            # pathname = '<anonymous>'
            pathname = ""
        if perm is None:
            perm = "    "

        return f"{self.start_addr:#18x} {self.end_addr:#18x} {self.size:#18x} {self.offset:#18x} {perm} {pathname}"


xd = "[0-9a-fA-F]"
xn = f"(?:0[xX])?{xd}+"
proc_maps_pattern_string = f"^\\s*(?P<start_addr>{xn})-(?P<end_addr>{xn})\\s+(?P<perm>[r\\-][w\\-][x\\-][ps])\\s+(?P<offset>{xn})\\s+(?P<major>{xn}):(?P<minor>{xn})\\s+(\\d+)(?:\\s+(?P<pathname>\\S+))?\\s*$"
gdb_maps_pattern_string = f"^\\s*(?P<start_addr>{xn})\\s+(?P<end_addr>{xn})\\s+(?P<size>{xn})\\s+(?P<offset>{xn})(?:\\s+(?P<perm>[r\\-][w\\-][x\\-][ps]))?(?:\\s+(?P<pathname>\\S+))?\\s*$"


class RePatterns:
    proc_maps_pattern = re.compile(proc_maps_pattern_string)
    gdb_maps_pattern = re.compile(gdb_maps_pattern_string)
    pass


class MemoryMappings:
    def __init__(self):
        self.mappings = []
        self.patterns = RePatterns()
        pass

    def parseMapsLine(self, line, pattern):
        m = re.match(pattern, line, flags=0)
        if m:
            # print(f"mapping line match the pattern: '{line}' {m.groups()}")
            start_addr = int(m["start_addr"], 16)
            end_addr = int(m["end_addr"], 16)
            perm = m["perm"]
            offset = int(m["offset"], 16)
            pathname = m["pathname"]
            self.mappings.append(
                MemoryMapping(
                    start_addr=start_addr,
                    end_addr=end_addr,
                    offset=offset,
                    pathname=pathname,
                    perm=perm,
                )
            )
        else:
            # print(f"mapping line does match the pattern: '{line}'")
            pass

    def parseProcMapsLine(self, line):
        self.parseMapsLine(line, self.patterns.proc_maps_pattern)
        pass

    def parseGDBMapsLine(self, line):
        # print(f"pattern: {gdb_maps_pattern_string}")
        self.parseMapsLine(line, self.patterns.gdb_maps_pattern)
        pass

    def loadGDBMappings(self):
        cmdresult = gdb.execute("info proc mappings", False, True)
        lines = cmdresult.splitlines()
        for line in lines:
            self.parseGDBMapsLine(line)

    def find_mapping(self, addr):
        # print(f"find_mapping: {addr:#x}")
        for mapping in self.mappings:
            if mapping.start_addr <= addr and mapping.end_addr >= addr:
                # print(f"find_mapping: {mapping}")
                return mapping
        return None

    def print(self, output):
        start_addr = "Start Addr"
        end_addr = "End Addr"
        size = "Size"
        offset = "Offset"
        perm = "Perm"
        pathname = "Pathname"

        print(
            f"{start_addr:>18s} {end_addr:>18s} {size:>18s} {offset:>18s} {
                perm:>4s} {pathname}"
        )
        for m in self.mappings:
            print(f"{m}")

    pass


#############################################################


class MemoryMappingsCmd(gdb.Command):
    def __init__(self):
        super(MemoryMappingsCmd, self).__init__(
            "mappings_ext", gdb.COMMAND_USER
        )
        pass

    def invoke(self, args, from_tty):
        mappings = MemoryMappings()
        mappings.loadGDBMappings()
        argv = args.split(" ")
        for x in mappings.mappings:
            if len(argv) > 0:
                print("{}".format(x))
                # if argv[0] == x.perms:
                #    print("{}".format(x))
                # else:
                #    print("{}".format(x))
                #    pass
            else:
                print("{}".format(x))
        pass

    pass


class BacktraceCmd(gdb.Command):
    def __init__(self):
        super(BacktraceCmd, self).__init__("backtrace_ext", gdb.COMMAND_USER)
        pass

    def doBacktrace(self):
        mappings = MemoryMappings()
        mappings.loadGDBMappings()
        frame = gdb.newest_frame()
        older_frame = frame.older()
        index = 0
        while frame is not None:
            pc = frame.pc()
            static_addr = 0
            mapping = mappings.find_mapping(pc)
            if mapping is not None:
                static_addr = pc - mapping.start_addr + mapping.offset
                # print(f"bt: mapping {mapping}")
                symtab = None
                sline = 0
                frame_symbol = frame.function()
                pathname = mapping.pathname
                if frame_symbol is not None:
                    symtab = frame_symbol.symtab
                    sline = frame_symbol.line
                    print(
                        f"#{index}\t{pc:#18x} {static_addr:#18x} {pathname} {
                            frame_symbol
                        } {symtab}:{sline}"
                    )
                else:
                    print(f"#{index}\t{pc:#18x} {static_addr:#18x} {pathname}")

            frame = older_frame
            index = index + 1
            if frame is not None:
                older_frame = frame.older()

        pass

    def invoke(self, args, from_tty):
        inf = gdb.selected_inferior()
        if inf is not None:
            selected_thread = gdb.selected_thread()
            if selected_thread is not None:
                self.doBacktrace()

        pass

    pass


# register new command
MemoryMappingsCmd()
BacktraceCmd()
