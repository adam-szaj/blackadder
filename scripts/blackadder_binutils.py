#!/usr/bin/env python3

import commands as comm
from commands import (
    RegexpReaderListener,
    runCommandWithoutInputFull,
    runCommandWithoutInput,
    runCommandWithInput,
)
from pathlib import Path
from hashlib import md5
from subprocess import PIPE
from blackadder_types import SectionHeader, BinaryLocator, Binary, Symbol
from sys import argv
import re


def md5sum(path: Path):
    digest = md5()
    array = bytearray(4096)
    with open(path, "rb") as file:
        while True:
            n = file.readinto(array)
            if n:
                digest.update(array[:n])
            else:
                break
    return digest.hexdigest()


class SilentReaderListener(comm.ReaderListener):
    def onLine(self, line):
        pass

    def onData(self, data, size):
        pass

    pass


def readDebugLink(path: Path):

    class DL:
        debug_link = None

        def __call__(self, m):
            self.debug_link = m.group(1)

        pass

    dl = DL()

    relst = RegexpReaderListener(
        "readelf",
        parser=comm.RegexpParser("^\\s+\\[\\s*0\\]\\s+(\\S+)\\s*$", dl),
    )
    args = ["/usr/bin/readelf", "--string-dump=.gnu_debuglink", str(path)]

    runCommandWithoutInputFull(
        args,
        stdout=PIPE,
        stderr=PIPE,
        stdout_listener=relst,
        stderr_listener=SilentReaderListener(),
    ).join()

    return dl.debug_link


def readSectionHeaders(path: Path, binary_id=None, callback=None):
    class Sections:
        callback = None
        binary_id = None

        def __init__(self, binary_id=None, callback=None):
            self.binary_id = binary_id
            self.callback = callback
            pass

        def __call__(self, m):
            if self.callback:
                self.callback(
                    SectionHeader(
                        binary_id=self.binary_id,
                        idx=int(m.group(1)),
                        name=m.group(2),
                        size=int(m.group(3), 16),
                        vma=int(m.group(4), 16),
                        lma=int(m.group(5), 16),
                        off=int(m.group(6), 16),
                        align=int(m.group(7)),
                    )
                )
            pass

        pass

    s = Sections(binary_id)

    relst = RegexpReaderListener(
        "objdump",
        parser=comm.RegexpParser(
            r"^\s*(\d+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+2\*\*(\d+)$",
            s,
        ),
    )
    args = ["/usr/bin/objdump", "-h", str(path)]

    return runCommandWithoutInput(
        args, stdout_listener=relst, stderr_listener=SilentReaderListener()
    ).join()


def readSymbols(path: Path, binary_id=None, callback=None):

    class Symbols:
        binary_id = None
        callback = None

        def __init__(self, binary_id, callback):
            self.binary_id = binary_id
            self.callback = callback
            pass

        def __call__(self, m):
            section = m.group(4)
            if section not in ["*ABS*", "*UND*"]:
                if self.callback:
                    self.callback(
                        Symbol(
                            binary_id=self.binary_id,
                            address=int(m.group(1), 16),
                            scope=m.group(2),
                            sym_type=m.group(3),
                            section=m.group(4),
                            size=int(m.group(5), 16),
                            name=m.group(6),
                        )
                    )
            pass

        pass

    s = Symbols(binary_id, callback)

    relst = RegexpReaderListener(
        "objdump",
        parser=comm.RegexpParser(
            r"^([0-9a-fA-F]+)\s(.{1,2})\s{4,5}(.{1,2})\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)\s*$",
            s,
        ),
    )
    args = ["/usr/bin/objdump", "--syms", str(path)]

    return runCommandWithoutInput(
        args, stdout_listener=relst, stderr_listener=SilentReaderListener()
    ).join()


class MemoryMapping:
    def __init__(self, start_addr, end_addr, offset, perm, pathname):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.size = end_addr - start_addr
        self.offset = offset
        self.perm = perm
        self.pathname = pathname
        pass

    def fromMappedToFileAddress(self, in_addr):
        return in_addr - self.start_addr + self.offset

    def __str__(self):
        pathname = self.pathname
        perm = self.perm
        if pathname is None:
            pathname = ""
        if perm is None:
            perm = "????"

        return f"{self.start_addr:#18x} {self.end_addr:#18x} {self.size:#18x} {self.offset:#18x} {perm} {pathname}"


xd = "[0-9a-fA-F]"
xn = f"(?:0[xX])?{xd}+"


class RePatterns:
    gdb_maps_pattern = re.compile(
        f"^\\s*(?P<start_addr>{xn})\\s+(?P<end_addr>{xn})\\s+(?P<size>{xn})\\s+(?P<offset>{xn})\\s+(?P<perm>[r\\-][w\\-][x\\-][ps])?(?:\\s+(?P<pathname>\\S+))?\\s*$"
    )
    proc_maps_pattern = re.compile(
        f"^\\s*(?P<start_addr>{xn})-(?P<end_addr>{xn})\\s+(?P<perm>[r\\-][w\\-][x\\-][ps])\\s+(?P<offset>{xn})\\s+(?P<major>{xn}):(?P<minor>{xn})\\s+(\\d+)\\s+(?P<pathname>\\S+)?\\s*$"
    )
    pass


class MemoryMappings:
    mappings = []
    patterns = RePatterns()

    def __init__(self):
        pass

    def parseMapsLine(self, line, pattern):
        m = re.match(pattern, line, flags=0)
        if m:
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

    def parseProcMapsLine(self, line):
        self.parseMapsLine(line, self.patterns.proc_maps_pattern)
        pass

    def parseGDBMapsLine(self, line):
        self.parseMapsLine(line, self.patterns.gdb_maps_pattern)
        pass

    def findMapping(self, addr):
        for mapping in self.mappings:
            if mapping.start_addr <= addr and mapping.end_addr >= addr:
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
            f"{start_addr:>18s} {end_addr:>18s} {size:>18s} {offset:>18s} {perm:>4s} {pathname}"
        )
        for m in self.mappings:
            print(f"{m}")

    pass


def addr2line(self, path: str, addresses):

    main_line = re.compile("^([^:]+):([^:]+): (\\S.+\\S) at ([^:]+):(\\d+).*$")
    inlined_line = re.compile(
        "^ \\(inlined by\\) (\\S.+\\S) at ([^:]+):(\\d+).*$"
    )
    no_addrline = re.compile("^([^:]+):([^:]+): \\?\\? \\?\\?:0.*$")

    binAddr2line = {}

    args = ["addr2line", "-ipfC", path]
    relst = RegexpReaderListener("addr2line")
    relst.addParser()
    runCommandWithInput(args)
    with open(f"{in_dir}/addr2line.txt", "r") as addr2line_file:
        binary = None
        address = 0
        symbol = ""
        file = ""
        line = ""
        addr2lines = None
        for line in addr2line_file:
            main_match = re.match(main_line, line, flags=0)
            inlined_match = re.match(inlined_line, line, flags=0)
            if main_match is not None:
                binary, address, symbol, file, line = main_match.group(
                    1, 2, 3, 4, 5
                )
                # print(f"main: {binary} {address} {symbol} {file} {line}")
                if binAddr2line is not None:
                    if binary not in binAddr2line:
                        binAddr2line[binary] = []

                addr2lines = Addr2Lines(binary, address, symbol, file, line)
                binAddr2line[binary].append(addr2lines)

            elif inlined_match is not None:
                symbol, file, line = inlined_match.group(1, 2, 3)
                # print(f"inlined: {binary} {address} {symbol} {file} {line}")
                if addr2lines is not None:
                    addr2lines.add(symbol, file, line)
                else:
                    print(f"wtf: no addr2lines for (inlined by)")
            else:
                print(f"wtf: {line}")
        pass
    return binAddr2line


def loadMappings(file_name: str):
    mmaps = MemoryMappings()
    with open(file_name, "r") as maps:
        for line in maps:
            mmaps.parseProcMapsLine(line)
            mmaps.parseGDBMapsLine(line)
            pass
        pass
    pass


def testBinary():
    path = Path(
        "/home/yvdev/PrivProjects/blackadder/scripts/GDB/yvos/zinc/opt/zinc/oss/lib/libWPEWebKit-1.1.so.0.0.7"
    )
    path = Path(
        "/home/yvdev/PrivProjects/blackadder/scripts/GDB/yvos/zinc/opt/zinc/lib/debug/opt/zinc/oss/lib/libgstreamer-1.0.so.0.1602.0.debug"
    )
    path = Path(
        "/home/yvdev/PrivProjects/blackadder/scripts/GDB/yvos/zinc/opt/zinc/lib/debug/opt/zinc/oss/lib/libWPEWebKit-1.1.so.0.0.7.debug"
    )
    md5hash = md5sum(path)
    debug_link = readDebugLink(path)
    print(f"debug_link: {debug_link}")

    for sh in readSectionHeaders(path, md5hash):
        print(f"{path.name}: {sh}")

    for sym in readSymbols(path):
        print(f"{path.name}: {sym}")
    pass


def main():
    mmaps = MemoryMappings()

    if len(argv) > 1:
        with open(argv[1], "r") as maps:
            for line in maps:
                mmaps.parseProcMapsLine(line)
                mmaps.parseGDBMapsLine(line)
                pass
            pass
        pass
    mmaps.print(None)


if __name__ == "__main__":
    main()
