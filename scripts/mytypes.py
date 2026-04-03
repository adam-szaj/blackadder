import os.path
import pathlib
import subprocess as subp
import re
from dataclasses import dataclass, astuple, asdict


class Binary:
    def __init__(self, name):
        self.name = name
        self.path = None
        self.debug_name = None
        self.debug_path = None
        self.is_stripped = None
        self.with_debug_info = None
        self.text_offset = None
        self.symbols = []
        self.pcs = {}
        pass

    def addPC(self, pc):
        self.pcs[pc.absPC] = pc

    def __str__(self):
        return f"name: {self.name} path: {self.path} debug_name: {self.debug_name} debug_path: {self.debug_path}"

    def load(self, binLoader):
        binLoader.load(self)
        pass

    def append(self, symbol):
        self.symbols.append(symbol)
        pass

    def findSymbol(self, address):
        for symbol in self.symbols:
            if symbol.containsAddress(address):
                return symbol
        return None
    pass


debug_link_pattern = re.compile('^ +\[ *0\] +([\S]+)$')


class BinaryLoader:

    def __init__(self, rootfs, debug_rootfs):
        self.rootfs_list = rootfs.split(':')
        self.debug_rootfs_list = debug_rootfs.split(':')
        pass

    def debugLinkParser(self, line, binary=None):
        if type(line) is str:
            match_res = re.match(debug_link_pattern, line)
            if match_res is not None:
                debug_link = match_res.group(1)
                if binary is not None:
                   binary.debug_name = debug_link
        pass

    def getDebugLink(self, binary):
        """
        c = comm.runCommandWithoutInputFull(['/usr/bin/readelf', '--string-dump=.gnu_debuglink', binary.path],
                stdin=None,
                stdout=subp.PIPE,
                stderr=subp.PIPE,
                bufsize=1024,
                output_cb_data=binary,
                stdout_cb=self.debugLinkParser,
                stderr_cb=None).join()
        """
        pass

    def readFileInfo(self, path):
        """
        result = comm.runCommand(['/usr/bin/file', path]).split('\n')

        is_elf = False
        has_debug_info = False
        is_dynamically_linked = False
        is_stripped = False

        ares = result[0].split(':')
        if len(ares) == 2:
            ret = {}
            ret['path'] = path
            ret['info'] = set(map(lambda s: s.strip(), ares[1].split(',')))
        else:

            """

        ret = None
        return ret

    def loadDebugLink(self, binary):
        self.getDebugLink(binary)
        pass

    def loadELF(self, binary, path):
        fileInfo = self.readFileInfo(path)
        is_elf = False
        for i in fileInfo['info']:
            if i.startswith('ELF'):
                is_elf = True

        if is_elf:
            binary.path = path
            if 'stripped' in fileInfo["info"]:
                binary.is_stripped = True
            elif 'not stripped' in fileInfo["info"]:
                binary.is_stripped = False

            if 'with debug_info' in fileInfo["info"]:
                binary.with_debug_info = True
                binary.debug_path = path
            else:
                binary.with_debug_info = False
                self.loadDebugLink(binary)
                if binary.debug_name is not None:
                    pp = pathlib.PurePath(binary.name)
                    dpp = pathlib.PurePath(binary.debug_name)
                    if dpp.is_absolute():
                        for p in self.debug_rootfs_list:
                            path_candidate = f"{p}{binary.debug_name}"
                            if os.path.isfile(path_candidate):
                                binary.debug_path = path_candidate
                    else:
                        for p in self.debug_rootfs_list:
                            path_candidate = f"{p}{
                                pp.parent}/{binary.debug_name}"
                            if os.path.isfile(path_candidate):
                                binary.debug_path = path_candidate

            return True

        return False

    def findBinary(self, binary, paths):
        for p in paths:
            path_candidate = f"{p}{binary.name}"
            if os.path.isfile(path_candidate):
                if not self.loadELF(binary, path_candidate):
                    print(f"path '{path_candidate}' exists but is not an ELF")
                else:
                    print(f"{binary}")

    def readTextOffset(self, binary):
        offset = -1


"""
        pattern = re.compile(
            '^ *[0-9]+ +\.text +([0-9a-fA-F]+) +([0-9a-fA-F]+) +([0-9a-fA-F]+) +([0-9a-fA-F]+) +[\S]+$')
        for line in comm.runCommand(['/usr/bin/objdump', '-j', '.text', '-h', binary.path ]).split('\n'):
            m = re.match(pattern, line)
            if m is not None:
                offset = int(m.group(4), 16)
"""
        return offset

    def load(self, binary):
        self.findBinary(binary, self.rootfs_list)
        offset = self.readTextOffset(binary)
        binary.text_offset = offset
        # print(f"{binary.name} offset: {offset:#x}")
        pass

class MemoryMapping:
    def __init__(self, addr_from, addr_to, perms, offset, objname):
        self.addr_from = addr_from
        self.addr_to = addr_to
        self.size = addr_to - addr_from
        self.offset = offset
        self.perms = perms 
        self.objname = objname
        self.binary = None
        pass

    def containsAddress(self, pc):
        return self.addr_from <= pc and self.addr_to >= pc

    def unmapAddress(self, pc):
        if self.containsAddress(pc):
            return pc - self.addr_from + self.offset
        return -1

    def __str__(self):
        return "{addr_from:#16x} {addr_to:#16x} {size:#10x} {offset:#10x} {perms:4} {objname}".format(
                addr_from=self.addr_from,
                addr_to=self.addr_to,
                size=self.size,
                offset=self.offset,
                perms=self.perms,
                objname=self.objname
                )
        pass

class MemoryMappings:
    def __init__(self):
        self.mappings = []

    def readMappings(self, filename):
        with open(filename, 'r') as maps:
            for line in maps:
                line = line.strip()
                x = line.split(' ')
                if len(x) == 7:
                    self.mappings.append(MemoryMapping(int(x[0],0), int(x[1],0), x[2], int(x[3], 0), x[6]))
                elif len(x) == 6:
                    self.mappings.append(MemoryMapping(int(x[0],0), int(x[1],0), x[2], int(x[3], 0), None))
        pass

    def findMapping(self, addr):
        for mapping in self.mappings:
            if mapping.containsAddress(addr):
                return mapping
        return None
    pass

class StaticProgramCounter:
    def __init__(self):
        pass

class ProgramCounter:
    def __init__(self, rtpc, absPC, binary):
        self.rtPC = rtpc
        self.absPC = absPC
        self.guessPC = 0
        self.symbol = None
        self.binary = binary
        if self.binary is not None:
            self.binary.addPC(self)
        pass
    def __str__(self):
        return f"rtpc: {self.rtPC} abspc: {self.absPC}"

class Backtrace:
    def __init__(self, btid, refcnt):
        self.btid = btid
        self.refcnt = refcnt
        self.pcs = []
        pass

    def add(self, pc):
        self.pcs.append(pc)
        pass
    
    def __str__(self):
        depth = len(self.pcs)
        return f"{self.btid:#x} depth: {depth} refcnt: {self.refcnt}"
    pass

class Backtraces:
    def __init__(self):
        self.backtraces = {}
        self.pcs = {}
        self.currentBacktrace = None
        pass

    def addPC(self, pc, mappings):
        if pc not in self.pcs:
            binary = None
            m = mappings.findMapping(pc)
            absPC = None

            if m is not None:
                binary = m.binary
                absPC = m.unmapAddress(pc)

            if binary is not None:
                # print(f"pc: {pc:#x} -> {binary.name}")
                pass
            else:
                print(f"pc: {pc:#x} -> <none>")

            aPC = ProgramCounter(pc, absPC, binary)
            self.pcs[pc] = aPC
        else:
            aPC = self.pcs[pc]

        self.currentBacktrace.add(aPC)
        pass

    def addBacktrace(self, btid, refcnt):
        self.currentBacktrace = Backtrace(btid, refcnt)
        self.backtraces[btid] = self.currentBacktrace
        pass

    def printBacktraces(self):

        print("print backtraces in progress")
        with open(f"./{PID}/backtraces.txt", 'w') as out:
            for btid, bt in self.backtraces.items():
                out.write(f"backtrace: {btid}\n")
                idx0=0
                for pc in bt.pcs:
                    if pc is not None:
                        if pc.addr2lines is not None:
                            idx = 0
                            for bt in pc.addr2lines.bt:
                                out.write(f"{idx0:02d}.{idx:02d}: {pc.pc:#x} {pc.binary}:{pc.guess_pc:#x} {bt}\n")
                                idx = idx + 1
                    idx0 = idx0 + 1
        pass
    pass


