#!/usr/bin/env python3

from blackadder_db import DataBase
from blackadder_types import (
    BinaryLocator,
    Binary,
    BinaryFinder,
    SectionHeader,
    Symbol,
)
from blackadder_binutils import (
    readDebugLink,
    md5sum,
    readSectionHeaders,
    readSymbols,
    loadMappings,
)
import argparse
import configparser


class BlackAdder:
    def __init__(self, config):
        self.config = config
        self.finder = BinaryFinder(config)
        self.db = DataBase(config["main"]["database"], echo=False)

        self.subcommands = {}
        self.subcommands["syms"] = self.__onSyms
        self.subcommands["load"] = self.__onLoad
        self.subcommands["addr2line"] = self.__onAddr2Line
        pass

    def fetchOrCreateDebugBinary(self, binary: Binary) -> Binary:
        ret_binary = None
        if binary.debug_link:
            debug_binary_locations = self.finder.findDebugBinary(
                binary.name, binary.debug_link
            )

            for debug_binloc in debug_binary_locations:
                print(f"debug_binloc: {debug_binloc}")
                newBinLoc = self.db.fetchBinaryLocatorByPath(debug_binloc.path)

                if newBinLoc is None or newBinLoc.mtime < binloc.mtime:
                    newBinLoc = self.reloadBinaryLocator(debug_binloc)
                    if newBinLoc:
                        self.db.insertOrUpdateBinaryLocator(newBinLoc)

                print(f"call fetchOrCreateBinary for debug_loc: {newBinLoc}")
                ret_binary = self.fetchOrCreateBinary(newBinLoc)

        else:
            # TODO check if binary has .debug_info section
            # then return binary itself
            session = self.db.session
            for r in (
                session.query(SectionHeader)
                .filter(SectionHeader.binary_id == binary.id)
                .filter(SectionHeader.name == ".debug_info")
            ):
                print("return self as it contains .debug_info section")
                return r

        print(f"debug_link binary: {ret_binary}")
        return ret_binary

    def fetchOrCreateBinary(self, binloc: BinaryLocator):

        binary = self.db.fetchBinaryByMd5Sum(binloc.md5sum)
        if binary is None:
            binary = Binary(
                md5sum=binloc.md5sum,
                name=binloc.name,
                debug_link=readDebugLink(binloc.path),
            )
            print(f"binary: {binary}")

            self.db.insertOrUpdateBinary(binary)
            self.fetchOrCreateDebugBinary(binary)

            readSectionHeaders(
                binloc.path, binary.id, lambda sh: self.db.session.add(sh)
            )
            readSymbols(
                binloc.path, binary.id, lambda s: self.db.session.add(s)
            )

            self.db.session.commit()

        else:
            print(f"fetchOrCreateBinary found binary: {binary}")

        print(f"fetchOrCreateBinary: {binary}")
        return binary

    def reloadBinaryLocator(self, binloc: BinaryLocator):
        binloc.md5sum = md5sum(binloc.path)

        return binloc

    def __handleLoad(self, binloc: BinaryLocator):

        newBinLoc = self.db.fetchBinaryLocatorByPath(binloc.path)

        if newBinLoc is None or newBinLoc.mtime < binloc.mtime:
            newBinLoc = self.reloadBinaryLocator(binloc)
            if newBinLoc:
                self.db.insertOrUpdateBinaryLocator(newBinLoc)

        return self.fetchOrCreateBinary(newBinLoc)

    def loadBinary(self, binloc: BinaryLocator):
        return self.__handleLoad(binloc)

    def findBinaries(self, binary_name: str):
        res = self.db.session.query(Binary).filter(Binary.name == binary_name)
        binaries = [bin for bin in res]
        if binaries:
            return binaries
        return [
            self.loadBinary(bl)
            for bl in self.finder.findBinary(binary_name)
            if bl is not None
        ]

    def findFirstBinary(self, binary_name: str):
        binaries = self.findBinaries(binary_name)
        if binaries:
            if type(binaries) is list:
                return binaries[0]
            return binaries
        return None

    def __onLoad(self, args):
        if args.executables is not None:
            for e in args.executables:
                binlocs = self.finder.findBinary(e)
                for bl in binlocs:
                    self.__handleLoad(bl)
        pass

    def __onSyms(self, args):
        binary = None
        maps = None
        if args.executable:
            binary = self.findFirstBinary(args.executable)
        elif args.maps:
            maps = loadMappings(args.maps)

        if binary is None:
            print(f"no binary: {args.executable}")
            return
        if args.addresses:
            for a in args.addresses:
                addr = int(a, 0)
                bin_name = binary.name
                # print(f"addr: {addr:#x} bin: {binary.name}")
                found = False
                while not found:
                    if binary:
                        for r in (
                            self.db.session.query(Symbol)
                            .filter(Symbol.binary_id == binary.id)
                            .filter(Symbol.address <= addr)
                            .filter((Symbol.address + Symbol.size) > addr)
                        ):
                            off = addr - r.address
                            print(
                                f"{addr:#18x} {bin_name:50} {r.name}<+{
                                    off:#x}>"
                            )
                            found = True
                            break
                    else:
                        break

                    if not found:
                        if binary.debug_link:
                            binary = self.findFirstBinary(binary.debug_link)
                            if binary is None:
                                break
                        else:
                            break

        pass

    def __onAddr2Line(self, args):
        raise Exception("Not Implemented command: 'addr2line'")
        pass

    def processCommand(self, args):
        if "subcommand" in args:
            if args.subcommand in self.subcommands:
                self.subcommands[args.subcommand](args)

    pass


def initLoadParser(subparsers):
    parser = subparsers.add_parser("load", help="load executable data")
    parser.add_argument("-e", "--executable", dest="executables", nargs="+")
    parser.set_defaults(subcommand="load")
    pass


def initSymsParser(subparsers):
    parser = subparsers.add_parser(
        "syms", help="prints a symbol asociated with given address"
    )

    parser.add_argument("-a", "--address", dest="addresses", nargs="*")
    parser.add_argument(
        "-e", "--executable", dest="executable", nargs="?", default=None
    )
    parser.add_argument(
        "-m", "--maps-file", dest="maps", nargs="?", default=None
    )
    parser.set_defaults(subcommand="syms")
    pass


def initAddr2LineParser(subparsers):
    parser = subparsers.add_parser(
        "addr2line", help="prints <file>:<line> asociated with given address"
    )
    parser.add_argument("-a", "--address", dest="addresses", nargs="*")
    parser.add_argument(
        "-b", "--backtrace", dest="backtrace", action="store_true"
    )
    parser.add_argument(
        "-e", "--executable", dest="executable", nargs="?", default=None
    )
    parser.add_argument(
        "-m", "--maps-file", dest="maps", nargs="?", default=None
    )
    parser.set_defaults(subcommand="addr2line")


def initCommandLineParser() -> argparse.ArgumentParser:
    mainParser = argparse.ArgumentParser(
        usage="%(prog)s [OPTION]",
        description="PostProcessor of the yamw log file",
    )
    mainParser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"{mainParser.prog} version 1.0.0",
    )
    mainParser.add_argument(
        "-v", "--verbose", dest="verbose", action="store_true"
    )
    mainParser.add_argument(
        "-r", "--rootfs", dest="rootfs", default=[], nargs="*"
    )
    mainParser.add_argument(
        "-d", "--debugfs", dest="debugfs", default=[], nargs="*"
    )
    mainParser.add_argument(
        "-c", "--config", dest="config", default="blackadder.conf", nargs="?"
    )
    mainParser.add_argument("-b", "--database", dest="database", nargs="?")
    mainParser.add_argument(
        "-p", "--progress", dest="progress", action="store_true"
    )

    subparsers = mainParser.add_subparsers(
        help="sub-command --help", required=False
    )
    initLoadParser(subparsers)
    initSymsParser(subparsers)
    initAddr2LineParser(subparsers)

    # mainParser.add_argument('files', nargs='*', default=['-'])
    return mainParser


def processArgs():
    mainParser = initCommandLineParser()
    args = mainParser.parse_args()
    return args


def readConfig(args):
    config = configparser.ConfigParser()
    if args.config is not None:
        config.read(args.config)
        """
        for c in config:
            for s in config[c]:
                v = config[c][s]
                print(f"{c} -> {s}: {v}")
        """
    # print("database:", config['main']['database'])
    return config


def main():
    args = processArgs()
    # print(args)
    blackAdder = BlackAdder(readConfig(args))
    blackAdder.processCommand(args)
    pass


if __name__ == "__main__":
    main()
