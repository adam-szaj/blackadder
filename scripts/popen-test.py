#!/usr/bin/env python3

import subprocess as subp
import threading as th


class Reader(th.Thread):
    def __init__(self, output, output_cb):
        th.Thread.__init__(self)
        self.output = output
        self.output_cb = output_cb
        pass

    def run(self):
        for line in self.output:
            self.output_cb(line)
        pass

    pass


def runCommandTest():
    args = [
        "/usr/bin/addr2line",
        "-e",
        "/opt/nfsroot/adam.szaj/enable-stacktrace-without-debug-info/yvos.sagemcom.rtiw387-atk-bolt/yvos/zinc/opt/zinc/lib/debug/opt/zinc/oss/lib/libgio-2.0.so.0.7000.1.debug",
        "-afpi",
    ]
    popen = subp.Popen(
        args,
        stdin=subp.PIPE,
        stderr=subp.PIPE,
        stdout=subp.PIPE,
        universal_newlines=True,
        bufsize=1,
        text=True,
        encoding="utf-8",
    )

    lines = ["0x00046af2", "0x000707f0", "0x0004f340"]
    # print(popen.__dict__)
    stdout_reader = Reader(popen.stdout, lambda line: print(line, end=""))
    stdout_reader.start()
    for line in lines:
        popen.stdin.write(f"{line}\n")
    popen.stdin.close()
    stdout_reader.join()


def defaultStderrCallback(line):
    print(f"stderr: {line}", end="")
    pass


def defaultStdoutCallback(line):
    print(f"stdout: {line}", end="")
    pass


class CommandInput:
    def __init__(self, popen, stdout_th, stderr_th):
        self.popen = popen
        self.stdout_th = stdout_th
        self.stderr_th = stderr_th
        pass

    def open(self):
        self.stdout_th.start()
        self.stderr_th.start()

    def write(self, args):
        self.popen.stdin.write(args)
        pass

    def close(self):
        self.popen.stdin.close()
        self.stdout_th.join()
        self.stderr_th.join()
        pass


def runCommandWithInput(args, stdout_cb, stderr_cb=defaultStderrCallback):
    popen = subp.Popen(
        args,
        stdin=subp.PIPE,
        stderr=subp.PIPE,
        stdout=subp.PIPE,
        universal_newlines=True,
        bufsize=1,
        text=True,
        encoding="utf-8",
    )

    stdout_th = Reader(popen.stdout, stdout_cb)
    stderr_th = Reader(popen.stderr, stderr_cb)
    return CommandInput(popen, stdout_th, stderr_th)


def __main__():
    args = [
        "/usr/bin/addr2line",
        "-e",
        "/opt/nfsroot/adam.szaj/enable-stacktrace-without-debug-info/yvos.sagemcom.rtiw387-atk-bolt/yvos/zinc/opt/zinc/lib/debug/opt/zinc/oss/lib/libgio-2.0.so.0.7000.1.debug",
        "-afpi",
    ]
    lines = ["0x00046af2", "0x000707f0", "0x0004f340"]

    input = runCommandWithInput(args, defaultStdoutCallback)
    input.open()
    for line in lines:
        input.write(f"{line}\n")
    input.close()
    pass


__main__()
