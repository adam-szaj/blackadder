#!/usr/bin/env python3

import re
import subprocess as subp
import threading as th


def defaultStderrCallback(user_data, line):
    print(f"stderr: {line}", end="")
    pass


def defaultStdoutCallback(user_data, line):
    print(f"stdout: {line}", end="")
    pass


class ReaderListener:
    def __init__(self, name=""):
        self.name = name
        pass

    def onData(self, buff, size):
        print(f"[{self.name}] data: {size} bytes")
        s = str(buff[0:size])
        print(f"[{self.name}] {s}")
        pass

    def onLine(self, line):
        print(f"[{self.name}] line: '{line}'", end="")
        pass

    pass


class Reader(th.Thread):
    def __init__(self, output, listener, text=True):
        th.Thread.__init__(self)
        self.text = text
        if output is None:
            raise Exception("output is none")
        self.output = output
        self.listener = listener
        pass

    def run(self):
        if self.text:
            # print("read output as text")
            for line in self.output:
                self.listener.onLine(line)
        else:
            buff = bytearray(1024)
            size = 0
            while True:
                size = self.output.readinto(buff)
                if size <= 0:
                    break
                self.listener.onData(buff, size)

    pass


class CommandWithInput:
    def __init__(self, popen, stdout_th, stderr_th):
        self.popen = popen
        self.stdout_th = stdout_th
        self.stderr_th = stderr_th
        pass

    def open(self):
        if self.stdout_th is not None:
            self.stdout_th.start()
        if self.stderr_th is not None:
            self.stderr_th.start()
        return self

    def write(self, args):
        if self.popen.stdin is not None:
            self.popen.stdin.write(args)
        else:
            raise Exception("stdin is None")

    def join(self):
        if self.popen.stdin is not None:
            self.popen.stdin.close()
        if self.stdout_th is not None:
            self.stdout_th.join()
        if self.stderr_th is not None:
            self.stderr_th.join()
        return self


def runCommandSimple(args, text=True):
    result = subp.run(args, capture_output=True, text=text)
    return result.stdout.strip()


def runCommandWithoutInputFull(
    args,
    bufsize=-1,
    executable=None,
    stdin=None,
    stdout=None,
    stderr=None,
    preexec_fn=None,
    close_fds=True,
    shell=False,
    cwd=None,
    env=None,
    startupinfo=None,
    creationflags=0,
    restore_signals=True,
    start_new_session=False,
    pass_fds=(),
    group=None,
    extra_groups=None,
    user=None,
    umask=-1,
    encoding=None,
    errors=None,
    text=None,
    pipesize=-1,
    process_group=None,
    stdout_listener=ReaderListener("stdout"),
    stderr_listener=ReaderListener("stderr"),
):

    popen = subp.Popen(
        args,
        bufsize=bufsize,
        executable=executable,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        preexec_fn=preexec_fn,
        close_fds=close_fds,
        shell=shell,
        cwd=cwd,
        env=env,
        startupinfo=startupinfo,
        creationflags=creationflags,
        restore_signals=restore_signals,
        start_new_session=start_new_session,
        pass_fds=pass_fds,
        group=group,
        extra_groups=extra_groups,
        user=user,
        umask=umask,
        encoding=encoding,
        errors=errors,
        text=text,
        pipesize=pipesize,
    )

    if popen.stdout is not None and stdout_listener is not None:
        stdout_th = Reader(popen.stdout, listener=stdout_listener, text=text)
    else:
        stdout_th = None

    if popen.stderr is not None and stderr_listener is not None:
        stderr_th = Reader(popen.stderr, listener=stderr_listener, text=text)
    else:
        stderr_th = None

    return CommandWithInput(popen, stdout_th, stderr_th).open()


def runCommandWithoutInput(
    args,
    stdout_listener=ReaderListener("stdout"),
    stderr_listener=ReaderListener("stderr"),
):

    return runCommandWithoutInputFull(
        args,
        stdin=None,
        stderr=subp.PIPE,
        stdout=subp.PIPE,
        bufsize=1,
        text=True,
        encoding="utf-8",
        stdout_listener=stdout_listener,
        stderr_listener=stderr_listener,
    )


def runCommandWithInput(
    args,
    stdout_listener=ReaderListener("stdout"),
    stderr_listener=ReaderListener("stderr"),
):
    return runCommandWithoutInputFull(
        args,
        stdin=subp.PIPE,
        stderr=subp.PIPE,
        stdout=subp.PIPE,
        bufsize=1,
        text=True,
        encoding="utf-8",
        stdout_listener=stdout_listener,
        stderr_listener=stderr_listener,
    )


def runCommandWithoutInputBinaryOutput(
    args,
    stdout_listener=ReaderListener("stdout"),
    stderr_listener=ReaderListener("stderr"),
):

    return runCommandWithoutInputFull(
        args,
        stdin=None,
        stderr=subp.PIPE,
        stdout=subp.PIPE,
        bufsize=1024,
        text=False,
        stdout_listener=stdout_listener,
        stderr_listener=stderr_listener,
    )


def runCommandWithInputBinaryOutput(
    args,
    stdout_listener=ReaderListener("stdout"),
    stderr_listener=ReaderListener("stderr"),
):
    return runCommandWithoutInputFull(
        args,
        stdin=subp.PIPE,
        stderr=subp.PIPE,
        stdout=subp.PIPE,
        bufsize=1024,
        text=False,
        stdout_listener=stdout_listener,
        stderr_listener=stderr_listener,
    )


class RegexpParser:
    def __init__(self, pattern, callback=None):
        if pattern is None:
            raise Exception("pattern is None")

        self.callback = callback
        self.pattern = None

        if type(pattern) is str:
            self.pattern = re.compile(pattern)
        elif type(pattern) is re.Pattern:
            self.pattern = pattern
        else:
            raise Exception("pattern is nither string nor re.Pattern")

    def onMatch(self, match):
        if self.callback is not None:
            self.callback(match)
        else:
            g = match.groups()
            print(f"match: {g}")

    def __call__(self, line):
        m = re.match(self.pattern, line, flags=0)
        if m is not None:
            self.onMatch(m)
        else:
            # print(f"failed to match: '{self.pattern}' vs '{line}'")
            pass

    pass


class RegexpReaderListener(ReaderListener):
    def __init__(self, name, parser=None, pattern=None, callback=None):
        ReaderListener.__init__(self, name)
        self.parsers = []

        if parser is not None:
            self.addParser(parser)
        elif pattern is not None and callback is not None:
            self.addSimpleParser(pattern, callback)

    def addParser(self, parser):
        if isinstance(parser, RegexpParser):
            self.parsers.append(parser)
        else:
            raise Exception("parser is not instance of RegexpParser")

    def addSimpleParser(self, pattern, callback):
        self.addParser(RegexpParser(pattern, callback))

    def onData(self, data, size):
        f = 0
        i = 0
        data = data[0:size]
        bs = bytes(data)
        # print(f"data: {data}\nbytes: {bs}")
        for b in bs:
            # print(f'byte: {b:02x}')
            line = None
            if b == 0x0A:
                try:
                    line = bs[f:i]
                    line = line.decode("utf-8")
                    # print(f"line: {line}")
                    self.onLine(line)
                except Exception as e:
                    print(f"Exception: '{line}': {e}")
                    pass
                finally:
                    f = i
                    pass
                """
                """
            i = i + 1
        pass

    def onLine(self, line):
        # print(f"line: '{line}'")
        for parser in self.parsers:
            parser(line)
