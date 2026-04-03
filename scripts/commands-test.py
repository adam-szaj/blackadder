#!/usr/bin/env python3

import subprocess as subp
import commands as comm

path = "/home/yvdev/PrivProjects/blackadder/scripts/GDB/yvos/rootfs/usr/lib/libc-2.30.so"
path = "/home/yvdev/PrivProjects/blackadder/scripts/GDB/yvos/zinc/opt/zinc/oss/lib/libWPEWebKit-1.1.so.0.0.7"

comm.runCommandWithoutInputFull(
    ["/usr/bin/readelf", "--string-dump=.gnu_debuglink", path],
    stdin=None,
    stdout=subp.PIPE,
    stderr=subp.PIPE,
    bufsize=1024,
).join()
