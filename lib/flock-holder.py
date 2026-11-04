"""Hold an OS flock only while the owning Node process keeps stdin open.

The lock file is never unlinked: waiters must always lock the same inode.
Nonblocking acquisition also watches stdin, so a killed waiting parent cannot
leave an orphan that later acquires the lock. No credentials cross this pipe.
"""
import fcntl
import os
import select
import sys

fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
try:
    while True:
        if select.select([sys.stdin.buffer], [], [], 0)[0]:
            if not os.read(0, 1):
                sys.exit(0)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if select.select([sys.stdin.buffer], [], [], 0.025)[0]:
                if not os.read(0, 1):
                    sys.exit(0)
    print("locked", flush=True)
    while os.read(0, 1):
        pass
finally:
    os.close(fd)
