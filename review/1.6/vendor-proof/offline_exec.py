"""Run a local proof writer or reader with sockets denied. Linux/libseccomp required."""
import ctypes
import errno
import os
import socket
import sys


def deny_sockets():
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7fff0000)
    if not ctx:
        raise RuntimeError("seccomp initialization failed")
    try:
        for name in (b"socket", b"socketpair", b"connect", b"bind", b"listen", b"accept", b"accept4"):
            number = lib.seccomp_syscall_resolve_name(name)
            if number < 0 or lib.seccomp_rule_add(ctx, 0x00050000 | errno.EPERM, number, 0):
                raise RuntimeError("socket policy unavailable")
        if lib.seccomp_load(ctx):
            raise RuntimeError("socket policy could not be loaded")
    finally:
        lib.seccomp_release(ctx)
    try:
        with socket.socket():
            raise RuntimeError("socket negative control failed")
    except PermissionError as error:
        if error.errno != errno.EPERM:
            raise


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("supply executable path and arguments")
    deny_sockets()
    os.execv(sys.argv[1], sys.argv[1:])
