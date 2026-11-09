"""Tests for fcntl().

Only the commands F_DUPFD and F_DUPFD_CLOEXEC duplicate a file descriptor.
Their third argument is the lowest acceptable new file descriptor, the new
file descriptor is the return value.

The trace lines follow the format of strace 7.3.
"""
import pytest

OPEN_DATA = """
    100 0.000000 openat(AT_FDCWD, "data.bin", O_WRONLY|O_CREAT, 0644) = 3 <0.000010>
"""


# ---------------------------------------------------------------------------
# only F_DUPFD and F_DUPFD_CLOEXEC duplicate a file descriptor
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("command", ["F_DUPFD", "F_DUPFD_CLOEXEC"])
def test_dupfd_duplicates(parse, command):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 fcntl(3, {}, 10) = 10 <0.000010>
    100 0.000010 write(10, "0123456789", 10) = 10 <0.000010>
    """.format(command))
    assert stats["data.bin"]["open_count"] == 2
    assert stats["data.bin"]["write_size"] == 10


@pytest.mark.parametrize("line", [
    # numeric third argument, which is no file descriptor
    "fcntl(3, F_SETPIPE_SZ, 524288) = 524288 <0.000010>",
    "fcntl(3, F_SETOWN, 1234) = 0 <0.000010>",
    # numeric return value, which is no file descriptor
    "fcntl(3, F_GETPIPE_SZ) = 65536 <0.000010>",
    "fcntl(3, F_GETOWN) = 1234 <0.000010>",
    # flags and locks
    "fcntl(3, F_GETFD) = 0x1 (flags FD_CLOEXEC) <0.000010>",
    "fcntl(3, F_SETFD, FD_CLOEXEC) = 0 <0.000010>",
    "fcntl(3, F_GETFL) = 0x8001 (flags O_WRONLY|O_LARGEFILE) <0.000010>",
    "fcntl(3, F_SETFL, O_WRONLY|O_NONBLOCK) = 0 <0.000010>",
    "fcntl(3, F_SETLK, {l_type=F_WRLCK, l_whence=SEEK_SET, l_start=0, l_len=0}) = 0 <0.000010>",
], ids=["F_SETPIPE_SZ", "F_SETOWN", "F_GETPIPE_SZ", "F_GETOWN", "F_GETFD",
        "F_SETFD", "F_GETFL", "F_SETFL", "F_SETLK"])
def test_other_commands_do_not_duplicate(parse, line):
    stats, _ = parse(OPEN_DATA + "    100 0.000010 " + line + "\n")
    assert stats["data.bin"]["open_count"] == 1
    assert stats["data.bin"]["open_fds"] == [3]


# ---------------------------------------------------------------------------
# the new file descriptor is the return value
# ---------------------------------------------------------------------------

def test_dupfd_registers_correct_fd(parse):
    # e.g. bash 'echo hi 2>&1 >out.bin' when fd 10 is taken already
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 fcntl(3, F_DUPFD, 10) = 11 <0.000010>
    100 0.000010 write(11, "0123456789", 10) = 10 <0.000010>
    100 0.000010 write(10, "abcde", 5) = 5 <0.000010>
    """)
    f = stats["data.bin"]
    assert f["open_fds"] == [3, 11]
    assert f["write_count"] == 1
    assert f["write_size"] == 10
