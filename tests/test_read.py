"""Tests for the read syscalls.

The trace lines follow the format of strace 7.3.
"""
import pytest

OPEN_DATA = """
    100 0.000000 openat(AT_FDCWD, "data.bin", O_RDONLY) = 3 <0.000010>
"""


@pytest.mark.parametrize("line", [
    'read(3, "0123456789", 100) = 10 <0.000020>',
    'readv(3, [{iov_base="01234", iov_len=5}, {iov_base="56789", iov_len=5}], 2) = 10 <0.000020>',
    'pread64(3, "0123456789", 100, 200) = 10 <0.000020>',
    'preadv(3, [{iov_base="01234", iov_len=5}, {iov_base="56789", iov_len=5}], 2, 200) = 10 <0.000020>',
    # used by glibc for preadv() on current systems
    'preadv2(3, [{iov_base="01234", iov_len=5}, {iov_base="56789", iov_len=5}], 2, 200, 0) = 10 <0.000020>',
], ids=["read", "readv", "pread64", "preadv", "preadv2"])
def test_read_variants(parse, line):
    stats, _ = parse(OPEN_DATA + "    100 0.000010 " + line + "\n")
    f = stats["data.bin"]
    assert f["read_count"] == 1
    assert f["read_size"] == 10
    assert f["read_time"] == pytest.approx(0.000020)


def test_reads_accumulate(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 read(3, "0123456789", 10) = 10 <0.000020>
    100 0.000010 read(3, "01234", 10) = 5 <0.000030>
    """)
    f = stats["data.bin"]
    assert f["read_count"] == 2
    assert f["read_size"] == 15
    assert f["read_time"] == pytest.approx(0.000050)


def test_read_at_end_of_file(parse):
    # counted as a read of 0 bytes
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 read(3, "", 100) = 0 <0.000020>
    """)
    assert stats["data.bin"]["read_count"] == 1
    assert stats["data.bin"]["read_size"] == 0


@pytest.mark.parametrize("line", [
    'read(3, 0x7f5336939be0, 100) = -1 EAGAIN (Resource temporarily unavailable) <0.000020>',
    'read(3, 0x7f5336939be0, 100) = -1 EIO (Input/output error) <0.000020>',
    'pread64(3, 0x7f5336939be0, 100, 200) = -1 EINVAL (Invalid argument) <0.000020>',
], ids=["EAGAIN", "EIO", "pread64-EINVAL"])
def test_failed_read_is_not_counted(parse, line):
    stats, _ = parse(OPEN_DATA + "    100 0.000010 " + line + "\n")
    assert stats["data.bin"]["read_count"] == 0
    assert stats["data.bin"]["read_size"] == 0
