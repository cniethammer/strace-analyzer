"""Tests for the write syscalls.

The trace lines follow the format of strace 7.3.
"""
import pytest

OPEN_DATA = """
    100 0.000000 openat(AT_FDCWD, "data.bin", O_WRONLY|O_CREAT, 0644) = 3 <0.000010>
"""


@pytest.mark.parametrize("line", [
    'write(3, "0123456789", 10) = 10 <0.000020>',
    'writev(3, [{iov_base="01234", iov_len=5}, {iov_base="56789", iov_len=5}], 2) = 10 <0.000020>',
    'pwrite64(3, "0123456789", 10, 200) = 10 <0.000020>',
    'pwritev(3, [{iov_base="01234", iov_len=5}, {iov_base="56789", iov_len=5}], 2, 200) = 10 <0.000020>',
], ids=["write", "writev", "pwrite64", "pwritev"])
def test_write_variants(parse, line):
    stats, _ = parse(OPEN_DATA + "    100 0.000010 " + line + "\n")
    f = stats["data.bin"]
    assert f["write_count"] == 1
    assert f["write_size"] == 10
    assert f["write_time"] == pytest.approx(0.000020)


def test_writes_accumulate(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 write(3, "0123456789", 10) = 10 <0.000020>
    100 0.000010 write(3, "01234", 5) = 5 <0.000030>
    """)
    f = stats["data.bin"]
    assert f["write_count"] == 2
    assert f["write_size"] == 15
    assert f["write_time"] == pytest.approx(0.000050)


def test_partial_write_counts_written_bytes(parse):
    # the return value, not the requested size, is the amount written
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 write(3, "0123456789"..., 100) = 10 <0.000020>
    """)
    assert stats["data.bin"]["write_size"] == 10
