"""Tests for syscalls copying data between file descriptors in the kernel.

The trace lines follow the format of strace 7.3.
"""
import pytest

OPEN_SRC_DST = """
    100 0.000000 openat(AT_FDCWD, "src.bin", O_RDONLY) = 3 <0.000010>
    100 0.000010 openat(AT_FDCWD, "dst.bin", O_WRONLY|O_CREAT, 0644) = 4 <0.000010>
"""


@pytest.mark.parametrize("line", [
    "splice(3, [220], 4, NULL, 80, 0) = 80 <0.000022>",
    "copy_file_range(3, [100], 4, [100], 80, 0) = 80 <0.000020>",
    # note the reversed order of the file descriptors
    "sendfile(4, 3, [0 => 80], 80) = 80 <0.000037>",
])
def test_copy_counts_read_and_write(parse, line):
    stats, _ = parse(OPEN_SRC_DST + "    100 0.000010 " + line + "\n")
    assert stats["src.bin"]["read_count"] == 1
    assert stats["src.bin"]["read_size"] == 80
    assert stats["dst.bin"]["write_count"] == 1
    assert stats["dst.bin"]["write_size"] == 80


def test_splice_end_of_input_counts_only_read(parse):
    stats, _ = parse(OPEN_SRC_DST + """
    100 0.000010 splice(3, NULL, 4, NULL, 524288, 0) = 0 <0.000012>
    """)
    assert stats["src.bin"]["read_count"] == 1
    assert stats["dst.bin"]["write_count"] == 0


def test_failed_copy_is_not_counted(parse):
    stats, _ = parse(OPEN_SRC_DST + """
    100 0.000010 copy_file_range(3, NULL, 4, NULL, 4096, 0) = -1 EXDEV (Invalid cross-device link) <0.000012>
    """)
    assert stats["src.bin"]["read_count"] == 0
    assert stats["dst.bin"]["write_count"] == 0


def test_tee_counts_only_write(parse):
    # tee duplicates pipe data without consuming it from the input
    stats, _ = parse("""
        100 0.000000 pipe2([3, 4], 0) = 0 <0.000010>
        100 0.000010 openat(AT_FDCWD, "dst.bin", O_WRONLY|O_CREAT, 0644) = 5 <0.000010>
        100 0.000010 tee(3, 5, 65536, 0) = 80 <0.000012>
    """)
    assert stats["<pipe>"]["read_count"] == 0
    assert stats["dst.bin"]["write_size"] == 80
