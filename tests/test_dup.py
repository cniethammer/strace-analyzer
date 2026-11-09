"""Tests for duplicating file descriptors with dup(), dup2() and dup3().

A duplicated file descriptor refers to the same file, so I/O on it is
accounted to that file. As for the existing dup2() handling, each
successful duplication counts as an open of the file.
"""

OPEN_DATA = """
    100 0.000000 openat(AT_FDCWD, "data.bin", O_WRONLY|O_CREAT, 0644) = 3 <0.000010>
"""


def test_dup(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup(3) = 4 <0.000010>
    100 0.000010 write(4, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["open_count"] == 2
    assert stats["data.bin"]["write_size"] == 10


def test_dup2(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup2(3, 5) = 5 <0.000010>
    100 0.000010 write(5, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["open_count"] == 2
    assert stats["data.bin"]["write_size"] == 10


def test_dup3(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup3(3, 5, O_CLOEXEC) = 5 <0.000010>
    100 0.000010 write(5, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["open_count"] == 2
    assert stats["data.bin"]["write_size"] == 10


def test_duplicate_stays_valid_after_closing_original(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup(3) = 4 <0.000010>
    100 0.000010 close(3) = 0 <0.000010>
    100 0.000010 write(4, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["write_size"] == 10


def test_dup2_redirects_stdout(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup2(3, 1) = 1 <0.000010>
    100 0.000010 write(1, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["write_size"] == 10
    assert stats["stdout"]["write_count"] == 0


def test_dup2_onto_open_fd_replaces_it(parse):
    # the file previously open on fd 4 is closed implicitly
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 openat(AT_FDCWD, "other.bin", O_WRONLY|O_CREAT, 0644) = 4 <0.000010>
    100 0.000010 dup2(3, 4) = 4 <0.000010>
    100 0.000010 write(4, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["write_size"] == 10
    assert stats["other.bin"]["write_count"] == 0


def test_dup2_onto_itself_is_no_new_open(parse):
    # dup2(fd, fd) only checks that fd is valid
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup2(3, 3) = 3 <0.000010>
    """)
    assert stats["data.bin"]["open_count"] == 1


def test_failed_duplication_is_ignored(parse):
    stats, _ = parse(OPEN_DATA + """
    100 0.000010 dup(9) = -1 EBADF (Bad file descriptor) <0.000010>
    100 0.000010 dup2(9, 5) = -1 EBADF (Bad file descriptor) <0.000010>
    100 0.000010 dup3(9, 5, 0) = -1 EBADF (Bad file descriptor) <0.000010>
    100 0.000010 dup3(3, 3, 0) = -1 EINVAL (Invalid argument) <0.000010>
    """)
    assert stats["data.bin"]["open_count"] == 1


def test_duplicating_unknown_fd_does_not_crash(parse, caplog):
    # e.g. a file descriptor inherited from outside of the trace
    stats, _ = parse("""
        100 0.000000 dup2(7, 1) = 1 <0.000010>
        100 0.000010 write(1, "0123456789", 10) = 10 <0.000010>
    """)
    assert "file descriptor 7" in caplog.text
    assert stats["stdout"]["write_count"] == 0
