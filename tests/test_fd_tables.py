"""Tests for tracking file descriptors per process (strace -f traces)."""


def test_fork_child_keeps_fd_closed_by_parent(parse):
    # bash pipeline: the parent closes its write end of the pipe after the
    # fork, the child still uses its copy to redirect stdout into the pipe
    stats, _ = parse("""
        100 0.000000 pipe2([3, 4], 0) = 0 <0.000010>
        100 0.000010 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7f0000000000) = 101 <0.000100>
        100 0.000010 close(4) = 0 <0.000010>
        101 0.000010 dup2(4, 1) = 1 <0.000010>
        101 0.000010 write(1, "0123456789", 10) = 10 <0.000010>
        100 0.000010 write(1, "parent", 6) = 6 <0.000010>
    """)
    assert stats["<pipe>"]["write_size"] == 10
    assert stats["stdout"]["write_size"] == 6


def test_threads_share_fds(parse):
    stats, _ = parse("""
        100 0.000000 clone(child_stack=0x7f0000000000, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, parent_tid=[101], tls=0x7f0000000000, child_tidptr=0x7f0000000000) = 101 <0.000100>
        101 0.000010 openat(AT_FDCWD, "data.bin", O_WRONLY|O_CREAT, 0644) = 3 <0.000010>
        100 0.000010 write(3, "0123456789", 10) = 10 <0.000010>
    """)
    assert stats["data.bin"]["write_size"] == 10


def test_child_appears_before_clone_returns(parse):
    stats, _ = parse("""
        100 0.000000 openat(AT_FDCWD, "data.bin", O_WRONLY|O_CREAT, 0644) = 3 <0.000010>
        100 0.000010 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD <unfinished ...>
        101 0.000010 write(3, "0123456789", 10) = 10 <0.000010>
        100 0.000010 <... clone resumed>, child_tidptr=0x7f0000000000) = 101 <0.000100>
        101 0.000010 write(3, "abcde", 5) = 5 <0.000010>
    """)
    assert stats["data.bin"]["write_size"] == 15


def test_fd_tables_are_per_input_file(parse):
    # e.g. two MPI ranks, fd 3 is only open in the first one
    stats, _ = parse(
        """
        100 0.000000 openat(AT_FDCWD, "rank0.dat", O_WRONLY|O_CREAT, 0644) = 3 <0.000010>
        """,
        """
        100 0.000000 write(3, "0123456789", 10) = 10 <0.000010>
        """,
    )
    assert stats["rank0.dat"]["write_count"] == 0
