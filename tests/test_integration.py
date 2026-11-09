"""End-to-end tests: trace real programs with strace and run the analyzer."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import strace_io_stats

requires_strace = pytest.mark.skipif(shutil.which("strace") is None,
                                     reason="strace not installed")


def run_strace(tmp_path, *cmd, check=True):
    log = tmp_path / "trace.strace"
    # same options as strace-wrapper.sh
    subprocess.run(["strace", "-f", "-r", "-T", "-o", str(log)] + list(cmd),
                   cwd=str(tmp_path), check=check,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return log


def parse_files(*paths):
    stats, unknown = strace_io_stats.parseInputFiles([str(p) for p in paths])
    strace_io_stats.calc_file_access_stats(stats)
    return stats, unknown


@requires_strace
def test_dd_with_syscallist(tmp_path):
    """Copy syscallist.txt with dd, one line per read()/write().

    syscallist.txt lists every Linux syscall name followed by '(', one per
    line, each line padded with spaces to exactly 128 bytes (incl. newline).
    With bs=128 each read()/write() carries one line, so every syscall name
    appears at the start of the traced data, e.g.
        read(0, "openat(                         "..., 128) = 128 <0.000012>
    """
    syscall_list = Path(__file__).resolve().parent / "syscallist.txt"
    infile = str(syscall_list)
    outfile = "out.bin"
    size = syscall_list.stat().st_size
    bs = 128
    assert size % bs == 0, "syscallist.txt lines must be exactly 128 bytes"
    blocks = size // bs
    # run in tmp_path, the trace and thus the stats key contain the name exactly as passed to dd
    log = run_strace(tmp_path, "dd", "if=" + infile, "of=" + outfile,
                     "bs={}".format(bs))
    assert (tmp_path / outfile).stat().st_size == size

    stats, _ = parse_files(log)
    inp = stats[infile]
    assert inp["read_size"] == size
    assert inp["read_count"] == blocks + 1  # final read returns 0 at EOF
    out = stats[outfile]
    assert out["write_size"] == size
    assert out["write_count"] == blocks


requires_bash = pytest.mark.skipif(shutil.which("bash") is None,
                                   reason="bash not installed")


@requires_strace
@requires_bash
def test_bash_echo_redirect(tmp_path):
    """Trace the output redirection bash -c 'echo "Hello" > out.bin'.

    Stresses the handling of redirected stdout.
    """
    outfile = "out.bin"
    log = run_strace(tmp_path, "bash", "-c", 'echo "Hello" > ' + outfile)

    stats, _ = parse_files(log)
    out = stats[outfile]
    assert out["write_count"] == 1
    assert out["write_size"] == len("Hello\n")


@requires_strace
@requires_bash
def test_bash_pipe_echo_cat(tmp_path):
    """Trace the shell pipeline bash -c 'echo hi | cat > out.bin'.

    bash creates a pipe and starts one child process for each side of it.
    The echo child writes "hi\\n" into the pipe, the cat child copies it to
    out.bin. Depending on the coreutils version cat copies with
    read()/write() or with splice().
    """
    outfile = "out.bin"
    log = run_strace(tmp_path, "bash", "-c", "echo hi | cat > " + outfile)
    assert (tmp_path / outfile).read_text() == "hi\n"

    stats, _ = parse_files(log)
    out = stats[outfile]
    assert out["write_size"] == 3


@requires_strace
@requires_bash
def test_bash_pipe_fd_limit(tmp_path):
    """Trace bash -c 'ulimit -n 3; echo hi | cat'.

    With only the standard streams allowed, creating the pipe fails
    (EMFILE) and bash reports an error on stderr. Stresses the handling of
    failed syscalls.
    """
    log = run_strace(tmp_path, "bash", "-c", "ulimit -n 3; echo hi | cat",
                     check=False)

    stats, _ = parse_files(log)
    assert stats["stderr"]["write_count"] >= 1  # bash's error message


@requires_strace
def test_python_threads_blocking_fifo_reads(tmp_path):
    """Two threads block in openat() and read() on FIFOs.

    While they wait, the main thread keeps issuing syscalls, so strace
    splits the blocked calls into '<unfinished ...>' and '<... resumed>'
    lines. Stresses the handling of interrupted and resumed syscalls.
    """
    script = """
import os, threading, time

def reader(path):
    fd = os.open(path, os.O_RDONLY)  # blocks until the writer opens the FIFO
    os.read(fd, 4096)                # blocks until data arrives
    os.close(fd)

os.mkfifo("fifo1")
os.mkfifo("fifo2")
threads = [threading.Thread(target=reader, args=(p,)) for p in ("fifo1", "fifo2")]
for t in threads:
    t.start()
time.sleep(0.2)
w1 = os.open("fifo1", os.O_WRONLY)
w2 = os.open("fifo2", os.O_WRONLY)
time.sleep(0.2)
os.write(w1, b"x" * 100)
os.write(w2, b"y" * 200)
for t in threads:
    t.join()
"""
    log = run_strace(tmp_path, sys.executable, "-S", "-c", script)
    trace = log.read_text()
    assert "<unfinished ...>" in trace and "resumed>" in trace, \
        "no interrupted syscalls in the trace, the test checks nothing"

    stats, _ = parse_files(log)
    for fifo, size in (("fifo1", 100), ("fifo2", 200)):
        assert stats[fifo]["open_count"] == 2  # reader + writer
        assert stats[fifo]["read_count"] == 1
        assert stats[fifo]["read_size"] == size
        assert stats[fifo]["write_count"] == 1
        assert stats[fifo]["write_size"] == size
