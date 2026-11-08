"""End-to-end tests: trace real programs with strace and run the analyzer."""
import shutil
import subprocess
from pathlib import Path

import pytest

import strace_io_stats

requires_strace = pytest.mark.skipif(shutil.which("strace") is None,
                                     reason="strace not installed")


def run_strace(tmp_path, *cmd):
    log = tmp_path / "trace.strace"
    # same options as strace-wrapper.sh
    subprocess.run(["strace", "-f", "-r", "-T", "-o", str(log)] + list(cmd),
                   cwd=str(tmp_path), check=True,
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
