# strace I/O Analyzer

[![tests](https://github.com/cniethammer/strace-analyzer/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/cniethammer/strace-analyzer/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

The strace I/O analyzer helps to understand the I/O behaviour of serial and
MPI-parallel applications. The application is traced with
[strace](https://strace.io), and the analyzer reads the resulting trace files
and reports statistics for every accessed file: number, size and duration of
reads and writes, and of opens and closes.

## Installation

Requirements:
- strace to create the traces
- Python 3.9 or newer to analyze them (no further dependencies)

The scripts can be used directly from a clone of the repository:
```
git clone https://github.com/cniethammer/strace-analyzer
cd strace-analyzer
./strace_io_stats.py --help
```

Alternatively, install them with pip, which provides the commands
`strace-io-stats` and `strace-wrapper.sh`:
```
pip install .
```
or with [uv](https://docs.astral.sh/uv/):
```
uv tool install .                         # install the commands
uvx --from . strace-io-stats --help       # or run without installing
```

## Usage

### Creating traces

Trace an application with the strace wrapper:
```
./strace-wrapper.sh ./my_app [APP OPTIONS]
```
This creates the trace file `<host>.<pid>.strace` in the directory
`strace-logs`, which is created if it does not exist. The environment variable
`LOGDIR` selects another directory:
```
LOGDIR=my_log_dir ./strace-wrapper.sh ./my_app [APP OPTIONS]
```

#### MPI-parallel applications
For MPI-parallel applications, start the wrapper with the MPI launcher:
```
mpirun [MPI OPTIONS] ./strace-wrapper.sh ./my_app [APP OPTIONS]
```
This creates one trace file per process, named `r<rank>-<host>.<pid>.strace`.
The MPI rank is taken from the environment set by the MPI launcher
(`PMI_RANK`, `PMIX_RANK`, `OMPI_COMM_WORLD_RANK` or `ALPS_APP_PE`).

For runs with many processes, tracing can be restricted to some ranks. The
environment variable `RANK_FILTER` holds a regular expression which is matched
against the MPI rank; only matching ranks are traced:
```
RANK_FILTER='^[0-4]$' mpirun [MPI OPTIONS] ./strace-wrapper.sh ./my_app [APP OPTIONS]
```

**Note:** Depending on the MPI implementation and the system, environment
variables like `LOGDIR` and `RANK_FILTER` are not passed on to the processes
started by the MPI launcher, in particular to processes on other nodes. Then
they have to be passed explicitly, e.g. with `mpirun -x LOGDIR -x RANK_FILTER`
for Open MPI or `mpiexec -genv LOGDIR my_log_dir` for MPICH and Intel MPI;
Slurm's `srun` passes the environment on by default. On multiple nodes,
`LOGDIR` has to be on a file system shared by all nodes to collect all trace
files in one place.

#### Tracing without the wrapper
Traces can also be created with strace directly. The analyzer requires the
options used by the wrapper: `-f` (follow child processes and threads), `-r`
(relative timestamps), `-T` (duration of each call) and `-o` (write the trace
to a file):
```
strace -f -r -T -o my_app.strace ./my_app [APP OPTIONS]
```
**Note:** The trace has to be written to a file with `-o`: only then strace
starts each line with the plain process id, which the analyzer needs to track
the file descriptors of each process. Without `-o`, strace writes the trace to
stderr, mixed with the output of the application, omits the process id for the
first process and marks the other processes with `[pid  1234]`, which the
analyzer does not recognize.

### Analyzing traces

Analyze all traces of a run:
```
./strace_io_stats.py strace-logs/*.strace
```
(or `strace-io-stats strace-logs/*.strace` when installed). The traces of all
files are combined into one table with one line per accessed file:

| Column | Meaning |
|---|---|
| `write_time`, `write_count`, `write_size` | total duration (s), number and bytes of writes |
| `read_time`, `read_count`, `read_size` | total duration (s), number and bytes of reads |
| `open_time`, `open_count` | total duration (s) and number of opens |
| `open_from_count` | number of trace files (e.g. MPI ranks) which opened the file |
| `close_time`, `close_count` | total duration (s) and number of closes |

Important options (see `--help` for all):
- `--format FIELDS`: comma-separated list of columns to show, or `all`
- `--sort-by FIELD`: column to sort by (descending)
- `--filter-files REGEX`: show only files whose name matches the regular
  expression at its start, e.g. `'/scratch/'` or `'.*\.h5$'`
- `--file-details`: additionally write detailed statistics for each shown file
  into the current directory, as CSV files named after the file with `/`
  replaced by `__`, e.g. `__data__input.dat.read.stat.txt`. The `read` and
  `write` files contain count, durations and bandwidths per request size, the
  `open` file the number of opens per trace file.
- `--unknown-call-stats`: also show number and duration of all other syscalls
- `--loglevel LEVEL`: e.g. `WARNING` to see warnings about unexpected trace
  content

### What is counted

- Opens: `open`, `openat`, and duplications of file descriptors with `dup`,
  `dup2`, `dup3` and `fcntl(F_DUPFD)`, which count as an open of the file
- Reads and writes: `read`, `readv`, `pread64`, `preadv`, `preadv2` and the
  corresponding write syscalls
- Copies inside the kernel: `splice`, `copy_file_range` and `sendfile` count as
  a read from the input and a write to the output, `tee` as a write
- Closes: `close`

Pipes, sockets and event file descriptors are reported as the pseudo files
`<pipe>`, `<socket>` and `<eventfd>`. File descriptors whose creation is not
part of the trace, but which are duplicated, are reported as `<unknown>`.
Failed calls are not counted. File descriptors are tracked per process, so
traces of shells and multi-process applications are analyzed correctly.

Limitations:
- I/O through memory mappings (`mmap`) is not visible in a trace.
- Reads and writes on file descriptors whose creation is not part of the
  trace are ignored with a warning.
- File descriptors opened with `O_CLOEXEC` are not closed on `execve`.

## Development

The strace I/O analyzer has a test suite with unit tests for the parser, based
on hand-written trace lines, and integration tests, which trace small programs
and bash use cases like redirections and pipelines.

To run all tests manually, e.g. before committing changes, run pytest from
the root of the repository:
```
pytest
```
The tests import the analyzer directly from the repository, so no
installation is needed if pytest is available. Otherwise install the test
dependencies with pip:
```
pip install ".[test]"
pytest
```
or run the tests with uv, which provides pytest itself:
```
uv run --extra test pytest
```
The integration tests trace real programs and are skipped if strace is not
installed.


## Legal Info and Contact
Copyright (c) 2017-2019 HLRS, University of Stuttgart.
This software is published under the terms of the BSD license, see
[LICENSE](LICENSE).

Contact: Christoph Niethammer <niethammer@hlrs.de>
