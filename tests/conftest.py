import textwrap

import pytest

import strace_io_stats


@pytest.fixture
def parse(tmp_path):
    """Parse one or more strace logs given as strings.

    Each argument is the content of one trace file (as produced by
    ``strace -f -r -T``). Leading indentation is removed, so traces can be
    written as indented triple-quoted strings in the tests.

    Returns ``(file_access_stats, unknown_calls)`` with the derived totals
    (write_count, read_size, ...) already computed.
    """
    def _parse(*traces):
        paths = []
        for i, trace in enumerate(traces):
            path = tmp_path / "trace{}.strace".format(i)
            path.write_text(textwrap.dedent(trace).lstrip("\n"))
            paths.append(str(path))
        stats, unknown = strace_io_stats.parseInputFiles(paths)
        strace_io_stats.calc_file_access_stats(stats)
        return stats, unknown

    return _parse
