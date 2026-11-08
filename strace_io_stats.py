#!/usr/bin/env python3
#
# Strace output I/O analyzer.
#
# Copyright (c) 2017-2019 HLRS, University of Stuttgart.
# This software is published under the terms of the BSD license.
#
# Contact: Christoph Niethammer <niethammer@hlrs.de>
#
# usage:
# --------
# Generate trace with strace wrapper
#   ./strace-wrapper.sh ./my_app [APP OPTIONS]
# or use the strace-wrapper.sh for MPI parallel programs like
#   mpirun [MPI OPTIONS] ./strace-wrapper.sh ./my_app [APP OPTIONS]
# which will generate a set of strace log files, one for each process.
#

import os
import sys

try:
  import optparse
  import re
  import logging
  import statistics
except ImportError as e:
  print("python 3.4 or greater required, found %s" % sys.version)
  raise ImportError(e)


def print_output_section_title(title):
  print('-'*78 + "\n" + title + ":\n" + '-'*78)

def print_output_section_footer(title):
  print('-'*78 + "\n")

def print_file_statistics(filedata, formatstr, properties):
  values = [filedata[p] for p in properties]
  print(formatstr.format(*values))


def write_io_details(data, filename):
  """!@brief Write io statistics to file
  @param data      Dict containing pairs of the form {size: time}
  @param filename  Name of output file
  """
  stats = dict()
  for size, time in data:
    if size not in stats:
      stats[size] = []
    stats[size].append(time)
  with open(filename, "w+") as f:
    f.write(",".join(["size", "count", "time_tot", "time_min", "time_max", "time_median", "bw_avg", "bw_min", "bw_max"]) + "\n")
    for size in sorted(stats.keys()):
      count = len(stats[size])
      t_tot = sum(stats[size])
      t_min = min(stats[size])
      t_max = max(stats[size])
      t_median = statistics.median_high(stats[size])
      f.write(",".join(map(str, [size, count, t_tot, t_min, t_max, t_median, size * count / t_tot, size / t_max, size / t_min])) + "\n")

def write_open_details(filedata, filename):
  with open(filename, "w+") as f:
    f.write(",".join(["opened_from", "count"]) + "\n")
    for open_from, count in filedata['open_from'].items():
      f.write(",".join(map(str, [open_from, count])) + "\n")

def save_file_details(filedata):
  """!@brief Save write and read statistics for the given filedata to files
  @param filedata  filedata object
  """
  filename = filedata['filename']
  # stats for writes
  writestat_file = filename.replace("/", "__") + ".write.stat.txt"
  writestat_data = zip(filedata['write_sizes'], filedata['write_times'])
  write_io_details(writestat_data, writestat_file)
  # stats for reads
  readstat_file = filename.replace("/", "__") + ".read.stat.txt"
  readstat_data = zip(filedata['read_sizes'], filedata['read_times'])
  write_io_details(readstat_data, readstat_file)
  # stats for opens
  openstat_file = filename.replace("/", "__") + ".open.stat.txt"
  write_open_details(filedata, openstat_file)


def new_file_access_stats_entry(filename):
  data = dict()
  data['filename'] = filename
  data['open_times'] = []
  data['open_fds'] = []
  data['open_from'] = dict()
  data['write_times'] = []
  data['write_sizes'] = []
  data['read_times'] = []
  data['read_sizes'] = []
  data['close_times'] = []
  # cache values for sorting and output
  data['write_time'] = 0.0
  data['write_count'] = 0
  data['write_size'] = 0.0
  data['read_time'] = 0.0
  data['read_count'] = 0
  data['read_size'] = 0.0
  data['open_time'] = 0.0
  data['open_count'] = 0
  data['open_from_count'] = 0
  data['close_time'] = 0.0
  data['close_count'] = 0
  return data


class OpenFileTracker:
  def __init__(self):
    self.open_files = dict()
  def register_open(self, filename, fd):
    self.open_files[fd] = filename
  def register_close(self, fd):
    del self.open_files[fd]
  def is_open(self, fd):
    return fd in self.open_files
  def get_filename(self, fd):
    return self.open_files[fd]
  def get_open_files(self):
    return self.open_files
  def copy(self):
    tracker = OpenFileTracker()
    tracker.open_files = dict(self.open_files)
    return tracker


class ProcessTracker:
  """File descriptor tables of the traced processes.

  Each process has its own table. A child created by fork() or clone()
  starts with a copy of its parent's table, threads (clone with
  CLONE_FILES) share the table of their parent.
  """
  def __init__(self):
    self.tables = dict()  # pid -> OpenFileTracker

  def table(self, pid):
    """Table of a process, created with the standard streams if unknown."""
    if pid not in self.tables:
      tracker = OpenFileTracker()
      tracker.register_open("stdin", 0)
      tracker.register_open("stdout", 1)
      tracker.register_open("stderr", 2)
      self.tables[pid] = tracker
    return self.tables[pid]

  def clone(self, parent, child, share_files):
    parent_table = self.table(parent)
    self.tables[child] = parent_table if share_files else parent_table.copy()

  def exit(self, pid):
    self.tables.pop(pid, None)

  def get_open_files(self):
    """Open files of all remaining processes as {(pid, fd): filename}."""
    open_files = dict()
    seen = set()
    for pid, tracker in self.tables.items():
      if id(tracker) in seen:  # table shared by threads
        continue
      seen.add(id(tracker))
      for fd, filename in tracker.get_open_files().items():
        open_files[(pid, fd)] = filename
    return open_files


# Process id (strace -f, None without) and name of the syscall at the start
# of a line produced by strace -f -r -T, e.g.
# "1234      0.000049 openat(AT_FDCWD, ...". Only this position is
# considered, so syscall names inside string arguments are never matched.
SYSCALL_NAME_RE = re.compile(r'^\s*(?:([0-9]+)\s+)?[0-9]+\.[0-9]+\s+(\w+)\(')
# Process id at the start of a line (strace -f), None for traces without it.
LINE_PID_RE = re.compile(r'^\s*([0-9]+)\s+[0-9]+\.[0-9]+\s')
# Markers of interrupted syscalls, see parseInputFiles(). The optional space
# after "resumed>" is printed by strace 4 only.
UNFINISHED_SUFFIX = " <unfinished ...>"
RESUMED_RE = re.compile(r'^\s*(?:([0-9]+)\s+)?[0-9]+\.[0-9]+\s+<\.\.\. \w+ resumed> ?')
# End of a process: "1234 0.000010 +++ exited with 0 +++" or "+++ killed by ..."
EXITED_RE = re.compile(r'^\s*(?:([0-9]+)\s+)?[0-9]+\.[0-9]+\s+\+\+\+ (?:exited|killed) ')
# Syscalls creating a new process or thread, their return value is the new pid.
CLONE_SYSCALLS = {"clone", "clone3", "fork", "vfork"}
CLONE_START_RE = re.compile(r'^\s*(?:[0-9]+\s+)?[0-9]+\.[0-9]+\s+(?:clone3?|v?fork)\(')
RETURN_VALUE_RE = re.compile(r'\) += (-?[0-9]+)[^=]*$')
STANDARD_STREAMS = {0: "stdin", 1: "stdout", 2: "stderr"}
READ_SYSCALLS = {"read", "readv", "pread64", "preadv"}
WRITE_SYSCALLS = {"write", "writev", "pwrite64", "pwritev"}


def parseInputFiles(inputfiles):
  file_access_stats = dict()
  unknown_calls = dict()

  for filename in STANDARD_STREAMS.values():
    file_access_stats[filename] = new_file_access_stats_entry(filename)

  num_ignored_lines = 0
  unfinished = dict()

  for inputfile in inputfiles:
    logging.info("Processing " + str(inputfile) + " ...")
    # each input file contains independent processes, e.g. one MPI rank
    processes = ProcessTracker()
    with open(inputfile, 'r') as fh:
      for lineno, line in enumerate(fh):
        # logging.debug("LINE {0}: {1}".format(lineno, line.strip()))
        if "ERESTARTSYS" in line:
          continue

        # Interrupted syscalls are split into two lines, which are joined
        # again here, e.g. for strace >= 5:
        #   1234 0.000010 read(3 <unfinished ...>
        #   1234 0.000050 <... read resumed>, "abc", 4096) = 3 <0.000050>
        # and for strace 4:
        #   1234 0.000010 read(3,  <unfinished ...>
        #   1234 0.000050 <... read resumed> "abc", 4096) = 3 <0.000050>
        if line.rstrip("\n").endswith(UNFINISHED_SUFFIX):
          pid_match = LINE_PID_RE.match(line)
          pid = pid_match.group(1) if pid_match else None
          unfinished[pid] = line.rstrip("\n")[:-len(UNFINISHED_SUFFIX)]
          continue
        resumed = RESUMED_RE.match(line)
        if resumed:
          pid = resumed.group(1)
          if pid not in unfinished:
            logging.debug("Resumed syscall without start: '{}'".format(line.strip()))
            num_ignored_lines = num_ignored_lines + 1
            continue
          line = unfinished.pop(pid) + line[resumed.end():]

        if line.endswith("+++\n"):
          exited = EXITED_RE.match(line)
          if exited:
            processes.exit(exited.group(1))
            continue

        name_match = SYSCALL_NAME_RE.match(line)
        pid, syscall = name_match.groups() if name_match else (None, None)
        if pid not in processes.tables:
          # A child may show up before the clone() of its parent returned.
          # If exactly one clone() is pending, it belongs to that parent.
          parents = [p for p, start in unfinished.items()
                     if CLONE_START_RE.match(start)]
          if len(parents) == 1:
            processes.clone(parents[0], pid,
                            "CLONE_FILES" in unfinished[parents[0]])
        open_file_tracker = processes.table(pid)

        if syscall in CLONE_SYSCALLS:
          ret = RETURN_VALUE_RE.search(line)
          if ret and int(ret.group(1)) > 0:
            child = ret.group(1)
            if child not in processes.tables:  # see above
              processes.clone(pid, child, "CLONE_FILES" in line)
        if syscall == "exit_group":
          # only this process ends; with strace -f others continue
          processes.exit(pid)
          continue
        elif syscall == "execve":
          # logging.debug("execve")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) execve\((.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          if match:
            continue
        elif syscall == "dup2":
          # logging.debug("dup2:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) dup2\((?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd1 = int(match.group('fd1'))
          fd = int(match.group('fd'))
          if fd == -1:
            continue
          filename = open_file_tracker.get_filename(fd1)
          open_file_tracker.register_open(filename, fd)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append(fd)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif syscall == "open":
          # logging.debug("OPEN:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) open\(\"(?P<filename>.*)\", (?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1:
            continue
          filename = match.group('filename')
          open_file_tracker.register_open(filename, fd)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append(fd)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif syscall == "openat":
          # logging.debug("OPEN:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) openat\((?P<dirfd>.*), \"(?P<filename>.*)\", (?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1:
            continue
          filename = match.group('filename')
          dirfd = match.group('dirfd')
          if dirfd != "AT_FDCWD" and not os.path.isabs(filename):
            filename = open_file_tracker.get_filename(int(dirfd)) + "/" + filename
          open_file_tracker.register_open(filename, fd)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append(fd)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif syscall == "fcntl":
          # logging.debug("fcntl:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) fcntl\((?P<fd1>[0-9]+), .*, (?P<fd2>[0-9]+)\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          if not match:
             continue
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if int(match.group('ret')) == -1:
            continue
          filename = open_file_tracker.get_filename(fd1)
          open_file_tracker.register_open(filename, fd2)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append(fd2)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif syscall == "eventfd2":
          # logging.debug("OPEN EVENTFD:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) eventfd2\((?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1:
            continue
          filename = '<eventfd>'
          open_file_tracker.register_open(filename, fd)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append(fd)
        elif syscall == "socket":
          # logging.debug("OPEN SOCKET:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) socket\((?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1:
            continue
          filename = '<socket>'
          open_file_tracker.register_open(filename, fd)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append(fd)
        elif syscall == "socketpair":
          # logging.debug("OPEN SOCKET PAIR:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) socketpair\((?P<mode>.*), \[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\]\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if match.group('ret') == -1:
            continue
          filename = '<socket>'
          open_file_tracker.register_open(filename, fd1)
          open_file_tracker.register_open(filename, fd2)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif syscall in ("pipe", "pipe2"):
          # logging.debug("OPEN PIPE:")
          # pipe([3, 4]) = 0, pipe2([3, 4], O_CLOEXEC) = 0
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) pipe2?\(\[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\](?:, [^)]*)?\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          if not match:  # failed call, e.g. pipe2(0x7ffd..., 0) = -1 EMFILE
            continue
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if match.group('ret') == -1:
            continue
          filename = '<pipe>'
          open_file_tracker.register_open(filename, fd1)
          open_file_tracker.register_open(filename, fd2)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif syscall == "close":
          # logging.debug("CLOSE:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) close\((?P<fd>[0-9]+)\).*= (?P<ret>-?[0-9]+).*<(?P<close_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if not open_file_tracker.is_open(fd):
            logging.warning("Closing unrecognized file descriptor {0}".format(fd))
            continue
          filename = open_file_tracker.get_filename(fd)
          file_access_stats[filename]['close_times'].append(float(match.group('close_time')))
          open_file_tracker.register_close(fd)
        elif syscall in WRITE_SYSCALLS:
          # logging.debug("WRITE(V)(:")
          match = re.search(
                  r'(?P<difftime>[0-9]+\.[0-9]+) p?write(?:64|v)?\((?P<fd>[0-9]+), ?.*, (?P<size>[0-9]+)\).*= (?P<write_size>-?[0-9]+).*<(?P<write_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if open_file_tracker.is_open(fd):
            filename = open_file_tracker.get_filename(fd)
            file_access_stats[filename]['write_times'].append(float(match.group('write_time')))
            file_access_stats[filename]['write_sizes'].append(int(match.group('write_size')))
          else:
            logging.warning("No Open file found for file descriptor {}".format(fd))
        elif syscall in READ_SYSCALLS:
          # logging.debug("READ(V):")
          match = re.search(
                  r'(?P<difftime>[0-9]+\.[0-9]+) p?read(?:64|v)?\((?P<fd>[0-9]+), ?.*, (?P<size>[0-9]+)\).*= (?P<read_size>-?[0-9]+).*<(?P<read_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if open_file_tracker.is_open(fd):
            filename = open_file_tracker.get_filename(fd)
            file_access_stats[filename]['read_times'].append(float(match.group('read_time')))
            file_access_stats[filename]['read_sizes'].append(int(match.group('read_size')))
          else:
            logging.warning("No Open file found for file descriptor {}".format(fd))
        else:
          logging.debug("Unknown line type: '{}'".format(line.strip()))
          num_ignored_lines = num_ignored_lines + 1
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) (?P<func>.*?)\(.*\).*=.*<(?P<time>[0-9]+\.[0-9]+)>', line)
          if match != None:
            # logging.debug('{0}'.format(match.groupdict()))
            callname = match.group('func')
            calltime = float(match.group('time'))
            # logging.warning("Unknown call to {0} took {1}".format(callname, calltime))
            if callname not in unknown_calls:
              unknown_calls[callname] = dict()
              unknown_calls[callname]['times'] = []
              unknown_calls[callname]['count'] = 0
            unknown_calls[callname]['times'].append(calltime)
            unknown_calls[callname]['count'] = unknown_calls[callname]['count'] + 1

    # processes which did not exit within the trace
    open_files = {key: filename
                  for key, filename in processes.get_open_files().items()
                  if STANDARD_STREAMS.get(key[1]) != filename}
    if open_files:
      logging.warning("There are open files at the end of {}:".format(inputfile))
      for (pid, fd), filename in sorted(open_files.items(), key=str):
        logging.warning("  {}[{}] (pid {})".format(filename, fd, pid))

  if num_ignored_lines > 0:
    logging.warning("Number of ignored lines: {0}".format(num_ignored_lines))

  return file_access_stats, unknown_calls



def calc_file_access_stats(file_access_stats):
  for filename in file_access_stats.keys():
    file_access_stats[filename]['write_time'] = sum(file_access_stats[filename]['write_times'], 0.0)
    file_access_stats[filename]['write_count'] = len(file_access_stats[filename]['write_times'])
    file_access_stats[filename]['write_size'] = sum(file_access_stats[filename]['write_sizes'])
    file_access_stats[filename]['read_time'] = sum(file_access_stats[filename]['read_times'], 0.0)
    file_access_stats[filename]['read_count'] = len(file_access_stats[filename]['read_times'])
    file_access_stats[filename]['read_size'] = sum(file_access_stats[filename]['read_sizes'])
    file_access_stats[filename]['open_time'] = sum(file_access_stats[filename]['open_times'], 0.0)
    file_access_stats[filename]['open_count'] = len(file_access_stats[filename]['open_times'])
    file_access_stats[filename]['close_time'] = sum(file_access_stats[filename]['close_times'], 0.0)
    file_access_stats[filename]['close_count'] = len(file_access_stats[filename]['close_times'])
    file_access_stats[filename]['open_from_count'] = len(file_access_stats[filename]['open_from'])


def main():
  optparser = optparse.OptionParser("usage: %prog [options] STRACE_LOG ...", version="%prog 0.1")
  optparser.add_option('--loglevel',
                  help="enable verbose output. Supported leveles: CRITICAL, ERROR, WARNING, INFO, DEBUG",
                  action="store",
                  type="string",
                  metavar="LEVEL",
                  dest="loglevel",
                  default="ERROR"
                  )
  optparser.add_option('--filter-files',
                  help="filter for a specific file",
                  action="store",
                  type="string",
                  metavar="REGEX",
                  dest="filter_files",
                  default=".*"
                  )
  optparser.add_option('--file-details',
                  help="save detailed stats for each file",
                  action="store_true",
                  dest="file_details",
                  default=False
                  )
  all_properties = ['write_time', 'write_count', 'write_size', 'read_time', 'read_count', 'read_size', 'open_time', 'open_count', 'open_from_count', 'close_time', 'close_count']
  optparser.add_option('--format',
                  help="Comma separated list of fields to include in the output. Supported fields are {} and 'all'. (Default: %default)".format(", ".join(all_properties)),
                  dest="format",
                  default="write_time,write_count,write_size,read_time,read_count,read_size,open_time,open_count,open_from_count"
                  )
  optparser.add_option('--unknown-call-stats',
                  help="print statistics about untracked calls",
                  action="store_true",
                  dest="unknown_call_stats",
                  default=False
                  )
  optparser.add_option('--sort-by',
                  help="Sort results by property, defaults to first column specified in format",
                  action="store",
                  type="string",
                  metavar="STRING",
                  dest="sort_by",
                  default="write_time"
                  )
  (options, args) = optparser.parse_args()
  numeric_loglevel = getattr(logging, options.loglevel.upper(), None)
  if not isinstance(numeric_loglevel, int):
    raise ValueError('Invalid log level: {0}'.format(options.loglevel))
  logging.basicConfig(format='%(levelname)s: %(message)s', level=numeric_loglevel)

  file_access_stats, unknown_calls = parseInputFiles(args)
  calc_file_access_stats(file_access_stats)

  properties = options.format.split(',')
  if 'all' in properties:
    properties = all_properties
  formatstr = ""
  headerstr = ""
  for i, property in enumerate(properties):
      if i:
          formatstr += " "
          headerstr += " "
      if len(property) <= 8:
          headerstr += "{:>.8}".format(property)
      else:
          headerstr += property
      if property.endswith("_time") or property == "time":
          formatstr += "{" + str(i) + ":>" + str(max(8, len(property))) + ".6}"
      else:
          formatstr += "{" + str(i) + ":>" + str(max(8, len(property))) + "}"
  formatstr = formatstr + " {{{0}}}".format(len(properties))
  properties.append('filename')
  headerstr += " filename"

  sort_by = properties[0]
  if options.sort_by not in all_properties:
    logging.error("Unknown sort-by value '{0}'. Falling back to '{1}'".format(options.sort_by, sort_by))
  else:
    sort_by = options.sort_by
  sorted_filenames = sorted(file_access_stats.values(), reverse=True, key=lambda k: k[sort_by])

  print_output_section_title("I/O STATISTICS (sorted by {0})".format(sort_by))
  print(headerstr)
  for filedata in sorted_filenames:
    filename = filedata['filename']
    if re.match(options.filter_files, filename):
      print_file_statistics(file_access_stats[filename], formatstr, properties)
      if options.file_details:
        save_file_details(file_access_stats[filename])
  print_output_section_footer("I/O STATISTICS")

  if options.unknown_call_stats:
    print_output_section_title("HIDDEN STATISTICS (sorted by time)")
    unknown_call_times = dict()
    for callname in unknown_calls.keys():
      unknown_call_times[callname] = sum(unknown_calls[callname]['times'])
    print("{0:16} {1:>12} {2:>12}".format("callname", "count", "time"))
    for callname, time in sorted(unknown_call_times.items()):
      print("{0:16} {1:>12} {2:>12.9}".format(callname, unknown_calls[callname]['count'], time))
    print_output_section_footer("HIDDEN STATISTICS")

if __name__ == "__main__":
  main()
