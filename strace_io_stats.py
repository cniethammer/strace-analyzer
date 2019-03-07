#!/usr/bin/env python3
#
# Strace output I/O analyzer.
#
# Copyright (c) 2017-2018 HLRS, University of Stuttgart.
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

import sys

try:
    import optparse
    import re
    import logging
    import statistics
except ImportError as e:
    print("python 3.4 or greater required, found %s" % sys.version)
    raise ImportError(e)


def print_output_section_title(title) :
  print('-'*78 + "\n" + title + ":\n" + '-'*78)

def print_output_section_footer(title) :
  print('-'*78 + "\n")

def print_file_statistics(filedata, formatstr, properties) :
  values = [filedata[p] for p in properties]
  print(formatstr.format(*values))


def write_io_details(data, filename) :
  """!@brief Write io statistics to file
  @param data      Dict containing pairs of the form {size : time}
  @param filename  Name of output file
  """
  stats = dict()
  for size, time in data :
    if size not in stats :
      stats[size] = []
    stats[size].append(time)
  with open(filename, "w+") as f :
    f.write(",".join(["size", "count", "time_tot", "time_min", "time_max", "time_median", "bw_avg", "bw_min", "bw_max"]) + "\n")
    for size in sorted(stats.keys()) :
      count = len(stats[size])
      t_tot = sum(stats[size])
      t_min = min(stats[size])
      t_max = max(stats[size])
      t_median = statistics.median_high(stats[size])
      f.write(",".join(map(str, [size, count, t_tot, t_min, t_max, t_median, size * count / t_tot, size / t_max, size / t_min ])) + "\n")

def write_open_details(filedata, filename) :
  with open(filename, "w+") as f :
    f.write(",".join(["opened_from", "count"]) + "\n")
    for open_from, count in filedata['open_from'].items() :
      f.write(",".join(map(str, [open_from, count])) + "\n")

def save_file_details(filedata):
  """!@brief Save write and read statistics for the given filedata to files
  @param filedata  filedata object
  """
  filename = filedata['filename']
  # stats for writes
  writestat_file = filename.replace("/","__") + ".write.stat.txt"
  writestat_data = zip(filedata['write_sizes'], filedata['write_times'])
  write_io_details(writestat_data, writestat_file)
  # stats for reads
  readstat_file = filename.replace("/","__") + ".read.stat.txt"
  readstat_data = zip(filedata['read_sizes'], filedata['read_times'])
  write_io_details(readstat_data, readstat_file)
  # stats for opens
  openstat_file = filename.replace("/","__") + ".open.stat.txt"
  write_open_details(filedata, openstat_file)


def new_file_access_stats_entry(filename) :
  data = dict()
  data['filename'] = filename
  data['open_times'] = []
  data['open_modes'] = []
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


class OpenFileTracker :
  def __init__(self) :
    self.open_files = dict()
  def register_open(self, filename, fd) :
    self.open_files[fd] = filename
  def register_close(self, fd) :
    del self.open_files[fd]
  def is_open(self, fd) :
    return fd in self.open_files
  def get_filename(self, fd) :
    return self.open_files[fd]
  def get_open_files(self)  :
    return self.open_files


def parseInputFiles(inputfiles):
  open_file_tracker = OpenFileTracker()
  file_access_stats = dict()
  unknown_calls = dict()

  open_file_tracker.register_open("stdin", 0)
  file_access_stats["stdin"] = new_file_access_stats_entry("stdin")
  open_file_tracker.register_open("stdout", 1)
  file_access_stats["stdout"] = new_file_access_stats_entry("stdout")
  open_file_tracker.register_open("stderr", 2)
  file_access_stats["stderr"] = new_file_access_stats_entry("stderr")

  num_ignored_lines = 0
  unfinished = dict()

  for inputfile in inputfiles:
    logging.info("Processing " + str(inputfile) + " ...")
    with open(inputfile, 'r') as f:
      lineno = 0
      for line in f:
        lineno = lineno + 1
        # logging.debug("LINE {0}: {1}".format(lineno, line.strip()))
        if "ERESTARTSYS" in line:
          continue
        if "exit_group" in line:
          break

        if "<unfinished ...>" in line:
          pid = int(line.split()[0])
          unfinished[pid] = line[:-len(" <unfinished ...>")].rstrip()
          continue
        elif " resumed> " in line:
          pid = int(line.split()[0])
          rest = line[line.find(" resumed> ") + len(" resumed> "):].rstrip()
          line = unfinished[pid] + rest
          del unfinished[pid]
        if "execve" in line:
          # logging.debug("execve")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) execve\((.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          if match:
            continue
        elif "dup2(" in line:
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
          file_access_stats[filename]['open_modes'].append(file_access_stats[filename]['open_modes'][-1])
          file_access_stats[filename]['open_fds'].append(fd)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif "open(" in line:
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
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif "openat(" in line:
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
          if dirfd != "AT_FDCWD":
            filename = open_file_tracker.get_filename(int(dirfd)) + "/" + filename
          open_file_tracker.register_open(filename, fd)
          if filename not in file_access_stats:
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
          if inputfile not in file_access_stats[filename]['open_from']:
            file_access_stats[filename]['open_from'][inputfile] = 0
          file_access_stats[filename]['open_from'][inputfile] = file_access_stats[filename]['open_from'][inputfile] + 1
        elif "eventfd2(" in line:
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
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "socket(" in line:
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
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "socketpair(" in line:
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
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif "pipe(" in line:
          # logging.debug("OPEN PIPE:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) pipe\(\[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\]\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
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
        elif "close(" in line:
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
        elif "write(" in line or "writev(" in line and not "process_vm_writev" in line:
          # logging.debug("WRITE(V)(:")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) p?writev?\((?P<fd>[0-9]+), ?.*, (?P<size>[0-9]+)\).*= (?P<write_size>-?[0-9]+).*<(?P<write_time>[0-9]+\.[0-9]+)>',
            line)
          # logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if open_file_tracker.is_open(fd):
            filename = open_file_tracker.get_filename(fd)
            file_access_stats[filename]['write_times'].append(float(match.group('write_time')))
            file_access_stats[filename]['write_sizes'].append(int(match.group('write_size')))
          else:
            logging.warning("No Open file found for file descriptor {}".format(fd))
        elif "read(" in line or "readv(" in line and not "process_vm_readv" in line:
          # logging.debug("READ(V):")
          match = re.search(
            r'(?P<difftime>[0-9]+\.[0-9]+) p?readv?\((?P<fd>[0-9]+), ?.*, (?P<size>[0-9]+)\).*= (?P<read_size>-?[0-9]+).*<(?P<read_time>[0-9]+\.[0-9]+)>',
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
          logging.warning("Unknown line type")
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

  if num_ignored_lines > 0:
    logging.warning("Number of ignored lines: {0}".format(num_ignored_lines))
  if open_file_tracker.is_open(0):
    logging.warning("Ignoring open sdtin[0]")
    open_file_tracker.register_close(0)
  if open_file_tracker.is_open(1):
    logging.warning("Ignoring open sdtout[1]")
    open_file_tracker.register_close(1)
  if open_file_tracker.is_open(2):
    logging.warning("Ignoring open sdterr[2]")
    open_file_tracker.register_close(2)
  open_files = open_file_tracker.get_open_files()
  if open_files:
    logging.warning("There are open files at the end of file processing:")
    for fd in open_files.keys():
      logging.warning("  " + open_files[fd] + "[" + str(fd) + "]")

  return file_access_stats, unknown_calls



def calc_file_access_stats(file_access_stats):
  for filename in file_access_stats.keys() :
    file_access_stats[filename]['write_time'] = sum(file_access_stats[filename]['write_times'])
    file_access_stats[filename]['write_count'] = len(file_access_stats[filename]['write_times'])
    file_access_stats[filename]['write_size'] = sum(file_access_stats[filename]['write_sizes'])
    file_access_stats[filename]['read_time'] = sum(file_access_stats[filename]['read_times'])
    file_access_stats[filename]['read_count'] = len(file_access_stats[filename]['read_times'])
    file_access_stats[filename]['read_size'] = sum(file_access_stats[filename]['read_sizes'])
    file_access_stats[filename]['open_time'] = sum(file_access_stats[filename]['open_times'])
    file_access_stats[filename]['open_count'] = len(file_access_stats[filename]['open_times'])
    file_access_stats[filename]['close_time'] = sum(file_access_stats[filename]['close_times'])
    file_access_stats[filename]['close_count'] = len(file_access_stats[filename]['close_times'])
    file_access_stats[filename]['open_from_count'] = len(file_access_stats[filename]['open_from'])


def main(argv) :
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
  logging.basicConfig(format='%(levelname)s: %(message)s',level=numeric_loglevel)

  file_access_stats, unknown_calls = parseInputFiles(args)
  calc_file_access_stats(file_access_stats)

  properties = options.format.split(',')
  if 'all' in properties:
    properties = all_properties
  formatstr = '{0}{1}{2}'.format('{',':>8} {'.join(map(str,list(range(len(properties))))),':>8}')
  formatstr = formatstr + " {{{0}}}".format(len(properties))
  properties.append('filename')

  sort_by = properties[0]
  if options.sort_by not in all_properties :
    logging.error("Unknown sort-by value '{0}'. Falling back to '{1}'".format(options.sort_by, sort_by))
  else:
    sort_by = options.sort_by
  sorted_filenames = sorted(file_access_stats.values(), reverse=True, key=lambda k : k[sort_by])

  print_output_section_title("I/O STATISTICS (sorted by {0})".format(sort_by))
  print(formatstr.format(*properties))
  for filedata in sorted_filenames:
    filename = filedata['filename']
    if re.match(options.filter_files, filename) :
      print_file_statistics(file_access_stats[filename], formatstr, properties)
      if options.file_details :
        save_file_details(file_access_stats[filename])
  print_output_section_footer("I/O STATISTICS")

  if options.unknown_call_stats :
    print_output_section_title("HIDDEN STATISTICS (sorted by time)")
    unknown_call_times = dict()
    for callname in unknown_calls.keys() :
      unknown_call_times[callname] = sum(unknown_calls[callname]['times'])
    print("{0:16} {1:>12} {2:>12}".format("callname", "count", "time"))
    for callname, time in sorted(unknown_call_times.items()) :
      print("{0:16} {1:>12} {2:>12.9}".format(callname, unknown_calls[callname]['count'], time))
    print_output_section_footer("HIDDEN STATISTICS")

if "__main__" == __name__ :
  main(sys.argv)
