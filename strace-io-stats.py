#!/usr/bin/env python
#
# Strace output I/O analyzer.
#
# Copyright (c) 2017      Christoph Niethammer <niethammer@hlrs.de>
#
# usage:
# --------
# Generate trace with strace via
#   strace -r -T ./my_app
# or use the strace-mpi-wrapper.sh for MPI parallel programs
#   mpirun [MPI OPTIONS] ./strace-mpi-wrapper.sh APP [APP OPTIONS]
# which will generate a set of strace log files, one for each process.
#

import sys
import optparse
import re
import logging

          
def print_file_statistics(filedata) :
  print(filedata['filename'])
  print("  opens: # = " + str(len(filedata['open_times'])))
  print("  writes: #: " + str(len(filedata['write_times'])) + ", size: " + str(sum(filedata['write_sizes'])) + ", time: " + str(sum(filedata['write_times'])))
  print("  reads: #: " + str(len(filedata['read_times'])) + ", size: " + str(sum(filedata['read_sizes'])) + ", time: " + str(sum(filedata['read_times'])))


def new_file_access_stats_entry(filename) :
  data = dict()
  data['filename'] = filename
  data['open_times'] = []
  data['open_modes'] = []
  data['open_fds'] = []
  data['write_times'] = []
  data['write_sizes'] = []
  data['read_times'] = []
  data['read_sizes'] = []
  data['close_times'] = []
  return data


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
  (options, args) = optparser.parse_args()
  numeric_loglevel = getattr(logging, options.loglevel.upper(), None)
  if not isinstance(numeric_loglevel, int):
    raise ValueError('Invalid log level: {0}'.format(options.loglevel))
  logging.basicConfig(format='%(levelname)s: %(message)s',level=numeric_loglevel)

  inputfiles = args

  open_files = dict() # table holding the filenames to open file descriptors
                      # TODO may not be save in parallel when two MPI procs open file with same FD number?
  file_access_stats = dict()

  filename = "stdin"
  fd = 0
  open_files[fd] = filename
  file_access_stats[filename] = new_file_access_stats_entry(filename)
  filename = "stdout"
  fd = 1
  open_files[fd] = filename
  file_access_stats[filename] = new_file_access_stats_entry(filename)
  filename = "stderr"
  fd = 2
  open_files[fd] = filename
  file_access_stats[filename] = new_file_access_stats_entry(filename)
  
  
  num_ignored_lines = 0

  for inputfile in inputfiles :
    logging.info("Processing " + str(inputfile) + " ...")
    with open(inputfile, 'r') as f :
      lineno=1
      for line in f :
        logging.debug("LINE {0}: {1}".format(lineno, line.strip()))
        lineno = lineno + 1
        if "execve" in line :
          logging.debug("execve")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) execve\((.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          if match :
            continue
        elif "open(" in line :
          logging.debug("OPEN:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) open\(\"(?P<filename>.*)\", (?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1 :
            continue
          filename = match.group('filename')
          open_files[fd] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(match.group('open_time'))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "eventfd2(" in line :
          logging.debug("OPEN EVENTFD:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) eventfd2\((?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1 :
            continue
          filename = '<eventfd>'
          open_files[fd] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(match.group('open_time'))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "socket(" in line :
          logging.debug("OPEN SOCKET:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) socket\((?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1 :
            continue
          filename = '<socket>'
          open_files[fd] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(match.group('open_time'))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "socketpair(" in line :
          logging.debug("OPEN SOCKET PAIR:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) socketpair\((?P<mode>.*), \[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\]\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if match.group('ret') == -1 :
            continue
          filename = '<socket>'
          open_files[fd1] = filename
          open_files[fd2] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(match.group('open_time'))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif "pipe(" in line :
          logging.debug("OPEN PIPE:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) pipe\(\[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\]\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if match.group('ret') == -1 :
            continue
          filename = '<pipe>'
          open_files[fd1] = filename
          open_files[fd2] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(match.group('open_time'))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif "close(" in line :
          logging.debug("CLOSE:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) close\((?P<fd>[0-9]+)\).*= (?P<ret>-?[0-9]+).*<(?P<close_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd not in open_files :
            logging.warning("Closing unrecognized file descriptor {0}".format(fd))
            continue
          filename = open_files[fd]
          file_access_stats[filename]['close_times'].append(match.group('close_time'))
#delete from open file table
          del open_files[fd]
        elif "write(" in line or "writev" in line:
          logging.debug("WRITE(V)(:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) writev?\((?P<fd>[0-9]+), .*, (?P<size>[0-9]+)\).*= (?P<write_size>-?[0-9]+).*<(?P<write_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          filename = open_files[fd]
          file_access_stats[filename]['write_times'].append(float(match.group('write_time')))
          file_access_stats[filename]['write_sizes'].append(int(match.group('write_size')))
        elif "read(" in line or "readv" in line:
          logging.debug("READ(V):")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) readv?\((?P<fd>[0-9]+), .*, (?P<size>[0-9]+)\).*= (?P<read_size>-?[0-9]+).*<(?P<read_time>[0-9]+\.[0-9]+)>', line)
          logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          filename = open_files[fd]
          file_access_stats[filename]['read_times'].append(float(match.group('read_time')))
          file_access_stats[filename]['read_sizes'].append(int(match.group('read_size')))
        else :
          logging.warning("Unknown line type")
          num_ignored_lines = num_ignored_lines + 1
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) (?P<func>.*)\(.*\).*=', line)
          if match != None :
            logging.debug('{0}'.format(match.groupdict()))
            logging.warning("Unknown call to {0}".format(match.group('func')))

  if num_ignored_lines > 0 :
    logging.warning("Number of ignored lines: {0}".format(num_ignored_lines))
  if 0 in open_files :
    logging.warning("Ignoring open sdtin[0]")
    del open_files[0]
  if 1 in open_files :
    logging.warning("Ignoring open sdtout[1]")
    del open_files[1]
  if 2 in open_files :
    logging.warning("Ignoring open sdterr[2]")
    del open_files[2]
  if open_files :
    logging.warning("There are open files at the end of file processing:")
    for fd in open_files.keys() :
      logging.warning("  " + open_files[fd] + "[" + str(fd) + "]")
  print("STATISTICS:")
  for filename in file_access_stats.keys() :
    if re.match(options.filter_files, filename) :
      print_file_statistics(file_access_stats[filename])

if "__main__" == __name__ :
  main(sys.argv)
