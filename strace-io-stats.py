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
import statistics

          
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
  # cache values for sorting and output
  data['write_time'] = 0.0
  data['write_count'] = 0
  data['write_size'] = 0.0
  data['read_time'] = 0.0
  data['read_count'] = 0
  data['read_size'] = 0.0
  data['open_time'] = 0.0
  data['open_count'] = 0
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
  optparser.add_option('--file-details',
                  help="save detailed stats for each file",
                  action="store_true",
                  dest="file_details",
                  default=False
                  )
  optparser.add_option('--unknown-call-stats',
                  help="print statistics about untracked calls",
                  action="store_true",
                  dest="unknown_call_stats",
                  default=False
                  )
  optparser.add_option('--sort-by',
                  help="Sort results by property, default: write_time",
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

  inputfiles = args

  open_files = dict() # table holding the filenames to open file descriptors
                      # TODO may not be save in parallel when two MPI procs open file with same FD number?
  file_access_stats = dict()
  unknown_calls = dict()

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
        #logging.debug("LINE {0}: {1}".format(lineno, line.strip()))
        lineno = lineno + 1
        if "execve" in line :
          #logging.debug("execve")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) execve\((.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          if match :
            continue
        elif "open(" in line :
          #logging.debug("OPEN:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) open\(\"(?P<filename>.*)\", (?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1 :
            continue
          filename = match.group('filename')
          open_files[fd] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "eventfd2(" in line :
          #logging.debug("OPEN EVENTFD:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) eventfd2\((?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1 :
            continue
          filename = '<eventfd>'
          open_files[fd] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "socket(" in line :
          #logging.debug("OPEN SOCKET:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) socket\((?P<mode>.*)\).*= (?P<fd>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd == -1 :
            continue
          filename = '<socket>'
          open_files[fd] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append(fd)
        elif "socketpair(" in line :
          #logging.debug("OPEN SOCKET PAIR:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) socketpair\((?P<mode>.*), \[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\]\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if match.group('ret') == -1 :
            continue
          filename = '<socket>'
          open_files[fd1] = filename
          open_files[fd2] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_modes'].append(match.group('mode'))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif "pipe(" in line :
          #logging.debug("OPEN PIPE:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) pipe\(\[(?P<fd1>[0-9]+), (?P<fd2>[0-9]+)\]\).*= (?P<ret>-?[0-9]+).*<(?P<open_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd1 = int(match.group('fd1'))
          fd2 = int(match.group('fd2'))
          if match.group('ret') == -1 :
            continue
          filename = '<pipe>'
          open_files[fd1] = filename
          open_files[fd2] = filename
          if filename not in file_access_stats :
            file_access_stats[filename] = new_file_access_stats_entry(filename)
          file_access_stats[filename]['open_times'].append(float(match.group('open_time')))
          file_access_stats[filename]['open_fds'].append([fd1, fd2])
        elif "close(" in line :
          #logging.debug("CLOSE:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) close\((?P<fd>[0-9]+)\).*= (?P<ret>-?[0-9]+).*<(?P<close_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          if fd not in open_files :
            logging.warning("Closing unrecognized file descriptor {0}".format(fd))
            continue
          filename = open_files[fd]
          file_access_stats[filename]['close_times'].append(float(match.group('close_time')))
#delete from open file table
          del open_files[fd]
        elif "write(" in line or "writev" in line:
          #logging.debug("WRITE(V)(:")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) writev?\((?P<fd>[0-9]+), .*, (?P<size>[0-9]+)\).*= (?P<write_size>-?[0-9]+).*<(?P<write_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          filename = open_files[fd]
          file_access_stats[filename]['write_times'].append(float(match.group('write_time')))
          file_access_stats[filename]['write_sizes'].append(int(match.group('write_size')))
        elif "read(" in line or "readv" in line:
          #logging.debug("READ(V):")
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) readv?\((?P<fd>[0-9]+), .*, (?P<size>[0-9]+)\).*= (?P<read_size>-?[0-9]+).*<(?P<read_time>[0-9]+\.[0-9]+)>', line)
          #logging.debug("{0}".format(match.groupdict()))
          fd = int(match.group('fd'))
          filename = open_files[fd]
          file_access_stats[filename]['read_times'].append(float(match.group('read_time')))
          file_access_stats[filename]['read_sizes'].append(int(match.group('read_size')))
        else :
          logging.warning("Unknown line type")
          num_ignored_lines = num_ignored_lines + 1
          match = re.search(r'(?P<difftime>[0-9]+\.[0-9]+) (?P<func>.*?)\(.*\).*=.*<(?P<time>[0-9]+\.[0-9]+)>', line)
          if match != None :
            #logging.debug('{0}'.format(match.groupdict()))
            callname = match.group('func')
            calltime = float(match.group('time'))
            logging.warning("Unknown call to {0} took {1}".format(callname, calltime))
            if callname not in unknown_calls :
              unknown_calls[callname] = dict()
              unknown_calls[callname]['times'] = []
              unknown_calls[callname]['count'] = 0
            unknown_calls[callname]['times'].append(calltime)
            unknown_calls[callname]['count'] = unknown_calls[callname]['count'] + 1

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


  for filename in file_access_stats.keys() :
    file_access_stats[filename]['write_time'] = sum(file_access_stats[filename]['write_times'])
    file_access_stats[filename]['write_count'] = len(file_access_stats[filename]['write_times'])
    file_access_stats[filename]['write_size'] = sum(file_access_stats[filename]['write_sizes'])
    file_access_stats[filename]['read_time'] = sum(file_access_stats[filename]['read_times'])
    file_access_stats[filename]['read_count'] = len(file_access_stats[filename]['read_times'])
    file_access_stats[filename]['read_size'] = sum(file_access_stats[filename]['read_sizes'])
    file_access_stats[filename]['open_time'] = sum(file_access_stats[filename]['open_times'])
    file_access_stats[filename]['open_count'] = len(file_access_stats[filename]['open_times'])

  properties = ['write_time', 'write_count', 'write_size', 'read_time', 'read_count', 'read_size', 'open_time', 'open_count']
  formatstr = '{0}{1}{2}'.format('{',':>8} {'.join(map(str,list(range(len(properties))))),':>8}')
  formatstr = formatstr + " {{{0}}}".format(len(properties))
  properties.append('filename')

  if options.sort_by not in properties :
    logging.error("Unknown sort-by value '{0}'. Falling back to 'write_time'".format(options.sort_by))
  sorted_filenames = sorted(file_access_stats.values(), reverse=True, key=lambda k : k[options.sort_by])

  print("STATISTICS (sorted by {0}):".format(options.sort_by))
  print(formatstr.format(*properties))
  for filedata in sorted_filenames :
    filename = filedata['filename']
    if re.match(options.filter_files, filename) :
      print_file_statistics(file_access_stats[filename], formatstr, properties)
      if options.file_details :
        save_file_details(file_access_stats[filename])
  if options.unknown_call_stats :
    print("HIDDEN STATISTICS:")
    unknown_call_times = dict()
    unknown_call_counts = dict()
    for callname in unknown_calls.keys() :
      unknown_call_times[callname] = sum(unknown_calls[callname]['times'])
    print("callname,count,time")
    for callname, time in sorted(unknown_call_times.items()) :
      print(",".join([callname, str(unknown_calls[callname]['count']), str(time)]))

if "__main__" == __name__ :
  main(sys.argv)
