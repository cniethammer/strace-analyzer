# Strace Output I/O Analyzer.

The strace output I/O analyser is a tool to analyze the I/O behaviour of serial and parallel applications.
It traces the system calls and generates statistics for every accessed file.

## Getting Started

### Prerequisites
The strace output I/O analyzer requires
- strace to generate traces
- python 3.4 or greater to analyze the traces

### Installation
Just clone the directory and use the scripts. No additional steps required.

### Usage:
#### Trace Generation
Generate a trace with the strace wrapper
```
  ./strace-wrapper.sh ./my_app [APP OPTIONS]
```
or use the strace-wrapper.sh for MPI parallel programs like
```
  mpirun [MPI OPTIONS] ./strace-wrapper.sh ./my_app [APP OPTIONS]
```
which will generate a set of strace log files - one for each MPI process.

#### Analyzing Traces

To analyze the created traces run

```
./strace-io-stats.py *.strace
```
To get help how to use and control strace-io-stats.py run
```
./strace-io-stats.py --help
```


## Legal Info and Contact
Copyright (c) 2017     HLRS, University of Stuttgart.
This software is published under the terms of the BSD license.

Contact: Christoph Niethammer <niethammer@hlrs.de>

