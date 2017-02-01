#!/bin/sh
#
# mpirun [MPI OPTIONS] ./strace-mpi-wrapper.sh APP [APP OPTIONS]
#
LOGFILE="$(hostname).$$.strace"
strace -r -T -o "$LOGFILE" "$@"
