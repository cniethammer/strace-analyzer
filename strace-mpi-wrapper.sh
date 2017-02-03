#!/bin/sh
#
# mpirun [MPI OPTIONS] ./strace-mpi-wrapper.sh APP [APP OPTIONS]
#

MPI_RANK=${MPI_RANK:=$PMI_RANK}
MPI_RANK=${MPI_RANK:=$OMPI_COMM_WORLD_RANK}
MPI_RANK=${MPI_RANK:=$ALPS_APP_PE}

LOGFILE="${MPI_RANK:+r${MPI_RANK}-}$(hostname).$$.strace"
strace -r -T -o "$LOGFILE" "$@"
