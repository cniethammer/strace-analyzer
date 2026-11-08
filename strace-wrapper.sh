#!/bin/sh
#
# mpirun [MPI OPTIONS] ./strace-mpi-wrapper.sh APP [APP OPTIONS]
#

cd $PWD

MPI_RANK=${MPI_RANK:=$PMI_RANK}
MPI_RANK=${MPI_RANK:=$PMIX_RANK}
MPI_RANK=${MPI_RANK:=$OMPI_COMM_WORLD_RANK}
MPI_RANK=${MPI_RANK:=$ALPS_APP_PE}

LOGDIR=${LOGDIR:=strace-logs}
if ! test -d $LOGDIR ; then
  mkdir -p $LOGDIR
fi
HOST=$(uname -n 2>/dev/null || cat /proc/sys/kernel/hostname)
LOGFILE="$LOGDIR/${MPI_RANK:+r${MPI_RANK}-}${HOST}.$$.strace"


if  ! test -z $MPI_RANK  &&  ! test -z $RANK_FILTER  &&  ! [[ $MPI_RANK =~ $RANK_FILTER ]] ; then
  echo "# Rank $MPI_RANK not traced" > $LOGFILE
  "$@"
else
  strace -f -r -T -o "$LOGFILE" "$@"
fi
