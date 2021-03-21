#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

export LD_LIBRARY_PATH=${SHELL_PATH}/libs-linux:$LD_LIBRARY_PATH
echo $LD_LIBRARY_PATH


