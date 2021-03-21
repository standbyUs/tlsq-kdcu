#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

make distclean

rm -rf ./build-linux
mkdir build-linux

./Configure linux-generic32 shared -DL_ENDIAN \
	--prefix=${SHELL_PATH}/build-linux

make
make install

