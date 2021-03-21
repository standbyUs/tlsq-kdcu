#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

rm -rf ./build-linux
mkdir build-linux

./configure \
	--prefix=${SHELL_PATH}/build-linux \
	CFLAGS=-I${SHELL_PATH}/../openssl-1.1.1g/build-linux/include \
	LDFLAGS=-L${SHELL_PATH}/../openssl-1.1.1g/build-linux/lib \
	LIBS="-lssl -lcrypto"

make
make install

