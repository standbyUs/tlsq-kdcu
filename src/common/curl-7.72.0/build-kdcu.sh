#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

TOOL_CHAIN=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/

rm -rf ./build-kdcu
mkdir build-kdcu

./configure --host=arm-linux-gnueabihf \
	CC=${TOOL_CHAIN}arm-linux-gnueabihf-gcc \
	CXX=${TOOL_CHAIN}arm-linux-gnueabihf-g++ \
	NM=${TOOL_CHAIN}arm-linux-gnueabihf-nm \
	AR=${TOOL_CHAIN}arm-linux-gnueabihf-ar \
	RANLIB=${TOOL_CHAIN}arm-linux-gnueabihf-ranlib \
	LD=${TOOL_CHAIN}arm-linux-gnueabihf-ld \
	--prefix=${SHELL_PATH}/build-kdcu \
	CFLAGS=-I${SHELL_PATH}/../openssl-1.1.1g/build-kdcu/include \
	LDFLAGS=-L${SHELL_PATH}/../openssl-1.1.1g/build-kdcu/lib \
	LIBS="-lssl -lcrypto"

make
make install
tar cvzf build-kdcu.tar.gz build-kdcu/include/ build-kdcu/lib/

make distclean

 

