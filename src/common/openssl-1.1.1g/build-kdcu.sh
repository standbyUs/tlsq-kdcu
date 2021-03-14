#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

TOOL_CHAIN=/media/alex/ex-hard/oct/gcc-linaro-arm-linux-gnueabihf-4.7-2013.03-20130313_linux/bin/

make distclean

rm -rf ./build-kdcu
mkdir build-kdcu

./Configure linux-generic32 shared -DL_ENDIAN \
	CC=${TOOL_CHAIN}arm-linux-gnueabihf-gcc \
	CXX=${TOOL_CHAIN}arm-linux-gnueabihf-g++ \
	NM=${TOOL_CHAIN}arm-linux-gnueabihf-nm \
	AR=${TOOL_CHAIN}arm-linux-gnueabihf-ar \
	RANLIB=${TOOL_CHAIN}arm-linux-gnueabihf-ranlib \
	LD=${TOOL_CHAIN}arm-linux-gnueabihf-ld \
	--prefix=${SHELL_PATH}/build-kdcu

make
make install
#make clean
tar cvzf build-kdcu.tar.gz build-kdcu/include/ build-kdcu/lib/
make distclean
