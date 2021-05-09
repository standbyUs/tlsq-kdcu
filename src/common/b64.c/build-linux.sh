#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

rm -rf build-linux
mkdir -p build-linux/build

cd build-linux
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain.linux.cmake -DCMAKE_INSTALL_PREFIX=$SHELL_PATH/build-linux/build ../
make 
make install

tar cvzf ../build-linux.tar.gz ./build/include/ ./build/lib/

make clean

