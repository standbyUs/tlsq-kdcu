#!/bin/sh

SHELL_PATH=`pwd -P`
echo $SHELL_PATH

rm -rf build-kdcu
mkdir -p build-kdcu/build

cd build-kdcu
cmake -DCMAKE_TOOLCHAIN_FILE=../toolchain.kdcu.cmake -DCMAKE_INSTALL_PREFIX=$SHELL_PATH/build-kdcu/build ../
make 
make install

tar cvzf ../build-kdcu.tar.gz ./build/include/ ./build/lib/

make clean

