cp common/curl-7.72.0/build-kdcu/include/curl/ include/ -a
cp common/json-c/build-kdcu/build/include/json-c/ include/ -a
cp common/libzmq/build-kdcu/include/* include/
cp common/czmq/build-kdcu/include/* include/
cp common/openssl-1.1.1g/build-kdcu/include/openssl/ include/ -a

cp common/curl-7.72.0/build-kdcu/lib/libcurl.so.* libs/ -a
cp common/czmq/build-kdcu/lib/libczmq.so* libs/ -a
cp common/json-c/build-kdcu/build/lib/libjson-c.so* libs/ -a
cp common/libzmq/build-kdcu/lib/libzmq.so* libs/ -a
cp common/openssl-1.1.1g/build-kdcu/lib/libcrypto.so* libs/ -a
cp common/openssl-1.1.1g/build-kdcu/lib/libssl.so* libs-linux/ -a

