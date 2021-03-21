cp common/curl-7.72.0/build-linux/include/curl/ include/ -a
cp common/json-c/build-linux/build/include/json-c/ include/ -a
cp common/libzmq/build-linux/include/* include/
cp common/czmq/build-linux/include/* include/
cp common/openssl-1.1.1g/build-linux/include/openssl/ include/ -a

cp common/curl-7.72.0/build-linux/lib/libcurl.so.* libs-linux/ -a
cp common/czmq/build-linux/lib/libczmq.so* libs-linux/ -a
cp common/json-c/build-linux/build/lib/libjson-c.so* libs-linux/ -a
cp common/libzmq/build-linux/lib/libzmq.so* libs-linux/ -a
cp common/openssl-1.1.1g/build-linux/lib/libcrypto.so* libs-linux/ -a
cp common/openssl-1.1.1g/build-linux/lib/libssl.so* libs-linux/ -a
