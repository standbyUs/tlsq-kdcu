./configure \
	--prefix=/media/alex/ex-hard/oct/curl-7.72.0/build-linux \
	CFLAGS=-I/media/alex/ex-hard/oct/openssl-1.1.1g/build-linux/include \
	LDFLAGS=-L/media/alex/ex-hard/oct/openssl-1.1.1g/build-linux/lib \
	LIBS="-lssl -lcrypto"

make
make install

