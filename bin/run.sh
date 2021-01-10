#! /bin/sh

export AAA_HOME=${HOME}/workplace/kdcu/run
export AAA_CERT=${AAA_HOME}/conf/cert
export OPENSSL_ENGINES=${AAA_HOME}/lib/engines
export LD_LIBRARY_PATH=${AAA_HOME}/lib:${AAA_HOME}/bin/kepcrypto:/usr/lib:/usr/local/lib

cd ${AAA_HOME}/bin

${AAA_HOME}/bin/iaaaManager

