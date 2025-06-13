#!/bin/bash
set -e
apt-get update
apt-get install build-essential git gettext flex bison libtool autoconf automake pkg-config libpcap-dev libjson-c-dev libnuma-dev libpcre2-dev libmaxminddb-dev librrd-dev libsqlite3-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools -y
git clone https://github.com/ntop/nDPI.git
cd nDPI
git checkout 4.14-stable
./autogen.sh
./configure
make
make install
ldconfig
cd ..
rm -rf nDPI
