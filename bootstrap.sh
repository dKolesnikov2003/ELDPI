#!/usr/bin/env bash
set -euo pipefail

apt-get update
apt-get install -y \
    lcc lcc-devel \
    git build-essential gettext flex bison libtool autoconf automake pkg-config \
    libpcap-dev zlib1g-dev libjson-c-dev libnuma-dev libpcre2-dev \
    libmaxminddb-dev librrd-dev libsqlite3-dev \
    qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools

git clone --depth 1 --branch 4.14-stable https://github.com/ntop/nDPI.git
cd nDPI

export CC=lcc
export CFLAGS="-O2 -m64 -me2k -mvliw -vectorize -fPIC"
export LDFLAGS="-m64"

./autogen.sh       
./configure \
    CC="$CC" \
    CFLAGS="$CFLAGS" \
    LDFLAGS="$LDFLAGS" \
    --prefix=/usr/local   \
    --with-pic 

make -j"$(nproc)"
sudo make install
sudo ldconfig

file /usr/local/lib/libndpi.so | grep -q "E2K" \
  && echo "nDPI собран нативно (E2K)" \
  || echo "Внимание: libndpi не E2K!"
