#!/usr/bin/env bash
set -euo pipefail

# ---- 0. Определяем дистрибутив и пакетный менеджер -------------------------
source /etc/os-release

if grep -qi "Astra" <<<"$NAME"; then
    PM_UPDATE="apt-get update -y"
    PM_INSTALL="apt-get install -y"
elif grep -qi "Elbrus" <<<"$NAME"; then       
    PM_UPDATE="yum update -y"                 
    PM_INSTALL="yum install -y"               
else
    echo "Unsupported distro: $NAME"
    exit 1
fi

$PM_UPDATE
$PM_INSTALL \
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
    --with-pic            # гарантируем правильный PIC в .so

make -j"$(nproc)"
sudo make install
sudo ldconfig

file /usr/local/lib/libndpi.so | grep -q "E2K" \
  && echo "nDPI собран нативно (E2K)" \
  || echo "Внимание: libndpi не E2K!"
