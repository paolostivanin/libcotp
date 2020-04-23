#!/bin/bash

set -e

git clone https://github.com/paolostivanin/libbaseencode.git
cd libbaseencode && mkdir build && cd "$_"
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make -j2
make install
cd ../..
