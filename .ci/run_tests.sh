#!/bin/bash

set -e

mkdir build && cd $_
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_TESTING=ON
make -j2
./tests/test_cotp
make install
