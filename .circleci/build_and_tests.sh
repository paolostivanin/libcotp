#!/bin/bash

mkdir build && cd "$_"
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_TESTING=ON
make
make install
./tests/test_cotp
