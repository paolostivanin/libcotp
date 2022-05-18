#!/bin/bash

mkdir build && cd "$_"
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
make install
