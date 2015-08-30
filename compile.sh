#!/bin/bash

LIBNAMEVER="libcotp.so.1.0.1"
LIBNAME="libcotp.so"

echo "[I] Compiling..."
gcc -fPIC -c src/base32.c -o src/base32.o
gcc -fPIC -c src/otp.c -o src/otp.o
gcc -shared -o ${LIBNAMEVER} src/otp.o src/base32.o -lgcrypt
ln -s ${LIBNAMEVER} ${LIBNAME}

echo "[I] Removing object files..."
rm -v src/base32.o
rm -v src/otp.o
