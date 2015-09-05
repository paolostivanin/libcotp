#!/bin/bash

LIBNAMEVER="libcotp.so.1.0.1"
LIBNAME="libcotp.so"

echo "[I] Compiling..."
gcc -fPIC -c src/base32.c -o src/base32.o
gcc -fPIC -c src/otp.c -o src/otp.o
gcc -shared -o ${LIBNAMEVER} src/otp.o src/base32.o -lgcrypt

echo "[I] Installing lib..."
if [ $(id -u) != 0 ]
then
    echo "[E] You must be root to install the library, exiting..."
    exit -1
else
    mv $LIBNAMEVER /usr/lib/
    install -v -o root -g root -m 755 -T $LIBNAMEVER /usr/lib/
    install -v -o root -g root -m 644 -T src/libcotp.h /usr/include/
    ln -s /usr/lib/${LIBNAMEVER} /usr/lib/${LIBNAME}
fi

echo "[I] Installation finished. Cleanin-up build files..."
rm -v src/base32.o
rm -v src/otp.o

echo "[I] All done :)"
exit 0
