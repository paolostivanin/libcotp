# libcotp
C library that generates TOTP and HOTP according to [RFC-6238](https://tools.ietf.org/html/rfc6238)

Build and Install
------------
```
$ git clone https://github.com/paolostivanin/libcotp.git
$ cd libcotp
$ mkdir build && cd $_
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ../
$ make
# make install
```

How To Use It
-------------

```
char *totp = get_totp ('secretkey', digits, algo);
free (totp);

char *hotp = get_hotp ('secretkey', counter, digits, algo);
free (hotp);

int is_valid = totp_verify ('secretkey', digits, 'totp', algo); // returns either TOTP_VALID or TOTP_NOT_VALID

int is_valid = hotp_verify ('secretkey', counter, digits, 'hotp', algo); // returns either HOTP_VALID or HOTP_NOT_VALID
```

where:
- `digits` is either `6` or `8`
- `counter` is a value decided with the server
- `algo` is either `SHA1`, `SHA256` or `SHA512`

<br><br>Please note that you **must free** the memory allocated for the totp/hotp value(s) once you're done with it(them)!
