# libcotp
C library that generates TOTP and HOTP

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
char *totp = get_totp ('secretkey', digits);
free (totp);

char *hotp = get_hotp ('secretkey', counter, digits);
free (hotp);

int is_valid = totp_verify ('secretkey', digits, 'totp'); // returns either TOTP_VALID or TOTP_NOT_VALID

int is_valid = hotp_verify ('secretkey', counter, digits, 'hotp'); // returns either HOTP_VALID or HOTP_NOT_VALID
```

where ```digits``` is either ```6``` or ```8``` and ```counter``` is a value decided with the server. 
<br><br>Please note that you **must free** the memory allocated for the totp/hotp value(s) once you're done with it(them)!
