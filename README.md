# libcotp
<a href="https://scan.coverity.com/projects/paolostivanin-libcotp">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/12748/badge.svg"/>
</a>

<a href="https://app.shippable.com/github/paolostivanin/libcotp">
  <img alt="Shippable Build Status"
       src="https://api.shippable.com/projects/58e3d5759401b40600a7c026/badge?branch=master"/>
</a>

C library that generates TOTP and HOTP according to [RFC-6238](https://tools.ietf.org/html/rfc6238)

## Requirements
- [libbaseencode](https://github.com/paolostivanin/libbaseencode)
- GCC/Clang and CMake to build the library

## Build and Install
```
$ git clone https://github.com/paolostivanin/libcotp.git
$ cd libcotp
$ mkdir build && cd $_
$ cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr ../   # add -DBUILD_TESTING=ON if you want to compile also the tests
$ make
# make install
```

## How To Use It
```
char *totp = get_totp ("base32_encoded_secret", digits, algo);
free (totp);

char *hotp = get_hotp ("base32_encoded_secret", counter, digits, algo);
free (hotp);

int is_valid = totp_verify ('secretkey', digits, 'totp', algo); // returns either TOTP_VALID or TOTP_NOT_VALID

int is_valid = hotp_verify ('secretkey', counter, digits, 'hotp', algo); // returns either HOTP_VALID or HOTP_NOT_VALID
```

where:
- `secret_key` is the **base32 encoded** secret. Usually, a website gives you the secret already base32 encoded, so you should pay attention to not encode the secret again.
The format of the secret can either be `hxdm vjec jjws` or `HXDMVJECJJWS`. In the first case, the library will normalize the secret to second format before computing the OTP.
- `digits` is either `6` or `8`
- `counter` is a value decided with the server
- `algo` is either `SHA1`, `SHA256` or `SHA512`

Please note that the value returned by `get_totp` and `get_hotp` **must be freed** once not needed any more.
