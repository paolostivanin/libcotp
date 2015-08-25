# libcotp
C library that generates TOTP and HOTP

How To Use
----------

```
char *totp = TOTP('secretkey', digits);
free (totp)

char *hotp = HOTP('secretkey', counter, digits);
free (hotp);
```

where ```digits``` is either ```6``` or ```8``` and ```counter``` is a value decided with the server. 
