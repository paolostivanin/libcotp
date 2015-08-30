# libcotp
C library that generates TOTP and HOTP

How To Use It
-------------

```
char *totp = get_totp ('secretkey', digits);
free (totp);

char *hotp = get_hotp ('secretkey', counter, digits);
free (hotp);
```

where ```digits``` is either ```6``` or ```8``` and ```counter``` is a value decided with the server. 
<br><br>Please note that you **must free** the memory allocated for the totp/hotp value(s) once you're done with it(them)!
