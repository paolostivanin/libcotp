#ifndef LIBCOTP_H_INCLUDED
#define LIBCOTP_H_INCLUDED

#define VERSION "1.0.1"
#define DEVELOPER "Paolo Stivanin"
#define DEV_MAIL "info@paolostivanin.com"
#define DEV_WEBSITE "http://paolostivanin.com"
#define LIB_WEBSITE "https://github.com/paolostivanin/libcotp"

char *get_hotp (const char *, long, int);
char *get_totp (const char *, int);

#endif
