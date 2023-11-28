#pragma once

typedef struct whmac_handle_s whmac_handle_t;

int             whmac_check      (void);

whmac_handle_t* whmac_gethandle  (int algo);

size_t          whmac_getlen     (whmac_handle_t* hd);

void            whmac_freehandle (whmac_handle_t *hd);

int             whmac_setkey     (whmac_handle_t *hd,
                                  unsigned char  *buffer,
                                  size_t         buflen);

void            whmac_update     (whmac_handle_t *hd,
                                  unsigned char  *buffer,
                                  size_t         buflen);

ssize_t         whmac_finalize   (whmac_handle_t *hd,
                                  unsigned char  *buffer,
                                  size_t         buflen);

