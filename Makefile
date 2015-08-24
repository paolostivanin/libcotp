CC = gcc
#CC = clang

#if GCC < 4.9.0
#CFLAGS = -Wall -Wextra -O2 -Wformat=2 -fstack-protector-all -fPIE -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align $(shell pkg-config --cflags gtk+-3.0)
#else
CFLAGS = -Wall -Wextra -O2 -Wformat=2 -fstack-protector-all -fPIC -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align
DFLAGS = -D_FILE_OFFSET_BITS=64 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
LDFLAGS = -shared
LIBS = -lgcrypt -lm

SOURCES = $(wildcard src/*.c)
OBJS = ${SOURCES:.c=.o}

PROG = libotp.so

.SUFFIXES:.c .o

.c.o:
	$(CC) -c $(CFLAGS) $(NOFLAGS) $(DFLAGS) $< -o $@

all: $(PROG)


$(PROG) : $(OBJS)
	$(CC) $(CFLAGS) $(NOFLAGS) $(DFLAGS) $(OBJS) -o $@ $(LIBS) $(LDFLAGS)


.PHONY: clean

clean :
	rm -f $(PROG) $(OBJS)


#install:

#uninstall:
