CC = gcc
#CC = clang

LIBNAME="libotp.so.1"
LIBNAMEVER="libotp.so.1.0.1"

#if GCC < 4.9.0
#CFLAGS = -Wall -Wextra -O2 -Wformat=2 -fstack-protector-all -fPIE -Wstrict-prototypes -Wunreachable-code  -Wwrite-strings -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wcast-align $(shell pkg-config --cflags gtk+-3.0)
#else
CFLAGS = -Wall -Wextra -fPIC -g -fdiagnostics-color=always
LDFLAGS = -shared -Wl,-soname,${LIBNAME}
LIBS = -lgcrypt

SOURCES = $(wildcard src/*.c)
OBJS = ${SOURCES:.c=.o}

PROG = ${LIBNAMEVER}

.SUFFIXES:.c .o

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

all: $(PROG)

$(PROG) : $(OBJS)
	$(CC) $(LDFLAGS) -o $(LIBNAMEVER) $(LIBS)


.PHONY: clean

clean :
	rm -f $(PROG) $(OBJS)


#install:

#uninstall:
