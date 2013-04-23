#
# Autor: Roman Janko
# Login: xjanko04
# Datum: 3. 11. 2012
# Projekt: 1. projekt do predmetu BIS
#

server_name = server
obj-m = rootkit.o
login = xjanko04
allfiles = $(server_name).c rootkit.c Makefile dokumentace.pdf
KVERSION = $(shell uname -r)

all: server rootkit

server: $(server_name).c
	gcc $(server_name).c -o $(server_name) -lpthread

rootkit:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

pack:
	zip $(login).zip $(allfiles)

clean:
	rm *~ *.o *.ko $(server_name)
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
