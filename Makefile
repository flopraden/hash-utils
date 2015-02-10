build:
	gcc -lcrypt -lcrypto -o passwd-tools passwd-tools.c base64.c
install:
	mkdir -p ${DESTDIR}/usr/bin/
	cp passwd-tools ${DESTDIR}/usr/bin/
clean:
	rm -f *.o passwd-tools
