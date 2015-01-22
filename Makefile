LIB = utils.c base64.c tweetnacl.c
DEPS = ${LIB} clmm.h
OBJS = genkeys encrypt decrypt sign verify
all: ${OBJS}

genkeys: genkeys.c ${DEPS}
	gcc genkeys.c ${LIB} -o genkeys

encrypt: encrypt.c ${DEPS}
	gcc encrypt.c $(LIB) -o encrypt

decrypt: decrypt.c ${DEPS}
	gcc decrypt.c $(LIB) -o decrypt

sign: sign.c ${DEPS}
	gcc sign.c $(LIB) -o sign

verify: verify.c ${DEPS}
	gcc verify.c $(LIB) -o verify

clean:
	rm -f ${OBJS}
