LIB = utils.c base64.c tweetnacl.c
CC = gcc -Wall --std=c99
DEPS = ${LIB} clmm.h
OBJS = genkeys encrypt decrypt sign verify
all: ${OBJS}

genkeys: genkeys.c ${DEPS}
	${CC} genkeys.c ${LIB} -o genkeys

encrypt: encrypt.c ${DEPS}
	${CC} encrypt.c $(LIB) -o encrypt

decrypt: decrypt.c ${DEPS}
	${CC} decrypt.c $(LIB) -o decrypt

sign: sign.c ${DEPS}
	${CC} sign.c $(LIB) -o sign

verify: verify.c ${DEPS}
	${CC} verify.c $(LIB) -o verify

clean:
	rm -f ${OBJS}
