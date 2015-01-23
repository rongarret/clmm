#ifdef __linux
#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <strings.h>
#include <sys/stat.h>
#include <pwd.h>

#include "tweetnacl.h"
#include "base64.h"

#define sek_size crypto_box_SECRETKEYBYTES
#define pek_size crypto_box_PUBLICKEYBYTES
#define ssk_size crypto_sign_SECRETKEYBYTES
#define psk_size crypto_sign_PUBLICKEYBYTES

typedef unsigned char u8;
typedef unsigned long long u64;
typedef char* c_string;

// tweetnacl uses buffers with leading padding.  This structure hides
// that crufty detail.
//
typedef struct p_vector {
  size_t size;  // Size of the data without padding
  u8 *padding;
  u8 *data;
} *p_vector;

void randombytes(u8 *buf, u64 cnt);

void die(char *msg);
p_vector mkvector(size_t size, size_t padding);
long file_size(char* path);
p_vector file_contents(char* path, size_t padding);
int write_pvector(c_string path, p_vector v);
int write_cstring(c_string path, c_string s);
c_string b64encode(p_vector v);
p_vector b64decode(c_string input, size_t padding);
