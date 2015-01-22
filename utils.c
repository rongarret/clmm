#include "clmm.h"

void die(char *msg) {
  puts(msg);
  exit(-1);
}

void randombytes(u8 *buf, u64 cnt) {
  int devrandom = open("/dev/random", O_RDONLY);
  if (devrandom < 0) die("Failed to open /dev/random");
  int n = read(devrandom, buf, cnt);
  if (n != cnt) die("Failed to read enough random bytes from /dev/random");
  close(devrandom);
}

long file_size(char* path) {
  struct stat stats;
  return stat(path, &stats) ? -1 : stats.st_size;
}

p_vector mkvector(size_t size, size_t padding) {
  size_t psize = size + padding;
  u8 *p = malloc(psize);
  bzero(p, psize);
  p_vector v = malloc(sizeof(struct p_vector));
  v->size = size;
  v->padding = p;
  v->data = p + padding;
  return v;
}

FILE *open_file(c_string path, c_string mode) {
  FILE *f = fopen(path, mode);
  if (!f) {
    perror(path);
    exit(-1);
  }
  return f;
}

p_vector file_contents(char* path, size_t padding) {
  FILE *f = open_file(path, "r");
  p_vector v = mkvector(file_size(path), padding);
  if (fread(v->data, v->size, 1, f) != 1) die("Failed to read file");
  return v;
}

int write_pvector(c_string path, p_vector v) {
  FILE *f = open_file(path, "w");
  int result = fwrite(v->data, v->size, 1, f);
  fclose(f);
  return result;
}

int write_cstring(c_string path, c_string s) {
  FILE *f = open_file(path, "w");
  int result = fputs(s, f);
  fclose(f);
  return result;
}

c_string b64encode(p_vector v) {
  c_string result = malloc(Base64encode_len(v->size));
  Base64encode(result, (char *)v->data, v->size);
  return result;
}

p_vector b64decode(c_string input, size_t padding) {
  size_t bytecnt_estimate = Base64decode_len(input);
  p_vector v = mkvector(bytecnt_estimate, padding);
  size_t bytecnt = Base64decode((char *)v->data, input);
  if ((bytecnt > bytecnt_estimate) || (bytecnt < bytecnt_estimate-3)) {
    die("Failed to decode base64 string");
  }
  v->size = bytecnt;
  return v;
}
