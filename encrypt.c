
#include "clmm.h"

int main(int argc, char** argv) {

  struct passwd *pw = getpwuid(getuid());

  c_string filename, to_id, from_id;

  if (argc == 3) {
    filename = argv[1];
    to_id = argv[2];
    from_id = pw->pw_name;
  } else if (argc == 4) {
    filename = argv[1];
    to_id = argv[2];
    from_id = argv[3];
  } else {
    printf("Usage: %s filename recipient_key_id [sender_key_id]\n", argv[0]);
    exit(1);
  }

  c_string homedir = pw->pw_dir;
  c_string clmm_path, to_pk_path, from_sk_path, from_pk_path;
  asprintf(&clmm_path, "%s/.clmm", homedir);

  asprintf(&to_pk_path, "%s/%s.public_encryption_key", clmm_path, to_id);
  c_string to_pk_b64 = (c_string)file_contents(to_pk_path, 0)->data;
  u8* to_pk = b64decode(to_pk_b64, 0)->data;

  asprintf(&from_pk_path, "%s/%s.public_encryption_key", clmm_path, from_id);
  c_string from_pk_b64 = (c_string)file_contents(from_pk_path, 0)->data;
  u8* from_pk = b64decode(from_pk_b64, 0)->data;

  asprintf(&from_sk_path, "%s/%s.secret_encryption_key", clmm_path, from_id);
  u8 from_sk[sek_size];
  FILE *f = fopen(from_sk_path, "r");
  fread(from_sk, sek_size, 1, f);
  fclose(f);

  // Decrypt the secret key
  char *passwd = getpass("Enter a pass phrase: ");
  u8 passwd_hash[crypto_hash_BYTES];
  crypto_hash(passwd_hash, (u8*)passwd, strlen(passwd));
  for (int i=0; i<sek_size; i++) from_sk[i] ^= passwd_hash[i];

  u8 from_pk1[pek_size];
  crypto_scalarmult_base(from_pk1, from_sk);
  if (crypto_verify_16(from_pk, from_pk1)) die("Incorrect pass phrase");

  p_vector msg = file_contents(filename, crypto_box_ZEROBYTES);
  u8 *m = msg->padding;
  size_t mlen = msg->size;
  size_t clen = mlen + crypto_box_ZEROBYTES;

  // Pre-encryption

  unsigned char k1[crypto_box_BEFORENMBYTES];
  if (crypto_box_beforenm(k1, to_pk, from_sk) != 0)
    die("Crypto setup failed");

  p_vector nonce = mkvector(crypto_box_NONCEBYTES, 0);
  randombytes(nonce->data, crypto_box_NONCEBYTES);

  // Allocate ciphertext
  size_t offset = crypto_box_BOXZEROBYTES;
  p_vector ciphertext = mkvector(clen - offset, offset);
  u8 *c = ciphertext->padding;

  // Encrypt

  if (crypto_box_afternm(c, m, clen, nonce->data, k1) != 0)
    die("Encrpytion failed");

  // Output

  c_string s = b64encode(ciphertext);
  c_string s_end = s + strlen(s) - 76;

  printf("%s\n%s\n", b64encode(nonce), from_pk_b64);
  c_string s1 = s;
  for (; s1<s_end; s1+=76) {
    fwrite(s1, 76, 1, stdout);
    putchar('\n');
  }
  puts(s1);
  putchar('\n');
}
