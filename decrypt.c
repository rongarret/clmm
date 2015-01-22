
#include "clmm.h"

int main(int argc, char** argv) {

  struct passwd *pw = getpwuid(getuid());

  c_string filename, to_id;

  if (argc == 2) {
    filename = argv[1];
    to_id = pw->pw_name;
  } else if (argc == 3) {
    filename = argv[1];
    to_id = argv[2];
  } else {
    printf("Usage: %s filename [recipient_key_id]\n", argv[0]);
    exit(1);
  }

  // Get the keys

  c_string homedir = pw->pw_dir;
  c_string clmm_path, from_pk_path, to_sk_path, to_pk_path;
  asprintf(&clmm_path, "%s/.clmm", homedir);
  
  asprintf(&to_pk_path, "%s/%s.public_encryption_key", clmm_path, to_id);
  c_string to_pk_b64 = (c_string)file_contents(to_pk_path, 0)->data;
  u8* to_pk = b64decode(to_pk_b64, 0)->data;
  
  asprintf(&to_sk_path, "%s/%s.secret_encryption_key", clmm_path, to_id);
  u8* to_sk = file_contents(to_sk_path, 0)->data;

  // Decrypt the secret key

  char *passwd = getpass("Enter a pass phrase: ");
  u8 passwd_hash[crypto_hash_BYTES];
  crypto_hash(passwd_hash, (u8*)passwd, strlen(passwd));
  for (int i=0; i<sek_size; i++) to_sk[i] ^= passwd_hash[i];
  
  u8 to_pk1[pek_size];
  crypto_scalarmult_base(to_pk1, to_sk);
  if (crypto_verify_32(to_pk, to_pk1)) die("Incorrect pass phrase");

  // Get the from_key, nonce and ciphertext from the encrypted message

  c_string s = (c_string)file_contents(filename, 0)->data;
  c_string nonce_b64 = strtok(s, "\n");
  c_string from_pk_b64 = strtok(0, "\n");
  c_string ciphertext_b64 = strtok(0, "\0");

  u8* nonce = b64decode(nonce_b64, 0)->data;
  u8* from_pk = b64decode(from_pk_b64, 0)->data;

  // Remove newlines from ciphertext
  c_string s1,s2;
  s1 = s2 = ciphertext_b64;
  do {
    if (*s1 != '\n') *s2++ = *s1;
  } while (*s1++);
  *s2++ = '\0';

  size_t offset = crypto_box_BOXZEROBYTES;
  p_vector ciphertext = b64decode(ciphertext_b64, offset);
  u8* c = ciphertext->padding;
  size_t clen = ciphertext->size + offset;

  // Allocate cleartext buffer
  p_vector msg = mkvector(clen, crypto_box_ZEROBYTES);

  // Pre-decryption

  unsigned char k1[crypto_box_BEFORENMBYTES];
  if (crypto_box_beforenm(k1, from_pk, to_sk) != 0)
    die("Crypto setup failed");

  // Decrypt

  if (crypto_box_open_afternm(msg->padding, c, clen, nonce, k1) != 0)
    die("Decrpytion failed");

  fwrite(msg->data, clen-crypto_box_ZEROBYTES, 1, stdout);
}
