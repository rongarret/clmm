
#include "clmm.h"

int main(int argc, char** argv) {

  struct passwd *pw = getpwuid(getuid());

  c_string key_id, filename;

  if (argc == 2) {
    filename = argv[1];
    key_id = pw->pw_name;
  } else if (argc == 3) {
    filename = argv[1];
    key_id = argv[2];
  } else {
    printf("Usage: %s filename [key_id]\n", argv[0]);
    exit(1);
  }

  c_string homedir = pw->pw_dir;
  c_string clmm_path, pk_path, sk_path;
  asprintf(&clmm_path, "%s/.clmm", homedir);

  asprintf(&pk_path, "%s/%s.public_signing_key", clmm_path, key_id);
  c_string pk_b64 = (c_string)file_contents(pk_path, 0)->data;
  u8* pk = b64decode(pk_b64, 0)->data;

  asprintf(&sk_path, "%s/%s.secret_signing_key", clmm_path, key_id);
  u8* sk = file_contents(sk_path, 0)->data;

  // Decrypt the secret key
  char *passwd = getpass("Enter a pass phrase: ");
  u8 passwd_hash[crypto_hash_BYTES];
  crypto_hash(passwd_hash, (u8*)passwd, strlen(passwd));
  for (int i=0; i<ssk_size; i++) sk[i] ^= passwd_hash[i];

  // Read the file to sign

  p_vector msg = file_contents(filename, 0);
  p_vector hash = mkvector(crypto_hash_BYTES, 0);
  crypto_hash(hash->data, msg->data, msg->size);

  // Sign it

  u64 smlen;
  p_vector signature = mkvector(crypto_sign_BYTES + crypto_hash_BYTES, 0);
  crypto_sign(signature->padding, &smlen, hash->data, hash->size, sk);

  // Verify the signature

  u64 mlen;  // What a crazy API
  u8* buffer = malloc(smlen);
  int status = crypto_sign_open(buffer, &mlen, signature->padding, smlen, pk);
  if (status) die("Incorrect pass phrase");

  // Output the signature
  printf("CLMM signed by: %s\n", pk_b64);
  for (int i=0; i<signature->size; i++) {
    printf("%02x", signature->data[i]);
    if ((i+1)%32 == 0) printf("\n");
  }
}
