
#include "clmm.h"

int main(int argc, char** argv) {

  // Construct the path to the ~/.clmm directory and make sure it exsits
  struct passwd *pw = getpwuid(getuid());
  c_string homedir = pw->pw_dir;
  c_string clmm_path, mkdir_cmd;
  asprintf(&clmm_path, "%s/.clmm", homedir);
  asprintf(&mkdir_cmd, "mkdir -p %s", clmm_path);
  if (system(mkdir_cmd)) {
    perror("mkdir");
    exit(-1);
  }
  chmod(clmm_path, 0700);

  // Get the key name, default to the user's name
  c_string key_name = (argc == 1 ? pw->pw_name : argv[1]);

  // Construct the paths to the key files
  c_string pek_path, sek_path, psk_path, ssk_path;
  asprintf(&pek_path, "%s/%s.public_encryption_key", clmm_path, key_name);
  asprintf(&sek_path, "%s/%s.secret_encryption_key", clmm_path, key_name);
  asprintf(&psk_path, "%s/%s.public_signing_key", clmm_path, key_name);
  asprintf(&ssk_path, "%s/%s.secret_signing_key", clmm_path, key_name);

  if (file_size(sek_path)>0 || file_size(ssk_path)>0 ||
      file_size(psk_path)>0 || file_size(pek_path)>0) {
    printf("Keys for %s already exist.  If you want to re-generate them\n",
	   key_name);
    printf("you must first delete the existing keys by doing:\n");
    printf("  rm -f %s/%s.*\n", clmm_path, key_name);
    die("");
  }

  // Generate a secret key
  p_vector my_sek = mkvector(sek_size, 0);
  randombytes(my_sek->data, sek_size);

  // Generate the public key
  p_vector my_pek = mkvector(pek_size, 0);
  crypto_scalarmult_base(my_pek->data, my_sek->data);

  // Generate the signing keypair
  p_vector my_ssk = mkvector(ssk_size, 0);
  p_vector my_psk = mkvector(psk_size, 0);
  crypto_sign_keypair(my_psk->data, my_ssk->data);

  // Encrypt the secret keys
  char *passwd = getpass("Enter a pass phrase: ");
  u8 passwd_hash[crypto_hash_BYTES];
  crypto_hash(passwd_hash, (u8*)passwd, strlen(passwd));
  for (int i=0; i<sek_size; i++) (my_sek->data[i]) ^= passwd_hash[i];

  c_string passwd1 = malloc(strlen(passwd));
  strcpy(passwd1, passwd);
  passwd = getpass("Verify pass phrase: ");
  if (strcmp(passwd, passwd1)) die("Pass phrases do not match.");

  // Write the public keys

  umask(0333);
  write_cstring(pek_path, b64encode(my_pek));
  write_cstring(psk_path, b64encode(my_psk));

  // Write secret keys in binary to make it a little less tempting to share

  umask(0377);
  write_pvector(sek_path, my_sek);
  write_pvector(ssk_path, my_ssk);

  printf("Successfully generated new keys for %s\n", key_name);
}
