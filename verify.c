
#include "clmm.h"

int main(int argc, char** argv) {

  c_string filename;

  if (argc == 2) {
    filename = argv[1];
  } else {
    printf("Usage: %s filename\n", argv[0]);
    exit(1);
  }

  // Read the file to verify

  c_string signature_string = (c_string)file_contents(filename, 0)->data;

  // Parse the public key

  p_vector pk = b64decode(signature_string + strlen("CLMM signed by: "), 0);

  // Parse the signature

  u64 smlen = crypto_sign_BYTES + crypto_hash_BYTES;
  u8* buffer1 = malloc(smlen);
  u8* p1 = buffer1;
  c_string p2 = strstr(signature_string, "\n") + 1;

  for (int i=0; i<4; i++) {
    for (int j=0; j<32; j++) {
      int k;
      sscanf(p2, "%02x", &k);
      *p1++ = (u8)k;
      p2+=2;
    }
    p2+=1;
  }

  // Verify the signature

  u64 mlen;
  u8* buffer2 = malloc(smlen);
  int status = crypto_sign_open(buffer2, &mlen, buffer1, smlen, pk->data);
  printf(status ? "NOT valid\n" : "valid\n");
  return status;
    
}
