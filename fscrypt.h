#include "openssl/blowfish.h"

// block size for blowfish (bytes)
const int BLOCKSIZE = 8;

// encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);

// decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);
