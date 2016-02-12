#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fscrypt.h"

int main()
{
  char s[] = "hello world how are you today";
  char *outbuf, *recvbuf;
  char pass[] = "top secret";
  int len = 0;
  int recvlen = 0;

  outbuf = (char *) fs_encrypt((void *) s, strlen(s)+1, pass, &len);
  printf("%s %d\n", "length after encryption = ", len);

  int i = 0;
  printf("ciphertext = ");
  for (i = 0; i < len; i++)
      printf("%02x", outbuf[i]);
  printf("\n");

  recvbuf  = (char *) fs_decrypt((void *) outbuf, len, pass, &recvlen);
//   assert(memcmp(s, recvbuf, recvlen) == 0);
//   assert(recvlen == (strlen(s) + 1));
  printf("plaintext = %s\n", recvbuf);

  delete[] outbuf;
  delete[] recvbuf;

}