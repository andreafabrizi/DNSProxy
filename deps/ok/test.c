#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64.h"

int
main (void) {
  unsigned char *str = "brian the monkey and bradley the kinkajou are friends";
  char *enc = b64_encode(str, strlen(str));

  printf("%s\n", enc); // YnJpYW4gdGhlIG1vbmtleSBhbmQgYnJhZGxleSB0aGUga2lua2Fqb3UgYXJlIGZyaWVuZHM=

  char *dec = b64_decode(enc, strlen(enc));

  printf("%s\n", dec); // brian the monkey and bradley the kinkajou are friends
  free(enc);
  free(dec);
  return 0;
}
