/**
 * re-entrant base64url
 * @author jon <jon@wroth.org>
 * CC-BY-4.0
 */
#ifndef LIB_RB64U_H
#define LIB_RB64U_H
#include <stdlib.h>
#include <stdint.h>

#define RB64U_RXBUFSZ (4)

typedef struct b64ue b64ue_t;
typedef struct b64ud b64ud_t;

struct b64ue
{
  uint8_t   f;
  size_t    q, i, j, n;
  uint32_t  b[RB64U_RXBUFSZ], t, k;
  char r;
};

struct b64ud
{
  uint8_t   f, s, k, q;
  uint32_t  a, b, c, t;
  char r;
};


int base64url_encode(char *dest, const size_t maxlen, const char *src, const size_t len, size_t *dlen);

int base64url_decode(char *dest, const size_t maxlen, const char *src, const size_t len, size_t *dlen);


void base64url_encode_reset(b64ue_t *state);

int base64url_encode_ingest(b64ue_t *state, char c);

int base64url_encode_getc(b64ue_t *state);

int base64url_encode_finish(b64ue_t *state);


void base64url_decode_reset(b64ud_t *state);

int base64url_decode_ingest(b64ud_t *state, unsigned char c);

int base64url_decode_getc(b64ud_t *state);

int base64url_decode_finish(b64ud_t *state);


#endif
