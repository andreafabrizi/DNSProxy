#include <stdio.h>
#include <stdlib.h>
#include "ok.h"

/**
 * Represents the ok count
 */

static int ok_count_;

/**
 * Represents an optional
 * expected test count
 */

static int ok_expected_;

void
ok (const char *message) {
  if (NULL == message) {
    message = (const char *) "";
  }
  printf("ok %d %s\n", ++ok_count_, message);
}

void
ok_done (void) {
  if (0 != ok_expected_ &&
      ok_count_ != ok_expected_) {
    fprintf(stderr, "expected number of success conditions not met.\n");
    exit(1);
  }

  printf("1..%d\n", ok_count_);
}

void
ok_expect (int expected) {
  ok_expected_ = expected;
}

int
ok_expected () {
  return ok_expected_;
}

int
ok_count () {
  return ok_count_;
}

void
ok_reset () {
  ok_count_ = 0;
  ok_expected_ = 0;
}
