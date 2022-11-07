#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
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
ok(const char *format, ...) {
  va_list args;

  va_start(args, format);

  if (NULL == format) {
    format = (const char *) "";
  }

  printf("ok %d ", ++ok_count_);
  vprintf(format, args);
  printf("\n");
  va_end(args);
}

void
ok_done(void) {
  if (0 != ok_expected_ && ok_count_ != ok_expected_) {
    if (ok_expected_ > ok_count_) {
      fprintf(stderr, "expected number of success conditions not met.\n");
    } else {
      fprintf(stderr,
        "expected number of success conditions is less than the "
        "number of given success conditions.\n");
    }
    exit(1);
  }

  printf("1..%d\n", ok_count_);
}

void
ok_expect(int expected) {
  ok_expected_ = expected;
}

int
ok_expected() {
  return ok_expected_;
}

int
ok_count() {
  return ok_count_;
}

void
ok_reset() {
  ok_count_ = 0;
  ok_expected_ = 0;
}
