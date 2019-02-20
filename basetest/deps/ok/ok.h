/**
 * `ok.h` - libok
 *
 * Copyright (C) 2014 Joseph Werle <joseph.werle@gmail.com>
 */

#ifndef OK_H
#define OK_H 1

#ifdef __cplusplus
extern "C" {
#endif

/**
 * libok version
 */

#define OK_VERSION "0.0.1"

/**
 * Increments ok count and
 * outputs a message to stdout
 */

void
ok (const char *);

/**
 * Completes tests and asserts that
 * the expected test count matches the
 * actual test count if the expected
 * count is greater than 0
 */

void
ok_done (void);

/**
 * Sets the expectation count
 */

void
ok_expect (int);

/**
 * Returns the expected count
 */

int
ok_expected ();

/**
 * Returns the ok count
 */

int
ok_count ();

/**
 * Resets count and expected counters
 */

void
ok_reset ();

#ifdef __cplusplus
}
#endif

#endif
