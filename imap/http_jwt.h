/* http_jwt.h - HTTP JSON Web Token authentication */
/* SPDX-License-Identifier: BSD-3-Clause-CMU */
/* See COPYING file at the root of the distribution for more details. */

#ifndef HTTP_JWT_H
#define HTTP_JWT_H

int http_jwt_init(const char *keydir, int max_age);

int http_jwt_is_enabled(void);

int http_jwt_auth(const char *in, size_t inlen, char *out, size_t outlen);

int http_jwt_reset(void);

#endif /* HTTP_JWT_H */
