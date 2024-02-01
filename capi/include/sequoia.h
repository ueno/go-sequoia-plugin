/* SPDX-License-Identifier: LGPL-2.0-or-later */

#ifndef SEQUOIA_H_
#define SEQUOIA_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int pgp_verify_detached(const uint8_t *keyring_ptr,
			size_t keyring_len,
			const uint8_t *signature_ptr,
			size_t signature_len,
			const uint8_t *data_ptr,
			size_t data_len);

#ifdef __cplusplus
}
#endif

#endif	/* SEQUOIA_H_ */
