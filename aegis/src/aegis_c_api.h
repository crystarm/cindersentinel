#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Validate canonical CBOR policy bytes.
// Returns 0 on success, non-zero on failure and writes a short message to err_buf.
int aegis_validate(const uint8_t *data, size_t len, char *err_buf, size_t err_buf_len);

#ifdef __cplusplus
} // extern "C"
#endif