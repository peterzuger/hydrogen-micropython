// Header for libhydrogen use only.  Act like a Particle board for the random
// implementation.  This code is not actually called when just decrypting and
// verifying a signature, but a correct implementation is provided anyway.

#include "py/mphal.h"

static inline uint32_t HAL_RNG_GetRandomNumber(void) {
    return MICROPY_PY_URANDOM_SEED_INIT_FUNC;
}
