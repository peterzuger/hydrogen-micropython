// Header for libhydrogen use only.  Act like a Particle board for the random
// implementation.  This code is not actually called when just decrypting and
// verifying a signature, but a correct implementation is provided anyway.

#include "py/mphal.h"
#include "py/runtime.h"

static inline uint32_t HAL_RNG_GetRandomNumber(void) {
    #ifdef MICROPY_PY_RANDOM_SEED_INIT_FUNC
    return MICROPY_PY_RANDOM_SEED_INIT_FUNC;
    #else
    #error MICROPY_PY_RANDOM_SEED_INIT_FUNC not defined
    #endif /* MICROPY_PY_RANDOM_SEED_INIT_FUNC */
}
