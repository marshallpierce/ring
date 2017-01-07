#include <openssl/cpu.h>

/* Runtime CPU feature support */

#ifdef __linux__

/* |getauxval| is not available on Android until API level 20. Link it as a weak
 * symbol and use other methods as fallback. As of Rust 1.14 this weak linkage
 * isn't supported, so we do it in C. */
unsigned long getauxval(unsigned long type) __attribute__((weak));

unsigned long getauxval_wrapper(unsigned long type, char *success);

#include <errno.h>

unsigned long getauxval_wrapper(unsigned long type, char *success) {
    if (getauxval == NULL) {
        *success = 0;
        return 0;
    }

    unsigned long result = getauxval(type);
    if (errno != 0) {
        *success = 0;
        return 0;
    }

    *success = 1;
    return result;
}
#endif
