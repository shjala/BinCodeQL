/**
 * Manual Fuzzing Harness for SimpleImage Library
 *
 * This is a hand-written harness to compare against auto-generated harnesses.
 * It demonstrates best practices for fuzzing the library.
 */

#include "../include/simpleimage.h"
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Skip too small or too large inputs */
    if (size < 50 || size > 100 * 1024 * 1024) {
        return 0;
    }

    /* Try to load image from memory */
    Image* img = simg_load_from_memory(data, size);

    if (img) {
        /* If load succeeded, exercise other functions */

        /* Get image info */
        ImageInfo info;
        simg_get_info(img, &info);

        /* Try applying filters */
        simg_apply_filter(img, FILTER_BRIGHTNESS);
        simg_apply_filter(img, FILTER_CONTRAST);
        simg_apply_filter(img, FILTER_GRAYSCALE);

        /* Cleanup */
        simg_free(img);
    }

    return 0;
}
