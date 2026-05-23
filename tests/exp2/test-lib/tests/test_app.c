/**
 * Sample Application using SimpleImage library
 *
 * Demonstrates correct usage of the library API
 */

#include "../include/simpleimage.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image.simg> [filter]\n", argv[0]);
        fprintf(stderr, "Filters: brightness, contrast, grayscale\n");
        return 1;
    }

    const char* filename = argv[1];

    printf("Loading image: %s\n", filename);

    /* Load image */
    Image* img = simg_load_from_file(filename);
    if (!img) {
        fprintf(stderr, "Error: Failed to load image\n");
        return 1;
    }

    printf("✓ Image loaded successfully\n");

    /* Get and display image info */
    ImageInfo info;
    if (simg_get_info(img, &info) == 0) {
        printf("\nImage Information:\n");
        printf("  Width:  %u\n", info.width);
        printf("  Height: %u\n", info.height);
        printf("  Format: %s\n", info.format == FORMAT_RGB ? "RGB" : "RGBA");
        printf("  Title:  %s\n", info.title);
        printf("  Author: %s\n", info.author);
        printf("  Size:   %zu bytes\n",
               (size_t)info.width * info.height * (info.format == FORMAT_RGBA ? 4 : 3));
    }

    /* Apply filter if specified */
    if (argc >= 3) {
        const char* filter_name = argv[2];
        FilterType filter;

        if (strcmp(filter_name, "brightness") == 0) {
            filter = FILTER_BRIGHTNESS;
            printf("\n✓ Applying brightness filter\n");
        } else if (strcmp(filter_name, "contrast") == 0) {
            filter = FILTER_CONTRAST;
            printf("\n✓ Applying contrast filter\n");
        } else if (strcmp(filter_name, "grayscale") == 0) {
            filter = FILTER_GRAYSCALE;
            printf("\n✓ Applying grayscale filter\n");
        } else {
            fprintf(stderr, "\nWarning: Unknown filter '%s'\n", filter_name);
            simg_free(img);
            return 1;
        }

        if (simg_apply_filter(img, filter) == 0) {
            printf("✓ Filter applied successfully\n");
        } else {
            fprintf(stderr, "Error: Failed to apply filter\n");
        }
    }

    /* Cleanup */
    simg_free(img);
    printf("\n✓ Image freed\n");

    return 0;
}
