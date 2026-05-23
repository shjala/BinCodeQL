/**
 * SimpleImage Library - A minimal image format parser for fuzzing testing
 *
 * File Format: .simg (Simple Image)
 * - Text header with metadata (SIMG format)
 * - Binary pixel data (RGB/RGBA)
 *
 * This library intentionally contains realistic vulnerabilities for testing
 * automated fuzzing harness generation.
 */

#ifndef SIMPLEIMAGE_H
#define SIMPLEIMAGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct Image Image;
typedef struct ImageInfo ImageInfo;

/* Image format types */
typedef enum {
    FORMAT_RGB = 0,   /* 3 bytes per pixel */
    FORMAT_RGBA = 1   /* 4 bytes per pixel */
} ImageFormat;

/* Filter types for image processing */
typedef enum {
    FILTER_BRIGHTNESS = 0,
    FILTER_CONTRAST = 1,
    FILTER_GRAYSCALE = 2
} FilterType;

/* Image information structure */
struct ImageInfo {
    uint32_t width;
    uint32_t height;
    ImageFormat format;
    char title[64];
    char author[32];
    uint32_t timestamp;
};

/* === PUBLIC API (5 exported functions) === */

/**
 * Load an image from a file
 * @param filename Path to .simg file
 * @return Image pointer on success, NULL on failure
 */
Image* simg_load_from_file(const char* filename);

/**
 * Load an image from memory buffer
 * @param data Pointer to image data
 * @param size Size of data in bytes
 * @return Image pointer on success, NULL on failure
 */
Image* simg_load_from_memory(const uint8_t* data, size_t size);

/**
 * Get image information
 * @param img Image pointer
 * @param info Output structure for image info
 * @return 0 on success, -1 on failure
 */
int simg_get_info(const Image* img, ImageInfo* info);

/**
 * Apply a filter to the image
 * WARNING: This function has vulnerabilities for testing purposes
 * @param img Image pointer
 * @param filter Filter type to apply
 * @return 0 on success, -1 on failure
 */
int simg_apply_filter(Image* img, FilterType filter);

/**
 * Free an image and its resources
 * @param img Image pointer to free
 */
void simg_free(Image* img);

#ifdef __cplusplus
}
#endif

#endif /* SIMPLEIMAGE_H */
