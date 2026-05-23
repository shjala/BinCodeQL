/**
 * SimpleImage Library - Implementation
 *
 * Contains intentional vulnerabilities for fuzzing harness generation testing:
 * 1. Stack buffer overflow in parse_metadata()
 * 2. Heap buffer overflow in copy_pixel_data()
 * 3. Integer overflow in allocate_pixel_buffer()
 * 4. Off-by-one in read_text_line()
 */

#include "simpleimage.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* === INTERNAL STRUCTURES === */

typedef struct {
    char magic[5];        /* "SIMG\0" */
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t format;      /* ImageFormat enum */
} ImageHeader;

typedef struct {
    char title[64];
    char author[32];
    uint32_t timestamp;
} ImageMetadata;

struct Image {
    ImageHeader header;
    ImageMetadata metadata;
    uint8_t* pixels;
    size_t pixel_size;
};

/* === INTERNAL FUNCTION DECLARATIONS === */

/* Parsing layer (Level 2) */
static int parse_header(const uint8_t* data, size_t size, size_t* offset, ImageHeader* hdr);
static int parse_metadata(const uint8_t* data, size_t size, size_t* offset, ImageMetadata* meta);
static int decode_pixel_data(const uint8_t* data, size_t size, size_t offset, Image* img);

/* Validation layer (Level 3) */
static int validate_dimensions(uint32_t width, uint32_t height);
static int validate_format(uint32_t format);

/* Utility functions (Level 3-4) */
static int read_text_line(const uint8_t* data, size_t size, size_t* offset,
                          char* buffer, size_t bufsize);
static int parse_key_value(const char* line, char* key, char* value);

/* Memory operations (Level 4 - Vulnerable) */
static uint8_t* allocate_pixel_buffer(uint32_t width, uint32_t height, uint32_t format);
static void copy_pixel_data(uint8_t* dst, const uint8_t* src, size_t count);

/* Filter operations (Level 3 - Vulnerable) */
static void apply_brightness_filter(uint8_t* pixels, size_t count, int delta);
static void apply_contrast_filter(uint8_t* pixels, size_t count, float factor);

/* === LEVEL 4: UTILITY FUNCTIONS (Most Vulnerable) === */

/**
 * VULNERABILITY 1: Off-by-one error
 * Can write one byte past buffer end when line exactly fills buffer
 */
static int read_text_line(const uint8_t* data, size_t size, size_t* offset,
                          char* buffer, size_t bufsize) {
    size_t i = 0;
    size_t start = *offset;

    while (start + i < size && data[start + i] != '\n' && i < bufsize) {
        buffer[i] = data[start + i];
        i++;
    }

    /* BUG: Off-by-one when i == bufsize */
    buffer[i] = '\0';  /* Can write past buffer if i == bufsize */

    *offset = start + i + 1;  /* Skip newline */
    return (i > 0) ? 0 : -1;
}

/**
 * Parse key:value pairs from text line
 */
static int parse_key_value(const char* line, char* key, char* value) {
    const char* colon = strchr(line, ':');
    if (!colon) return -1;

    size_t key_len = colon - line;
    if (key_len >= 64) return -1;  /* Limit key length */

    strncpy(key, line, key_len);
    key[key_len] = '\0';

    strcpy(value, colon + 1);  /* Value after colon */
    return 0;
}

/**
 * VULNERABILITY 2: Integer overflow leading to small allocation
 * width * height * bytes_per_pixel can overflow uint32_t
 * Result: malloc with small size, later overflow when copying
 */
static uint8_t* allocate_pixel_buffer(uint32_t width, uint32_t height, uint32_t format) {
    uint32_t bytes_per_pixel = (format == FORMAT_RGBA) ? 4 : 3;

    /* BUG: Integer overflow here! */
    /* If width * height * bytes_per_pixel > UINT32_MAX, wraps around */
    size_t size = (size_t)(width * height * bytes_per_pixel);

    uint8_t* buffer = (uint8_t*)malloc(size);
    if (buffer) {
        memset(buffer, 0, size);
    }

    return buffer;
}

/**
 * VULNERABILITY 3: Heap buffer overflow
 * No bounds checking - copies count bytes regardless of dst size
 */
static void copy_pixel_data(uint8_t* dst, const uint8_t* src, size_t count) {
    /* BUG: No validation of dst buffer size! */
    /* If dst allocated with overflow, this will overflow heap */
    memcpy(dst, src, count);
}

/* === LEVEL 3: VALIDATION & PROCESSING === */

/**
 * Validate image dimensions
 */
static int validate_dimensions(uint32_t width, uint32_t height) {
    /* Reasonable limits */
    if (width == 0 || height == 0) return -1;
    if (width > 8192 || height > 8192) return -1;

    /* Check for potential integer overflow */
    if (width > 0xFFFF || height > 0xFFFF) {
        /* Additional check but not sufficient to prevent all overflows */
        if ((uint64_t)width * height > 0xFFFFFFFF / 4) {
            return -1;
        }
    }

    return 0;
}

/**
 * Validate format type
 */
static int validate_format(uint32_t format) {
    return (format == FORMAT_RGB || format == FORMAT_RGBA) ? 0 : -1;
}

/**
 * VULNERABILITY 4: Brightness filter with potential overflow
 * Combined with copy_pixel_data vulnerability
 */
static void apply_brightness_filter(uint8_t* pixels, size_t count, int delta) {
    /* This function itself is safe, but is called in vulnerable context */
    for (size_t i = 0; i < count; i++) {
        int new_val = (int)pixels[i] + delta;
        if (new_val < 0) new_val = 0;
        if (new_val > 255) new_val = 255;
        pixels[i] = (uint8_t)new_val;
    }
}

/**
 * Apply contrast filter
 */
static void apply_contrast_filter(uint8_t* pixels, size_t count, float factor) {
    for (size_t i = 0; i < count; i++) {
        int new_val = (int)((pixels[i] - 128) * factor + 128);
        if (new_val < 0) new_val = 0;
        if (new_val > 255) new_val = 255;
        pixels[i] = (uint8_t)new_val;
    }
}

/* === LEVEL 2: PARSING FUNCTIONS === */

/**
 * Parse image header from text section
 */
static int parse_header(const uint8_t* data, size_t size, size_t* offset, ImageHeader* hdr) {
    char line[128];
    char key[64], value[64];

    /* Read magic line */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (strcmp(line, "SIMG") != 0) return -1;
    strcpy(hdr->magic, "SIMG");

    /* Parse version */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (parse_key_value(line, key, value) < 0) return -1;
    if (strcmp(key, "VERSION") != 0) return -1;
    hdr->version = atoi(value);

    /* Parse width */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (parse_key_value(line, key, value) < 0) return -1;
    if (strcmp(key, "WIDTH") != 0) return -1;
    hdr->width = atoi(value);

    /* Parse height */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (parse_key_value(line, key, value) < 0) return -1;
    if (strcmp(key, "HEIGHT") != 0) return -1;
    hdr->height = atoi(value);

    /* Parse format */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (parse_key_value(line, key, value) < 0) return -1;
    if (strcmp(key, "FORMAT") != 0) return -1;
    if (strcmp(value, "RGB") == 0) {
        hdr->format = FORMAT_RGB;
    } else if (strcmp(value, "RGBA") == 0) {
        hdr->format = FORMAT_RGBA;
    } else {
        return -1;
    }

    /* Validate header */
    if (validate_dimensions(hdr->width, hdr->height) < 0) return -1;
    if (validate_format(hdr->format) < 0) return -1;

    return 0;
}

/**
 * VULNERABILITY 5: Stack buffer overflow in metadata parsing
 * strcpy without bounds check when TITLE or AUTHOR too long
 */
static int parse_metadata(const uint8_t* data, size_t size, size_t* offset, ImageMetadata* meta) {
    char line[128];
    char key[64], value[256];  /* value buffer larger than metadata fields */

    /* Initialize metadata */
    memset(meta, 0, sizeof(ImageMetadata));

    /* Parse TITLE - BUG: no length check before strcpy */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (parse_key_value(line, key, value) < 0) return -1;
    if (strcmp(key, "TITLE") == 0) {
        /* BUG: Stack buffer overflow if value > 64 bytes */
        strcpy(meta->title, value);
    }

    /* Parse AUTHOR - BUG: no length check before strcpy */
    if (read_text_line(data, size, offset, line, sizeof(line)) < 0) return -1;
    if (parse_key_value(line, key, value) < 0) return -1;
    if (strcmp(key, "AUTHOR") == 0) {
        /* BUG: Stack buffer overflow if value > 32 bytes */
        strcpy(meta->author, value);
    }

    /* Optional: timestamp */
    meta->timestamp = 0;  /* Default */

    return 0;
}

/**
 * Decode pixel data from binary section
 * Combines multiple vulnerabilities through call chain
 */
static int decode_pixel_data(const uint8_t* data, size_t size, size_t offset, Image* img) {
    /* Check if we have [BINARY] marker */
    char marker[16];
    size_t marker_offset = offset;

    if (read_text_line(data, size, &marker_offset, marker, sizeof(marker)) < 0) {
        return -1;
    }

    if (strcmp(marker, "[BINARY]") != 0) return -1;

    offset = marker_offset;

    /* Calculate expected pixel data size */
    uint32_t bytes_per_pixel = (img->header.format == FORMAT_RGBA) ? 4 : 3;
    size_t expected_size = (size_t)img->header.width * img->header.height * bytes_per_pixel;

    /* Check if we have enough data */
    if (offset + expected_size > size) return -1;

    /* Allocate pixel buffer - VULNERABLE to integer overflow */
    img->pixels = allocate_pixel_buffer(img->header.width, img->header.height, img->header.format);
    if (!img->pixels) return -1;

    img->pixel_size = expected_size;

    /* Copy pixel data - VULNERABLE to heap overflow if allocation was too small */
    copy_pixel_data(img->pixels, data + offset, expected_size);

    return 0;
}

/* === LEVEL 1: PUBLIC API FUNCTIONS === */

/**
 * Load image from memory buffer
 * Main entry point - establishes call chain to vulnerable functions
 */
Image* simg_load_from_memory(const uint8_t* data, size_t size) {
    if (!data || size == 0) return NULL;

    Image* img = (Image*)calloc(1, sizeof(Image));
    if (!img) return NULL;

    size_t offset = 0;

    /* Parse header (Level 2) */
    if (parse_header(data, size, &offset, &img->header) < 0) {
        free(img);
        return NULL;
    }

    /* Parse metadata (Level 2) - VULNERABLE to stack overflow */
    if (parse_metadata(data, size, &offset, &img->metadata) < 0) {
        free(img);
        return NULL;
    }

    /* Decode pixel data (Level 2->3->4) - VULNERABLE to heap overflow */
    if (decode_pixel_data(data, size, offset, img) < 0) {
        free(img);
        return NULL;
    }

    return img;
}

/**
 * Load image from file
 */
Image* simg_load_from_file(const char* filename) {
    if (!filename) return NULL;

    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;

    /* Get file size */
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 100 * 1024 * 1024) {  /* Max 100MB */
        fclose(f);
        return NULL;
    }

    /* Read file into memory */
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    if (fread(data, 1, size, f) != (size_t)size) {
        free(data);
        fclose(f);
        return NULL;
    }

    fclose(f);

    /* Load from memory */
    Image* img = simg_load_from_memory(data, size);
    free(data);

    return img;
}

/**
 * Get image information
 */
int simg_get_info(const Image* img, ImageInfo* info) {
    if (!img || !info) return -1;

    info->width = img->header.width;
    info->height = img->header.height;
    info->format = (ImageFormat)img->header.format;
    strncpy(info->title, img->metadata.title, sizeof(info->title) - 1);
    info->title[sizeof(info->title) - 1] = '\0';
    strncpy(info->author, img->metadata.author, sizeof(info->author) - 1);
    info->author[sizeof(info->author) - 1] = '\0';
    info->timestamp = img->metadata.timestamp;

    return 0;
}

/**
 * Apply filter to image
 * Creates call chain: apply_filter -> apply_*_filter -> copy_pixel_data
 */
int simg_apply_filter(Image* img, FilterType filter) {
    if (!img || !img->pixels) return -1;

    size_t pixel_count = img->pixel_size;

    switch (filter) {
        case FILTER_BRIGHTNESS:
            /* Apply brightness - vulnerable through copy_pixel_data in complex scenarios */
            apply_brightness_filter(img->pixels, pixel_count, 20);
            break;

        case FILTER_CONTRAST:
            apply_contrast_filter(img->pixels, pixel_count, 1.5f);
            break;

        case FILTER_GRAYSCALE:
            /* Simple grayscale conversion */
            if (img->header.format == FORMAT_RGB || img->header.format == FORMAT_RGBA) {
                int step = (img->header.format == FORMAT_RGBA) ? 4 : 3;
                for (size_t i = 0; i < pixel_count; i += step) {
                    uint8_t gray = (uint8_t)((img->pixels[i] + img->pixels[i+1] + img->pixels[i+2]) / 3);
                    img->pixels[i] = img->pixels[i+1] = img->pixels[i+2] = gray;
                }
            }
            break;

        default:
            return -1;
    }

    return 0;
}

/**
 * Free image resources
 */
void simg_free(Image* img) {
    if (!img) return;

    if (img->pixels) {
        free(img->pixels);
        img->pixels = NULL;
    }

    free(img);
}
