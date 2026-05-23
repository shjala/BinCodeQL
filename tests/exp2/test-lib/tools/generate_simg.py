#!/usr/bin/env python3
"""
SimpleImage Format Generator

Generates .simg files with the following format:
SIMG
VERSION:1
WIDTH:640
HEIGHT:480
FORMAT:RGB
TITLE:My Image
AUTHOR:John Doe
[BINARY]
<pixel data>
"""

import sys
import os
import struct
import random
import argparse


def generate_valid_image(width, height, title="Test Image", author="Generator", format_type="RGB"):
    """Generate a valid .simg file"""

    # Text header
    header = f"""SIMG
VERSION:1
WIDTH:{width}
HEIGHT:{height}
FORMAT:{format_type}
TITLE:{title}
AUTHOR:{author}
[BINARY]
"""

    # Calculate pixel data size
    bytes_per_pixel = 4 if format_type == "RGBA" else 3
    pixel_count = width * height * bytes_per_pixel

    # Generate pixel data (simple pattern for testing)
    pixels = bytearray()
    for i in range(width * height):
        # Create a gradient pattern
        r = (i % width) * 255 // width
        g = (i // width) * 255 // height
        b = 128
        pixels.extend([r, g, b])
        if format_type == "RGBA":
            pixels.append(255)  # Alpha channel

    return header.encode('ascii') + pixels


def generate_random_image(width, height, format_type="RGB"):
    """Generate image with random pixel data"""

    header = f"""SIMG
VERSION:1
WIDTH:{width}
HEIGHT:{height}
FORMAT:{format_type}
TITLE:Random Image
AUTHOR:RandomGen
[BINARY]
"""

    bytes_per_pixel = 4 if format_type == "RGBA" else 3
    pixel_count = width * height * bytes_per_pixel

    pixels = bytes([random.randint(0, 255) for _ in range(pixel_count)])

    return header.encode('ascii') + pixels


def generate_overflow_metadata(width=100, height=100):
    """Generate image with oversized metadata to trigger stack overflow"""

    # Create very long title and author strings
    long_title = "A" * 128  # Larger than 64-byte buffer
    long_author = "B" * 64  # Larger than 32-byte buffer

    header = f"""SIMG
VERSION:1
WIDTH:{width}
HEIGHT:{height}
FORMAT:RGB
TITLE:{long_title}
AUTHOR:{long_author}
[BINARY]
"""

    pixel_count = width * height * 3
    pixels = bytes([0] * pixel_count)

    return header.encode('ascii') + pixels


def generate_integer_overflow_dimensions():
    """Generate image with dimensions that cause integer overflow"""

    # Use dimensions that multiply to overflow uint32_t
    # 65536 * 65536 * 3 = 12,884,901,888 > 2^32
    width = 65536
    height = 65536

    header = f"""SIMG
VERSION:1
WIDTH:{width}
HEIGHT:{height}
FORMAT:RGB
TITLE:Overflow Test
AUTHOR:OverflowGen
[BINARY]
"""

    # Only include small amount of pixel data (allocation will be small due to overflow)
    pixels = bytes([255] * 1024)  # Much less than expected

    return header.encode('ascii') + pixels


def generate_malformed_header(malformation_type):
    """Generate images with malformed headers"""

    if malformation_type == "missing_magic":
        header = """NOTIMG
VERSION:1
WIDTH:100
HEIGHT:100
FORMAT:RGB
TITLE:Bad Magic
AUTHOR:MalformGen
[BINARY]
"""
    elif malformation_type == "invalid_format":
        header = """SIMG
VERSION:1
WIDTH:100
HEIGHT:100
FORMAT:INVALID
TITLE:Bad Format
AUTHOR:MalformGen
[BINARY]
"""
    elif malformation_type == "negative_dimensions":
        header = """SIMG
VERSION:1
WIDTH:-100
HEIGHT:-100
FORMAT:RGB
TITLE:Negative Size
AUTHOR:MalformGen
[BINARY]
"""
    elif malformation_type == "zero_dimensions":
        header = """SIMG
VERSION:1
WIDTH:0
HEIGHT:0
FORMAT:RGB
TITLE:Zero Size
AUTHOR:MalformGen
[BINARY]
"""
    elif malformation_type == "huge_dimensions":
        header = """SIMG
VERSION:1
WIDTH:999999
HEIGHT:999999
FORMAT:RGB
TITLE:Huge
AUTHOR:MalformGen
[BINARY]
"""
    elif malformation_type == "missing_binary_marker":
        return """SIMG
VERSION:1
WIDTH:100
HEIGHT:100
FORMAT:RGB
TITLE:No Binary
AUTHOR:MalformGen
""".encode('ascii') + bytes([0] * 30000)
    else:
        header = """SIMG
VERSION:1
WIDTH:100
HEIGHT:100
FORMAT:RGB
TITLE:Unknown Malform
AUTHOR:MalformGen
[BINARY]
"""

    # Add some pixel data
    pixels = bytes([128] * 1024)
    return header.encode('ascii') + pixels


def main():
    parser = argparse.ArgumentParser(description='Generate SimpleImage (.simg) files')
    parser.add_argument('output', help='Output file path')
    parser.add_argument('-w', '--width', type=int, default=100, help='Image width')
    parser.add_argument('-H', '--height', type=int, default=100, help='Image height')
    parser.add_argument('-f', '--format', choices=['RGB', 'RGBA'], default='RGB', help='Pixel format')
    parser.add_argument('-t', '--title', default='Generated Image', help='Image title')
    parser.add_argument('-a', '--author', default='Generator', help='Image author')
    parser.add_argument('--random', action='store_true', help='Generate random pixel data')
    parser.add_argument('--overflow-metadata', action='store_true', help='Generate with oversized metadata')
    parser.add_argument('--overflow-int', action='store_true', help='Generate with integer overflow dimensions')
    parser.add_argument('--malformed', choices=['missing_magic', 'invalid_format', 'negative_dimensions',
                                                 'zero_dimensions', 'huge_dimensions', 'missing_binary_marker'],
                        help='Generate malformed image')

    args = parser.parse_args()

    # Generate based on type
    if args.overflow_metadata:
        data = generate_overflow_metadata(args.width, args.height)
    elif args.overflow_int:
        data = generate_integer_overflow_dimensions()
    elif args.malformed:
        data = generate_malformed_header(args.malformed)
    elif args.random:
        data = generate_random_image(args.width, args.height, args.format)
    else:
        data = generate_valid_image(args.width, args.height, args.title, args.author, args.format)

    # Write to file
    with open(args.output, 'wb') as f:
        f.write(data)

    print(f"Generated {args.output} ({len(data)} bytes)")


if __name__ == '__main__':
    main()
