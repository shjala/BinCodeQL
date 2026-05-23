#!/usr/bin/env python3
"""
Generate a complete fuzzing corpus for SimpleImage library
Creates valid, edge case, and malformed test inputs
"""

import os
import sys
import subprocess


def run_generator(output_dir, filename, args):
    """Run generate_simg.py with arguments"""
    script_path = os.path.join(os.path.dirname(__file__), 'generate_simg.py')
    output_path = os.path.join(output_dir, filename)

    cmd = [sys.executable, script_path, output_path] + args
    subprocess.run(cmd, check=True)
    print(f"  ✓ {filename}")


def generate_corpus(output_dir):
    """Generate complete test corpus"""

    os.makedirs(output_dir, exist_ok=True)

    print("Generating valid samples...")

    # Valid samples - various sizes
    run_generator(output_dir, "valid_tiny_10x10.simg", ["-w", "10", "-H", "10"])
    run_generator(output_dir, "valid_small_100x100.simg", ["-w", "100", "-H", "100"])
    run_generator(output_dir, "valid_medium_640x480.simg", ["-w", "640", "-H", "480"])
    run_generator(output_dir, "valid_large_1920x1080.simg", ["-w", "1920", "-H", "1080"])

    # Different formats
    run_generator(output_dir, "valid_rgba_100x100.simg", ["-w", "100", "-H", "100", "-f", "RGBA"])

    # With metadata
    run_generator(output_dir, "valid_with_title.simg",
                  ["-w", "200", "-H", "200", "-t", "My Test Image", "-a", "Test Author"])

    # Random data
    run_generator(output_dir, "valid_random_256x256.simg",
                  ["-w", "256", "-H", "256", "--random"])

    print("\nGenerating boundary cases...")

    # Boundary dimensions
    run_generator(output_dir, "boundary_1x1.simg", ["-w", "1", "-H", "1"])
    run_generator(output_dir, "boundary_8192x1.simg", ["-w", "8192", "-H", "1"])
    run_generator(output_dir, "boundary_1x8192.simg", ["-w", "1", "-H", "8192"])
    run_generator(output_dir, "boundary_max_8192x8192.simg", ["-w", "8192", "-H", "8192"])

    # Long metadata (but valid)
    long_title = "A" * 63  # Just under limit
    long_author = "B" * 31  # Just under limit
    run_generator(output_dir, "boundary_long_metadata.simg",
                  ["-w", "50", "-H", "50", "-t", long_title, "-a", long_author])

    print("\nGenerating vulnerability triggers...")

    # Stack buffer overflow
    run_generator(output_dir, "vuln_overflow_metadata.simg", ["--overflow-metadata"])

    # Integer overflow
    run_generator(output_dir, "vuln_integer_overflow.simg", ["--overflow-int"])

    print("\nGenerating malformed samples...")

    # Various malformations
    malformation_types = [
        "missing_magic",
        "invalid_format",
        "negative_dimensions",
        "zero_dimensions",
        "huge_dimensions",
        "missing_binary_marker"
    ]

    for mtype in malformation_types:
        run_generator(output_dir, f"malformed_{mtype}.simg", ["--malformed", mtype])

    print(f"\n✅ Corpus generation complete!")
    print(f"   Output directory: {output_dir}")
    print(f"   Total files: {len(os.listdir(output_dir))}")


if __name__ == '__main__':
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "../samples"
    generate_corpus(output_dir)
