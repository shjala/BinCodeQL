# SimpleImage Library - Test Library for Harness Generation

A deliberately vulnerable image parsing library designed for testing automated fuzzing harness generation. Contains realistic vulnerabilities with multi-level call chains to exercise binary analysis and harness generation agents.

## Overview

**SimpleImage** is a minimal image format parser (`.simg` format) that implements:
- ✅ **5 exported API functions** (entry points)
- ✅ **14 total functions** with 3-4 level call chains
- ✅ **Multiple data structures** (header, metadata, pixel buffer)
- ✅ **5 realistic vulnerabilities** (stack overflow, heap overflow, integer overflow, off-by-one)
- ✅ **Text + binary format** (metadata as text, pixels as binary)

### File Format (`.simg`)

```
SIMG
VERSION:1
WIDTH:640
HEIGHT:480
FORMAT:RGB
TITLE:My Image
AUTHOR:John Doe
[BINARY]
<raw pixel bytes: width * height * bytes_per_pixel>
```

---

## Quick Start

### Build Library (Linux x86-64)

```bash
# Build all variants
make all

# Or build specific variants:
make debug      # With debug symbols, -O0 (for Binary Ninja)
make release    # Optimized, with symbols
make stripped   # No symbols (realistic scenario)
```

### Generate Test Corpus

```bash
make corpus
```

This creates `samples/` directory with:
- 7 valid images (various sizes)
- 5 boundary cases
- 2 vulnerability triggers
- 6 malformed inputs

### Run Tests

```bash
make test
```

### Build Fuzzing Harness (Manual)

```bash
make manual_harness

# Run it
./build/manual_fuzzer samples/
```

---

## Architecture

### Call Chains (Depth 3-4)

```
LEVEL 1: Public API (5 exported functions)
├─ simg_load_from_file
├─ simg_load_from_memory ⭐ Main entry point
├─ simg_get_info
├─ simg_apply_filter
└─ simg_free

LEVEL 2: Parsing Functions
├─ parse_header
│   ├─ read_text_line (Level 3)
│   ├─ parse_key_value (Level 3)
│   └─ validate_dimensions (Level 3)
├─ parse_metadata ⚠️ VULNERABLE (strcpy overflow)
│   ├─ read_text_line (Level 3)
│   └─ parse_key_value (Level 3)
└─ decode_pixel_data
    ├─ read_text_line (Level 3)
    ├─ allocate_pixel_buffer ⚠️ VULNERABLE (Level 4)
    └─ copy_pixel_data ⚠️ VULNERABLE (Level 4)

LEVEL 3: Filter Operations
├─ apply_brightness_filter
├─ apply_contrast_filter
└─ copy_pixel_data ⚠️ VULNERABLE
```

### Data Structures

```c
/* Internal header structure */
typedef struct {
    char magic[5];
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t format;
} ImageHeader;

/* Metadata (fixed-size buffers - vulnerability target) */
typedef struct {
    char title[64];   ⚠️ Stack overflow target
    char author[32];  ⚠️ Stack overflow target
    uint32_t timestamp;
} ImageMetadata;

/* Main image structure */
struct Image {
    ImageHeader header;
    ImageMetadata metadata;
    uint8_t* pixels;  ⚠️ Heap overflow target
    size_t pixel_size;
};
```

---

## Vulnerabilities

### 1. Stack Buffer Overflow (High Severity)

**Location:** `parse_metadata()` in simpleimage.c:248
**Function Chain:** `simg_load_from_memory` → `parse_metadata` → `strcpy`

**Trigger:**
```python
# TITLE or AUTHOR field > buffer size
python3 tools/generate_simg.py samples/crash_stack.simg --overflow-metadata
```

**Root Cause:**
```c
// No bounds check before strcpy
strcpy(meta->title, value);   // title buffer is 64 bytes
strcpy(meta->author, value);  // author buffer is 32 bytes
```

**Harness Test:** Target `parse_metadata` directly or through `simg_load_from_memory`

---

### 2. Integer Overflow → Heap Buffer Overflow (Critical)

**Location:** `allocate_pixel_buffer()` in simpleimage.c:91
**Function Chain:** `simg_load_from_memory` → `decode_pixel_data` → `allocate_pixel_buffer` → `copy_pixel_data`

**Trigger:**
```python
# Dimensions: 65536 * 65536 * 3 bytes > UINT32_MAX
python3 tools/generate_simg.py samples/crash_int.simg --overflow-int
```

**Root Cause:**
```c
// Integer overflow in size calculation
size_t size = (size_t)(width * height * bytes_per_pixel);  // Overflows!
uint8_t* buffer = malloc(size);  // Allocates small buffer

// Later: heap overflow
memcpy(buffer, data, expected_size);  // expected_size much larger than allocated
```

**Harness Test:** Target `allocate_pixel_buffer` or `decode_pixel_data`

---

### 3. Heap Buffer Overflow (High Severity)

**Location:** `copy_pixel_data()` in simpleimage.c:102
**Function Chain:** `decode_pixel_data` → `copy_pixel_data`

**Trigger:** Combined with integer overflow above

**Root Cause:**
```c
// No validation of destination buffer size
static void copy_pixel_data(uint8_t* dst, const uint8_t* src, size_t count) {
    memcpy(dst, src, count);  // BUG: No bounds checking!
}
```

**Harness Test:** Target `copy_pixel_data` with varying buffer sizes

---

### 4. Off-by-One Error (Medium Severity)

**Location:** `read_text_line()` in simpleimage.c:64
**Function Chain:** Multiple parsing functions → `read_text_line`

**Trigger:** Line that exactly fills buffer

**Root Cause:**
```c
while (...  && i < bufsize) {
    buffer[i] = data[start + i];
    i++;
}
buffer[i] = '\0';  // BUG: i can equal bufsize, writing past end
```

**Harness Test:** Target `read_text_line` with edge case inputs

---

### 5. Use-After-Free (Potential)

**Location:** `simg_apply_filter()` in simpleimage.c:361
**Trigger:** Multiple filter applications

**Note:** Less severe, but good for testing filter code paths

---

## Target Functions for Harness Generation

### Primary Targets (High Priority)

1. **`simg_load_from_memory`** (Complexity: Medium)
   - Entry point with good depth
   - Reaches multiple vulnerabilities
   - Parameters: `(const uint8_t* data, size_t size)`

2. **`parse_metadata`** (Complexity: Low-Medium)
   - Direct path to stack overflow
   - Parameters: `(const uint8_t* data, size_t size, size_t* offset, ImageMetadata* meta)`
   - Requires struct initialization

3. **`decode_pixel_data`** (Complexity: Medium)
   - Path to integer overflow + heap overflow
   - Parameters: `(const uint8_t* data, size_t size, size_t offset, Image* img)`
   - Requires Image struct initialization

### Secondary Targets (Testing Call Graph)

4. **`allocate_pixel_buffer`** (Complexity: Low)
   - Integer overflow vulnerability
   - Parameters: `(uint32_t width, uint32_t height, uint32_t format)`

5. **`copy_pixel_data`** (Complexity: Low)
   - Heap overflow vulnerability
   - Parameters: `(uint8_t* dst, const uint8_t* src, size_t count)`

---

## Testing Agent Capabilities

### Agent 1: Discovery
Should identify:
- ✅ Function signatures with correct parameter types
- ✅ Struct definitions (ImageHeader, ImageMetadata, Image)
- ✅ Complexity assessment (low/medium/high)

### Agent 2: Call Graph
Should find:
- ✅ Path: `simg_load_from_memory → parse_metadata` (depth 1)
- ✅ Path: `simg_load_from_memory → decode_pixel_data → allocate_pixel_buffer` (depth 2)
- ✅ Path: `simg_load_from_memory → decode_pixel_data → copy_pixel_data` (depth 2)

### Agent 3: Data Flow
Should discover:
- ✅ No initialization for `simg_load_from_memory` (simple)
- ✅ Need to initialize `Image*` for `decode_pixel_data`
- ✅ Need to initialize `ImageMetadata*` for `parse_metadata`

### Agent 4: Harness Synthesis
Should generate:
- ✅ LibFuzzer harness for `simg_load_from_memory`
- ✅ Harness with struct initialization for internal functions
- ✅ Size constraints (min 50 bytes, max reasonable)

### Agent 5: Compilation Feedback
Should handle:
- ✅ Missing declarations (add `extern` for functions)
- ✅ Struct forward declarations
- ✅ Type mismatches (const correctness)

---

## Build Variants

### Debug Version (For Analysis)
```bash
make debug
# Output: build/libsimpleimage_debug.so
# - Debug symbols included
# - -O0 (no optimization)
# - Perfect for Binary Ninja HLIL analysis
```

### Release Version (With Symbols)
```bash
make release
# Output: build/libsimpleimage.so
# - Optimized (-O2)
# - Symbols included
# - Good for testing harness against realistic build
```

### Stripped Version (Realistic)
```bash
make stripped
# Output: build/libsimpleimage_stripped.so
# - Optimized (-O2)
# - Symbols removed (stripped)
# - Tests true binary-only scenario
```

---

## Windows Build (DLL)

### Using MinGW-w64 (Cross-compilation from Linux)
```bash
# Install MinGW
sudo apt-get install mingw-w64

# Build DLL
x86_64-w64-mingw32-gcc -shared -O2 -Wall -Wextra \
    -I./include \
    -o build/simpleimage.dll \
    src/simpleimage.c

# Build test application
x86_64-w64-mingw32-gcc -O2 -Wall -Wextra \
    -I./include \
    -o build/test_app.exe \
    tests/test_app.c \
    -L./build -lsimpleimage
```

### Using Visual Studio (Native Windows)
```batch
REM Set up MSVC environment
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

REM Compile library
cl.exe /LD /O2 /W4 /I.\include /Fe:build\simpleimage.dll src\simpleimage.c

REM Create import library
lib.exe /DEF /OUT:build\simpleimage.lib /MACHINE:X64 build\simpleimage.dll

REM Compile test app
cl.exe /O2 /W4 /I.\include /Fe:build\test_app.exe tests\test_app.c build\simpleimage.lib
```

---

## Usage Examples

### Building and Using Test Application

The test application ([tests/test_app.c](tests/test_app.c)) demonstrates proper library usage.

#### Option 1: Build with Makefile (Recommended)

```bash
# Build library and test app (includes library dependency)
make test_app

# If you get "make: nothing to be done for test_app"
# This means the binary is already built and up-to-date
# To force rebuild:
make clean && make test_app

# Or just rebuild test app:
rm -f build/test_app && make test_app
```

#### Option 2: Standalone Compilation with GCC

If you want to compile manually without Make:

```bash
# First, ensure the library is built
make release

# Then compile test_app.c directly with gcc
gcc -Wall -Wextra -I./include -O2 \
    tests/test_app.c \
    -o build/test_app \
    -L./build -lsimpleimage \
    -Wl,-rpath,'$$ORIGIN'

# Note: The -Wl,-rpath,'$$ORIGIN' ensures the binary finds the .so at runtime
```

**Standalone compilation (absolute paths, no rpath):**
```bash
# Build library first
gcc -Wall -Wextra -I./include -O2 -fPIC -shared \
    src/simpleimage.c \
    -o build/libsimpleimage.so

# Build test app
gcc -Wall -Wextra -I./include -O2 \
    tests/test_app.c \
    -o build/test_app \
    -L./build -lsimpleimage

# Run with LD_LIBRARY_PATH
LD_LIBRARY_PATH=build ./build/test_app samples/valid_small_100x100.simg
```

#### Running Test Application

```bash
# Run with valid image
LD_LIBRARY_PATH=build ./build/test_app samples/valid_small_100x100.simg

# Apply filter (brightness or contrast)
LD_LIBRARY_PATH=build ./build/test_app samples/valid_small_100x100.simg brightness

# Test with malformed input (should fail gracefully)
LD_LIBRARY_PATH=build ./build/test_app samples/malformed_invalid_format.simg
```

**Note:** `LD_LIBRARY_PATH=build` is only needed if the binary wasn't built with rpath. If you used `make test_app`, rpath is included and you can run directly:

```bash
./build/test_app samples/valid_small_100x100.simg
```

### Using in Binary Ninja
```bash
# Build debug version
make debug

# Open in Binary Ninja
binaryninja build/libsimpleimage_debug.so

# Analyze functions:
# - simg_load_from_memory
# - parse_metadata
# - allocate_pixel_buffer
```

### Manual Fuzzing
```bash
# Build manual harness
make manual_harness

# Run LibFuzzer
./build/manual_fuzzer -max_len=100000 samples/

# With ASan for better crash detection
ASAN_OPTIONS=detect_leaks=0 ./build/manual_fuzzer samples/
```

---

## File Structure

```
test-lib/
├── include/
│   └── simpleimage.h          # Public API (5 exported functions)
├── src/
│   └── simpleimage.c          # Implementation (~500 lines, 5 vulnerabilities)
├── tests/
│   ├── test_app.c             # Sample application
│   └── manual_harness.cpp     # Manual fuzzing harness (for comparison)
├── tools/
│   ├── generate_simg.py       # Generate .simg files
│   └── generate_corpus.py     # Generate test corpus
├── samples/                   # Test inputs (generated by make corpus)
│   ├── valid_*.simg          # Valid test cases
│   ├── boundary_*.simg       # Edge cases
│   ├── vuln_*.simg           # Vulnerability triggers
│   └── malformed_*.simg      # Malformed inputs
├── build/                     # Build outputs
│   ├── libsimpleimage_debug.so
│   ├── libsimpleimage.so
│   ├── libsimpleimage_stripped.so
│   ├── test_app
│   └── manual_fuzzer
├── Makefile                   # Build system
└── README.md                  # This file
```

---

## Validation Checklist

Use this library to validate harness generation system:

### ✅ Binary Analysis
- [ ] Load library in Binary Ninja
- [ ] Decompile `simg_load_from_memory` to HLIL
- [ ] Identify all exported functions
- [ ] Trace call graph to vulnerabilities

### ✅ Agent 1: Discovery
- [ ] Extract function signature for `simg_load_from_memory`
- [ ] Identify all parameters with types
- [ ] Find data structures (Image, ImageHeader, ImageMetadata)
- [ ] Assess complexity correctly

### ✅ Agent 2: Call Graph
- [ ] Find path from `simg_load_from_memory` to `parse_metadata`
- [ ] Find path from `simg_load_from_memory` to `allocate_pixel_buffer`
- [ ] Rank paths by viability

### ✅ Agent 3: Data Flow
- [ ] Identify no initialization needed for `simg_load_from_memory`
- [ ] Trace parameter flow through call chain
- [ ] Identify struct requirements for internal functions

### ✅ Agent 4: Synthesis
- [ ] Generate LibFuzzer harness
- [ ] Generate AFL++ Untracer harness (Linux)
- [ ] Include proper size constraints
- [ ] Compile successfully

### ✅ Agent 5: Feedback
- [ ] Fix missing declarations
- [ ] Fix type mismatches
- [ ] Handle const correctness
- [ ] Compile after fixes

### ✅ End-to-End
- [ ] Generated harness compiles
- [ ] Fuzzer runs without crashes on valid inputs
- [ ] Fuzzer finds vulnerabilities in samples/vuln_*.simg
- [ ] Compare with manual harness

---

## Expected Harness for `simg_load_from_memory`

The auto-generated harness should look similar to this:

```cpp
#include <stdint.h>
#include <stddef.h>

extern "C" {
    typedef struct Image Image;
    Image* simg_load_from_memory(const uint8_t* data, size_t size);
    void simg_free(Image* img);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Skip very small or very large inputs
    if (size < 50 || size > 100 * 1024 * 1024) return 0;

    // Call target function
    Image* img = simg_load_from_memory(data, size);

    // Cleanup if successful
    if (img) {
        simg_free(img);
    }

    return 0;
}
```

---

## Troubleshooting

### Library Not Found
```bash
# Set LD_LIBRARY_PATH
export LD_LIBRARY_PATH=$(pwd)/build:$LD_LIBRARY_PATH

# Or use rpath (already in Makefile)
```

### Clang Not Found for Fuzzing
```bash
# Install clang
sudo apt-get install clang

# Or use gcc for library, clang only for fuzzer
make release
clang++ -fsanitize=fuzzer tests/manual_harness.cpp -L./build -lsimpleimage
```

### Binary Ninja Can't Find Symbols
```bash
# Make sure you're using debug or release version, not stripped
binaryninja build/libsimpleimage_debug.so
```

---

## License

This is test code for research purposes. The vulnerabilities are intentional for educational/testing use only.

---

## Contact / Issues

This library is part of the automated harness generation testing framework. Report issues or improvements to the main project.
