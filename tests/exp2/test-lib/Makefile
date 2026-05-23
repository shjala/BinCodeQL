# SimpleImage Library - Makefile

CC = gcc
CXX = g++
CFLAGS = -Wall -Wextra -fPIC -I./include
CFLAGS_DEBUG = $(CFLAGS) -g -O0  # For Binary Ninja analysis
CFLAGS_RELEASE = $(CFLAGS) -O2

# Directories
SRC_DIR = src
INC_DIR = include
TEST_DIR = tests
BUILD_DIR = build
SAMPLES_DIR = samples

# Library files
LIB_SRC = $(SRC_DIR)/simpleimage.c
LIB_OBJ_DEBUG = $(BUILD_DIR)/simpleimage_debug.o
LIB_OBJ_RELEASE = $(BUILD_DIR)/simpleimage_release.o
LIB_SO_DEBUG = $(BUILD_DIR)/libsimpleimage_debug.so
LIB_SO_RELEASE = $(BUILD_DIR)/libsimpleimage.so
LIB_SO_STRIPPED = $(BUILD_DIR)/libsimpleimage_stripped.so

# Test files
TEST_APP = $(BUILD_DIR)/test_app
MANUAL_HARNESS = $(BUILD_DIR)/manual_fuzzer

.PHONY: all clean test corpus debug release stripped

all: debug release stripped test_app manual_harness

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Debug version (for Binary Ninja analysis, with symbols)
debug: $(LIB_SO_DEBUG)

$(LIB_OBJ_DEBUG): $(LIB_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS_DEBUG) -c $< -o $@

$(LIB_SO_DEBUG): $(LIB_OBJ_DEBUG)
	$(CC) -shared -o $@ $<
	@echo "✓ Debug library built: $@"
	@echo "  (with debug symbols, not stripped)"

# Release version (optimized, with symbols)
release: $(LIB_SO_RELEASE)

$(LIB_OBJ_RELEASE): $(LIB_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS_RELEASE) -c $< -o $@

$(LIB_SO_RELEASE): $(LIB_OBJ_RELEASE)
	$(CC) -shared -o $@ $<
	@echo "✓ Release library built: $@"
	@echo "  (with symbols, not stripped)"

# Stripped version (no symbols, realistic scenario)
stripped: $(LIB_SO_STRIPPED)

$(LIB_SO_STRIPPED): $(LIB_SO_RELEASE)
	cp $< $@
	strip $@
	@echo "✓ Stripped library built: $@"
	@echo "  (symbols removed)"

# Test application
test_app: $(TEST_APP)

$(TEST_APP): $(TEST_DIR)/test_app.c $(LIB_SO_RELEASE) | $(BUILD_DIR)
	$(CC) $(CFLAGS_RELEASE) $< -o $@ -L$(BUILD_DIR) -lsimpleimage -Wl,-rpath,$(shell pwd)/$(BUILD_DIR)
	@echo "✓ Test application built: $@"

# Manual fuzzing harness (LibFuzzer)
manual_harness: $(MANUAL_HARNESS)

$(MANUAL_HARNESS): $(TEST_DIR)/manual_harness.cpp $(LIB_SO_RELEASE) | $(BUILD_DIR)
	@echo "Building manual fuzzing harness..."
	@echo "Note: Requires clang++ with -fsanitize=fuzzer support"
	clang++ -fsanitize=fuzzer,address -g $(CFLAGS_RELEASE) $< -o $@ -L$(BUILD_DIR) -lsimpleimage -Wl,-rpath,$(shell pwd)/$(BUILD_DIR) || \
		echo "Warning: clang++ with fuzzer support not available. Skipping manual harness build."

# Generate test corpus
corpus: $(SAMPLES_DIR)
	@echo "Generating test corpus..."
	python3 tools/generate_corpus.py $(SAMPLES_DIR)

$(SAMPLES_DIR):
	mkdir -p $(SAMPLES_DIR)

# Run basic tests
test: test_app corpus
	@echo "\n=== Running Tests ==="
	@echo "\n1. Testing valid small image..."
	LD_LIBRARY_PATH=$(BUILD_DIR) ./$(TEST_APP) $(SAMPLES_DIR)/valid_small_100x100.simg

	@echo "\n2. Testing with filter..."
	LD_LIBRARY_PATH=$(BUILD_DIR) ./$(TEST_APP) $(SAMPLES_DIR)/valid_small_100x100.simg brightness

	@echo "\n3. Testing malformed image (should fail gracefully)..."
	LD_LIBRARY_PATH=$(BUILD_DIR) ./$(TEST_APP) $(SAMPLES_DIR)/malformed_invalid_format.simg || echo "  ✓ Failed as expected"

	@echo "\n✅ Basic tests complete"

# Quick build for Binary Ninja analysis
binja: debug
	@echo "\n📊 Library ready for Binary Ninja analysis:"
	@echo "   File: $(LIB_SO_DEBUG)"
	@echo "   Contains debug symbols"
	@echo "   Not stripped"

# Info about vulnerabilities
vulns:
	@echo "\n🐛 Known Vulnerabilities in Library:"
	@echo ""
	@echo "1. Stack Buffer Overflow (parse_metadata)"
	@echo "   - Trigger: TITLE or AUTHOR field > 64/32 bytes"
	@echo "   - Path: simg_load_from_memory → parse_metadata → strcpy"
	@echo "   - Sample: samples/vuln_overflow_metadata.simg"
	@echo ""
	@echo "2. Integer Overflow (allocate_pixel_buffer)"
	@echo "   - Trigger: width * height * bpp > UINT32_MAX"
	@echo "   - Path: simg_load_from_memory → decode_pixel_data → allocate_pixel_buffer"
	@echo "   - Sample: samples/vuln_integer_overflow.simg"
	@echo ""
	@echo "3. Heap Buffer Overflow (copy_pixel_data)"
	@echo "   - Trigger: Combined with integer overflow"
	@echo "   - Path: decode_pixel_data → copy_pixel_data"
	@echo ""
	@echo "4. Off-by-One (read_text_line)"
	@echo "   - Trigger: Line exactly fills buffer"
	@echo "   - Path: Various parsing functions → read_text_line"
	@echo ""
	@echo "Target functions for harness generation:"
	@echo "  - simg_load_from_memory (main entry point)"
	@echo "  - parse_metadata (direct vulnerability)"
	@echo "  - decode_pixel_data (multi-step vulnerability)"
	@echo "  - allocate_pixel_buffer (integer overflow)"
	@echo ""

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(SAMPLES_DIR)
	@echo "✓ Clean complete"

# Help
help:
	@echo "SimpleImage Library - Build Targets"
	@echo ""
	@echo "Main targets:"
	@echo "  all            - Build everything (debug, release, stripped, tests)"
	@echo "  debug          - Build library with debug symbols (for analysis)"
	@echo "  release        - Build optimized library with symbols"
	@echo "  stripped       - Build library without symbols (realistic)"
	@echo "  test_app       - Build test application"
	@echo "  manual_harness - Build manual fuzzing harness (requires clang++)"
	@echo "  corpus         - Generate test input corpus"
	@echo ""
	@echo "Utility targets:"
	@echo "  test           - Run basic functionality tests"
	@echo "  binja          - Prepare for Binary Ninja analysis"
	@echo "  vulns          - Show information about vulnerabilities"
	@echo "  clean          - Remove build artifacts"
	@echo ""
	@echo "Library variants:"
	@echo "  build/libsimpleimage_debug.so    - Debug symbols, -O0"
	@echo "  build/libsimpleimage.so          - Optimized, with symbols"
	@echo "  build/libsimpleimage_stripped.so - Stripped (no symbols)"
	@echo ""
