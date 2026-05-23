// taint_test.c
//
// A test program for our Binary Ninja taint analysis plugin.
//
// How to compile and run:
//   gcc -o taint_test taint_test.c
//   echo "This is some test data" > input.txt
//   ./taint_test input.txt
//
// Expected Taint Flow Path:
//   main -> read_file_data -> process_data -> copy_to_buffer -> strcpy (sink)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// --- Function Prototypes ---
char* read_file_data(const char* filename, int* data_size);
char* process_data(char* raw_data, int size);
void copy_to_buffer(char* processed_data);
void log_operation(const char* message); // A distractor function

// --- Main Function (The "Root" of our slice) ---
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    char* filename = argv[1];
    int size = 0;
    
    // Taint source is introduced here via `read_file_data`
    // Expected Summary for main: None (data flows out, not back in)
    char* file_contents = read_file_data(filename, &size);

    if (file_contents) {
        // Data flows from `file_contents` into `process_data`
        char* processed_contents = process_data(file_contents, size);
        
        // Data flows from `processed_contents` into `copy_to_buffer`
        copy_to_buffer(processed_contents);
        
        free(file_contents);
        free(processed_contents);
    }

    log_operation("Operations complete."); // This call should NOT be in our slice.

    return 0;
}

// --- Taint Propagator (via return value) ---
// Reads data from a file and returns it.
// DATA FLOW: Taint originates here from `fread`. The return value is tainted.
//            The `data_size` pointer argument is also modified.
// EXPECTED SUMMARY: R=(filename); data_size=()  (or similar, showing data_size is written to)
char* read_file_data(const char* filename, int* data_size) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *string = malloc(fsize + 1);
    fread(string, 1, fsize, f); // TAINT SOURCE
    fclose(f);

    string[fsize] = 0;
    *data_size = fsize; // Pointer argument is written to.

    return string; // TAINTED return
}

// --- Taint Propagator (via argument and return) ---
// "Processes" the data by allocating a new buffer and copying it.
// DATA FLOW: Taint flows from `raw_data` into the return value.
// EXPECTED SUMMARY: R=(raw_data, size)
char* process_data(char* raw_data, int size) {
    // Allocate a new buffer, size is influenced by an argument.
    char* new_data = malloc(size + 1);
    if (new_data) {
        // Taint propagates from raw_data to new_data
        memcpy(new_data, raw_data, size);
        new_data[size] = 0;
    }
    return new_data; // TAINTED return
}

// --- Taint Sink Function ---
// Copies the processed data into a small, vulnerable local buffer.
// DATA FLOW: Taint flows from `processed_data` into the `strcpy` sink.
// EXPECTED SUMMARY: None (it's a sink, data terminates here)
void copy_to_buffer(char* processed_data) {
    char local_buffer[20]; // Vulnerable small buffer

    // TAINT SINK: If processed_data is > 19 chars, this will overflow.
    strcpy(local_buffer, processed_data); 
    
    printf("Final buffer: %s\n", local_buffer);
}

// --- Distractor Function ---
// This function is called from main but does not touch tainted data.
// It should be correctly excluded from our call graph slice.
void log_operation(const char* message) {
    printf("LOG: %s\n", message);
}

