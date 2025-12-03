/**
 * vulnerable_utils.c
 *
 *
 * A second C demonstration application containing more subtle vulnerabilities
 * for the purpose of testing static analysis security tools (SAST). This
 * file focuses on race conditions, complex memory issues, and logic errors.
 *
 * --- INTENTIONALLY INSECURE ---
 *
 * To compile (and suppress expected warnings):
 * gcc -o vulnerable_utils vulnerable_utils.c -w
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For access(), sleep()
#include <stdint.h> // For size_t

void demonstrate_race_condition(const char* filename);
void demonstrate_int_overflow_heap_corruption(unsigned int count, unsigned int data_size);
void demonstrate_uninitialized_variable();
void demonstrate_sensitive_data_exposure(const char* user, const char* pass);


int main(int argc, char* argv[]) {
    printf("--- Starting Advanced Vulnerable C Utils Demonstration ---\n");

    printf("\n[1] Demonstrating Race Condition (TOCTOU)...\n");
    // In a real attack, an attacker would try to swap this file with a symlink
    // to a sensitive file between the 'access' check and the 'fopen' call.
    demonstrate_race_condition("user_temp_file.log");

    printf("\n[2] Demonstrating Integer Overflow leading to Heap Corruption...\n");
    // We provide values that, when multiplied, will wrap around a 32-bit integer.
    // e.g., 65535 * 65537 overflows, resulting in a tiny allocation.
    demonstrate_int_overflow_heap_corruption(65535, 65537);

    printf("\n[3] Demonstrating Use of Uninitialized Variable...\n");
    // This function may or may not initialize a pointer, then uses it.
    demonstrate_uninitialized_variable();

    printf("\n[4] Demonstrating Sensitive Data Exposure in Logs...\n");
    demonstrate_sensitive_data_exposure("roop.singh", "P@ssw0rdD3c2025!");

    printf("\n--- Advanced Demonstration Complete ---\n");
    return 0;
}

/**
 * CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
 * A classic race condition where the state of a resource is checked, but then
 * the resource is used later, allowing an attacker to change it in between.
 */
void demonstrate_race_condition(const char* filename) {
    printf("  - Checking file permissions for '%s'...\n", filename);
    // Time of Check: We check if we can write to the file.
    if (access(filename, W_OK) == 0) {
        printf("    File is writable. Proceeding to open...\n");

        // Artificial delay to widen the race window for demonstration.
        sleep(1);

        // Time of Use: We open the file for writing.
        // An attacker could have replaced 'filename' with a symbolic link
        // to a critical system file (e.g., /etc/shadow) in the sleep interval.
        FILE* f = fopen(filename, "w");
        if (f) {
            fprintf(f, "This is some log data.\n");
            printf("    Successfully wrote to file.\n");
            fclose(f);
        } else {
            printf("    Error: Failed to open file for writing after check!\n");
        }
    } else {
        printf("    File does not exist or is not writable.\n");
    }
}

/**
 * CWE-190: Integer Overflow or Wraparound
 * leading to
 * CWE-122: Heap-based Buffer Overflow
 */
void demonstrate_int_overflow_heap_corruption(unsigned int count, unsigned int data_size) {
    // This multiplication can easily overflow if count and data_size are large.
    size_t total_size = count * data_size;
    printf("  - Requested records: %u, size per record: %u\n", count, data_size);
    printf("  - Calculated total allocation size: %zu\n", total_size);

    // If total_size overflowed, it will be a small number, and malloc will succeed.
    char* buffer = (char*)malloc(total_size);
    if (!buffer) {
        printf("    Malloc failed.\n");
        return;
    }
    printf("    Allocation successful.\n");

    // This loop will now write far beyond the allocated small buffer, corrupting the heap.
    printf("  - Writing %u records to the incorrectly sized buffer...\n", count);
    for (unsigned int i = 0; i < count; ++i) {
        // This write will go out of bounds almost immediately.
        memset(buffer + (i * data_size), 'A', data_size);
    }
    printf("    Heap corruption likely occurred.\n");
    free(buffer);
}

/**
 * CWE-457: Use of Uninitialized Variable
 */
void demonstrate_uninitialized_variable() {
    int* secret_value_ptr; // Pointer is declared but not initialized.
    int should_init = 0; // Control variable

    // In a complex program, this block might be skipped.
    if (should_init) {
        int secret = 12345;
        secret_value_ptr = &secret;
    }
    
    // If should_init was 0, secret_value_ptr contains a garbage address.
    // Dereferencing it here leads to undefined behavior (likely a crash).
    printf("  - Reading from a potentially uninitialized pointer...\n");
    // The next line will cause a crash if the pointer is not initialized.
    // printf("    The secret value is: %d\n", *secret_value_ptr);
    printf("    (Skipping dereference to avoid crash, but CodeQL will find it).\n");
}


/**
 * CWE-532: Insertion of Sensitive Information into Log File
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 */
void demonstrate_sensitive_data_exposure(const char* user, const char* pass) {
    // This is a very common mistake where developers log sensitive credentials
    // during debugging and forget to remove the log statement.
    printf("  - DEBUG: Authenticating user...\n");
    fprintf(stderr, "    Login attempt for user '%s' with password '%s'\n", user, pass);
    printf("    (Sensitive credentials written to stderr, simulating a log file).\n");
}
