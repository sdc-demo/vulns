/**
 * vulnerable_app.c
 *
 * A demonstration C application containing a wide variety of vulnerabilities
 * for the purpose of testing static analysis security tools (SAST) like CodeQL.
 *
 * --- INTENTIONALLY INSECURE ---
 *
 * To compile (and suppress the expected flood of warnings):
 * gcc -o vulnerable_app vulnerable_app.c -w
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // For system(), execlp() on POSIX systems
#include <limits.h> // For INT_MAX

// Forward declarations
void demonstrate_buffer_overflows(const char* input);
void demonstrate_format_string(const char* input);
void demonstrate_command_injection(const char* filename);
void demonstrate_sql_injection(const char* userId);
void demonstrate_path_traversal(const char* filepath);
void demonstrate_memory_management_issues();
void demonstrate_integer_overflow();
void demonstrate_null_pointer_dereference(char* data);
void demonstrate_risky_crypto();
void demonstrate_dangerous_functions(char* input);


int main(int argc, char* argv[]) {
    printf("--- Starting Vulnerable C Application Demonstration ---\n");

    // Prepare some malicious-looking input strings
    char long_input[256];
    memset(long_input, 'A', 255);
    long_input[255] = '\0';

    char format_string_input[] = "User supplied data: %s%s%s%s%s%s%s%n";
    char command_injection_input[] = "nonexistent.txt; ls -la /";
    char sql_injection_input[] = "' OR '1'='1";
    char path_traversal_input[] = "../../../../etc/passwd";
    char dangerous_func_input[] = "This is some user input for a dangerous function.";

    // --- Triggering Vulnerabilities ---
    printf("\n[1] Demonstrating Buffer Overflows...\n");
    demonstrate_buffer_overflows(long_input);

    printf("\n[2] Demonstrating Format String Vulnerability...\n");
    demonstrate_format_string(format_string_input);

    printf("\n[3] Demonstrating OS Command Injection...\n");
    demonstrate_command_injection(command_injection_input);
    
    printf("\n[4] Demonstrating SQL Injection...\n");
    demonstrate_sql_injection(sql_injection_input);

    printf("\n[5] Demonstrating Path Traversal...\n");
    demonstrate_path_traversal(path_traversal_input);

    printf("\n[6] Demonstrating Memory Management Issues...\n");
    demonstrate_memory_management_issues();

    printf("\n[7] Demonstrating Integer Overflow...\n");
    demonstrate_integer_overflow();
    
    printf("\n[8] Demonstrating NULL Pointer Dereference...\n");
    demonstrate_null_pointer_dereference(NULL); // Pass NULL to trigger it

    printf("\n[9] Demonstrating Risky Cryptography Usage...\n");
    demonstrate_risky_crypto();
    
    printf("\n[10] Demonstrating Use of Potentially Dangerous Functions...\n");
    demonstrate_dangerous_functions(dangerous_func_input);


    printf("\n--- Demonstration Complete ---\n");
    return 0;
}

/**
 * CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
 * CWE-121: Stack-based Buffer Overflow
 * CWE-787: Out-of-bounds Write
 * CWE-131: Incorrect Calculation of Buffer Size
 */
void demonstrate_buffer_overflows(const char* input) {
    char stack_buffer[50];
    
    // CWE-120, CWE-121, CWE-787: strcpy does not check bounds and will write past the end of stack_buffer.
    printf("  - Triggering stack overflow with strcpy...\n");
    strcpy(stack_buffer, input); 
    printf("    Data in stack_buffer: %s\n", stack_buffer); // Potentially corrupted stack

    // CWE-131, CWE-122 (Heap-based Buffer Overflow)
    char* heap_buffer = (char*)malloc(strlen(input)); // CWE-131: Incorrect size, forgot +1 for null terminator.
    if (heap_buffer) {
        // This copy will write the null terminator out of bounds.
        strcpy(heap_buffer, input); // CWE-122: Heap-based buffer overflow.
        printf("  - Triggering heap overflow with incorrect malloc size...\n");
        free(heap_buffer);
    }
}

/**
 * CWE-134: Use of Externally-Controlled Format String
 */
void demonstrate_format_string(const char* input) {
    printf("  - Triggering format string vulnerability...\n");
    // If 'input' contains format specifiers (%x, %s, %n), this will read from the stack or write to memory.
    printf(input); 
    printf("\n");
}

/**
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
 */
void demonstrate_command_injection(const char* filename) {
    char command[256];
    // Constructing a command string with untrusted user input.
    sprintf(command, "cat %s", filename); 
    printf("  - Executing command: %s\n", command);
    // An attacker can inject commands, e.g., by providing "file.txt; rm -rf /" as the filename.
    system(command); // CWE-78: Executing the tainted command.
}

/**
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
 */
void demonstrate_sql_injection(const char* userId) {
    char query[256];
    // A classic example of building a SQL query by concatenating strings.
    sprintf(query, "SELECT * FROM users WHERE id = '%s'", userId);
    printf("  - Constructed SQL Query: %s\n", query);
    // An attacker input of "' OR '1'='1" would bypass authentication.
    // In a real app, this query would be executed against a database.
    printf("    (Simulating query execution)\n");
}

/**
 * CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
 */
void demonstrate_path_traversal(const char* filepath) {
    char full_path[1024];
    // Prepending a base path to a user-supplied file path without sanitization.
    sprintf(full_path, "/var/www/uploads/%s", filepath);
    printf("  - Attempting to open file at: %s\n", full_path);
    // An input like "../../../../etc/passwd" would allow reading sensitive files.
    FILE* f = fopen(full_path, "r");
    if (f) {
        printf("    File opened successfully (this is bad!).\n");
        fclose(f);
    } else {
        printf("    File could not be opened (as expected on most systems).\n");
    }
}

/**
 * CWE-416: Use After Free
 * CWE-415: Double Free
 */
void demonstrate_memory_management_issues() {
    printf("  - Allocating memory...\n");
    char* ptr = (char*)malloc(20);
    if (!ptr) return;
    
    strcpy(ptr, "hello world");
    printf("    Data: %s\n", ptr);
    
    printf("  - Freeing memory...\n");
    free(ptr);
    
    // CWE-416: Using the pointer after it has been freed. The behavior is undefined.
    // It might crash, it might print garbage, or it might appear to work.
    printf("  - Triggering Use-After-Free by printing data again: %s\n", ptr);

    // CWE-415: Freeing the same memory block again can corrupt heap metadata, leading to a crash.
    printf("  - Triggering Double-Free...\n");
    // free(ptr); // Uncommenting this line will likely cause an immediate crash.
    printf("    (Skipping actual double free call to prevent immediate crash)\n");
}

/**
 * CWE-190: Integer Overflow or Wraparound
 * CWE-20: Improper Input Validation (related)
 */
void demonstrate_integer_overflow() {
    int items = 2;
    int item_size = INT_MAX / 2 + 5; // A large size
    printf("  - Calculating memory size with potentially overflowing integers...\n");
    
    // CWE-190: This multiplication can overflow 'total_size' if 'items' is user-controlled.
    // The result wraps around to a small positive or negative number.
    int total_size = items * item_size;
    
    printf("    Calculated size: %d\n", total_size);
    if (total_size < 0) {
        printf("    Integer overflow detected!\n");
    }
    
    // The wrongly calculated size is then used for allocation, which is a common follow-on vulnerability.
    char* buffer = (char*)malloc(total_size);
    if (buffer) {
        printf("    Allocation based on overflowed size was successful (this is bad).\n");
        free(buffer);
    } else {
        printf("    Allocation failed or was for a small amount.\n");
    }
}

/**
 * CWE-476: NULL Pointer Dereference
 */
void demonstrate_null_pointer_dereference(char* data) {
    // If 'data' is NULL (which we ensure from main), this is a NULL pointer dereference.
    printf("  - Attempting to access data from a pointer...\n");
    // A common scenario is a function that fails to check if a pointer returned
    // from another function (e.g., malloc) is NULL before using it.
    printf("    First character: %c\n", data[0]); // CWE-476 is here
}


/**
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 */
void demonstrate_risky_crypto() {
    char password[] = "mySuperSecretPassword123";
    printf("  - 'Hashing' password with MD5 (a broken algorithm for this purpose).\n");
    // In a real program, you would call a crypto library here, e.g., OpenSSL's MD5_Init, etc.
    // Static analysis tools can recognize the use of functions and constants associated with weak crypto.
    // e.g. EVP_des_ede3_cbc() or using "MD5" as a string parameter.
    printf("    (Simulating call to a function using 'MD5' or 'DES')\n");
}

/**
 * CWE-676: Use of Potentially Dangerous Function
 */
void demonstrate_dangerous_functions(char* input) {
    char temp_buffer[100];
    printf("  - Using gets() to read input (EXTREMELY DANGEROUS)...\n");
    // gets() is impossible to use safely as it performs no bounds checking.
    // It's deprecated but serves as a perfect example for this CWE.
    // gets(temp_buffer); // CWE-676: This line is fundamentally insecure.
    printf("    (Skipping actual gets() call to prevent program from blocking for input).\n");
}
