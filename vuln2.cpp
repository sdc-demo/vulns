/**
 * vulnerable_oop.cpp
 *
 *
 * A C++ demonstration application focusing on vulnerabilities common in
 * object-oriented programming (OOP) and C++-specific language features.
 *
 * --- INTENTIONALLY INSECURE ---
 *
 * To compile:
 * g++ -o vulnerable_oop vulnerable_oop.cpp
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib> // For system()

// --- Base and Derived Classes for Destructor/Memory Leak Demo ---

class MediaFile {
public:
    MediaFile(const std::string& name) : filename(name) {
        std::cout << "  - MediaFile base constructor called for: " << filename << std::endl;
    }

    // CWE-459: Incomplete Cleanup / Missing virtual destructor
    // Because the destructor is not virtual, deleting a derived class object
    // through a base class pointer will not call the derived class destructor.
    ~MediaFile() {
        std::cout << "  - MediaFile base destructor called for: " << filename << std::endl;
    }
protected:
    std::string filename;
};

class VideoFile : public MediaFile {
public:
    VideoFile(const std::string& name) : MediaFile(name) {
        std::cout << "    - VideoFile derived constructor called." << std::endl;
        // CWE-401: Missing Release of Memory ('Memory Leak')
        // This memory will be leaked if the destructor is not called.
        this->codec_buffer = new char[1024];
    }

    ~VideoFile() {
        std::cout << "    - VideoFile derived destructor called. Freeing memory." << std::endl;
        delete[] this->codec_buffer;
    }
private:
    char* codec_buffer;
};


void demonstrate_command_injection(std::string remote_host) {
    std::cout << "\n[2] Demonstrating Command Injection with C++ strings..." << std::endl;

    // CWE-78: OS Command Injection
    // The vulnerability is the same as in C, but the mechanics use C++ strings.
    std::string command = "ping -c 1 " + remote_host;
    std::cout << "  - Executing command: " << command << std::endl;

    // An input like "8.8.8.8; ls -l" would execute a second command.
    system(command.c_str());
}

void demonstrate_vector_out_of_bounds() {
    std::cout << "\n[3] Demonstrating Out-of-Bounds Write on std::vector..." << std::endl;
    std::vector<int> user_ids(5); // Vector holds 5 elements, indices 0-4.
    std::cout << "  - Vector created with size " << user_ids.size() << std::endl;

    // CWE-787: Out-of-bounds Write
    // The loop condition should be i < user_ids.size(), not <=.
    // The last iteration (i=5) writes past the end of the vector's managed memory.
    for (size_t i = 0; i <= user_ids.size(); ++i) {
        std::cout << "    - Writing to index " << i << std::endl;
        user_ids[i] = i * 100; // This will write out of bounds when i = 5
    }

    std::cout << "  - Out-of-bounds write completed. Program may be unstable." << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "--- Starting Vulnerable C++ OOP Demonstration ---" << std::endl;

    // --- 1. Memory Leak due to missing virtual destructor ---
    std::cout << "\n[1] Demonstrating Memory Leak from improper class design..." << std::endl;
    // We create a derived object but store it in a base class pointer.
    MediaFile* file = new VideoFile("movie.mp4");
    
    // When we delete the base pointer, only the base destructor is called.
    // The VideoFile destructor is skipped, and its 'codec_buffer' is leaked.
    delete file;
    std::cout << "  - Notice the 'VideoFile derived destructor' message was never printed." << std::endl;


    // --- 2. Command Injection ---
    std::string malicious_host = "example.com; echo 'Command Injection Successful'";
    demonstrate_command_injection(malicious_host);


    // --- 3. Vector Out-of-Bounds Write ---
    // This may or may not crash immediately depending on memory layout.
    demonstrate_vector_out_of_bounds();


    std::cout << "\n--- C++ OOP Demonstration Complete ---" << std::endl;

    return 0;
}
