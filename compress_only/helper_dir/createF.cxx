//g++ -std=c++11 create_fileSizes.cxx -o createF.EXE


#include <iostream>
#include <fstream>
#include <cstdlib>  // For rand()
#include <ctime>    // For time()
#include <string>   // For std::string

void create_random_file(const std::string& filename, double size_in_mb) {
    size_t size_in_bytes = static_cast<size_t>(size_in_mb * 1024 * 1024);  // Convert MB to bytes
    std::ofstream file(filename);  // Open file in text mode

    if (!file) {
        std::cerr << "Failed to create the file.\n";
        return;
    }

    // Seed the random number generator
    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    // Generate and write random characters until we reach the desired size
    for (size_t i = 0; i < size_in_bytes; ++i) {
        char random_char = 'A' + (std::rand() % 26);  // Random uppercase letter
        file.put(random_char);  // Write single character to file
    }

    file.close();
    std::cout << "Text file created successfully!" << std::endl;
}

int main() {
    create_random_file("data.txt", 1.5);  // Create a 1.5MB text file
    return 0;
}
