#include <iostream>
#include <fstream>
#include <zlib.h>
#include <thread>
#include <mutex>
#include <vector>
#include <chrono>

std::mutex file_mutex;

void compress_file(const std::string& input_file, const std::string& output_file) {
    std::lock_guard<std::mutex> lock(file_mutex); // Ensure no race condition on file access
    
    std::ifstream file(input_file, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open the input file!" << std::endl;
        return;
    }

    std::ofstream compressed_file(output_file, std::ios::binary);
    if (!compressed_file.is_open()) {
        std::cerr << "Failed to open the output file!" << std::endl;
        return;
    }

    const size_t buffer_size = 128 * 1024; // 128 KB buffer
    std::vector<char> buffer(buffer_size);

    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    deflateInit(&zs, Z_BEST_COMPRESSION);

    int flush;
    do {
        file.read(buffer.data(), buffer.size());
        zs.avail_in = file.gcount();
        flush = file.eof() ? Z_FINISH : Z_NO_FLUSH;

        do {
            char out[buffer_size];
            zs.next_in = reinterpret_cast<unsigned char*>(buffer.data());
            zs.avail_out = buffer_size;
            zs.next_out = reinterpret_cast<unsigned char*>(out);
            deflate(&zs, flush);
            compressed_file.write(out, buffer_size - zs.avail_out);
        } while (zs.avail_out == 0);
    } while (flush != Z_FINISH);

    deflateEnd(&zs);

    std::cout << "Compression completed." << std::endl;
}

void decompress_file(const std::string& input_file, const std::string& output_file) {
    std::lock_guard<std::mutex> lock(file_mutex);

    std::ifstream compressed_file(input_file, std::ios::binary);
    if (!compressed_file.is_open()) {
        std::cerr << "Failed to open the input file!" << std::endl;
        return;
    }

    std::ofstream decompressed_file(output_file, std::ios::binary);
    if (!decompressed_file.is_open()) {
        std::cerr << "Failed to open the output file!" << std::endl;
        return;
    }

    const size_t buffer_size = 128 * 1024;
    std::vector<char> buffer(buffer_size);

    z_stream zs;
    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;
    inflateInit(&zs);

    int flush;
    do {
        compressed_file.read(buffer.data(), buffer.size());
        zs.avail_in = compressed_file.gcount();
        flush = compressed_file.eof() ? Z_FINISH : Z_NO_FLUSH;

        do {
            char out[buffer_size];
            zs.next_in = reinterpret_cast<unsigned char*>(buffer.data());
            zs.avail_out = buffer_size;
            zs.next_out = reinterpret_cast<unsigned char*>(out);
            inflate(&zs, flush);
            decompressed_file.write(out, buffer_size - zs.avail_out);
        } while (zs.avail_out == 0);
    } while (flush != Z_FINISH);

    inflateEnd(&zs);

    std::cout << "Decompression completed." << std::endl;
}

int main() {
    std::string input_file = "../data.txt"; // Replace with a real file path
    std::string compressed_file = "data_compressed.gz";
    std::string decompressed_file = "data_decompressed.txt";

    auto start = std::chrono::high_resolution_clock::now();

    // Compress the file in a separate thread
    std::thread compression_thread(compress_file, input_file, compressed_file);
    compression_thread.join();

    auto compress_end = std::chrono::high_resolution_clock::now();

    // Decompress the file in a separate thread
    std::thread decompression_thread(decompress_file, compressed_file, decompressed_file);
    decompression_thread.join();

    auto decompress_end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> compress_duration = compress_end - start;
    std::chrono::duration<double> decompress_duration = decompress_end - compress_end;

    std::cout << "Compression took: " << compress_duration.count() << " seconds." << std::endl;
    std::cout << "Decompression took: " << decompress_duration.count() << " seconds." << std::endl;

    return 0;
}
