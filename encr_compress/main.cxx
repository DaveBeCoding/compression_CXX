#include <iostream>
#include <fstream>
#include <zlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>  // Required for AES_BLOCK_SIZE
#include <openssl/rand.h>
#include <thread>
#include <mutex>
#include <chrono>
#include <vector>

std::mutex file_mutex;

// Compress file using zlib
void compress_file(const std::string& input_file, const std::string& output_file) {
    std::lock_guard<std::mutex> lock(file_mutex);

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

    const size_t buffer_size = 128 * 1024;  // 128 KB buffer
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

// Decompress file using zlib
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

    const size_t buffer_size = 128 * 1024;  // 128 KB buffer
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

// Encrypt the file using AES (with OpenSSL's EVP API)
void encrypt_aes(const std::string& input_file, const std::string& output_file, const unsigned char* key) {
    std::lock_guard<std::mutex> lock(file_mutex);

    std::ifstream file(input_file, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open the input file!" << std::endl;
        return;
    }

    std::ofstream encrypted_file(output_file, std::ios::binary);
    if (!encrypted_file.is_open()) {
        std::cerr << "Failed to open the output file!" << std::endl;
        return;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);  // Generate random IV (Initialization Vector)
    encrypted_file.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);  // Save IV in the encrypted file

    unsigned char buffer_in[AES_BLOCK_SIZE], buffer_out[AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int out_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);  // Use AES 128 CBC encryption

    while (file.read(reinterpret_cast<char*>(buffer_in), AES_BLOCK_SIZE)) {
        EVP_EncryptUpdate(ctx, buffer_out, &out_len, buffer_in, AES_BLOCK_SIZE);
        encrypted_file.write(reinterpret_cast<char*>(buffer_out), out_len);
    }

    EVP_EncryptFinal_ex(ctx, buffer_out, &out_len);
    encrypted_file.write(reinterpret_cast<char*>(buffer_out), out_len);

    EVP_CIPHER_CTX_free(ctx);
    file.close();
    encrypted_file.close();
    std::cout << "Encryption completed." << std::endl;
}

// Decrypt the file using AES (with OpenSSL's EVP API)
void decrypt_aes(const std::string& input_file, const std::string& output_file, const unsigned char* key) {
    std::lock_guard<std::mutex> lock(file_mutex);

    std::ifstream encrypted_file(input_file, std::ios::binary);
    if (!encrypted_file.is_open()) {
        std::cerr << "Failed to open the input file!" << std::endl;
        return;
    }

    std::ofstream decrypted_file(output_file, std::ios::binary);
    if (!decrypted_file.is_open()) {
        std::cerr << "Failed to open the output file!" << std::endl;
        return;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    encrypted_file.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);  // Read the IV from the encrypted file

    unsigned char buffer_in[AES_BLOCK_SIZE], buffer_out[AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int out_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);  // Use the IV for decryption

    while (encrypted_file.read(reinterpret_cast<char*>(buffer_in), AES_BLOCK_SIZE)) {
        EVP_DecryptUpdate(ctx, buffer_out, &out_len, buffer_in, AES_BLOCK_SIZE);
        decrypted_file.write(reinterpret_cast<char*>(buffer_out), out_len);
    }

    EVP_DecryptFinal_ex(ctx, buffer_out, &out_len);
    decrypted_file.write(reinterpret_cast<char*>(buffer_out), out_len);

    EVP_CIPHER_CTX_free(ctx);
    encrypted_file.close();
    decrypted_file.close();
    std::cout << "Decryption completed." << std::endl;
}

int main() {
    /**
     * To encrypt and decrypt, you will need to generate a key and save it securely.
     * The key is essential for both encrypting and decrypting the files.
     *
     * If you are creating an encrypted file (Step 1: Compression and Step 2: Encryption),
     * you must generate a key, save it securely, and share it if needed for decryption.
     *
     * If you receive an encrypted file, use the saved key to decrypt and decompress it.
     */

    std::string log_file = "../data.txt";  // Original log file
    std::string compressed_log_file = "compressed_log.gz";
    std::string encrypted_log_file = "encrypted_log.dat";
    std::string decrypted_log_file = "decrypted_log.gz";  // Decrypted file will still be compressed
    std::string final_output_file = "final_data.txt";  // Final decompressed file

    unsigned char key[AES_BLOCK_SIZE];

    // --------------------- ENCRYPTION PROCESS ---------------------

    // Step 1: Generate a random key (for the first time) and save it securely
    RAND_bytes(key, AES_BLOCK_SIZE);  // Generate a random AES key

    // Save the key to a file for later use
    std::ofstream key_file("encryption_key.bin", std::ios::binary);
    key_file.write(reinterpret_cast<const char*>(key), AES_BLOCK_SIZE);  // Save the key to a file
    key_file.close();
    std::cout << "Encryption key saved to encryption_key.bin" << std::endl;

    // Step 2: Compress the original log file
    std::thread compress_thread(compress_file, log_file, compressed_log_file);
    compress_thread.join();

    // Step 3: Encrypt the compressed file
    std::thread encrypt_thread(encrypt_aes, compressed_log_file, encrypted_log_file, key);
    encrypt_thread.join();

    std::cout << "Encryption process completed. Encrypted file: " << encrypted_log_file << std::endl;

    // --------------------- DECRYPTION PROCESS ---------------------

    // If decrypting a received file, load the saved encryption key:
    // Read the saved key from the file
    std::ifstream key_input("encryption_key.bin", std::ios::binary);
    key_input.read(reinterpret_cast<char*>(key), AES_BLOCK_SIZE);  // Load the encryption key from the file
    key_input.close();

    // Step 4: Decrypt the encrypted file to get back the compressed file
    std::thread decrypt_thread(decrypt_aes, encrypted_log_file, decrypted_log_file, key);
    decrypt_thread.join();

    // Step 5: Decompress the decrypted file to restore the original file
    std::thread decompress_thread(decompress_file, decrypted_log_file, final_output_file);
    decompress_thread.join();

    std::cout << "The original data has been restored to: " << final_output_file << std::endl;

    return 0;
}
