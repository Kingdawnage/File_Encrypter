#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <fstream>
#include <iostream> 

// Function to generate a secure encryption key using PBKDF2
std::vector<unsigned char> GenerateEncryptionKey(const std::string& password, const std::vector<unsigned char>& salt)
{
    const int iterations = 10000; // Adjust the number of iterations as per your requirements
    const int keyLength = 32;     // Adjust the key length as per the encryption algorithm

    std::vector<unsigned char> key(keyLength);
    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
        salt.data(), static_cast<int>(salt.size()), iterations,
        EVP_sha256(), keyLength, key.data());

    return key;
}

void FileEncrypt(const std::string& inputPath, const std::string& outputPath, const std::string& password)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // IV generation
    std::vector<unsigned char> IV(EVP_MAX_IV_LENGTH);
    if (RAND_bytes(IV.data(), EVP_MAX_IV_LENGTH) != 1) {
        return;
    }

    // Generate salt for key derivation
    std::vector<unsigned char> salt(EVP_MAX_KEY_LENGTH);
    if (RAND_bytes(salt.data(), EVP_MAX_KEY_LENGTH) != 1) {
        return;
    }

    // Generate encryption key using PBKDF2
    std::vector<unsigned char> key = GenerateEncryptionKey(password, salt);

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), IV.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Open input and output files
    std::ifstream inputFile(inputPath, std::ios::binary);
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!inputFile || !outputFile) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Write salt and IV to the output file
    outputFile.write(reinterpret_cast<const char*>(salt.data()), EVP_MAX_KEY_LENGTH);
    outputFile.write(reinterpret_cast<const char*>(IV.data()), EVP_MAX_IV_LENGTH);

    std::vector<unsigned char> buffer(EVP_CIPHER_CTX_block_size(ctx));
    int bytesProcessed = 0;
    while (inputFile.good()) {
        inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        int bytesRead = static_cast<int>(inputFile.gcount());

        if (EVP_EncryptUpdate(ctx, buffer.data(), &bytesProcessed, buffer.data(), bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        outputFile.write(reinterpret_cast<const char*>(buffer.data()), bytesProcessed);
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, buffer.data(), &bytesProcessed) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    outputFile.write(reinterpret_cast<const char*>(buffer.data()), bytesProcessed);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void FileDecrypt(const std::string& inputPath, const std::string& outputPath, const std::string& password)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // Read salt and IV from input file
    std::ifstream inputFile(inputPath, std::ios::binary);
    if (!inputFile) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::vector<unsigned char> salt(EVP_MAX_KEY_LENGTH);
    inputFile.read(reinterpret_cast<char*>(salt.data()), EVP_MAX_KEY_LENGTH);

    std::vector<unsigned char> IV(EVP_MAX_IV_LENGTH);
    inputFile.read(reinterpret_cast<char*>(IV.data()), EVP_MAX_IV_LENGTH);

    // Derive decryption key using the provided password and salt
    std::vector<unsigned char> key = GenerateEncryptionKey(password, salt);

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), IV.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Set padding to false
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Open output file
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Decrypt and write data
    std::vector<unsigned char> buffer(EVP_CIPHER_CTX_block_size(ctx));
    int bytesProcessed = 0;
    while (inputFile.good()) {
        inputFile.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        int bytesRead = static_cast<int>(inputFile.gcount());

        if (EVP_DecryptUpdate(ctx, buffer.data(), &bytesProcessed, buffer.data(), bytesRead) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return;
        }

        outputFile.write(reinterpret_cast<const char*>(buffer.data()), bytesProcessed);
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, buffer.data(), &bytesProcessed) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    outputFile.write(reinterpret_cast<const char*>(buffer.data()), bytesProcessed);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

void SelectOperation(int& choice) {
    if (choice == 0) {

        std::string inputpath;
        std::string outputpath;

        std::cout << "Enter the path of the file you would like to encrypt: " << std::endl;
        std::cin >> inputpath;

        std::cout << "Enter the save path of your encrypted file: " << std::endl;
        std::cin >> outputpath;

        std::cout << "Enter a secure password: " << std::endl;
        std::string pin;
        std::cin >> pin;

        FileEncrypt(inputpath, outputpath, pin);
        std::cout << "File encrypted successfully!" << std::endl;

        return;
    }
    else if (choice == 1) {

        std::string inputpath;
        std::string outputpath;

        std::cout << "Enter the path of the file you would like to decrypt: " << std::endl;
        std::cin >> inputpath;


        std::cout << "Enter the save path of your decrypted file: " << std::endl;
        std::cin >> outputpath;

        std::cout << "Enter the password used when encrypting the file: " << std::endl;
        std::string pin;
        std::cin >> pin;

        FileDecrypt(inputpath, outputpath, pin);
        std::cout << "File decrypted successfully!" << std::endl;

        return;
    }
    else {
        std::cout << "Invalid input. Try again" << std::endl;

        return;
    }
}

int main()
{
    std::cout << "Would you like to encrypt(0) or decrypt(1)?" << std::endl;

    int choice;

    std::cin >> choice;

    SelectOperation(choice);

    /*
    // Test Encryption and Decryption
    std::string inputFilePath = "C:/Users/katch/Desktop/Test/test.txt";
    std::string encryptedFilePath = "C:/Users/katch/Desktop/Test/encrypt.txt";
    std::string decryptedFilePath = "C:/Users/katch/Desktop/Test/decrypt.txt";

    // Test password (for demo purposes; replace with secure password in practice)
    std::string password = "MySecurePassword";

    // Perform Encryption
    FileEncrypt(inputFilePath, encryptedFilePath, password);
    std::cout << "File encrypted successfully.\n";

    // Perform Decryption
    FileDecrypt(encryptedFilePath, decryptedFilePath, password);
    std::cout << "File decrypted successfully.\n"; */

    return 0;
}