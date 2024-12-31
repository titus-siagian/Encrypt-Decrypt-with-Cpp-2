#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <cstring>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

RSA* generateRSAKeyPair(int bits) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();

    // Set public exponent e = 65537
    if (!BN_set_word(e, RSA_F4)) handleErrors();

    // Generate RSA key pair
    if (!RSA_generate_key_ex(rsa, bits, e, NULL)) handleErrors();

    BN_free(e);
    return rsa;
}

std::string rsaEncrypt(RSA* rsa, const std::string& plaintext) {
    std::string encrypted(RSA_size(rsa), '\0');

    int result = RSA_public_encrypt(
        plaintext.size(),
        reinterpret_cast<const unsigned char*>(plaintext.c_str()),
        reinterpret_cast<unsigned char*>(&encrypted[0]),
        rsa,
        RSA_PKCS1_OAEP_PADDING);

    if (result == -1) handleErrors();
    encrypted.resize(result);
    return encrypted;
}

std::string rsaDecrypt(RSA* rsa, const std::string& ciphertext) {
    std::string decrypted(RSA_size(rsa), '\0');

    int result = RSA_private_decrypt(
        ciphertext.size(),
        reinterpret_cast<const unsigned char*>(ciphertext.c_str()),
        reinterpret_cast<unsigned char*>(&decrypted[0]),
        rsa,
        RSA_PKCS1_OAEP_PADDING);

    if (result == -1) handleErrors();
    decrypted.resize(result);
    return decrypted;
}

int main() {
    // Generate RSA key pair
    RSA* rsa = generateRSAKeyPair(2048);
    std::cout << "RSA Key Pair Generated (2048 bits)" << std::endl;

    // Example plaintext
    std::string plaintext = "Hello, this is a secret message!";
    std::cout << "Original Plaintext: " << plaintext << std::endl;

    // Encrypt the plaintext
    std::string encrypted = rsaEncrypt(rsa, plaintext);
    std::cout << "Encrypted Ciphertext (in hex): ";
    for (unsigned char c : encrypted) {
        printf("%02x", c);
    }
    std::cout << std::endl;

    // Decrypt the ciphertext
    std::string decrypted = rsaDecrypt(rsa, encrypted);
    std::cout << "Decrypted Plaintext: " << decrypted << std::endl;

    // Free RSA structure
    RSA_free(rsa);

    return 0;
}
