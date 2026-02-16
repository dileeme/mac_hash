#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

void print_hex(unsigned char *data, int len) {
    for(int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main() {
    const char *message = "HelloWorld";
    const char *key = "SecretKey";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, key, strlen(key));
    EVP_DigestUpdate(mdctx, message, strlen(message));
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    print_hex(digest, digest_len);
    EVP_MD_CTX_free(mdctx);

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, key, strlen(key));
    EVP_DigestUpdate(mdctx, message, strlen(message));
    EVP_DigestFinal_ex(mdctx, digest, &digest_len);
    print_hex(digest, digest_len);
    EVP_MD_CTX_free(mdctx);

    HMAC(EVP_sha256(), key, strlen(key), (unsigned char*)message, strlen(message), digest, &digest_len);
    print_hex(digest, digest_len);

    HMAC(EVP_md5(), key, strlen(key), (unsigned char*)message, strlen(message), digest, &digest_len);
    print_hex(digest, digest_len);

    return 0;
}
