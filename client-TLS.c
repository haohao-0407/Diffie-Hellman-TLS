#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/rand.h>

#define PORT 12345
#define HOST "127.0.0.1"

// 错误处理函数
void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}
void derive_aes_key_pbkdf2(unsigned char *shared_secret, unsigned char *aes_key) {
    unsigned char shared_secret_bytes[256];  // 假设共享密钥最多为 256 位
    unsigned char salt[] = "Diffie-Hellman";  // 示例盐值
    memset(shared_secret_bytes, 0, sizeof(shared_secret_bytes));
    sprintf((char *)shared_secret_bytes, "%s", shared_secret);

    if (!PKCS5_PBKDF2_HMAC((char *)shared_secret_bytes, strlen((char *)shared_secret_bytes),
                           salt, strlen((char *)salt),
                           100000,  // 迭代次数
                           EVP_sha256(), 32, aes_key)) {
        fprintf(stderr, "PBKDF2 failed\n");
    }
}
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *key, unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) return -1;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) return -1;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) return -1;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) return -1;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *tag, unsigned char *key,
                    unsigned char *iv, int iv_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len, ret;

    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) return -1;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) return -1;
    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) return -1;

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;  // 解密失败
    }
}
SSL_CTX* init_client_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = TLS_client_method();  // Use the client-side TLS method
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
void print_openssl_errors() {
    unsigned long err_code;
    while ((err_code = ERR_get_error()) != 0) {
        char *err_string = ERR_error_string(err_code, NULL);
        if (err_string != NULL) {
            fprintf(stderr, "OpenSSL error: %s\n", err_string);
        }
    }
}

// 生成 Diffie-Hellman 密钥对
EVP_PKEY* generate_dh_key() {
    EVP_PKEY_CTX *pkey_ctx;
    EVP_PKEY *pkey = NULL;

    // Initialize context for Diffie-Hellman key pair generation
    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pkey_ctx) {
        handle_error("EVP_PKEY_CTX_new_id failed");
    }
    print_openssl_errors();

    // Set up parameters for Diffie-Hellman (2048-bit prime size)
    if (EVP_PKEY_paramgen_init(pkey_ctx) <= 0) {
        handle_error("EVP_PKEY_paramgen_init failed");
    }
    print_openssl_errors();

    // Set the prime size for Diffie-Hellman key generation (2048 bits)
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pkey_ctx, 2048) <= 0) {
        handle_error("EVP_PKEY_CTX_set_dh_paramgen_prime_len failed");
    }
    print_openssl_errors();

    // Generate the Diffie-Hellman parameters (prime and base)
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        print_openssl_errors();
        handle_error("EVP_PKEY_keygen failed");
        
    }

    // Clean up context
    EVP_PKEY_CTX_free(pkey_ctx);
    return pkey;
}


// 计算共享密钥
unsigned char* compute_shared_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_pub_key, size_t *secret_len) {
    EVP_PKEY_CTX *ctx;
    unsigned char *shared_secret = NULL;

    // Create a context for key derivation
    ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) {
        handle_error("EVP_PKEY_CTX_new failed");
    }

    // Initialize key derivation
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        handle_error("EVP_PKEY_derive_init failed");
    }

    // Set peer public key
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        handle_error("EVP_PKEY_derive_set_peer failed");
    }

    // Calculate the shared secret size
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        handle_error("EVP_PKEY_derive failed");
    }

    // Allocate memory for the shared secret
    shared_secret = (unsigned char*) OPENSSL_malloc(*secret_len);
    if (shared_secret == NULL) {
        handle_error("Memory allocation failed");
    }

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, shared_secret, secret_len) <= 0) {
        handle_error("EVP_PKEY_derive failed");
    }

    // Clean up
    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}


// 连接到服务器并交换密钥
void client_exchange_keys() {
    SSL_CTX *ctx;
    SSL *ssl;
    int sock;
    struct sockaddr_in server_addr;
    unsigned char buffer[1024];
    int bytes_read;
    size_t shared_secret_len;
    // Initialize OpenSSL
    SSL_library_init();

    // Set up SSL context
    ctx = init_client_context();

    // 创建 socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        handle_error("Socket creation failed");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(HOST);

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        handle_error("Connection failed");
    }
    // Create SSL object
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform SSL/TLS handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("SSL/TLS handshake completed\n");

    // 生成本地 Diffie-Hellman 密钥对
    //EVP_PKEY *priv_key = generate_dh_key();
    int priv_len = 2 * 112;
    OSSL_PARAM params[3];
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);

    params[0] = OSSL_PARAM_construct_utf8_string("group", "ffdhe2048", 0);
    /* "priv_len" is optional */
    params[1] = OSSL_PARAM_construct_int("priv_len", &priv_len);
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_params(pctx, params);
    EVP_PKEY_generate(pctx, &pkey);

    // 获取并发送公钥
    EVP_PKEY *pub_key = EVP_PKEY_dup(pkey);  // 复制私钥以便提取公钥
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pub_key);
    int pub_key_len = BIO_read(bio, buffer, sizeof(buffer));
    //send(sock, buffer, pub_key_len, 0);
    BIO_free(bio);
    // Send public key to the server
    if (SSL_write(ssl, buffer, pub_key_len) <= 0)
        handle_error("Send failed");

    printf("Client sent public key to server\n");

    // 接收服务端的公钥
    //bytes_read = recv(sock, buffer, sizeof(buffer), 0);
    //if (bytes_read <= 0) {
    //    handle_error("Failed to receive server public key");
    //}
    // Receive server's public key
    unsigned char server_pub_key_buf[2048];
    int server_pub_key_len = SSL_read(ssl, server_pub_key_buf, sizeof(server_pub_key_buf));
    if (server_pub_key_len <= 0)
        handle_error("Receive failed");

    BIO *peer_bio = BIO_new_mem_buf(server_pub_key_buf, server_pub_key_len);
    EVP_PKEY *peer_pub_key = PEM_read_bio_PUBKEY(peer_bio, NULL, NULL, NULL);
    BIO_free(peer_bio);

    // 计算共享密钥
    unsigned char *shared_secret = compute_shared_secret(pkey, peer_pub_key, &shared_secret_len);

    // 打印共享密钥
    printf("Shared secret: ");
    for (size_t i = 0; i < shared_secret_len; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");
    unsigned char aes_key[32];
    derive_aes_key_pbkdf2(shared_secret, aes_key);
    printf("Derived AES-256 key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", aes_key[i]);
    }
    printf("\n");
    //AES
    unsigned char plaintext[128] = {0};
    unsigned char ciphertext[128] = {0};
    unsigned char decryptedtext[128] = {0};
    unsigned char iv[12] = {0};  // 96 位随机 IV
    unsigned char tag[16] = {0}; // 128 位认证标签
    int ciphertext_len, decryptedtext_len;
    printf("enter plaintext:");
    int i=0;
	int j;
	char ch;
	while((ch=getchar())!='\n')//一直接收缓冲区的字符。直至收到回车
	{
	   	plaintext[i]=ch;
	   	i++;
	}
	plaintext[i]='\0';

    // 生成随机 IV
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Failed to generate IV\n");
    }

    printf("Plaintext: %s\n", plaintext);

    // 加密
    ciphertext_len = aes_gcm_encrypt(plaintext, strlen((char *)plaintext),
                                     aes_key, iv, sizeof(iv),
                                     ciphertext, tag);
    if (ciphertext_len == -1) {
        fprintf(stderr, "Encryption failed\n");
    }

    printf("Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    //send(sock,&ciphertext_len,sizeof(ciphertext_len),0);
    if (SSL_write(ssl, &ciphertext_len, sizeof(ciphertext_len)) <= 0)
        handle_error("Send failed");
    //send(sock,&ciphertext,ciphertext_len*sizeof(char),0);
    if (SSL_write(ssl, &ciphertext, ciphertext_len*sizeof(char)) <= 0)
        handle_error("Send failed");
    //send(sock,&iv,sizeof(iv),0);
    if (SSL_write(ssl, &iv, sizeof(iv)) <= 0)
        handle_error("Send failed");
    //send(sock,&tag,sizeof(tag),0);
    if (SSL_write(ssl, &tag, sizeof(tag)) <= 0)
        handle_error("Send failed");


    // 释放内存
    OPENSSL_free(shared_secret);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_pub_key);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

int main() {
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) == 0) {
        fprintf(stderr, "OpenSSL initialization failed\n");
        return 1;
    }

    client_exchange_keys();
    return 0;
}
