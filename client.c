#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>

#define PORT 12345
#define HOST "127.0.0.1"

// 错误处理函数
void handle_error(const char *msg) {
    perror(msg);
    exit(1);
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
    int sock;
    struct sockaddr_in server_addr;
    unsigned char buffer[1024];
    int bytes_read;
    size_t shared_secret_len;

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
    send(sock, buffer, pub_key_len, 0);
    BIO_free(bio);

    // 接收服务端的公钥
    bytes_read = recv(sock, buffer, sizeof(buffer), 0);
    if (bytes_read <= 0) {
        handle_error("Failed to receive server public key");
    }

    BIO *peer_bio = BIO_new_mem_buf(buffer, bytes_read);
    EVP_PKEY *peer_pub_key = PEM_read_bio_PUBKEY(peer_bio, NULL, NULL, NULL);
    BIO_free(peer_bio);

    // 计算共享密钥
    unsigned char *shared_secret = compute_shared_secret(pkey, peer_pub_key, &shared_secret_len);

    // 打印共享密钥（只为示范，实际应用中应避免打印密钥）
    printf("Shared secret: ");
    for (size_t i = 0; i < shared_secret_len; i++) {
        printf("%02x", shared_secret[i]);
    }
    printf("\n");

    // 释放内存
    OPENSSL_free(shared_secret);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_pub_key);
    close(sock);
}

int main() {
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) == 0) {
        fprintf(stderr, "OpenSSL initialization failed\n");
        return 1;
    }

    client_exchange_keys();
    return 0;
}
