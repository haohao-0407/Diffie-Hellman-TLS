# Diffie-Hellman-TLS
使用libssl的Diffie-Hellman协议示例，首先建立TLS连接，DH协商密钥，PBKDF2密钥拓展，最后使用AES-256-GCM加密消息
# 使用前需要创建自己的证书
openssl req -x509 -newkey rsa:2048 -keyout server-key.pem -out server-cert.pem -days 365 -nodes
