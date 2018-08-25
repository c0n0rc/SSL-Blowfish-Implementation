# SSL-Blowfish-Implementation

To run:
```bash
g++  main.cc fscrypt.cc -lcrypto
```

Text to be encrypted/decrypted is hardcoded in main. 

fscrypt2.cc uses BF_cbc_encrypt, while fscrypt.cc uses BF_ecb_encrypt.
