import OpenSSL.crypto

privatekey = OpenSSL.crypto.PKey()
privatekey.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)

with open('mypkey.pem', 'w') as f:
    # ruleid: pem_cipher-openssl_python
    f.write(str(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, privatekey,'aes256',b'test')))

with open('mypkey.pem', 'w') as f:
    # ruleid: pem_cipher-openssl_python
    f.write(str(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, privatekey,passphrase=b'test',cipher='aes256')))
