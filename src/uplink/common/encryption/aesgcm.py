# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from Crypto.Cipher import AES


def encrypt_aesgcm(plain_data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.encrypt(plain_data)


def decrypt_aesgcm(cipher_data: bytes, key: bytes, nonce: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt(cipher_data)
