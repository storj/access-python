# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from nacl.secret import SecretBox


def encrypt_secretbox(plain_data: bytes, key: bytes, nonce: bytes) -> bytes:
    box = SecretBox(key)
    return box.encrypt(plain_data, nonce).ciphertext


def decrypt_secretbox(cipher_data: bytes, key: bytes, nonce: bytes) -> bytes:
    box = SecretBox(key)
    return box.decrypt(cipher_data, nonce)
