from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def decrypt_aes_ecb(ciphertext: bytes, key: bytes):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> decrypt_aes_ecb(bytes([215, 221, 59, 138, 96, 94, 155, 69, 52, 90, 212, 108, 49, 65, 138, 179]),key)
    b'lovecryptography'
    >>> decrypt_aes_ecb(bytes([147, 140, 44, 177, 97, 209, 42, 239, 152, 124, 241, 175, 202, 164, 183, 18]),key)
    b'!!really  love!!'
    '''
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data


def xor_byte_arrays(ciphertext1: bytes, ciphertext2: bytes):
    '''
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([2,3,4,5]))
    b'\\x03\\x01\\x07\\x01'
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([]))
    b'\\x01\\x02\\x03\\x04'
    >>> xor_byte_arrays(bytes([1,2,3,4]),bytes([1,2]))
    b'\\x01\\x02\\x02\\x06'
    >>> xor_byte_arrays(bytes([1,2,4,8,16,32,64,128]),bytes([1,1,1,1,1,1,1,1]))
    b'\\x00\\x03\\x05\\t\\x11!A\\x81'
    '''
    max_length = 0
    cipher_length_1 = len(ciphertext1)
    cipher_length_2 = len(ciphertext2)

    if (cipher_length_1 > cipher_length_2):
        max_length = cipher_length_1
    elif (cipher_length_2 > cipher_length_1):
        max_length = cipher_length_2
    else:
        max_length = cipher_length_1

    input1_padded = ciphertext1.rjust(max_length, bytes([0]))
    input2_padded = ciphertext2.rjust(max_length, bytes([0]))

    xor_applied = bytes([b1 ^ b2
                         for b1, b2 in zip(input1_padded, input2_padded)])
    return xor_applied


def decrypt_aes_cbc_with_ecb(cipher_text: bytes, key: bytes, iv: bytes):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
    >>> decrypt_aes_cbc_with_ecb(bytes([255, 18, 67, 115, 172, 117, 242, 233, 246, 69, 81, 156, 52, 154, 123, 171]),key,iv)
    b'hello world 1234'
    >>> decrypt_aes_cbc_with_ecb(bytes([171, 218, 160, 96, 193, 134, 73, 81, 221, 149, 19, 180, 31, 247, 106, 64]),key,iv)
    b'lovecryptography'
    >>> decrypt_aes_cbc_with_ecb(bytes([171, 218, 160, 96, 193, 134, 73, 81, 221, 149, 19, 180, 31, 247, 106, 64] * 2),bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220]),bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204]))
    b'lovecryptography6&\\x94\\x84`\\xd6\\x15\\x12E\\xbf\\xc8\\x0b>\\x0b\\xf6\\xf5'
    '''
    blocks = [cipher_text[i:i + AES.block_size]
              for i in range(0, len(cipher_text), AES.block_size)]
    decrypted_blocks = []
    previous_block = iv

    for block in blocks:
        decrypted_block = decrypt_aes_ecb(block, key)
        decrypted_block_xored = bytes(
            a ^ b for a, b in zip(decrypted_block, previous_block))
        decrypted_blocks.append(decrypted_block_xored)
        previous_block = block

    return b''.join(decrypted_blocks)


def encrypt_aes_ecb(plain_text: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_text = cipher.encrypt(plain_text)
    return cipher_text


def encrypt_aes_cbc_with_ecb(plain_text: bytes, key: bytes, iv: bytes):
    '''
    >>> key = bytes([57, 226, 240, 61, 125, 240, 75, 68, 22, 35, 124, 205, 144, 27, 118, 220])
    >>> iv = bytes([241, 147, 66, 129, 194, 34, 37, 51, 236, 69, 188, 205, 64, 140, 244, 204])
    >>> encrypt_aes_cbc_with_ecb(b'hello world 1234',key,iv)
    b'\\xff\\x12Cs\\xacu\\xf2\\xe9\\xf6EQ\\x9c4\\x9a{\\xab'
    >>> encrypt_aes_cbc_with_ecb(bytes(b'lovecryptography'),key,iv)
    b'\\xab\\xda\\xa0`\\xc1\\x86IQ\\xdd\\x95\\x13\\xb4\\x1f\\xf7j@'
    '''
    blocks = [plain_text[i:i + AES.block_size]
              for i in range(0, len(plain_text), AES.block_size)]
    cipher_text_blocks = []
    previous_block = iv
    for block in blocks:

        xor_block = xor_byte_arrays(block, previous_block)
        encrypted_block = encrypt_aes_ecb(xor_block, key)
        cipher_text_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return b''.join(cipher_text_blocks)
