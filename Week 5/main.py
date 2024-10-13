def encrypt_by_add_mod(text, key):
    '''
    >>> encrypt_by_add_mod('Hello',123)
    'Ãàççê'
    >>> encrypt_by_add_mod(encrypt_by_add_mod('Hello',123),133)
    'Hello'
    >>> encrypt_by_add_mod(encrypt_by_add_mod('Cryptography',10),246)
    'Cryptography'
    '''
    encrypted = [chr((ord(text[i]) + key) % 256) for i in range(len(text))]
    return "".join(encrypted)


def encrypt_xor_with_changing_key_by_prev_cipher(text, key, mode):
    '''
    >>> encrypt_xor_with_changing_key_by_prev_cipher('Hello',123,'encrypt')
    '3V:V9'
    >>> encrypt_xor_with_changing_key_by_prev_cipher(encrypt_xor_with_changing_key_by_prev_cipher('Hello',123,'encrypt'),123,'decrypt')
    'Hello'
    >>> encrypt_xor_with_changing_key_by_prev_cipher(encrypt_xor_with_changing_key_by_prev_cipher('Cryptography',10,'encrypt'),10,'decrypt')
    'Cryptography'
    '''
    result = []
    for char in text:
        if (mode == 'encrypt'):
            key = ord(char) ^ key
            result.append(chr(key))
        else:
            result.append(chr(key ^ ord(char)))
            key = ord(char)

    return "".join(result)


def encrypt_xor_with_changing_key_by_prev_cipher_longer_key(text, key_list, mode):
    '''
    >>> key_list = [0x20, 0x44, 0x54,0x20]
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key('abcdefg', key_list, 'encrypt')
    'A&7D$@P'
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key('aaabbbb', key_list, 'encrypt')
    'A%5B#GW'
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key(
    ...    encrypt_xor_with_changing_key_by_prev_cipher_longer_key('abcdefg',key_list,'encrypt'),
    ...        key_list,'decrypt')
    'abcdefg'
    >>> encrypt_xor_with_changing_key_by_prev_cipher_longer_key(
    ...    encrypt_xor_with_changing_key_by_prev_cipher_longer_key('Hellobello, it will work for a long message as well',key_list,'encrypt'),
    ...        key_list,'decrypt')
    'Hellobello, it will work for a long message as well'
    '''
    result = list(text)

    for key_index in range(4):
        chunks = [text[i] for i in range(key_index, len(text), 4)]
        sub_result = encrypt_xor_with_changing_key_by_prev_cipher(
            "".join(chunks), key_list[key_index], mode)

        for i, char in enumerate(sub_result):
            result[key_index + i * 4] = char

    return "".join(result)
