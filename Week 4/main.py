
def hex2string(hex_string):
    '''
    >>> hex2string('61')
    'a'
    >>> hex2string('776f726c64')
    'world'
    >>> hex2string('68656c6c6f')
    'hello'
    '''
    result = ''
    for i in range(0, len(hex_string), 2):
        result += chr(int(hex_string[i] + hex_string[i + 1], 16))

    return result


def string2hex(str):
    '''
    >>> string2hex('a')
    '61'
    >>> string2hex('hello')
    '68656c6c6f'
    >>> string2hex('world')
    '776f726c64'
    >>> string2hex('foo')
    '666f6f'
    '''
    hex_chars = [hex(ord(char))[2:] for char in str]
    return "".join(hex_chars)


def hex_xor(hex_str, key):
    '''
    >>> hex_xor('0aabbf11','12345678')
    '189fe969'
    >>> hex_xor('12cc','12cc')
    '0000'
    >>> hex_xor('1234','2345')
    '3171'
    >>> hex_xor('111','248')
    '359'
    >>> hex_xor('8888888','1234567')
    '9abcdef'
    '''
    hex_str = hex_str.ljust(len(key), '0')
    result = ''
    for i, char in enumerate(hex_str):
        xor = int(char, 16) ^ int(key[i], 16)
        result += hex(xor)[2:]
    return result


def encrypt_single_byte_xor(hex_str, hex_key):
    '''
    >>> encrypt_single_byte_xor('aaabbccc','00')
    'aaabbccc'
    >>> encrypt_single_byte_xor(string2hex('hello'),'aa')
    'c2cfc6c6c5'
    >>> hex2string(encrypt_single_byte_xor(encrypt_single_byte_xor(string2hex('hello'),'aa'),'aa'))
    'hello'
    >>> hex2string(encrypt_single_byte_xor(encrypt_single_byte_xor(string2hex('Encrypt and decrypt are the same'),'aa'),'aa'))
    'Encrypt and decrypt are the same'
    '''
    key = int(hex_key, 16)
    result = bytearray(len(hex_str) // 2)

    for i in range(0, len(hex_str), 2):
        byte = int(hex_str[i:i+2], 16)
        result[i // 2] = byte ^ key

    return result.hex()


def decrypt_single_byte_xor(hex_str):
    '''
    >>> decrypt_single_byte_xor('e9c88081f8ced481c9c0d7c481c7ced4cfc581ccc480')
    'Hi! You have found me!'
    >>> decrypt_single_byte_xor('b29e9f96839085849d9085989e9f82d1889e84d199908794d197989f95d1859994d181908282869e8395d0')
    'Congratulations you have find the password!'
    >>> decrypt_single_byte_xor('e1ded996ddd8d9c1c596c1ded7c296dfc596ded7c6c6d3d8dfd8d18996e1ded3c4d396d7db96ff89')
    'Who knows what is happening? Where am I?'
    '''
    valid_characters = "abcdefghijklmnopqrstuvxyz ABCDEFGHIJKLMNOPQRSTUVXYZ"
    best_decrypted_text = ""
    for key in range(256):
        hex_key = format(key, '02x')
        decrypted_text = encrypt_single_byte_xor(hex_str, hex_key)
        score = sum(1 for char in hex2string(
            decrypted_text) if char in valid_characters)

        if score > sum(1 for char in best_decrypted_text if char in valid_characters):
            best_decrypted_text = hex2string(decrypted_text)

    return best_decrypted_text
