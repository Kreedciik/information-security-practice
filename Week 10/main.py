# PC-1 table for DES
PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63,
       55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

# PC-2 table for DES
PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def left_shift(bits, shifts):
    return bits[shifts:] + bits[:shifts]


def permute(bits, table):
    return [bits[i-1] for i in table]


def bytes2binary(byte_arr: bytes):
    '''
    >>> bytes2binary(b'\\x01')
    '00000001'
    >>> bytes2binary(b'\\x03')
    '00000011'
    >>> bytes2binary(b'\\xf0')
    '11110000'
    >>> bytes2binary(b'\\xf0\\x80')
    '1111000010000000'
    '''
    decoded_bytes = bytes(byte_arr.decode('unicode_escape'), 'latin1')
    return ''.join(f'{byte:08b}' for byte in decoded_bytes)


def binary2bytes(bin_string):
    '''
    >>> binary2bytes('00000001')
    b'\\x01'
    >>> binary2bytes('00000011')
    b'\\x03'
    >>> binary2bytes('11110000')
    b'\\xf0'
    >>> binary2bytes('1111000010000000')
    b'\\xf0\\x80'
    '''
    return bytes(int(bin_string[i:i+8], 2) for i in range(0, len(bin_string), 8))


def bin_xor(bin_str_1, bin_str_2):
    '''
    >>> bin_xor('1011','0000')
    '1011'
    >>> bin_xor('1','0000')
    '0001'
    >>> bin_xor('1101','1011')
    '0110'
    >>> bin_xor('10101010','01010101')
    '11111111'
    '''
    max_length = max(len(bin_str_1), len(bin_str_2))
    binary1_padded = bin_str_1.rjust(max_length, '0')
    binary2_padded = bin_str_2.rjust(max_length, '0')
    return ''.join('1' if binary1_padded[i] != binary2_padded[i] else '0' for i in range(max_length))

    '''
    >>> create_DES_subkeys('0001001100110100010101110111100110011011101111001101111111110001')
    ['000110110000001011101111111111000111000001110010', '011110011010111011011001110110111100100111100101', '010101011111110010001010010000101100111110011001', '011100101010110111010110110110110011010100011101', '011111001110110000000111111010110101001110101000', '011000111010010100111110010100000111101100101111', '111011001000010010110111111101100001100010111100', '111101111000101000111010110000010011101111111011',
        '111000001101101111101011111011011110011110000001', '101100011111001101000111101110100100011001001111', '001000010101111111010011110111101101001110000110', '011101010111000111110101100101000110011111101001', '100101111100010111010001111110101011101001000001', '010111110100001110110111111100101110011100111010', '101111111001000110001101001111010011111100001010', '110010110011110110001011000011100001011111110101']
    '''
    key = [int(k) for k in key]
    key1 = permute(key, PC1)

    left_half = key1[:28]
    right_half = key1[28:]

    sub_keys = []
    for _, shift_count in enumerate(SHIFTS):
        left_half = left_shift(left_half, shift_count)
        right_half = left_shift(right_half, shift_count)

        combined_half = left_half + right_half
        sub_key = permute(combined_half, PC2)
        sub_keys.append(''.join(map(str, sub_key)))

    return sub_keys


def create_DES_subkeys(text):
    """
    >>> create_DES_subkeys('0001001100110100010101110111100110011011101111001101111111110001')
    ['000110110000001011101111111111000111000001110010', '011110011010111011011001110110111100100111100101', '010101011111110010001010010000101100111110011001', '011100101010110111010110110110110011010100011101', '011111001110110000000111111010110101001110101000', '011000111010010100111110010100000111101100101111', '111011001000010010110111111101100001100010111100', '111101111000101000111010110000010011101111111011', '111000001101101111101011111011011110011110000001', '101100011111001101000111101110100100011001001111', '001000010101111111010011110111101101001110000110', '011101010111000111110101100101000110011111101001', '100101111100010111010001111110101011101001000001', '010111110100001110110111111100101110011100111010', '101111111001000110001101001111010011111100001010', '110010110011110110001011000011100001011111110101']
    """
    permuted = permute(text, PC1)
    left, right = permuted[:int(len(PC1)/2)], permuted[int(len(PC1)/2):]
    sub_keys = []

    for shifts in SHIFTS:
        left = left[shifts:] + left[:shifts]
        right = right[shifts:] + right[:shifts]
        sub_key = [(left+right)[i - 1] for i in PC2]
        sub_keys.append(("".join(sub_key)))

    return sub_keys


def encrypt_DES(key, message):
    """
    >>> encrypt_DES(b'\\x13\\x34\\x57\\x79\\x9b\\xbc\\xdf\\xf1',b'\\x01\\x23\\x45\\x67\\x89\\xab\\xcd\\xef')
    b'\\x85\\xe8\\x13T\\x0f\\n\\xb4\\x05'
    """
    message = bytes2binary(message)
    key = bytes2binary(key)

    permuted_block = ''.join([message[i - 1] for i in IP])
    L, R = permuted_block[:32], permuted_block[32:]

    subkeys = create_DES_subkeys(key)

    for i in range(16):
        L_new = R
        R_new = bin_xor(L, f(R, subkeys[i]))
        L, R = L_new, R_new

    combined = R + L

    ciphertext = ''.join([combined[i - 1] for i in IP_inverse])
    return binary2bytes(ciphertext)
