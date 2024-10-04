def hex2bin(x):
    '''
    >>> hex2bin('f')
    '1111'
    >>> hex2bin('5')
    '101'
    >>> hex2bin('1')
    '1'
    '''
    return bin(int(x, base=16))[2:]


def bin2hex(bin_text):
    '''
    >>> bin2hex('1111')
    'f'
    >>> bin2hex('100001')
    '21'
    >>> bin2hex('1')
    '1'
    '''
    return hex(int(bin_text, base=2))[2:]


def fillupbyte(bin_text):
    '''
    >>> fillupbyte('011')
    '00000011'
    >>> fillupbyte('1')
    '00000001'
    >>> fillupbyte('10111')
    '00010111'
    >>> fillupbyte('11100111')
    '11100111'
    >>> fillupbyte('111001111')
    '0000000111001111'
    '''
    l = len(bin_text)
    if (l > 8):
        return bin_text.zfill(l + (8 - abs(l - 8)))

    return bin_text.zfill(8)


def int2base64(hex_numb):
    '''
    >>> int2base64(0x61)
    'YQ=='
    >>> int2base64(0x78)
    'eA=='
    '''
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    base64_str = ''
    bin_str = bin(hex_numb)[2:]
    padding_bits = (8 - len(bin_str) % 8) % 8
    bin_str = bin_str.zfill(len(bin_str) + padding_bits)
    padding_bits = (6 - len(bin_str) % 6) % 6
    bin_str = bin_str.ljust(len(bin_str) + padding_bits, '0')

    for i in range(0, len(bin_str), 6):
        base64_str += base64_chars[int(bin_str[i: i + 6], 2)]

    base64_str = base64_str.ljust((len(base64_str) + 3) // 4 * 4, '=')
    return base64_str


def hex2base64(hex_str):
    '''
    >>> hex2base64('61')
    'YQ=='
    >>> hex2base64('123456789abcde')
    'EjRWeJq83g=='
    '''
    return int2base64(int(hex_str, 16))
