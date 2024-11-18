# Rules
# I give some test cases for the code, but if your code fulfills the test cases that doesn't mean the function is proper! It only helps understanding and easier development.
# The test cases can contain error, if you think so, write me on teams.
#
# For grade 2 I check only functionality (you have to complete at least the first two task), but to get grade 5, you have to have a well-commented and formatted code.
#
# You are not allowed to use external library, but you can use the solution codes from the canvas, but in your code you have to add a link where you copied from.
# You can copy from the internet as well, but you have to refer properly as well.
# You can use external library only for the task
# If I find similarity without reference, both of the exam will be graded to 0 points. Seriously, every year there are complaining about it, but there are no excuses, I can find easily similarities if you copy from the same site.
# If you are using some AI, then put the conversation share link into comment.
#
# If you have any problem/question write on teams private message.
#
# In the following you can find the skeleton of the exam.
# Fill the functions body part and submit this file.

# Implement a function that converts a 2-length string to integer (separately the two character as ascii character).
# The first character will be the most significant byte of the output integer.
# The second character will be the least significant byte.
# Check the doctest examples.
# Hint: use ord separately for the two characters of the parameter.
# Ref: https://www.geeksforgeeks.org/python-bitwise-operators/
def two_character_to_int(two_character_string):
    '''
    >>> hex(two_character_to_int('aa'))
    '0x6161'
    >>> two_character_to_int('aa')
    24929
    >>> hex(two_character_to_int('ab'))
    '0x6162'
    >>> two_character_to_int('ab')
    24930
    >>> hex(two_character_to_int('Ab'))
    '0x4162'
    >>> two_character_to_int('Ab')
    16738
    >>> hex(two_character_to_int('&v'))
    '0x2676'
    >>> hex(two_character_to_int('~ '))
    '0x7e20'
    '''

    # shifting the bits of the number 8 positions to the left
    m_significant_byte = ord(two_character_string[0]) << 8
    l_significant_byte = ord(two_character_string[1])

    #
    return m_significant_byte | l_significant_byte

# Create a function that converts an integer (that can be at most 2 byte sized),
# to ascii characters separately by bytes.
# Every byte of the input integer has to be converted to ascii separately.
# Hint: You can convert it directly by mod and div.
# Hint: You can convert to hex and use the 1,2 bytes and then the 3,4th bytes.

# Ref: https://chatgpt.com/c/670f7a58-61b4-8013-9bad-75ee718ce481


def two_byte_int_to_string(two_byte_int):
    '''
    >>> two_byte_int_to_string(0x6161)
    'aa'
    >>> two_byte_int_to_string(0x6162)
    'ab'
    >>> two_byte_int_to_string(0x4162)
    'Ab'
    >>> two_byte_int_to_string(0x2676)
    '&v'
    >>> two_byte_int_to_string(0x7e20)
    '~ '
    '''

    f_byte = two_byte_int >> 8
    s_byte = two_byte_int & 0xFF
    return chr(f_byte) + chr(s_byte)

# Implement a function that encrypts an input string by a two byte sized integer key with xor.
# In this case you have two byte blocks and encrypt all the 2 byte sized blocks by the same key.
# If the message is odd length, then pad it from the right with zero, and cut the resulting cipher to the original length.


def encpryt_xor_by_two_byte_sized_key(message, key):
    '''
    >>> encpryt_xor_by_two_byte_sized_key('abcdefghij{}',0x2020)
    'ABCDEFGHIJ[]'
    >>> encpryt_xor_by_two_byte_sized_key('ABCDEFGHIJ{}',0x2020)
    'abcdefghij[]'
    >>> encpryt_xor_by_two_byte_sized_key('ABCDEFGHIJL',0x2020)
    'abcdefghijl'
    >>> encpryt_xor_by_two_byte_sized_key('ABCDEFG',0x0101)
    '@CBEDGF'
    >>> encpryt_xor_by_two_byte_sized_key('0123456789',0x1040)
    ' q"s$u&w(y'
    '''
    result = []

    is_odd_length = len(message) % 2 != 0
    if (is_odd_length):
        message = message.ljust(len(message) + 1, '0')

    for i in range(0, len(message), 2):
        b = two_character_to_int(message[i:i+2])
        encrypted = b ^ key
        result.append(two_byte_int_to_string(encrypted))

    return ''.join(result)[:len(message) - (1 if is_odd_length else 0)]


# Create an improved version of the previous function by change the key block by block by squaring the key and modulo by 2**16.
# The first block (2 byte) will be encrypted similarly as in the previous task,
# but the second block's key will be calculated by the first block's key by squaring and modulo by 2**16 and so on.
# For example if the first block's key is 0x0002, then the second block will be encrypted by the 0x0004 key, the third by 0x0010 and so on
def encpryt_xor_by_two_byte_sized_key_changing_key(message, key):
    '''
    >>> encpryt_xor_by_two_byte_sized_key_changing_key('abcdefghij{}',0x2020) #block keys: 0x2020, 0x0400, 0x0000, 0x0000
    'ABgdefghij{}'
    >>> encpryt_xor_by_two_byte_sized_key_changing_key('ABCDEFG',0x0101) #block keys: 0x0101, 0x0201, 0x0401, 0x0801
    '@CAEAGO'
    >>> encpryt_xor_by_two_byte_sized_key_changing_key('0123456789',0x1040) # block keys: 0x1040, 0x1000, 0x0000
    ' q"3456789'
    >>> encpryt_xor_by_two_byte_sized_key_changing_key('APPLE',0x0011) # block keys: 0x0011, 0x0121, 0x4641
    'AAQm\\x03'
    >>> encpryt_xor_by_two_byte_sized_key_changing_key(encpryt_xor_by_two_byte_sized_key_changing_key('APPLE',0x0011),0x0011)
    'APPLE'
    >>> encpryt_xor_by_two_byte_sized_key_changing_key(encpryt_xor_by_two_byte_sized_key_changing_key('purple......???!!!',0x1234),0x1234)
    'purple......???!!!'
    >>> encpryt_xor_by_two_byte_sized_key_changing_key(encpryt_xor_by_two_byte_sized_key_changing_key('test: ?!136/--*+~~2+!%/=();>*#>*',0x644f),0x644f)
    'test: ?!136/--*+~~2+!%/=();>*#>*'
    '''
    result = []

    is_odd_length = len(message) % 2 != 0
    if (is_odd_length):
        message = message.ljust(len(message) + 1, '0')

    for i in range(0, len(message), 2):
        b = two_character_to_int(message[i:i+2])
        encrypted = b ^ key
        result.append(two_byte_int_to_string(encrypted))
        key = (key ** 2) % (2**16)

    return ''.join(result)[:len(message) - (1 if is_odd_length else 0)]
