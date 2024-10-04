def test_function(int_arr):
    '''
    >>> test_function([88, 85, 84, 71, 66, 72, 65, 82, 74, 70, 87, 70, 85, 68, 74, 84, 81, 87, 79, 82])
    'tgbharjftgbharjf'
    >>> test_function([84, 81, 67, 82, 66, 84, 67, 83, 87, 89, 72, 74, 74, 84, 78, 65, 72, 67, 72, 71])
    'crbtcswycrbtcswy'
    >>> test_function([84, 67, 90, 84, 72, 73, 65, 65, 73, 69, 68, 66, 77, 65, 89, 69, 85, 70, 70, 82])
    'zthiaaiezthiaaie'
    >>> test_function([85, 73, 85, 72, 88, 72, 76, 89, 68, 78, 75, 69, 78, 74, 83, 66, 75, 80, 75, 82])
    'uhxhlydnuhxhlydn'
    >>> test_function([77, 71, 86, 84, 87, 86, 77, 88, 71, 88, 69, 72, 68, 69, 83, 86, 68, 83, 88, 69])
    'vtwvmxgxvtwvmxgx'
    '''
    chars = [chr(numb) for numb in int_arr]
    s = "".join(chars).lower()
    return s[2:10] * 2
