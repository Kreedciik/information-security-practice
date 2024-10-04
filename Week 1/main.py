def bound_value(value, minimum_value=0, maximum_value=100):
    '''
    >>> bound_value(12)
    12
    >>> bound_value(-2)
    0
    >>> bound_value(111)
    100
    >>> bound_value(0)
    0
    >>> bound_value(1)
    1
    >>> bound_value(99)
    99
    >>> bound_value(199, maximum_value=200)
    199
    >>> bound_value(199, minimum_value=100)
    100
    >>> bound_value(-100, minimum_value=100)
    100
    >>> bound_value(100, minimum_value=100)
    100
    >>> bound_value(100, 1, 4)
    4
    >>> bound_value(-1, 2, 4)
    2
    >>> bound_value(3011, 2, 4)
    4
    '''
    if (value >= minimum_value and value <= maximum_value):
        return value
    if (value < minimum_value):
        return minimum_value
    return maximum_value
