import hashlib
from itertools import product


def sha256(text):
    '''
    >>> sha256('I')
    'a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c'
    >>> sha256('love')
    '686f746a95b6f836d7d70567c302c3f9ebb5ee0def3d1220ee9d4e9f34f5e131'
    >>> sha256('crypto')
    'da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4'
    '''
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def authenticate(user_name, password):
    '''
    >>> authenticate('admin','admin')
    True
    >>> authenticate('admin','admin2')
    False
    >>> authenticate('user','hello')
    True
    >>> authenticate('user','helo')
    False
    '''
    user = {
        # sha256('admin')
        'admin': '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',
        # sha256('hello')
        'user': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    }
    return user.get(user_name) == sha256(password)


def hack_sha256_fixed_size(hash, fixed_length):
    '''
    >>> hack_sha256_fixed_size('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918',5)
    'admin'
    >>> hack_sha256_fixed_size('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',5)
    'hello'
    >>> hack_sha256_fixed_size('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b',5)
    'crypt'
    >>> hack_sha256_fixed_size('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6',3)
    'asd'
    >>> hack_sha256_fixed_size('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214',4)
    'elte'
    '''
    chars = 'abcdefghijklmnopqrstuvxyz'

    for combo in product(chars, repeat=fixed_length):
        candidate = "".join(combo)
        if hash == sha256(candidate):
            return candidate

    return None


def hack_sha256(hash):
    '''
    >>> hack_sha256('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918')
    'admin'
    >>> hack_sha256('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    'hello'
    >>> hack_sha256('a819d7cd38e9101be2e496298e8bf426ce9cdf78d2af35ddf44c6ad25d50158b')
    'crypt'
    >>> hack_sha256('688787d8ff144c502c7f5cffaafe2cc588d86079f9de88304c26b0cb99ce91c6')
    'asd'
    >>> hack_sha256('7ec658e98073955c48314d0146593497a163d79f4e1dfea4bab03b79af227214')
    'elte'
    '''
    iterations = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    for i in iterations:
        candidate = hack_sha256_fixed_size(hash, i)
        if candidate:
            return candidate


def authenticate_with_pepper(user_name, password):
    '''
    >>> authenticate_with_pepper('admin','admin')
    True
    >>> authenticate_with_pepper('admin','admin2')
    False
    >>> authenticate_with_pepper('user','hello')
    True
    >>> authenticate_with_pepper('user','helo')
    False
    '''
    pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
    users_with_pepper = {
        # sha256('this_can_help_to_confuse_the_attacker_admin')
        'admin': {'passwordHash': '89e6b5ed137e3864d99ec9b421cf6f565d611f4c2b98e31a7d353d63aa748e9c'},
        # sha256('this_can_help_to_confuse_the_attacker_hello')
        'user': {'passwordHash': '6dc765830e675d5fa4a9afb248be09a0407f6353d44652fd9b36038884a76323'},
    }

    password_hash = sha256(pepper_prefix + password)
    return users_with_pepper[user_name]['passwordHash'] == password_hash


def authenticate_with_pepper_and_salt(user_name, password):
    '''
    >>> authenticate_with_pepper_and_salt('admin','admin')
    True
    >>> authenticate_with_pepper_and_salt('admin','admin2')
    False
    >>> authenticate_with_pepper_and_salt('user','hello')
    True
    >>> authenticate_with_pepper_and_salt('user','helo')
    False
    '''
    pepper_prefix = 'this_can_help_to_confuse_the_attacker_'
    users_with_pepper_and_salt = {
        # sha256('this_can_help_to_confuse_the_attacker_admin5294976873732394418')
        'admin': {'passwordHash': 'd3eab7f4d6974f1db32b9cd9923fce9b434b28dc229b6582b845f1fca770d9f7', 'salt': "5294976873732394418"},
        # sha256('this_can_help_to_confuse_the_attacker_hello1103733363818826232')
        'user': {'passwordHash': '976c73e0b408c89df3c1a12c3b0c45a6fee71bc1de5b47a88fae1a5e69ba6e28', 'salt': '1103733363818826232'},
    }
    password_hash = sha256(
        pepper_prefix + password + users_with_pepper_and_salt[user_name]['salt'])
    return users_with_pepper_and_salt[user_name]['passwordHash'] == password_hash
