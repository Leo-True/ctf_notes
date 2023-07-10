import hashlib
from itertools import product

known_message = bytes.fromhex('497625a6d2')
known_hash = '520dc1cebc492b91dcc96787a791c182328d54adb63afef73c485e93f714627a'


def calculate_hash(message):
    return hashlib.sha256(message).hexdigest()


def bruteforce():
    # 3字节的所有可能性，每个字节可以是0-255之间的任何值
    for i in product(range(256), repeat=3):
        guess = known_message + bytes(i)
        if calculate_hash(guess) == known_hash:
            return guess


result = bruteforce()
print(result.hex())
