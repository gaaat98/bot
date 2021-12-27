#!/usr/bin/env python3
from random import randbytes
from hashlib import sha256
from binascii import hexlify


def main():
    user = input("Insert username: ")
    pw = input("Insert password: ")

    salt = hexlify(randbytes(4))
    h = sha256(salt+pw.encode()).hexdigest().encode()

    hh = salt + b'$' + h
    print("Insert this in USERS: ")
    print(f"'{user}': {hh}")


if __name__ == "__main__":
    main()