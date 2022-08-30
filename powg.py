#!/usr/bin/python3

#Cynthia Zhu
#Professor Krzyzanowski
#Computer Security (01:198:419:02)
#April 24, 2022

#Project 4, Part 1/2
#generate proof-of-work

#powg.py <number of zero bits> <input file>

import sys
import time
import hashlib
from collections import deque

n = -1

def get_hash(s):
    return hashlib.sha256(s).hexdigest()

#method 1
def get_permutations(pow):
    list = [pow + chr(33)]
    for i in range(35, 127):
        list.append(pow + chr(i))
    return list

#method 2
def get_next_pow(pow):
    next_pow_array = list(pow)
    i = len(next_pow_array) - 1
    while next_pow_array[i] == chr(126):
        next_pow_array[i] = chr(35)
        i -= 1
    if i == -1:
        next_pow_array.insert(0, chr(34))
        i = 0
    next_pow_array[i] = chr(ord(next_pow_array[i]) + 1)
    return "".join(next_pow_array)

def hex_to_bin(hash_hex):
    return f"{int(hash_hex, 16):0>256b}"

def count_zero_bits(hash_bin):
    i = 0
    while hash_bin[i] == '0':
        i += 1
    return i

def is_valid_hash(hash_hex):
    global n
    hash_bin = hex_to_bin(hash_hex)
    if count_zero_bits(hash_bin) >= n:
        return True
    else:
        return False

def main():
    global n
    
    if len(sys.argv) < 3:
        print("Error: Too few arguments")
        sys.exit(1)
    if len(sys.argv) > 3:
        print("Error: Too many arguments")
        sys.exit(1)
    
    try:
        n = int(sys.argv[1])
        if not 0 <= n <= 256:
            print("Error: Invalid number of zero bits")
            sys.exit(1)
    except SystemExit:
        sys.exit(1)
    except:
        print("Error: Invalid number of zero bits")
        sys.exit(1)
    
    input_file_name = sys.argv[2]
    first_hash = ""
    try:
        with open(input_file_name, "rb") as input_file:
            input = input_file.read()
            first_hash = get_hash(input)
    except:
        print("Error: Input file error")
        sys.exit(1)
    
    pow = ""
    hash_hex = first_hash
    i = 0
    
    #method 1
    begin = time.time()
    primary = deque(get_permutations(pow))
    secondary = deque()
    while not is_valid_hash(hash_hex):
        pow = primary.popleft()
        secondary.append(pow)
        if not primary:
            primary.extend(get_permutations(secondary.popleft()))
        hash_hex = get_hash((first_hash + pow).encode())
        i += 1
    end = time.time()
    
    #method 2
    begin = time.time()
    if not is_valid_hash(hash_hex):
        pow = chr(34)
        while not is_valid_hash(hash_hex):
            pow = get_next_pow(pow)
            hash_hex = get_hash((first_hash + pow).encode())
            i += 1
    end = time.time()
    
    running_time = end - begin
    
    hash_bin = hex_to_bin(hash_hex)
    hash_zero_bits = count_zero_bits(hash_bin)
    
    print(f"input-file: {input_file_name}")
    print(f"first-hash: {first_hash}")
    print(f"proof-of-work: {pow}")
    print(f"hash: {hash_hex}")
    print(f"zero-bits: {hash_zero_bits}")
    print(f"iterations: {i}")
    print(f"running-time: {running_time}")

if __name__ == "__main__":
    main()