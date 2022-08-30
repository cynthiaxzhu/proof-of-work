#!/usr/bin/python3

#Cynthia Zhu
#Professor Krzyzanowski
#Computer Security (01:198:419:02)
#April 24, 2022

#Project 4, Part 2/2
#validate proof-of-work

#powv.py <summary file> <input file>

import sys
import hashlib

def get_hash(s):
    return hashlib.sha256(s).hexdigest()

def hex_to_bin(hash_hex):
    return f"{int(hash_hex, 16):0>256b}"

def count_zero_bits(hash_bin):
    i = 0
    while hash_bin[i] == '0':
        i += 1
    return i

def main():
    if len(sys.argv) < 3:
        print("Error: Too few arguments")
        sys.exit(1)
    if len(sys.argv) > 3:
        print("Error: Too many arguments")
        sys.exit(1)
    
    first_hash = ""
    try:
        with open(sys.argv[2], "rb") as input_file:
            input = input_file.read()
            first_hash = get_hash(input)
    except:
        print("Error: Input file error")
        sys.exit(1)
    
    valid = True
    
    try:
        with open(sys.argv[1], "r") as summary_file:
            first_hash_summary = ""
            pow_summary = ""
            hash_hex_summary = ""
            hash_zero_bits_summary = ""
            
            has_pow = False
            
            for line in summary_file:
                s = line.strip().lower()
                if s.startswith("first-hash:"):
                    first_hash_summary = line[(line.find(":") + 1):].strip()
                elif s.startswith("proof-of-work:"):
                    has_pow = True
                    pow_summary = line[(line.find(":") + 1):].strip()
                elif s.startswith("hash:"):
                    hash_hex_summary = line[(line.find(":") + 1):].strip()
                elif s.startswith("zero-bits:"):
                    hash_zero_bits_summary = line[(line.find(":") + 1):].strip()
            
            if not has_pow:
                print("Error: Missing proof-of-work")
                sys.exit(1)
            
            hash_hex = first_hash if pow_summary == "" else get_hash((first_hash + pow_summary).encode())
            hash_bin = hex_to_bin(hash_hex)
            hash_zero_bits = str(count_zero_bits(hash_bin))
            
            if first_hash == first_hash_summary:
                print("pass: first hash")
            else:
                valid = False
                print("fail: first hash")
                if first_hash_summary == "":
                    print("missing first hash")
                else:
                    print(f"first hash in summary file: {first_hash_summary}")
                    print(f"first hash: {first_hash}")
            
            if hash_hex == hash_hex_summary:
                print("pass: hash")
            else:
                valid = False
                print("fail: hash")
                if hash_hex_summary == "":
                    print("missing hash")
                else:
                    print(f"hash in summary file: {hash_hex_summary}")
                    print(f"hash: {hash_hex}")
            
            if hash_zero_bits == hash_zero_bits_summary:
                print("pass: zero bits")
            else:
                valid = False
                print("fail: zero bits")
                if hash_zero_bits_summary == "":
                    print("missing zero bits")
                else:
                    print(f"zero bits in summary file: {hash_zero_bits_summary}")
                    print(f"zero bits: {hash_zero_bits}")
    except SystemExit:
        sys.exit(1)
    except:
        print("Error: Summary file error")
        sys.exit(1)
    
    if valid:
        print("pass")
    else:
        print("fail")

if __name__ == "__main__":
    main()