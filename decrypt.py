import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from cryptosteganography import CryptoSteganography
from PIL import Image

import random                                                           
max_PrimLength = 1000000000000


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generateRandomPrim():
    while(1):
        ranPrime = random.randint(0,max_PrimLength)
        if is_prime(ranPrime):
            return ranPrime

def generate_keyPairs():
    p = generateRandomPrim()
    q = generateRandomPrim()
    
    n = p*q
    '''phi(n) = phi(p)*phi(q)'''
    phi = (p-1) * (q-1) 
    
    '''choose e coprime to n and 1 > e > phi'''    
    e = random.randint(1, phi)
    g = gcd(e,phi)
    while g != 1:
        e = random.randint(1, phi)
        g = gcd(e, phi)
        
    print("e=",e," ","phi=",phi)
    '''d[1] = modular inverse of e and phi'''
    d = egcd(e, phi)[1]
    
    '''make sure d is positive'''
    d = d % phi
    if(d < 0):
        d += phi
        
    return ([e,n],[d,n])
def decrypt(ctext,private_key):
    try:
        key,n = private_key
        text = [chr(pow(char,key,n)) for char in ctext]
        return "".join(text)
    except TypeError as e:
        print(e)


def decrypted(key, filename):
    chunksize = 64 * 1024
    outputFile = filename[11:]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

def Main():
        a=int(input("Enter choice "))
        if(a==1):
            public_key,private_key = generate_keyPairs()
            print("Public: ",public_key)
            print("Private: ",private_key)
            with open('public.txt', 'w') as filehandle:
                filehandle.writelines("%s\n" % place for place in public_key)
            with open('private.txt', 'w') as filehandle:
                filehandle.writelines("%s\n" % place for place in private_key)
        elif(a==2):
            ctext=[]
            private_key=[]
            with open('cipher.txt', 'r') as filehandle:
                ctext= [current_place.rstrip() for current_place in filehandle.readlines()]
            with open('private.txt', 'r') as filehandle:
                private_key= [current_place.rstrip() for current_place in filehandle.readlines()]
            ctext = [int(i) for i in ctext]
            private_key = [int(i) for i in private_key]
            password= decrypt(ctext,private_key)
                
            filename = input("File to decrypt: ")
            
            print(ctext)
            decrypted(getKey(password), filename)
            crypto_steganography = CryptoSteganography('My secret password key')
            secret = crypto_steganography.retrieve('encrypted.png')
            print("this is ip adress",secret)
            print("Done.")
if __name__ == '__main__':
    Main()
