import sys
import ipaddress
import re
import socket
from cryptosteganography import CryptoSteganography
from PIL import Image
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import random

#addr = '127.0.0.2561'
max_PrimLength = 1000000000000


regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
      
# Define a function for 
# validate an Ip addess 
def check(Ip):
    
    # pass the regular expression 
    # and the string in search() method 
    if(re.search(regex, Ip)):  
        print("Valid Ip address")
        return 1
          
    else:  
        print("Invalid Ip address")
        return 0


#encryption
    
def encrypt(key, filename):
    chunksize = 64 * 1024
    outputFile = "(encrypted)" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


def encrypted(text,public_key):
    key,n = public_key
    ctext = [pow(ord(char),key,n) for char in text]
    print(ctext)
    return ctext
  
  
if __name__ == '__main__' :  
      
    # Enter the Ip address 
    hname=input()
    
    ip1=socket.gethostbyname(hname)
    print('host name is:'+ip1)
      
    # calling run function
    
    x=ipaddress.ip_address(ip1)
    if(check(ip1)==1 and x.version==4):
       print("it is ipv4 address")

    else:
        print("please enter a valid ip address")
    crypto_steganography = CryptoSteganography('My secret password key')

    input_image=input("Enter image path: ")
# Save the encrypted file inside the image
    crypto_steganography.hide(input_image, 'encrypted.png', ip1)

    img=Image.open("encrypted.png")
    img.save("encrypted.png")
#filename = input("File to encrypt: ")
    filename="encrypted.png"
    password = input("Password: ")
    encrypt(getKey(password), filename)
    public_key=[]
    places=[]
    with open('public.txt', 'r') as filehandle:
            places = [current_place.rstrip() for current_place in filehandle.readlines()]
    public_key=[int(i) for i in places]
    ctext = encrypted(password,public_key)
    print("encrypted  =",ctext)
    with open('cipher.txt', 'w') as filehandle:
            filehandle.writelines("%s\n" % place for place in ctext)





