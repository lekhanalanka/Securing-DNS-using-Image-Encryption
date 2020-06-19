import tkinter as tk
from tkinter import ttk,filedialog
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

max_PrimLength = 1000000000000
imagepath=""
filepath=""
filename=""

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
    outputFile = filename

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


def generatekeys():
    public_key,private_key = generate_keyPairs()
    print("Public: ",public_key)
    print("Private: ",private_key)
    with open('public.txt', 'w') as filehandle:
        filehandle.writelines("%s\n" % place for place in public_key)
    with open('private.txt', 'w') as filehandle:
        filehandle.writelines("%s\n" % place for place in private_key)
    generate.config(state="disabled")

def encrypt1(key, filename):
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
    return ctext

def getimagefile():
    global filename
    filename = tk.filedialog.askopenfilename(filetypes=[("Image Files",(".png"))])
    print(filename)
    decryptb.config(state="normal")

def getimagepath():
    global imagepath
    imagepath = tk.filedialog.askopenfilename(filetypes=[("Image Files",(".jpg"))])


def getfilename():
    global filepath
    filepath = tk.filedialog.askopenfilename(filetypes=[("Text Files",(".txt"))])

def decrypted1():
    global filename
    ctext=[]
    private_key=[]
    with open('cipher.txt', 'r') as filehandle:
        ctext= [current_place.rstrip() for current_place in filehandle.readlines()]
    with open('private.txt', 'r') as filehandle:
        private_key= [current_place.rstrip() for current_place in filehandle.readlines()]
    ctext = [int(i) for i in ctext]
    private_key = [int(i) for i in private_key]
    password= decrypt(ctext,private_key)
    print(ctext)
    decrypted(getKey(password), filename)
    crypto_steganography = CryptoSteganography('My secret password key')
    secret = crypto_steganography.retrieve('encrypted.png')
    outputentry.insert(0,secret)
    print("this is ip adress",secret)
    print("Done.")
    

def encryption():
    global imagepath,filepath
    domainname = domainentry.get()
    ip1=0
    try:
        ip1=socket.gethostbyname(domainname)
        error.config(text="Valid Address")
    except socket.gaierror:
        error.config(text="Enter Valid IP Address")
    x=ipaddress.ip_address(ip1)
    passwrd = passwordentry.get()
    #encryption starts
    # Save the encrypted file inside the image
    crypto_steganography = CryptoSteganography('My secret password key')
    crypto_steganography.hide(imagepath, 'encrypted.png', ip1)
    img=Image.open("encrypted.png")
    img.save("encrypted.png")
    #filename = input("File to encrypt: ")
    filename="encrypted.png"
    encrypt1(getKey(passwrd), filename)
    public_key=[]
    places=[]
    with open('public.txt', 'r') as filehandle:
            places = [current_place.rstrip() for current_place in filehandle.readlines()]
    public_key=[int(i) for i in places]
    ctext = encrypted(passwrd,public_key)
    comp.config(text="Cipher Text created")
    with open('cipher.txt', 'w') as filehandle:
            filehandle.writelines("%s\n" % place for place in ctext)
    encrypt.config(state="disabled")
    filenameentry.config(state="normal")


ui =tk.Tk()

tabcontrol = ttk.Notebook(ui)
tab1=ttk.Frame(tabcontrol)
tab2=ttk.Frame(tabcontrol)
tabcontrol.add(tab1,text = "Encrypt")
tabcontrol.add(tab2,text = "Decrypt")
tabcontrol.select(tab2)
tabcontrol.grid(row=0,column=0)

### TAB1 STARTS HERE ###
domain = tk.Label(tab1,text="Enter Domain")
domain.grid(row=0,column=0)
domainentry = tk.Entry(tab1)
domainentry.grid(row=0,column=1)
domainentry.focus()

error = tk.Label(tab1)
error.grid(row=1,column=1)

image = tk.Label(tab1,text="Upload Image")
image.grid(row=2,column=0)

button1 = tk.Button(tab1,text="Browse Image")
button1.grid(row=2,column=1)
button1.config(command=getimagepath)

password = tk.Label(tab1,text="Enter Password")
password.grid(row=3,column=0)
passwordentry = tk.Entry(tab1)
passwordentry.grid(row=3,column=1)

publickey = tk.Label(tab1,text="Upload Public Key")
publickey.grid(row=4,column=0)

button2 = tk.Button(tab1,text="Browse File")
button2.grid(row=4,column=1)
button2.config(command=getfilename)

encrypt = tk.Button(tab1,text="Encrypt")
encrypt.grid(row=6,column=1)
encrypt.config(command=encryption)

comp = tk.Label(tab1)
comp.grid(row=5,column=1)

### TAB2 STARTS HERE ###

generate = tk.Button(tab2,text="Generate Keys")
generate.grid(row=0,column=0)
generate.config(command=generatekeys)

filename=tk.Label(tab2,text="Enter Filename")
filename.grid(row=1,column=0)
filenameentry = tk.Button(tab2,text="Browse Image")
filenameentry.grid(row=1,column=1)
filenameentry.config(command=getimagefile,state="disabled")

output = tk.Label(tab2,text="IP Address")
output.grid(row=3,column=0)
outputentry = tk.Entry(tab2)
outputentry.grid(row=3,column=1)

decryptb = tk.Button(tab2,text="Decrypt")
decryptb.grid(row=2,column=1)
decryptb.config(state="disabled",command=decrypted1)

### TAB2 ENDS HERE ###
ui.mainloop()
