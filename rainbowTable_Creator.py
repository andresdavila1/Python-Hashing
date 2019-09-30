
import hashlib as letshash
import uuid as random
import os
import sys

class Hash(object):

    def __init__(self,hash=" "):
        self.hash = hash

    def md5hash(self, helloSexy):
        self.hash = letshash.md5(helloSexy.encode())
        return self.hash.hexdigest()

    def md5Salt(self,helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self. hash = (letshash.md5(salt.encode() + helloSexy.encode()).hexdigest()) + " : " + salt
        return self.hash

    def sha1(self,helloSexy): 
        self.hash = letshash.sha1(helloSexy.encode())
        return self.hash.hexdigest()

    def sha1Salt(self,helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifyin the salt at the end
        self. hash = (letshash.sha1(salt.encode() + helloSexy.encode()).hexdigest()) + " : " + salt
        return self.hash

    def sha224(self,helloSexy): 
        self.hash = letshash.sha224(helloSexy.encode())
        return self.hash.hexdigest()

    def sha224Salt(self, helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self. hash = (letshash.sha224(salt.encode() + helloSexy.encode()).hexdigest()) + " : " + salt
        return self.hash

    def sha256(self,helloSexy): 
        self.hash = letshash.sha256(helloSexy.encode())
        return self.hash.hexdigest()

    def sha256Salt(self, helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self. hash = (letshash.sha256(salt.encode() + helloSexy.encode()).hexdigest()) + " : " + salt
        return self.hash

    def sha384(self,helloSexy):
        self.hash = letshash.sha384(helloSexy.encode())
        return self.hash.hexdigest()
    
    def sha384Salt(self, helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self. hash = (letshash.sha384(salt.encode() + helloSexy.encode()).hexdigest()) + " : " + salt
        return self.hash

    def sha512(self,helloSexy): 
        self.hash = letshash.sha512(helloSexy.encode())
        return self.hash.hexdigest()

    def sha512Salt(self, helloSexy):
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self. hash = (letshash.sha512(salt.encode() + helloSexy.encode()).hexdigest()) + " : " + salt
        return self.hash

def hash():
    lol = Hash()

    file = open(sys.argv[1],  encoding = "ISO-8859-1")
    print("Hashing MD5, SHA1, SHA224, SHA256, SHA384, SHA512...\n")

    for line in file:
        line = line.split("\n")

        MD5 = lol.md5hash(line[0])
        SHA1 = lol.sha1(line[0])
        SHA224 = lol.sha224(line[0])
        SHA256 = lol.sha256(line[0])
        SHA384 = lol.sha384(line[0])
        SHA512 = lol.sha512(line[0])
        print(MD5 + " : " + SHA1 + " : " + SHA224 + " : " + SHA256 + " : " + SHA384 + " : " + SHA512 + " : " + line[0])
        
    


 




'''

def playGame():

    yes = input("Wanna play a game?\n")

    if yes == 'no' or yes == 'NO' or yes == 'n':
        return 0
    else:
        os.system("clear")
        password = input("Enter a password to be cracked against the rockyou word list: ")
        style = input("MD5 or SHA256?\n")

        if style == 'MD5' or style == 'md5':
            hash = letshash.md5(password.encode())
            hashhex = hash.hexdigest()

            file = open('rockyou.txt')

            for line in file:
                line = line.split("\n")
                rockyou = letshash.md5(line[0].encode())
                rockyouhex = rockyou.hexdigest()
                print(hashhex,rockyouhex)
                if rockyouhex == hashhex:
                    print("Password:", password)
                    print("Hash: ", rockyouhex)
                    break




        elif style == 'SHA256' or style == 'sha256':
            hash = letshash.sha256(password.encode())
            hashhex = hash.hexdigest()

            file = open('rockyou.txt')

            for line in file:
                line = line.split("\n")
                rockyou = letshash.sha256(line[0].encode())
                rockyouhex = rockyou.hexdigest()
                print(hashhex,rockyouhex)
                if rockyouhex == hashhex:
                    print("\n\nPassword:", password)
                    print("Hash: ", rockyouhex)
                    break
'''

def main():

    os.system('clear')
    print("MD5 : SHA1 : SHA224 : SHA256 : SHA384 : SHA512 : plaintext")
    hash()




if __name__ == "__main__":
    main()


