
import hashlib as letshash
import uuid as random
import os

class Hash(object):

    def __init__(self,hash=" "):
        self.hash = hash

    def md5hash(self, helloSexy):
        
        self.hash = letshash.md5(helloSexy.encode())
        return self.hash.hexdigest()

    def md5Salt(self,helloSexy): 

        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self. hash = letshash.md5(salt.encode() + helloSexy.encode()).hexdigest() + ":" + salt
        return self.hash

    def sha1(self,helloSexy): 
        self.hash = letshash.sha1(helloSexy.encode())
        return self.hash.hexdigest()

    def sha1Salt(self,helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifyin the salt at the end
        self.hash = letshash.sha1( helloSexy.encode()).hexdigest() + salt.encode() + ":" + salt
        return self.hash

    def sha224(self,helloSexy): 
        self.hash = letshash.sha224(helloSexy.encode())
        return self.hash.hexdigest()

    def sha224Salt(self, helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self.hash = letshash.sha224(salt.encode() + helloSexy.encode()).hexdigest() + ":" +salt
        return self.hash.hexdigest()

    def sha256(self,helloSexy): 
        self.hash = letshash.sha256(helloSexy.encode())
        return self.hash.hexdigest()

    def sha256Salt(self, helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self.hash = letshash.sha256(salt.encode() + helloSexy.encode()).hexdigest() + ":" +salt
        return self.hash.hexdigest()

    def sha384(self,helloSexy):
        self.hash = letshash.sha384(helloSexy.encode())
        return self.hash.hexdigest()
    
    def sha384Salt(self, helloSexy): 
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self.hash = letshash.sha384(salt.encode() + helloSexy.encode()).hexdigest() + ":" +salt
        return self.hash.hexdigest()

    def sha512(self,helloSexy): 
        self.hash = letshash.sha512(helloSexy.encode())
        return self.hash.hexdigest()

    def sha512Salt(self, helloSexy):
        salt = random.uuid4().hex
        #Returns the hash specifying the salt at the end
        self.hash = letshash.sha512(salt.encode() + helloSexy.encode()).hexdigest() + ":" +salt
        return self.hash.hexdigest()

def hash():
    lol = Hash()
    hash = input("What type of hash do you want?\n(MD5, SHA1, SHA224, SHA256, SHA384, SHA512)\n")

    if hash == "md5" or hash =="MD5" or hash =="mD5" or hash == "Md5":
        salt = (input("Salt or not? Yes or No\n"))

        if salt != "no" or salt != "NO" or salt != "No":
            value = input("Enter password: ")
            hashed = lol.md5Salt(value)
            print("Password is: ", hashed)
        else:
            value = input("Enter password: ")
            hashed = lol.md5hash(value)
            print("Password is:", hashed)
    
    if hash == "sha1" or hash == "SHA1":
        salt = (input("Salt or not? Yes or No\n"))

        if salt != "no" or salt != "NO" or salt != "No":
            value = input("Enter password: ")
            hashed = lol.sha1Salt(value)
            print("Password is: ", hashed)
        else:
            value = input("Enter password: ")
            hashed = lol.sha1(value)
            print("Password is:",hashed)

    if hash == "sha224" or hash == "SHA224":
        salt = (input("Salt or not? Yes or No\n"))

        if salt != "no" or salt != "NO" or salt != "No":
            value = input("Enter password: ")
            hashed = lol.sha224Salt(value)
            print("Password is: ", hashed)
        else:
            value = input("Enter password: ")
            hashed = lol.sha224(value)
            print("Password is:",hashed)

    if hash == "sha256" or hash == "SHA256":
        salt = (input("Salt or not? Yes or No\n"))

        if salt != "no" or salt != "NO" or salt != "No":
            value = input("Enter password: ")
            hashed = lol.sha256Salt(value)
            print("Password is: ", hashed)
        else:
            value = input("Enter password: ")
            hashed = lol.sha256(value)
            print("Password is:",hashed)
    if hash == "sha384" or hash == "SHA384":
        salt = (input("Salt or not? Yes or No\n"))

        if salt != "no" or salt != "NO" or salt != "No":
            value = input("Enter password: ")
            hashed = lol.sha384Salt(value)
            print("Password is: ", hashed)
        else:
            value = input("Enter password: ")
            hashed = lol.sha384(value)
            print("Password is:",hashed)
    if hash == "sha512" or hash == "SHA512":
        salt = (input("Salt or not? Yes or No\n"))

        if salt != "no" or salt != "NO" or salt != "No":
            value = input("Enter password: ")
            hashed = lol.sha512Salt(value)
            print("Password is: ", hashed)
        else:
            value = input("Enter password: ")
            hashed = lol.sha512(value)
            print("Password is:",hashed)



    

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


def main():
    os.system('clear')

    test = input("Wanna try hashing a word? Yes or No \n")
    while True:
        if test == "no" or test == "No" or test == "N" or test =="NO":
            break

        else:
            hash()
            test = input(("\nHash Again?"))
    
    playGame()






if __name__ == "__main__":
    main()


