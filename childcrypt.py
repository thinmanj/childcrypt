
# Just for testing
key = "123456789"
keySize = len(key)
letters = '''qrstuvwxyz .,:;-'"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,:;-'"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,:;-'"'''
cletters = '''123456789012345678abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,:;-'"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,:;-'"'''

test_text = "An example of text, for a simple crypt function 'childcrypt'."
test_encrypted = '''Bp;aE:Bhxm;llYzeHlc inyZh Bnumsia:zusucbCpklytrYcdngzdepGnB"g'''

# Cryptor definitio0ns
def add(data, key, ised=0):
    return letters[cletters.index(data)+key+ised]

def sub(data, key, ised=0):
    return letters[cletters.index(data)-key+ised]

operators = [add, sub]
operatorSize = len(operators)

def crypt(data, ised=0):
    result = []
    for i, a in enumerate(data):
        result.append(operators[i%operatorSize](a, int(key[i%keySize]), ised))
        ised = cletters.index(a)%10
    return "".join(result)

def decrypt(data, ised=0):
    result = []
    for i, a in enumerate(data):
        b = operators[(i+1)%operatorSize](a, int(key[i%keySize]), ised)
        result.append(b)
        ised = -(cletters.index(b)%10)
    return "".join(result)

if __name__ == '__main__':
    #Test the working of
    test = crypt(test_text, 0)
    print test
    print decrypt(test, 0)
