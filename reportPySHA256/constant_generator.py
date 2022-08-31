import math

# Sieves through a range of integers up to the input n. Sieved Integers are stored in their respective list
def eratosthenesSieve(k : int):    
    n = k
    p = 2                                   # first prime constant value
    primes=[]                               # list to hold generated primes
    primesBuffer = []                       # list to hold non-primes
    for i in range(p,n+1):                  # iterate through the range starting at p and ending at n+1
        if i not in primesBuffer:           # primesBuffer is empty so 2 will always be the first prime inserted
            primes.append(i)                # insert prime value i
            for j in range(i**2,n,i):       # for index j, take prime i and square it until the last value is reached. then increment i (begins at 2)
               primesBuffer.append(j)       # append all squares of primes to buffer. this removes them from the pool of potential primes.
    del primesBuffer                        # delete non-prime values
    return primes                           # return list of prime values

def cbrt(x : int):
    x = abs(x)
    cubeRoot = x**(1/3)
    return cubeRoot


def initHashValues():
    primes = eratosthenesSieve(19)          # first eight primes {2,3,5,7,11,13,17,19}
    hashValues = []                         # list to hold hash values
    x = len(primes)                         # number of list members
    for i in range(x):
        p = math.sqrt(primes[i])            # take the square root of prime at index i
        while(p >= 1):                      
            p -= 1                          # remove non-fractional values
        p = p*pow(2,32)                     # multiply fractional value by 32-bits (2^32)
        hashValues.append(hex(int(p)))      # store result as hexadecimal in list
        i += 1                              # increment index i
    return hashValues                       # return hashed results                          
    

def initkConstants():
    primes = eratosthenesSieve(311)         # first 64 prime numbers { 2, ... 311 }
    kConstants = []
    x = len(primes)
    for i in range(x):
        p = cbrt(primes[i])
        while(p >= 1):
            p -= 1
        p = p*pow(2,32)
        kConstants.append((int(p)))
        i += 1
    return kConstants
