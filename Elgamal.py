#!/usr/bin/env python
"""Elgamal.py: Implement the Elgamal cryptosystem."""

import math
import random
import cryptomath as cr

__author__ = "Raj Kane"
__version__ = "April 2017"

BLOCKSIZE = 128

def generatekeys():
    """Produces two text files containing public and private keys."""
    prime = cr.findPrime(bits=2048, tries=10000)
    coeff = random.randint(1,prime-1)
    foundxP = False
    while not foundxP:
        xP = random.randint(1,prime)
        xP_cubed = pow(xP, 3, prime)
        AxP = coeff*xP % prime
        X = xP_cubed + AxP % prime
        if pow(X, (prime-1)//2, prime) == 1:
            foundxP = True
    yP = pow(X,(prime+1)//4, prime)
    randPoint = [xP, yP]
    N = random.randint(2,prime-1)
    curve = [coeff, 0]
    Q = cr.ellipticCurveMultiplication(curve , prime, randPoint, N)

    # Write to file.
    fo = open('my_elgamal_public_key.txt', 'w')
    fo.write('%s, %s, %s, %s' % (prime, coeff, randPoint, Q))
    fo.close()
    fo = open('my_elgamal_private_key.txt', 'w')
    fo.write('%s, %s, %s, %s' % (prime, coeff, randPoint, N))
    fo.close()

def encrypt(publicKeyFilename='my_elgamal_public_key.txt', plaintextFilename='plaintext.txt'):
    """"Encrypts plaintext to ciphertext."""
    fo = open(plaintextFilename, 'r')
    plaintext = fo.read()
    fo.close()

    blocks = textToBlocks(plaintext)
    numbers = blocksToNumbers(blocks)
    fo = open(publicKeyFilename, 'r')
    content = fo.read()
    fo.close()

    prime = int(content.split(',')[0])
    coeff = int(content.split(',')[1])
    Px = content.split(',')[2].replace("[", "").replace("]", "").replace(",", "")
    Py = content.split(',')[3].replace("[", "").replace("]", "").replace(",", "")
    randPoint = [int(Px), int(Py)]
    Qx = content.split(',')[4].replace("[", "").replace("]", "").replace(",", "")
    Qy = content.split(',')[5].replace("[", "").replace("]", "").replace(",", "")
    Q = [int(Qx), int(Qy)]

    converted = []
    for n in numbers:
        nCubed = pow(n, 3, prime)
        nCoeff = coeff * n % prime
        X = nCubed + nCoeff % prime
        if pow(X, (prime - 1) // 2, prime) == 1:
            y = pow(X, (prime + 1) // 4, prime)
            converted.append([n, y])
        else:
            y = pow(-1 * X, (prime + 1) // 4, prime)
            n = prime - n
            converted.append([n, y])

    k = random.randint(2, prime - 1)
    curve = [coeff, 0]
    C1 = cr.ellipticCurveMultiplication(curve, prime, randPoint, k)
    C2List = []
    kQ = cr.ellipticCurveMultiplication(curve, prime, Q, k)
    for i in converted:
        points = [i, kQ]
        C2 = cr.ellipticCurveAddition(curve, prime, points)
        C2List.append(C2)
    ciphertext = [C1]
    for i in C2List:
        ciphertext.append(i)

    encryptedFile = open('elgamal_encrypted_message.txt', 'w')
    encryptedFile.write("%s" % (ciphertext))

def decrypt(privateKeyFilename='my_elgamal_private_key.txt',ciphertextFilename='elgamal_encrypted_message.txt'):
    """Decrypts ciphertext to plaintext."""
    fo = open(privateKeyFilename, 'r')
    privatekeycontent = fo.read()
    fo.close()

    prime = int(privatekeycontent.split(',')[0].replace("[", "").replace("]", "").replace(",", ""))
    coeff = int(privatekeycontent.split(',')[1].replace("[", "").replace("]", "").replace(",", ""))
    N = int(privatekeycontent.split(',')[4].replace("[", "").replace("]", "").replace(",", ""))
    fo = open(ciphertextFilename, 'r')
    content = fo.read()
    fo.close()

    C1x = int(content.split(',')[0].replace("[", "").replace("]", "").replace(",", ""))
    C1y = int(content.split(',')[1].replace("[", "").replace("]", "").replace(",", ""))
    C1 = [C1x, C1y]
    curve = [coeff, 0]
    NC1 = cr.ellipticCurveMultiplication(curve, prime, C1, N)
    [NC1X, NC1Y] = NC1
    negNC1 = [NC1X, -1 * NC1Y]

    convertedMessage = []
    blocks = []
    for i in range(2, len(content.split(','))):
        if i % 2 == 0:
            C2x = int(content.split(',')[i].replace("[", "").replace("]", "").replace(",", ""))
            C2y = int(content.split(',')[i + 1].replace("[", "").replace("]", "").replace(",", ""))
            C2 = [C2x, C2y]
            points = [C2, negNC1]
            ConvertedM = cr.ellipticCurveAddition(curve, prime, points)
            x = ConvertedM[0]
            if x < (prime // 2):
                x = x
            else:
                x = prime - x
            digits = base_b_digits(x, 256)
            textBlock = ''
            for d in digits:
                textBlock += chr(d)
            blocks.append(textBlock)

    plaintext = ''.join(blocks)
    fo = open('elgamal_decrypted_message.txt', 'w')
    fo.write("%s" % (plaintext))

def textToBlocks(plaintext):
    """Breaks up the plaintext into blocks."""
    textLength = len(plaintext)
    lastBlockLength = textLength % BLOCKSIZE
    fullBlocks = (textLength - lastBlockLength) // BLOCKSIZE
    blocks = []
    for i in range(fullBlocks):
        thisBlock = ''
        m = i * BLOCKSIZE
        for j in range(BLOCKSIZE):
            thisBlock += plaintext[m + j]
        blocks.append(thisBlock)
    if lastBlockLength > 0:
        lastBlock = ''
        m = fullBlocks*BLOCKSIZE
        for j in range(lastBlockLength):
            lastBlock += plaintext[m + j]
        blocks.append(lastBlock)
    return blocks

def blocksToNumbers(blockList):
    """Converts a list of text blocks into a list of numbers."""
    numbers = []
    for block in blockList:
        N = 0
        encodedBlock = list(block.encode('ascii'))
        for i in range(len(block)):
            N += encodedBlock[i] * (256 ** i)
        numbers.append(N)
    return numbers

def base_b_digits(x, b):
    """Builds a list of the base-b digits of x."""
    digits = []
    n = x
    while(n > 0):
        r = n % b
        digits.append(r)
        n = (n - r) // b
    return digits
