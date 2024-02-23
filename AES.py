# Homework Number: 4
# Name: Parthiv Patel
# ECN Login: pate1459
# Due Date: 2-13
# Code used from Avinash Kak Lecture 8

import sys
from BitVector import *

class AES():
# class constructor - when creating an AES object , the# class ’s constructor is executed and instance variables# are initialized
    def __init__(self , keyfile:str) -> None:
        self.AES_modulus = BitVector(bitstring='100011011')
        self.keyfile = keyfile 
# encrypt - method performs AES encryption on the plaintext and writes the ciphertext to disk
# Inputs: plaintext (str) - filename containing plaintext
# ciphertext (str) - filename containing ciphertext
# Return: void
        
    def encrypt(self , plaintext:str , ciphertext:str) -> None:
        bv = BitVector(filename = plaintext)
        f = open(ciphertext, "w")
        key_words, round_keys = self.gen_key_sched()
        byte_sub_table = self.gen_subbytes_table()
        while (bv.more_to_read):
            bitvec = bv.read_bits_from_file(128)
            if bitvec.length() < 128:
                bitvec.pad_from_right(128 - bitvec.length())
            statearray = [[0 for x in range(4)] for x in range(4)]
            for i in range(4):
                for j in range(4):
                    statearray[i][j] = bitvec[32*j + 8*i : 32*j + 8*(i+1)]
            
            for j in range(4): #xor'ed with the first word 4 times
                for i in range(4):
                    statearray[i][j] = statearray[i][j].__xor__(key_words[j][8*i:8*(i+1)])

            word_num = 4
            for z in range(14):
                #sub bytes
                for j in range(4):
                    for i in range(4):
                        val = statearray[i][j].__int__()
                        val = byte_sub_table[val]
                        statearray[i][j] = BitVector(intVal = val, size = 8)
                        #print(statearray[i][j].get_bitvector_in_hex())
                

                for i in range(1,4): #shift rows
                    statearray[i] = statearray[i][i:] + statearray[i][:i]

                if z != 13:
                    newstatearray = [[0 for x in range(4)] for x in range(4)] #mix cols
                    for j in range(4): 
                        for i in range(4):
                            if i == 0:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
                                second =  statearray[1][j].gf_multiply_modular(BitVector(intVal = 0x03), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ statearray[2][j] ^ statearray[3][j]
                            elif i == 1:
                                first = statearray[i][j].gf_multiply_modular(BitVector(intVal = 0x02, size = 8), self.AES_modulus, 8)
                                second = statearray[2][j].gf_multiply_modular(BitVector(intVal = 0x03, size = 8), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ statearray[0][j] ^ statearray[3][j]
                            elif i == 2:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
                                second =  statearray[3][j].gf_multiply_modular(BitVector(intVal = 0x03), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ statearray[0][j] ^ statearray[1][j]
                            elif i == 3:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
                                second =  statearray[0][j].gf_multiply_modular(BitVector(intVal = 0x03), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ statearray[1][j] ^ statearray[2][j]
                    
                    statearray = newstatearray
                

                print(statearray[2][0].get_bitvector_in_hex())  
                for j in range(4):
                    for i in range(4):
                        statearray[i][j] = statearray[i][j].__xor__(key_words[word_num][8*i:8*(i+1)])

                    word_num+=1

            for j in range(4):
                for i in range(4):
                    f.write(statearray[i][j].get_bitvector_in_hex())

    
    def gen_key_sched(self):
        key_words = []
        key_bv = self.get_key_from_user()
        keysize = 256
        key_words = self.gen_key_schedule_256(key_bv)

        key_schedule = []
        for word_index,word in enumerate(key_words):
            keyword_in_ints = []
            for i in range(4):
                keyword_in_ints.append(word[i*8:i*8+8].intValue())
            if word_index % 4 == 0: print("\n")
            #print("word %d:  %s" % (word_index, str(keyword_in_ints)))
            key_schedule.append(keyword_in_ints)
        num_rounds = 14
        round_keys = [None for i in range(num_rounds+1)]
        for i in range(num_rounds+1):
            round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                                        key_words[i*4+3]).get_bitvector_in_hex()
        return key_words,round_keys

    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.gen_subbytes_table()
        #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
        #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
        #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
        #  schedule. We will store all 60 keywords in the following list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal = 0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i*32 : i*32 + 32]
        for i in range(8,60):
            if i%8 == 0:
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
                key_words[i] = key_words[i-8] ^ kwd
            elif (i - (i//8)*8) < 4:
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            elif (i - (i//8)*8) == 4:
                key_words[i] = BitVector(size = 0)
                for j in range(4):
                    key_words[i] += BitVector(intVal = 
                                    byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
                key_words[i] ^= key_words[i-8]
            elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
                key_words[i] = key_words[i-8] ^ key_words[i-1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words

    def gen_subbytes_table(self):
        subBytesTable = []
        c = BitVector(bitstring='01100011')
        for i in range(0, 256):
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
        return subBytesTable
    
    def gen_decrypt_subbytes_table(self):
        invSubBytesTable = []
        d = BitVector(bitstring='00000101')
        for i in range(0,256):
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))
        return invSubBytesTable

    def get_key_from_user(self):
        f = open(self.keyfile, "r")
        key = f.read()
        keysize = 256
        key = key.strip()
        key += '0' * (keysize//8 - len(key)) if len(key) < keysize//8 else key[:keysize//8]  
        key_bv = BitVector( textstring = key )
        return key_bv
# decrypt - method performs AES decryption on the ciphertext and writes the recovered plaintext to disk
# Inputs: ciphertext (str) - filename containing ciphertext
# decrypted (str) - filename containing recovered plaintext
# Return: void
    def decrypt(self , ciphertext:str , decrypted:str) -> None:
        f_input = open(ciphertext, "r")
        hex_input = f_input.read()
        bv = BitVector( hexstring = hex_input )
        f = open(decrypted, "w", encoding="utf-8")
        key_words, round_keys = self.gen_key_sched()
        inv_byte_sub_table = self.gen_decrypt_subbytes_table()
        for i in range(int(bv._getsize() / 128)):
            bitvec = bv[i*128:i*128+128]

            if bitvec.length() < 128:
                bitvec.pad_from_right(128 - bitvec.length())
            statearray = [[0 for x in range(4)] for x in range(4)]

            for i in range(4):
                for j in range(4):
                    statearray[i][j] = bitvec[32*j + 8*i : 32*j + 8*(i+1)]


            for j in range(4): #xor'ed with the first word 4 times
                for i in range(4):
                    statearray[i][j] = statearray[i][j].__xor__(key_words[j+56][8*i:8*(i+1)])
                    
            word_num = 52
            
            for z in range(14):

                for i in range(1,4): #inv shift rows
                    statearray[i] = statearray[i][-i:] + statearray[i][:-i]
                
                #sub bytes
                for j in range(4):
                    for i in range(4):
                        val = statearray[i][j].__int__()
                        val = inv_byte_sub_table[val]
                        statearray[i][j] = BitVector(intVal = val, size = 8)
                        #print(statearray[i][j].get_bitvector_in_hex())
                

                for j in range(4): #xor'ed with the first word 4 times
                    for i in range(4):
                        statearray[i][j] = statearray[i][j].__xor__(key_words[word_num][8*i:8*(i+1)])
                        #print(statearray[i][j].get_bitvector_in_hex())  
                    word_num+=1 
                word_num -=8


                if z != 13:
                    newstatearray = [[0 for x in range(4)] for x in range(4)] #mix cols
                    for j in range(4): 
                        for i in range(4):
                            if i == 0:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 14), self.AES_modulus, 8)
                                second =  statearray[1][j].gf_multiply_modular(BitVector(intVal = 11), self.AES_modulus, 8)
                                third =  statearray[2][j].gf_multiply_modular(BitVector(intVal = 13), self.AES_modulus, 8)
                                fourth =  statearray[3][j].gf_multiply_modular(BitVector(intVal = 9), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ third ^ fourth
                            elif i == 1:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 14), self.AES_modulus, 8)
                                second =  statearray[2][j].gf_multiply_modular(BitVector(intVal = 11), self.AES_modulus, 8)
                                third =  statearray[3][j].gf_multiply_modular(BitVector(intVal = 13), self.AES_modulus, 8)
                                fourth =  statearray[0][j].gf_multiply_modular(BitVector(intVal = 9), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ third ^ fourth
                            elif i == 2:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 14), self.AES_modulus, 8)
                                second =  statearray[3][j].gf_multiply_modular(BitVector(intVal = 11), self.AES_modulus, 8)
                                third =  statearray[0][j].gf_multiply_modular(BitVector(intVal = 13), self.AES_modulus, 8)
                                fourth =  statearray[1][j].gf_multiply_modular(BitVector(intVal = 9), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ third ^ fourth
                            elif i == 3:
                                first =  statearray[i][j].gf_multiply_modular(BitVector(intVal = 14), self.AES_modulus, 8)
                                second =  statearray[0][j].gf_multiply_modular(BitVector(intVal = 11), self.AES_modulus, 8)
                                third =  statearray[1][j].gf_multiply_modular(BitVector(intVal = 13), self.AES_modulus, 8)
                                fourth =  statearray[2][j].gf_multiply_modular(BitVector(intVal = 9), self.AES_modulus, 8)
                                newstatearray[i][j] = first ^ second ^ third ^ fourth
                    
                    statearray = newstatearray

            for j in range(4):
                for i in range(4):
                    f.write(statearray[i][j].get_bitvector_in_())
            



if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], decrypted=sys.argv[4])
    else:
        sys.exit("Incorrect Command -Line Syntax")
