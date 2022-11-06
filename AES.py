#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Oct  8 11:32:09 2022

@author: Ali Mustafa
"""

#This code applies m rounds of AES-128 key encryption to text
#Writter by Ali Mustafa

key=input("Please input a key(128): ") #40404040404040404040404040404040
text=input("Please input text to encrypt: ") #000102030405060708090a0b0c0d0e0f


Rcon = ( 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a )
Sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        )
Mix=[['02','03','01','01'],['01','02','03','01'],['01','01','02','03'],['03','01','01','02']]


##########################

def rotateList(arr,d,n):
    arr[:]=arr[d:n]+arr[0:d]
    return arr

def printState(arr):
    for i in range(4):
        for j in range(4):
            print(arr[i][j])
            
def sxor8(s1,s2):    
    a=int(s1,16)
    b=int(s2,16)
    a=a^b
    return hex(a)[2:].zfill(8) # return a hex string of xor

def sxor2(s1,s2):    
    a=int(s1,16)
    b=int(s2,16)
    a=a^b
    return hex(a)[2:].zfill(2) # return a hex string of xor

def s_box_mapping(W):
    temp=[]
    spl=[W[i:i+2] for i in range(0, len(W), 2)]
    for i in spl:
        a=int(i,16)%16
        b=int(i,16)//16
        temp.append(hex(Sbox[b*16+a])[2:].zfill(2))
    return "".join(temp)
    
def splitter(text):
    long = [text[i:i+2] for i in range(0, len(text), 2)]
    state = [[0 for i in range(4)] for j in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j]=long[4*j+i]
    return state #converts a string into state

def rotator(temp):
    return "".join([temp[2:],temp[0:2]])

def printer (w):
    for i in range(4):
        for j in range(4):
            print(w[j][i],end="")
    print()

############################

def add_round_key(state,key):
    add_round_state = [[0 for i in range(4)] for j in range(4)]
    for i in range(4):
        for j in range(4):
            add_round_state[i][j]=sxor2(state[i][j],key[i][j])
    return add_round_state

def multiply(a,b) :
    if a=='01':
        return b
    elif a=='02':
        test = bin(int(b,16))[2:].zfill(8)
        if test[0]=='1':
            test=test[1:]+'0'
            return hex(int(sxor8(test,'00011011'),2))[2:]
        else :
            return hex(int(test[1:]+'0',2))[2:]
    elif a=='03':
        test = bin(int(b,16))[2:].zfill(8)
        test2=test
        if test[0]=='1':
            test=test[1:]+'0'
            test=sxor8(test,'00011011')
            test2=sxor8(test2,test)
            return hex(int(test2,2))[2:]
        else :
            test=test[1:]+'0'
            test2=sxor8(test2,test)
            return hex(int(test2,2))[2:]

def dot(A,B):
    sum="00"
    for i in range(4):
        temp=multiply(A[i],B[i])
        sum=sxor2(temp,sum)
    return sum
        
#################
#Key Generation Zone

key_sp = [key[i:i+2] for i in range(0, len(key), 2)]
word = [0] * 44

for i in range(4):
    word[i]=''.join([key_sp[4*i],key_sp[4*i+1],key_sp[4*i+2],key_sp[4*i+3]])

for i in range(4,44):
    temp=word[i-1]
    if (i%4==0):
        rcon = "".join([hex(Rcon[i//4])[2:].zfill(2),"00","00","00"])
        temp=sxor8(s_box_mapping(rotator(temp)) ,rcon)
    
    word[i]=sxor8(temp,word[i-4])
    
keys = ["".join(word[i:i+4]) for i in range(0, len(word), 4)]

#################
#AES encryption zone

#Adding Round Key
state=splitter(text)
key=splitter(keys[0])
w=add_round_key(state,key)



########## Rounds

for m in range(10):
    print("Round ",m+1)
    #Substitution
    for i in range(4):
        for j in range(4):
            w[i][j]=s_box_mapping(w[i][j])
    
    #Shift Rows
    for i in range(4):
        w[i]=rotateList(w[i],i,4)
    
    #Mix Columns
    if m!=9:
        w2=w
        tmp=""
        for i in range(4):
            for j in range(4):
                tmp+=str(dot(Mix[j],[row[i] for row in w]))
        state=splitter(tmp)
    else:
        state=w
    #Add Round Key
    
    key=splitter(keys[m+1])
    print("Key used: ",keys[m+1])
    w=add_round_key(state,key)
    printer(w)


