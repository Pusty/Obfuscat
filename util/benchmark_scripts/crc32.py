import subprocess
import os
from util import *
import random
import string

os.chdir('../tmp')



N = 10  # amount of runs per binary
M = 100 # amount of binaries per pass

SAMPLE_INPUTS = [''.join(random.choice(string.ascii_letters) for i in range(8)),
                 ''.join(random.choice(string.ascii_letters) for i in range(64)),
                 ''.join(random.choice(string.ascii_letters) for i in range(128)),
                 ''.join(random.choice(string.ascii_letters) for i in range(256)),
                 ''.join(random.choice(string.ascii_letters) for i in range(512)),
                 ''.join(random.choice(string.ascii_letters) for i in range(1024))
                 ]
                 


FILENAME = "CRC32" # CRC32, RC4, SHA1, AES128

solutions = []


for m in range(M):
    generateGCC(FILENAME)
    for inp in SAMPLE_INPUTS:
        tag = "GCC-"+FILENAME+"-None-"+str(len(inp))
        print(tag)
        for n in range(N):
            solutions.append(profile(tag,inp))

for mode in ["None", "BCF", "FLA", "SUB"]: #,"FAKE", "VARIABLE", "LITERAL"]: #"VIRT"
    for m in range(M):
        generateObfuscat(FILENAME, None if mode == "None" else OBFUSCATOR_FLAGS[mode]["Obfuscat"])
        for inp in SAMPLE_INPUTS:
            tag = "Obfuscat-"+FILENAME+"-"+mode+"-"+str(len(inp))
            print(tag)
            for n in range(N):
                solutions.append(profile(tag,inp))

for mode in ["BCF", "FLA", "SUB"]:
    for m in range(M):
        generateOLLVM(FILENAME, OBFUSCATOR_FLAGS[mode]["OLLVM"])
        for inp in SAMPLE_INPUTS:
            tag = "OLLVM-"+FILENAME+"-"+mode+"-"+str(len(inp))
            print(tag)
            for n in range(N):
                solutions.append(profile(tag,inp))

for mode in ["BCF", "FLA", "SUB"]:
    for m in range(M):
        generateTigress(FILENAME, OBFUSCATOR_FLAGS[mode]["Tigress"])
        for inp in SAMPLE_INPUTS:
            tag = "Tigress-"+FILENAME+"-"+mode+"-"+str(len(inp))
            print(tag)
            for n in range(N):
                solutions.append(profile(tag,inp))

import csv
import datetime
#print(solutions)

# Name, executed instructions, file size, sha256 hash, returned value

with open(datetime.datetime.now().strftime("../logs/"+FILENAME.lower()+"-%Y-%m-%d-%H-%M-%S.csv"), "w") as f:
     writer = csv.writer(f, delimiter=',')
     writer.writerows(solutions)


"""
javac --release 8 ./CRC32.java
java -jar ../obfuscat/Obfuscat.jar builder Class -path CRC32.class -entry crc32
java -jar ../obfuscat/Obfuscat.jar obfuscate Bogus -input build.fbin -output build.fbin
java -jar ../obfuscat/Obfuscat.jar compile Thumb -input build.fbin
cp ./output.bin ./program.bin
arm-linux-gnueabi-ld  -r -b binary -o ./program.bin.o ./program.bin
arm-linux-gnueabi-objcopy --rename-section .data=.text ./program.bin.o
arm-linux-gnueabi-gcc -march=armv8-a -mthumb ../target/wrapper.c ./program.bin.o -o ./a.out
qemu-arm  -cpu cortex-a15 -L /usr/arm-linux-gnueabi/ a.out test

print(profile("A"))
print(profile("AAA"))
print(profile("AAAAA"))
"""