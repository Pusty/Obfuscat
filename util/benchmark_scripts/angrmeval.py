import sys
import os
import random
import string

from util import *

SECRET_FLAG = 'ABCD1234'*4
M = 1 # amount of binaries per pass
N = 1 # amount of runs per binary

def generateVerify(flag):
    f = open("../target/Verify.c", "w")
    
    condition = ""
    for i in range(len(flag)):
        condition = condition + " && message["+str(i)+"] == "+hex(ord(flag[i]))
    
    f.write("""unsigned int _binary___program_bin_start(unsigned char* message, unsigned int len) {
    if(len == """+str(len(flag))+condition+""") return 1;
    return 0;
    }""")
    f.close()
    

def perfAngr(name):
    for i in range(N):
        #print(name)
        subprocess.Popen(("python3 ../scripts/angrmeval_sub.py "+name).split(" ")).wait()

os.chdir('../tmp')

solutions = []

for m in range(M):
    generateVerify(SECRET_FLAG)
    generateGCC("Verify")
    solutions.append(perfAngr("GCC-Verify"))

for flag in ["BCF", "FLA", "SUB"]:
    for m in range(M):
        generateVerify(SECRET_FLAG)
        generateTigress("Verify", OBFUSCATOR_FLAGS[flag]["Tigress"])
        solutions.append(perfAngr("Tigress-Verify-"+flag))
        
for flag in ["BCF", "FLA", "SUB"]:
    for m in range(M):
        generateVerify(SECRET_FLAG)
        generateOLLVM("Verify", OBFUSCATOR_FLAGS[flag]["OLLVM"])
        solutions.append(perfAngr("OLLVM-Verify-"+flag))
    

for flag in ["None", "BCF", "FLA", "SUB"]:
    for m in range(M):
        subprocess.Popen(("java -jar ../obfuscat/Obfuscat.jar builder Verify -data '"+SECRET_FLAG+"'").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
        generateObfuscatObf(None if flag == "None" else OBFUSCATOR_FLAGS[flag]["Obfuscat"])
        solutions.append(perfAngr("Obfuscat-Verify-"+flag))


#import csv
#import datetime
#print(solutions)

# Name, Avrg Time, Input Len, Error

#with open(datetime.datetime.now().strftime("../logs/angreval-%Y-%m-%d-%H-%M-%S.csv"), "w") as f:
#     writer = csv.writer(f, delimiter=',')
#     writer.writerows(solutions)