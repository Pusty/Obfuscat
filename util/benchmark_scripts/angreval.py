import angr
import claripy
import sys
import os
import timeit
import random
import string

from util import *

SECRET_FLAG_LENS = [4] # random string lengths to test
N = 1 # amount of angr solves per binary
M = 1 # amount of binaries per pass
    
ERROR = False
    
def perfAngr(name):
    global ERROR
    ERROR = False
    print(name+"-"+str(len(SECRET_FLAG)))
    v = timeit.timeit(stmt=runAngr, number=N)/N
    return (name, v, len(SECRET_FLAG), ERROR)
    
def runAngr():
    global ERROR
    inpStr = claripy.BVS("inpStr", 8*(len(SECRET_FLAG)+1))
    project = angr.Project('a.out')
    state = project.factory.entry_state(args=['./a.out', inpStr], add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    sm = project.factory.simgr(state)

    sm.run()
    solutions = 0
    for state in sm.deadended:
        state.solver.add(state.regs.r0 == 1)
        if not state.satisfiable(): continue
        answer = state.solver.eval(inpStr, cast_to=bytes).decode("utf-8")
        if(answer[:len(SECRET_FLAG)] != SECRET_FLAG): 
            ERROR = True
            print("WRONG ANSWER: "+answer)
        else:
            solutions = solutions + 1
            
    if solutions == 0:
        ERROR = True
        print("No solutions found?")
        print(sm)
    if solutions > 1:
        ERROR = True
        print("Multiple solutions found?")
        print(sm)
    
os.chdir('../tmp')

solutions = []

print(SECRET_FLAG_LENS, M, N)
for SECRET_FLAG_LEN in SECRET_FLAG_LENS:
    SECRET_FLAG = ''.join(random.choice(string.ascii_letters) for i in range(SECRET_FLAG_LEN))

    for m in range(M):
        generateVerify(SECRET_FLAG)
        generateGCC("Verify")
        solutions.append(perfAngr("GCC-Verify"))

    for flag in ["BCF", "SUB", "FLA"]:
        for m in range(M):
            generateVerify(SECRET_FLAG)
            generateTigress("Verify", OBFUSCATOR_FLAGS[flag]["Tigress"])
            solutions.append(perfAngr("Tigress-Verify-"+flag))
            
    for flag in ["BCF", "SUB", "FLA"]:
        for m in range(M):
            generateVerify(SECRET_FLAG)
            generateOLLVM("Verify", OBFUSCATOR_FLAGS[flag]["OLLVM"])
            solutions.append(perfAngr("OLLVM-Verify-"+flag))
        

    for flag in ["None", "BCF", "SUB", "FLA"]: #,"FAKE", "VARIABLE", "LITERAL"]: #"VIRT"
        for m in range(M):
            subprocess.Popen(("java -jar ../obfuscat/Obfuscat.jar builder Verify -data '"+SECRET_FLAG+"'").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
            generateObfuscatObf(None if flag == "None" else OBFUSCATOR_FLAGS[flag]["Obfuscat"])
            solutions.append(perfAngr("Obfuscat-Verify-"+flag))


import csv
import datetime
#print(solutions)

# Name, Avrg Time, Input Len, Error

#with open(datetime.datetime.now().strftime("../logs/angreval-%Y-%m-%d-%H-%M-%S.csv"), "w") as f:
#     writer = csv.writer(f, delimiter=',')
#     writer.writerows(solutions)