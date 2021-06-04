import operator
import random
import math
from sympy import *
import z3

# Information Hiding in Software with Mixed Boolean-Arithmetic Transforms - https://doi.org/10.1007/978-3-540-77535-5_5
# Obfuscation with Mixed Boolean-Arithmetic Expressions: reconstruction, analysis and simplification tools by Ninon Eyrolles 

def generateTable(vars, o):
    data = []
    for i in range(2**vars):
        xs = [(i>>(vars-j-1))&1 for j in range(vars)]
        data.append(o(xs))
    return data
    
    
def table_true(vars, a):  return generateTable(vars, lambda xs: xs[a])
def table_false(vars, a):  return generateTable(vars, lambda xs: 1-xs[a])
def table_and(vars): return generateTable(vars, lambda xs: reduce(operator.iand, xs))
def table_or(vars): return generateTable(vars,lambda xs: reduce(operator.ior, xs))
def table_xor(vars): return generateTable(vars, lambda xs: reduce(operator.ixor, xs))
def table_random(vars): return [int(random.getrandbits(1)) for i in range(2**vars)]
    
# generate 2 variables,  x0 = ....

def generateMBA():
    acceptable = None

    while acceptable == None:
        F = Matrix([table_true(3, 0), table_random(3), table_random(3)])
        F = F.transpose()
        
        solutions = F.nullspace()
        
        for i in range(len(solutions)): 
            solMat = solutions[i]
            if solMat[0] == 0: continue

            containsNullOrDenom = False
            for j in range(len(solMat)):
                if solMat[j] == 0:
                    containsNullOrDenom = True
                    break
                if solMat[j].as_content_primitive()[0].q != 1:
                    containsNullOrDenom = True
                    break
            
            if containsNullOrDenom: continue
     
            acceptable = (F, solMat)
            break

           
    return acceptable
    
def tableToExpression(table):
    varLen = int(math.log(len(table), 2))
    #vars = [Bool("var"+str(i)) for i in range(varLen)]
    vars = [symbols("vars["+str(i)+"]") for i in range(varLen)]
    minterms = []
    #exp = False
    for i in range(len(table)):
        if table[i] == 1:
            xs = [(i>>(varLen-j-1))&1 for j in range(varLen)]
            minterms.append(xs)
            #cur = And([vars[i] if xs[i] == 1 else Not(vars[i]) for i in range(varLen)])
            #exp = Or(exp,cur)
    #e1 = simplify(exp)
    return (SOPform(vars, minterms, [])) # simplify

def mbaIdentity():
    F, solMat = generateMBA()
    
    varLen = int(math.log(F.shape[0], 2))
    vars = [z3.BitVec("vars["+str(i)+"]", 32) for i in range(varLen)]
    
    formular = 0
    
    for i in range(F.shape[1]):
        frm = tableToExpression(F.col(i))
        frms = str(frm).replace("True", "-1") # True = !False = ~0 = -1
        o = eval(frms)
        v = int(solMat[i])
        
        if v > 0:
            if v == 1:
                formular = formular + o
            else:
                formular = formular + o * v
        elif v < 0:
            if v == -1:
                formular = formular - o
            else:
                formular = formular - o * abs(v)
        else:
            print("??? Should not be contain 0 "+str(solMat))
       
    formular = z3.simplify(formular)
    
    print(str(formular).replace("\n", " ")+" = 0")
    solver = z3.Solver()
    solver.add(formular != 0)
    
    if solver.check() == z3.sat:
        crash_here()
    

while True:
    mbaIdentity()