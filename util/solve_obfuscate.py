# Proof of concept for using z3 to optimize obfuscation settings
import subprocess
from z3 import *

SIZE_PER_BLOCK = 16
SWITCH_PER_BLOCK = 8

MAX_SIZE = 10000
TARGET_FILE = "rc4.fbin"

def loadInput(fileName):
    proc = subprocess.Popen(["java", "-jar", "Obfuscat.jar", "info", "-input", fileName], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    out = out.decode()
    out = out.split("{")[1].split("}")[0]

    mapData = {}
    for ent in out.split(", "):
        key, data = ent.split("=")
        mapData[key] = int(data)
        
    if not "aload" in mapData:
        mapData["aload"] = 0
    if not "astore" in mapData:
        mapData["astore"] = 0
    if not "const" in mapData:
        mapData["const"] = 0
    if not "custom" in mapData:
        mapData["custom"] = 0
    if not "load" in mapData:
        mapData["load"] = 0
    if not "math" in mapData:
        mapData["math"] = 0
    if not "store" in mapData:
        mapData["store"] = 0
        
    if not "conditionalBlocks" in mapData:
        mapData["conditionalBlocks"] = 0
    if not "switchBlocks" in mapData:
        mapData["switchBlocks"] = 0
    if not "exitBlocks" in mapData:
        mapData["exitBlocks"] = 0
    if not "jumpBlocks" in mapData:
        mapData["jumpBlocks"] = 0
        
    return mapData
    
def compileFile(fileName, outName):
    proc = subprocess.Popen(["java", "-jar", "Obfuscat.jar", "compile", "Thumb", "-input", fileName, "-output", outName], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    
def applyPass(fileName, passName):
    proc = subprocess.Popen(["java", "-jar", "Obfuscat.jar", "obfuscate", passName, "-input", fileName, "-output", fileName], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

def calculateSize(m):
    return (2+m["aload"]+m["astore"]+m["const"]+m["custom"]+m["load"]+m["math"]+m["store"]+m["conditionalBlocks"]*2+m["switchBlocks"]+m["exitBlocks"]+m["jumpBlocks"])*SIZE_PER_BLOCK

m = loadInput(TARGET_FILE)
print(m)
print(calculateSize(m))


def StoreTag(array, tag, node):
    return Store(array, hash(tag), node)
    
def LoadTag(array, tag):
    return Select(array, hash(tag))

# operation encode
def oe(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") * 10)
    tmp = StoreTag(tmp, "const"     , LoadTag(prevArray, "const") + LoadTag(prevArray, "math"))
    return tmp
    
# fake dependencies
def fd(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") + LoadTag(prevArray, "const") * 4)
    tmp = StoreTag(tmp, "load"      , LoadTag(prevArray, "load") + LoadTag(prevArray, "const"))
    return tmp
    
# literal encoding
def le(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") + LoadTag(prevArray, "const") * 5)
    tmp = StoreTag(tmp, "const"     , LoadTag(prevArray, "const") * 4)
    return tmp
    
# variable encode
def ve(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") + LoadTag(prevArray, "load") * 2 + LoadTag(prevArray, "store") * 2)
    tmp = StoreTag(tmp, "const"     , LoadTag(prevArray, "const") + LoadTag(prevArray, "load") * 2 + LoadTag(prevArray, "store") * 2)
    return tmp
    
    

def applyLevel(obfVar, prevArray):
    return If(obfVar == 1, oe(prevArray) , If(obfVar == 2, fd(prevArray), If(obfVar == 3, le(prevArray), If(obfVar == 4, ve(prevArray), prevArray))))


initialArray = Array('initialArray', IntSort(), IntSort())
totalSize = Int("totalSize")


for key in m:
    initialArray = StoreTag(initialArray, key, m[key])
#initialArray = StoreTag(initialArray, "math", 17)
#initialArray = StoreTag(initialArray, "const", 5)
#initialArray = StoreTag(initialArray, "load", 0)
#initialArray = StoreTag(initialArray, "store", 0)

MAX_DEPTH = 8
obfVars = [Int("obf"+str(i)) for i in range(MAX_DEPTH)]
opt = Optimize()

# limit obfVar options
for i in range(len(obfVars)):
    opt.add(obfVars[i] >= 0)
    opt.add(obfVars[i] <= 4)

lastArray = initialArray
    
for i in range(MAX_DEPTH):
    lastArray = applyLevel(obfVars[i], lastArray)
    
# Fullfill size requirements
#opt.add(totalSize == LoadTag(lastArray, "math") + LoadTag(lastArray, "const") + LoadTag(lastArray, "load") + LoadTag(lastArray, "store"))
opt.add(totalSize == (2+LoadTag(lastArray, "aload")+LoadTag(lastArray, "astore")+LoadTag(lastArray, "const")+LoadTag(lastArray, "custom")+LoadTag(lastArray, "load")+LoadTag(lastArray, "math")+LoadTag(lastArray, "store")+LoadTag(lastArray, "conditionalBlocks")*2+LoadTag(lastArray, "switchBlocks")+LoadTag(lastArray, "exitBlocks")+LoadTag(lastArray, "jumpBlocks"))*SIZE_PER_BLOCK)

opt.add(totalSize > 0, totalSize < MAX_SIZE) # constrain size/speed


countDistinct = Sum([If(Sum([If(obfVars[i] == type, 1, 0) for i in range(MAX_DEPTH)]) > 0, 1, 0) for type in range(1,4)])

obj1 = opt.maximize(countDistinct)
obj2 = opt.maximize(totalSize)

opt.set('priority', 'box')  # Setting Boxed Multi-Objective Optimization

if(opt.check() != sat):
    print("NO SOLUTION FOUND")
    exit(0)
m = opt.model()
#print(m)

obfuscationValues = [m[obfVars[i]].as_long() for i in range(MAX_DEPTH)]

nameArray = [None, "OperationEncode", "FakeDependency", "LiteralEncode", "VariableEncode"]
obfuscationValues = [nameArray[i] for i in obfuscationValues]

print("Settings: "+str(obfuscationValues))
print("Size:"+str(m[totalSize]))

from shutil import copyfile
copyfile(TARGET_FILE, "tmp.fbin")
for method in obfuscationValues:
    if method != None: applyPass("tmp.fbin", method)
compileFile("tmp.fbin", TARGET_FILE+".bin")

f = open(TARGET_FILE+".bin", "rb")
print("Actual Size:"+str(len(f.read())))
f.close()