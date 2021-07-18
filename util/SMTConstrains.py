from z3 import *

def StoreTag(array, tag, node):
    return Store(array, hash(tag), node)
    
def LoadTag(array, tag):
    return Select(array, hash(tag))


def oe(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") * 10)
    tmp = StoreTag(tmp, "const"     , LoadTag(prevArray, "const") + LoadTag(prevArray, "math"))
    return tmp
    
def fd(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") + LoadTag(prevArray, "const") * 4)
    tmp = StoreTag(tmp, "load"      , LoadTag(prevArray, "load") + LoadTag(prevArray, "const"))
    return tmp
    
def le(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") + LoadTag(prevArray, "const") * 5)
    tmp = StoreTag(tmp, "const"     , LoadTag(prevArray, "const") * 4)
    return tmp
    
def ve(prevArray):
    tmp = StoreTag(prevArray, "math", LoadTag(prevArray, "math") + LoadTag(prevArray, "load") * 2 + LoadTag(prevArray, "store") * 2)
    tmp = StoreTag(tmp, "const"     , LoadTag(prevArray, "const") + LoadTag(prevArray, "load") * 2 + LoadTag(prevArray, "store") * 2)
    return tmp
    
    

def applyLevel(obfVar, prevArray):
    return If(obfVar == 1, oe(prevArray) , If(obfVar == 2, fd(prevArray), If(obfVar == 3, le(prevArray), If(obfVar == 4, ve(prevArray), prevArray))))


initialArray = Array('initialArray', IntSort(), IntSort())
totalSize = Int("totalSize")

initialArray = StoreTag(initialArray, "math", 17)
initialArray = StoreTag(initialArray, "const", 5)
initialArray = StoreTag(initialArray, "load", 0)
initialArray = StoreTag(initialArray, "store", 0)

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
opt.add(totalSize == LoadTag(lastArray, "math") + LoadTag(lastArray, "const") + LoadTag(lastArray, "load") + LoadTag(lastArray, "store"))

opt.add(totalSize < 10000) # constrain size/speed


countDistinct = Sum([If(Sum([If(obfVars[i] == type, 1, 0) for i in range(MAX_DEPTH)]) > 0, 1, 0) for type in range(1,4)])

obj1 = opt.maximize(countDistinct)
obj2 = opt.maximize(totalSize)

opt.set('priority', 'box')  # Setting Boxed Multi-Objective Optimization

opt.check()
m = opt.model()
#print(m)
print("Settings: "+str([m[obfVars[i]] for i in range(MAX_DEPTH)]))
print("Size:"+str(m[totalSize]))