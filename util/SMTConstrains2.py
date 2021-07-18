from z3 import *

def StoreTag(array, tag, node):
    return Store(array, hash(tag), node)
    
def LoadTag(array, tag):
    return Select(array, hash(tag))


def oe(prev):
    new = {}
    for key in prev:
        new[key] = prev[key]
    new["math"] = prev["math"] * 10
    new["const"] = prev["const"] + prev["math"] * 2
    return new

def fd(prev):
    new = {}
    for key in prev:
        new[key] = prev[key]
    new["math"] = prev["math"] + prev["const"] * 4
    new["load"] = prev["load"] + prev["const"]
    return new
    
def le(prev):
    new = {}
    for key in prev:
        new[key] = prev[key]
    new["math"] = prev["math"] + prev["const"] * 5
    new["const"] = prev["const"] * 4
    return new
    
def ve(prev):
    new = {}
    for key in prev:
        new[key] = prev[key]
    new["math"] = prev["math"] + prev["load"] * 2 + prev["store"] * 2
    new["const"] = prev["const"] + prev["load"] * 2 + prev["store"] * 2
    return new
    
    

def applyLevel(obfVars, prev):
    changes = [prev,oe(prev),fd(prev),le(prev),ve(prev)]
    new = {}
    for i in range(len(changes)):
        for key in changes[i]:
            if key in new:
                new[key] = new[key] + (obfVars[i] * changes[i][key])
            else:
                new[key] = obfVars[i] * changes[i][key]
            new[key] = simplify(new[key])  
    return new


nodeMap = {}
nodeMap["math"] = 17
nodeMap["const"] = 5
nodeMap["load"] = 0
nodeMap["store"] = 0

MAX_DEPTH = 2
obfVars = [[Int("obf"+str(i)+"_"+str(j)) for j in range(5)] for i in range(MAX_DEPTH)]
totalSize = Int("totalSize")
opt = Optimize()

# limit obfVar options
for i in range(MAX_DEPTH):
    for j in range(len(obfVars[i])):
        opt.add(obfVars[i][j] >= 0)
        opt.add(obfVars[i][j] <= 1)
        


for i in range(MAX_DEPTH):
    nodeMap = applyLevel(obfVars[i], nodeMap)
print(nodeMap)
# Fullfill size requirements
opt.add(totalSize == nodeMap["math"]  +nodeMap["const"] + nodeMap["load"] + nodeMap["store"])

opt.add(totalSize < 10000) # constrain size/speed


#countDistinct = Sum([If(Sum([If(obfVars[i] == type, 1, 0) for i in range(MAX_DEPTH)]) > 0, 1, 0) for type in range(1,4)])

#obj1 = opt.maximize(countDistinct)
obj2 = opt.maximize(totalSize)

#opt.set('priority', 'box')  # Setting Boxed Multi-Objective Optimization

opt.check()
m = opt.model()
#print(m)
#print("Settings: "+str([m[obfVars[i]] for i in range(MAX_DEPTH)]))
print("Size:"+str(m[totalSize]))