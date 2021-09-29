import numpy as np
import csv
import sys

# Obfuscat-crc32-2021-08-29-04-53-20 Obfuscat-rc4-2021-08-29-04-55-37 Obfuscat-sha1-2021-08-29-05-00-30
CSVNAME = "Obfuscat-2021-09-13"

dataMap = {}

with open("../logs/"+CSVNAME+".csv", newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        idx = int(row[0].split("-")[-1])
        tag = row[0].split("-")[0]+"-"+row[0].split("-")[1]
        
        if not "SHA1" in tag:
            continue
        
        if not (idx in dataMap):
            dataMap[idx] = {}
        if not (tag in dataMap[idx]):
            dataMap[idx][tag] = {"exec": [], "size": []}
            
        dataMap[idx][tag]["exec"].append(int(row[1]))
        dataMap[idx][tag]["size"].append(int(row[2]))

NUMKEYS = [128, 256, 512, 1024]
keys = [key.split("-")[0]+"-"+key.split("-")[-1] for key in dataMap[1024]]

dataArray = [{} for i in range(len(keys))]

for NUMKEY in NUMKEYS:
    CTEsExec = [np.mean(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]]
    CTEsSize = [np.mean(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]]


    baseExec = CTEsExec[0]
    baseSize = CTEsSize[0]
    
    for i in range(len(keys)):
        key, mExec, mSize =  (keys[i], CTEsExec[i], CTEsSize[i])
        if i > 0:
            key, mExec, mSize =  (key, mExec/baseExec*100, mSize/baseSize*100)
        dataArray[i][0] = mSize
        dataArray[i][NUMKEY] = mExec


output = """\\begin{table}[H]
\\centering
\\caption[PLACEHOLDER ENTRY]{"""+CSVNAME+"""}
\\begin{tabular}{l|l|lllllll}
$Method$ & Size & Input 128 & Input 256 & Input 512 & Input 1024 \\\ \\hline\\hline
"""

for i in range(len(keys)):
    key, size, data128, data256, data512, data1024 =  keys[i], dataArray[i][0], dataArray[i][128], dataArray[i][256], dataArray[i][512], dataArray[i][1024]
    tableLine = "%s & $%.0f$\\%% & $%.0f$\\%% & $%.0f$\\%% & $%.0f$\\%% & $%.0f$\\%% \\\\" % (key, size, data128, data256, data512, data1024)
    output = output + tableLine + "\n"
    
output = output + """\\end{tabular}
\\end{table}"""
print(output)
