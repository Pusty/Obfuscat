import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import csv
import sys

# crc32-2021-08-14-06-01-56 rc4-2021-08-13-14-10-56, sha1-2021-08-14-07-18-15
CSVNAME = "crc32"

dataMap = {}

with open("../logs/"+CSVNAME+".csv", newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        idx = int(row[0].split("-")[-1])
        tag = row[0].split("-")[0]+"-"+row[0].split("-")[2]
        if "VIRT" in tag: continue 
        if not (idx in dataMap):
            dataMap[idx] = {}
        if not (tag in dataMap[idx]):
            dataMap[idx][tag] = {"exec": [], "size": []}
        
        dataMap[idx][tag]["exec"].append(int(row[1]))
        dataMap[idx][tag]["size"].append(int(row[2]))
        
        
keys = [key for key in dataMap]

xpos = np.arange(len(keys))

graphNames = [g for g in dataMap[keys[0]]]

CTEsExec = [[np.mean(dataMap[key][graphKey]["exec"]) for key in dataMap] for graphKey in graphNames]
stdExec = [[np.std(dataMap[key][graphKey]["exec"]) for key in dataMap] for graphKey in graphNames]
errorExec = stdExec

#print(graphNames)
#print(keys)
#print(CTEsExec)

plt.rcParams["axes.xmargin"] = 0
plt.rcParams["figure.figsize"] = (7,4)

fig, ax = plt.subplots()



linestyle_tuple = [
     ('solid',               (0, ())),
     ('densely dotted',      (0, (1, 1))),

     ('loosely dashed',      (0, (5, 10))),
     ('dashed',              (0, (5, 5))),
     ('densely dashed',      (0, (5, 1))),

     ('loosely dashdotted',  (0, (3, 10, 1, 10))),
     ('dashdotted',          (0, (3, 5, 1, 5))),
     ('densely dashdotted',  (0, (3, 1, 1, 1))),

     ('loosely dashdotdotted', (0, (3, 10, 1, 10, 1, 10))),
     ('dashdotdotted',         (0, (3, 5, 1, 5, 1, 5))),
     ('densely dashdotdotted', (0, (3, 1, 1, 1, 1, 1)))]

graphNames = [key.replace("None", "Default") for key in graphNames]
graphInx = range(len(graphNames))

indexArray = sorted(graphInx, key= lambda indx: CTEsExec[indx][-1])[::-1]

for i in range(len(graphNames)):
    indx = indexArray[i]
    barExec = ax.errorbar(xpos, CTEsExec[indx], linestyle=linestyle_tuple[i][1], yerr=errorExec[indx], alpha=0.5, capsize=0, label=graphNames[indx])

ax.set_ylabel('Instructions Executed')
ax.set_xlabel('Input Size')
ax.set_xticks(xpos)
ax.set_xticklabels(keys)
ax.set_title(CSVNAME.split("-")[0].upper()+' Evaluation - Overhead Growth')
 
plt.legend() 
#ax.legend(handles=[mpatches.Patch(color='red', label='Execution Time'), mpatches.Patch(color='blue', label='File Size')])
plt.tight_layout()
plt.savefig("../output/"+CSVNAME+"n.svg")
plt.show()
