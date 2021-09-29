import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import csv
import sys

CSVNAME = "rc4"

MODE = False # True = Size, False = Inst

NOT_MODE = not MODE

# OLLVM-CRC32-BCF-4,105101,8316,9b0729bc40d2f2046fcf1c611d090babf41ffd1e24b2716153ee82f9acefc17f,70
dataMap = {}

with open("../logs/"+CSVNAME+".csv", newline='') as csvfile:
    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        idx = int(row[0].split("-")[-1])
        tag = row[0].split("-")[0]+"-"+row[0].split("-")[2]
        if not (idx in dataMap):
            dataMap[idx] = {}
        if not (tag in dataMap[idx]):
            dataMap[idx][tag] = {"exec": [], "size": []}
        
        dataMap[idx][tag]["exec"].append(int(row[1]))
        dataMap[idx][tag]["size"].append(int(row[2]))

NUMKEY = 1024

plt.rcParams["axes.xmargin"] = 0
plt.rcParams["figure.figsize"] = (7,4)





keys = [key.split("-")[0]+"\n"+key.split("-")[-1] for key in dataMap[NUMKEY]]
xpos = np.arange(len(keys))
CTEsExec = [np.mean(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]]
stdExec = [np.std(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]]
errorExec = stdExec
#errorExec = [[np.mean(dataMap[NUMKEY][key]["exec"])-np.min(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]], [np.max(dataMap[NUMKEY][key]["exec"])-np.mean(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]]]
CTEsSize = [np.mean(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]]
stdSize = [np.std(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]]
errorSize = stdSize
#errorSize = [[np.mean(dataMap[NUMKEY][key]["size"])-np.min(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]], [np.max(dataMap[NUMKEY][key]["size"])-np.mean(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]]]
# executed instructions, file size
fig, ax = plt.subplots()


if MODE:
    barSize = ax.bar(xpos, CTEsSize, yerr=errorSize, alpha=0.5, ecolor='blue', capsize=15, visible=False)
if NOT_MODE:
    barExec = ax.bar(xpos, CTEsExec, yerr=errorExec, alpha=0.5, ecolor='red', capsize=15, visible=False)

if MODE and NOT_MODE:
    ax.set_ylabel('Size in Bytes / Instructions Executed')
elif MODE:
    ax.set_ylabel('Size in Bytes')
else:
    ax.set_ylabel('Instructions Executed')
ax.set_xticks(xpos)

keys = [key.replace("None", "Default").replace("Obfuscat", "Obfus-\ncat") for key in keys]
#keys = [key.replace("None", "Default").replace("BCF", "Bogus\nControl Flow").replace("FLA", "Flatten").replace("SUB", "Operation\nEncoding") for key in keys]
ax.set_xticklabels(keys)

if MODE and NOT_MODE:
    ax.set_title(CSVNAME.split("-")[0].upper()+' Evaluation - Output File Size\n'+'Instructions Executed '+str(NUMKEY)+" Bytes Input Length")
elif MODE:
    ax.set_title(CSVNAME.split("-")[0].upper()+' Evaluation - Output File Size')
else:
    ax.set_title(CSVNAME.split("-")[0].upper()+' Evaluation - Instructions Executed\n'+str(NUMKEY)+" Bytes Input Length")

"""
if MODE:
    for i, rectangle in enumerate(barSize):
        height = rectangle.get_height()
        plt.text(rectangle.get_x() + rectangle.get_width()/2, height+stdSize[i] + 0.3,
#             '$\mu=$%s \n $\sigma=$%s' % (str(round(height,3)),     str(round(stdSize[i],3))[0:]),
              '$\sigma=$%s' % (str(round(stdSize[i],3))[0:]),
                 ha='center', va='bottom')

if NOT_MODE:
    for i, rectangle in enumerate(barExec):
        height = rectangle.get_height()
        plt.text(rectangle.get_x() + rectangle.get_width()/2, height+stdExec[i] + 0.3,
#             '$\mu=$%s \n $\sigma=$%s' % (str(round(height,3)),     str(round(stdExec[i],3))[0:]),
              '$\sigma=$%s' % (str(round(stdExec[i],3))[0:]),
                 ha='center', va='bottom')
"""

if MODE and NOT_MODE:
    ax.legend(handles=[mpatches.Patch(color='red', label='Amount of Instructions Executed'), mpatches.Patch(color='blue', label='File Size in Bytes')])
    
if MODE:
    plt.ylim(bottom=sorted(CTEsSize)[0]-sorted(errorSize)[-1])
else:
    plt.ylim(bottom=sorted(CTEsExec)[0]-sorted(errorExec)[-1])

    
plt.tight_layout()

if MODE and NOT_MODE:
    pass
elif MODE:
    plt.savefig("../output/"+CSVNAME+"-SIZE.svg")
else:
    plt.savefig("../output/"+CSVNAME+"-INST.svg")
#plt.savefig("../output/"+CSVNAME+".svg")
plt.show()
