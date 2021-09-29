import numpy as np
import csv
import sys

# crc32-2021-08-14-06-01-56 rc4-2021-08-13-14-10-56, sha1-2021-08-14-07-18-15
CSVNAME = "Obfuscat-sha1-2021-08-29-05-00-30"

# NOTE IMPORTANT: OLLVM is screwed up in all of these, the obfuscations weren't applied >____>
# Need to recalculate these values after fixing the issue

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

keys = [key.split("-")[0]+"-"+key.split("-")[-1] for key in dataMap[NUMKEY]]
xpos = np.arange(len(keys))
CTEsExec = [np.mean(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]]
stdExec = [np.std(dataMap[NUMKEY][key]["exec"]) for key in dataMap[NUMKEY]]
errorExec = stdExec
CTEsSize = [np.mean(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]]
stdSize = [np.std(dataMap[NUMKEY][key]["size"]) for key in dataMap[NUMKEY]]
errorSize = stdSize


baseExec = CTEsExec[0]
baseSize = CTEsSize[0]


output = """\\section{Table}
\\begin{table}[H]
\\centering
\\caption[PLACEHOLDER ENTRY]{"""+CSVNAME+" \\# "+str(NUMKEY)+"""}
\\begin{tabular}{l|llllll}
$Method$ & Instructions & $\sigma$ & Size & $\sigma$ \\\ \\hline\\hline
"""

for i in range(len(keys)):
    if "OLLVM" in keys[i]: continue # skip messed up values
    key, mExec, sdExec, mSize, sdSize =  (keys[i], CTEsExec[i], errorExec[i], CTEsSize[i], errorSize[i])
    tableLine = "%s & $%.2f$ & $%.2f\\%%$ & $%.2f$ & $%.2f\\%%$ \\\\" % (key, (mExec/baseExec), (sdExec/mExec)*100.0, (mSize/baseSize), (sdSize/mSize)*100.0)
    output = output + tableLine + "\n"
    
output = output + """\\end{tabular}
\\end{table}"""
print(output)

"""\section{Table}
\begin{table}[H]
\centering
\caption[PLACEHOLDER ENTRY]{PLACEHOLDER DESCRIPTION}
\begin{tabular}{l|llllll}
$Method$ & Size & $\sigma$ & Instructions & $\sigma$ \\ \hline\hline
$f(t)$ & 1 & 1 & 4 & 9 \\
$f(t)$ & 1 & 1 & 4 & 9 \\
$f(t)$ & 1 & 1 & 4 & 9 \\
\end{tabular}
\end{table}
"""