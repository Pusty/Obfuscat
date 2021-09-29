import matplotlib.pyplot as plt
import numpy as np
import csv
import sys

FILENAME = "angrevalCombined"

dataMap = {}

with open("../logs/"+FILENAME+".txt", newline='') as csvfile:
    for line in csvfile:
        row = line[1:][:-2].replace("'", "").replace(" ", "").split(",")
        if not (row[0] in dataMap):
            dataMap[row[0]] = []
        dataMap[row[0]].append((float(row[1])))
        
print(dataMap)

NUMKEY = 4

plt.rcParams["axes.xmargin"] = 0.02
plt.rcParams["figure.figsize"] = (7,4)

keys = [key.split("-")[0]+"\n"+key.split("-")[-1] for key in dataMap]
keys = [key.replace("None", "Default").replace("Obfuscat\nFLA", "Obfuscat\nFLA+").replace("Obfuscat", "Obfus-\ncat") for key in keys]
xpos = np.arange(len(keys))
CTEs = [np.mean(dataMap[key]) for key in dataMap]
error = [np.std(dataMap[key]) for key in dataMap]

fig, ax = plt.subplots()
g = ax.bar(xpos, CTEs, yerr=error, alpha=0.5, align='center', ecolor='black', capsize=15)
ax.set_ylabel('Execution Time in Seconds')
ax.set_xticks(xpos)
ax.set_xticklabels(keys)
ax.set_title('Angr Evaluation Len - 64')

for i, rectangle in enumerate(g):
    height = rectangle.get_height()
    plt.text(rectangle.get_x() + rectangle.get_width()/2, height+error[i] + 0.3,
         '%ss' % (str(round(height,3))),
             ha='center', va='bottom')


    
plt.tight_layout()
plt.savefig("../output/"+FILENAME+".svg")
plt.show()