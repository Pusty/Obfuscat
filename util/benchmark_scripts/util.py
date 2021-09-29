import subprocess
import os
import sys
import random
import hashlib
import pathlib


STDOUT_MODE = subprocess.DEVNULL #subprocess.STDOUT
STDERR_MODE = subprocess.DEVNULL #subprocess.DEVNULL

def generateVerify(flag):
    f = open("../target/Verify.c", "w")
    
    condition = ""
    for i in range(len(flag)):
        condition = condition + " && message["+str(i)+"] == "+hex(ord(flag[i]))
    
    f.write("""unsigned int _binary___program_bin_start(unsigned char* message, unsigned int len) {
    if(len == """+str(len(flag))+condition+""") return 1;
    return 0;
    }""")
    f.close()
    
def generateGCC(file):
    if not os.getcwd().endswith("tmp"):
        print("ERROR")
        sys.exit(-1)
    subprocess.Popen(("arm-linux-gnueabi-gcc -march=armv8-a -mthumb -Wall ../target/wrapper.c ../target/"+file+".c").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("cp a.out gcc.elf").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()


# generateOLLVM("CRC32", "bcf")
def generateOLLVM(file, obf):
    if not os.getcwd().endswith("tmp"):
        print("ERROR")
        sys.exit(-1)
    subprocess.Popen(("../ollvm/bin/clang ../target/wrapper.c ../target/"+file+".c -target thumbv8-pc-linux-eabi -mllvm -"+obf).split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("cp a.out ollvm.elf").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()

# generateObfuscat("CRC32", "Bogus")
def generateObfuscat(file, obf):
    if not os.getcwd().endswith("tmp"):
        print("ERROR")
        sys.exit(-1)
    subprocess.Popen(("cp ../target/"+file+".java .").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("javac --release 8 ./"+file+".java").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("java -jar ../obfuscat/Obfuscat.jar builder Class -path "+file+".class -entry entry -merge").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    generateObfuscatObf(obf)
    
def generateObfuscatObf(obf):
    if not os.getcwd().endswith("tmp"):
        print("ERROR")
        sys.exit(-1)
    if obf != None and obf != "None": 
        obfList = []
        if(isinstance(obf, list)):
            obfList = obf
        else:
            obfList = [obf]
        for obfS in obfList:
            subprocess.Popen(("java -jar ../obfuscat/Obfuscat.jar obfuscate "+obfS+" -input build.fbin -output build.fbin").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    
    subprocess.Popen(("java -jar ../obfuscat/Obfuscat.jar compile Thumb -input build.fbin").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("cp ./output.bin ./program.bin").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("cp ../target/wrapper.c .").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("arm-linux-gnueabi-ld -r -b binary -o ./program.bin.o ./program.bin").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("arm-linux-gnueabi-objcopy --rename-section .data=.text ./program.bin.o").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("arm-linux-gnueabi-gcc -march=armv8-a -mthumb ../target/wrapper.c ./program.bin.o -o ./a.out").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
    subprocess.Popen(("cp a.out obfuscat.elf").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()

# generateTigress("CRC32", "--Transform=InitOpaque --Functions=main --Transform=UpdateOpaque --Functions=_binary___program_bin_start --Transform=AddOpaque --Functions=_binary___program_bin_start")
def generateTigress(file, obf):
    if not os.getcwd().endswith("tmp"):
        print("ERROR")
        sys.exit(-1)
    my_env = os.environ.copy()
    my_env["TIGRESS_HOME"] = os.getcwd()+"/../tigress/3.1"
    my_env["PATH"] = my_env["TIGRESS_HOME"] + ":" + my_env["PATH"]
    subprocess.Popen(("../tigress/3.1/tigress-merge ../target/wrapper.c ../target/"+file+".c --out=../tmp/tmp.c").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE, env=my_env).wait()
    subprocess.Popen(("rm a.out a.out_comb.o").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE, env=my_env).wait()
    subprocess.Popen(("../tigress/3.1/tigress --Seed=0 --Environment=armv8:Linux:Gcc:4.6 --gcc=arm-linux-gnueabi-gcc "+obf+" --out=../tmp/otmp.c ../tmp/tmp.c").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE, env=my_env).wait()
    subprocess.Popen(("cp a.out tigress.elf").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()

def profile(tag, inputString):
    proc = subprocess.Popen(("qemu-arm -singlestep -d exec,nochain -cpu cortex-a15 -L /usr/arm-linux-gnueabi/ ../tmp/a.out "+inputString).split(" "),stderr=subprocess.PIPE)

    instructions = 0
    for stdout_line in iter(proc.stderr.readline, ""):
        if not stdout_line: break
        stdout_line = stdout_line.decode("utf-8").strip()
        if not (': ' in stdout_line): continue
        #print(stdout_line)
        instructions += 1
        
    return_code = proc.wait()
    
    #executed instructions, file size, sha256 hash, returned value
    return (tag, instructions, os.path.getsize('../tmp/a.out'), hashlib.sha256(pathlib.Path('../tmp/a.out').read_bytes()).hexdigest(), return_code)


OBFUSCATOR_FLAGS = {
    "BCF": {
        "OLLVM": "bcf",
        "Obfuscat": "Bogus",
        "Tigress": "--Transform=InitOpaque --Functions=main --Transform=UpdateOpaque --Functions=_binary___program_bin_start --Transform=AddOpaque --Functions=_binary___program_bin_start"
    },
    "FLA": {
        "OLLVM": "fla",
        "Obfuscat": "Flatten",
        "Tigress": "--Transform=Flatten --Functions=_binary___program_bin_start --FlattenRandomizeBlocks=true"
    },
    "SUB": {
        "OLLVM": "sub",
        "Obfuscat": "OperationEncode",
        "Tigress": "--Transform=EncodeArithmetic --Functions=_binary___program_bin_start"
    },
    "VIRT": {
        "Obfuscat": "Virtualize",
    },
    "FAKE": {
        "Obfuscat": "FakeDependency",
    },
    "LITERAL": {
        "Obfuscat": "LiteralEncode",
    },
    "VARIABLE": {
        "Obfuscat": "VariableEncode",
    }
}

os.chdir('../tmp')
#generateObfuscat("Verify", "FLA")


subprocess.Popen(("java -jar ../obfuscat/Obfuscat.jar builder Verify -data 'Potato'").split(" "), stdout=STDOUT_MODE, stderr=STDERR_MODE).wait()
generateObfuscatObf("Flatten")