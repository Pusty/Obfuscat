import angr
import sys

# time: verify.bin        1.325s
# time: verify.vm.bin     
# time: verify.vm.vm.bin  

ref = open(sys.argv[1], "rb")
ref_data = ref.read()
ref.close()

project = angr.project.load_shellcode(ref_data, "Thumb", 0x1000001, 0x1000000)
state = project.factory.entry_state()

#state.memory.store(0x4000000, (b'\x00')*0x100000)
#state.memory.permissions(0x4000000, 4)

@project.hook(0xDEADC0DE, length=4)
def exit_lr(state):
    return []

for i in range(8):
    inp = state.solver.BVS("inp", 8)
    state.memory.store(0x2000000+i, inp) #, disable_actions=True, inspect=False)

inpLen = state.solver.BVS("inpLen", 64)
state.regs.r0 = 0x2000000
state.regs.r1 = inpLen
state.regs.r2 = 0
state.regs.r3 = 0
state.regs.r4 = 0
state.regs.r5 = 0
state.regs.r6 = 0
state.regs.r7 = 0
state.regs.r8 = 0
state.regs.lr = 0xDEADC0DE
state.regs.sp = 0x4000000

sm = project.factory.simgr(state)

sm.run()
print(sm)
for state in sm.deadended:
    state.solver.add(state.regs.r0 == 1)
    if not state.satisfiable(): continue
    val = int(state.solver.eval(inpLen))
    pw = ""
    for i in range(val):
        pw = pw + chr(int(state.solver.eval(state.memory.load(0x2000000+i, 1))))
    print("Password: "+pw)