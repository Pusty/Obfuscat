import angr


ref = open("output.bin", "rb")
ref_data = ref.read()
ref.close()

project = angr.project.load_shellcode(ref_data, "Thumb", 0x1000001, 0x1000000)
state = project.factory.entry_state()

#state.memory.store(0x2000000, memory, disable_actions=True, inspect=False)
#state.memory.permissions(0x2000000, 4)

#memory = "\0"*64

for i in range(64):
    inp = state.solver.BVS("inp", 8)
    state.memory.store(0x2000000+i, inp) #, disable_actions=True, inspect=False)
#state.memory.permissions(0x2000000, 5)

state.regs.r0 = 0x2000000
state.regs.r1 = 0
state.regs.r2 = 0
state.regs.r3 = 0
state.regs.sp = 0x1200000

sm = project.factory.simgr(state)

print(sm)

while sm.active:
    ac = sm.active[0]
    print([(ac.mem[0x2000000+offset].uint8_t.resolved) for offset in range(8)])
    print([chr(ac.solver.eval(ac.mem[0x2000000+offset].uint8_t.resolved)) for offset in range(8)])
    sm.step()