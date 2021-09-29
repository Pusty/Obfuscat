import angr
import claripy
import os
import sys
import timeit

SECRET_FLAG = 'ABCD1234'*4


def runAngr():
    inpStr = claripy.BVS("inpStr", 8*(len(SECRET_FLAG)+1))
    project = angr.Project('a.out')
    state = project.factory.entry_state(args=['./a.out', inpStr], add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    sm = project.factory.simgr(state)

    sm.run()
    solutions = 0
    for state in sm.deadended:
        state.solver.add(state.regs.r0 == 1)
        if not state.satisfiable(): continue
        answer = state.solver.eval(inpStr, cast_to=bytes).decode("utf-8")
        if(answer[:len(SECRET_FLAG)] != SECRET_FLAG): 
            print("[!] WRONG ANSWER: "+answer)
        else:
            solutions = solutions + 1
            
    if solutions == 0:
        print("[!] No solutions found? "+str(sm))
    if solutions > 1:
        print("[!] Multiple solutions found? "+str(sm))
        
os.chdir('../tmp')
v = timeit.timeit(stmt=runAngr, number=1)
print((sys.argv[1], v))
