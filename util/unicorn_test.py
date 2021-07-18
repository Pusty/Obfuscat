import sys
from unicorn import *
from unicorn.arm_const import *

ref = open(sys.argv[1], "rb")
ref_data = ref.read()
ref.close()

mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
mu.mem_map(0x1000000, 2 * 1024 * 1024)
mu.mem_map(0x2000000, 2 * 1024 * 1024)
mu.mem_map(0x4000000, 2 * 1024 * 1024)
mu.mem_write(0x1000000, ref_data)

mu.mem_write(0x2000000, b'SECRET')


mu.reg_write(UC_ARM_REG_R0, 0x2000000)
mu.reg_write(UC_ARM_REG_R1, 6)
mu.reg_write(UC_ARM_REG_R2, 0)
mu.reg_write(UC_ARM_REG_R3, 0)

mu.reg_write(UC_ARM_REG_SP, 0x4010000)
mu.reg_write(UC_ARM_REG_LR, 0xDEADC0DE)

try:
    mu.emu_start(0x1000001, 0x1000000 + len(ref_data))
except Exception as e:
    if mu.reg_read(UC_ARM_REG_PC) != 0xDEADC0DE:
        raise e

print(mu.reg_read(UC_ARM_REG_R0))