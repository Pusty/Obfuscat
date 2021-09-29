#include <stdio.h>
#include <stdint.h>
#include <string.h>



/*

sudo apt-get install gcc-arm-linux-gnueabi binutils-arm-linux-gnueabi

arm-linux-gnueabi-ld  -r -b binary -o program.bin.o program.bin
arm-linux-gnueabi-objcopy --rename-section .data=.text program.bin.o
arm-linux-gnueabi-gcc -march=armv8-a -mthumb wrapper.c program.bin.o -o wrapper.elf
qemu-arm -cpu cortex-a15 -L /usr/arm-linux-gnueabi/ wrapper.elf test

qemu-arm  -singlestep -d in_asm,nochain -cpu cortex-a15 -L /usr/arm-linux-gnueabi/ wrapper.elf test

*/

// alignment to 16 byte boundary for thumb code is important
extern uint32_t _binary___program_bin_start(unsigned char* message, unsigned int len) __attribute__((aligned (16)));

int main(int argc, char** argv) {
    if(argc != 2) {
        puts("Usage ./binary <input_str>");
        return 1;
    }
    
    uint32_t len = strlen(argv[1]);

    uint32_t ret = _binary_program_bin_start(argv[1], len, 0, 0);
    
    printf("Running program with input len('%s') = %d returned %08X \n", argv[1], len, ret);
    
    return 0;
}

#if defined(__GNUC__) || defined(__GNUG__)
__asm__(".balign 16");
#endif