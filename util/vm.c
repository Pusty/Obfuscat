#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#define OP_CONST   0x00 // CONST <X> - 00 XX XX XX RR XX
#define OP_LOAD8   0x01 // LOAD <SLOT S> - 01 SS SS 00 RR 00
#define OP_LOAD16  0x02
#define OP_LOAD32  0x03
#define OP_LOADP   0x04
#define OP_PLOAD8  0x05 // parameter load
#define OP_PLOAD16 0x06
#define OP_PLOAD32 0x07
#define OP_PLOADP  0x08
#define OP_STORE8  0x09 // STORE <SLOT S> <STORE CC> - 02 SS SS 00 CC 00
#define OP_STORE16 0x0A 
#define OP_STORE32 0x0B 
#define OP_STOREP  0x0C 
#define OP_ALOAD8 0x0D // ALOAD  <ARRAY A> <INDEX I> - 03 AA II 00 RR 00
#define OP_ALOAD16 0x0E
#define OP_ALOAD32 0x0F
#define OP_ALOADP 0x10
#define OP_ASTORE8 0x11 // ASTORE <ARRAY A> <INDEX I> <DATA D> - 04 AA II 00 DD 00
#define OP_ASTORE16 0x12
#define OP_ASTORE32 0x13
#define OP_ASTOREP 0x14
#define OP_NOT 0x15 // MATH <OP1 A> <OP2 B> - 05 AA BB 00 RR 00
#define OP_NEG 0x16
#define OP_NOP 0x17
#define OP_ADD 0x18
#define OP_SUB 0x19
#define OP_MUL 0x1A
#define OP_DIV 0x1B
#define OP_MOD 0x1C
#define OP_AND 0x1D
#define OP_OR 0x1E
#define OP_XOR 0x1F
#define OP_SHR 0x20
#define OP_USHR 0x21
#define OP_SHL 0x22
#define OP_COMPARE_EQUAL 0x23 // COMPARE <OP1 A> <OP2 B> <CONDITIONALJUMP J> - 06 AA BB JJ JJ 00
#define OP_COMPARE_NOTEQUAL 0x24
#define OP_COMPARE_LESSTHAN 0x25
#define OP_COMPARE_LESSEQUAL 0x26
#define OP_COMPARE_GREATERTHAN 0x27
#define OP_COMPARE_GREATEREQUAL 0x28
#define OP_SWITCH 0x29 // SWITCH <SWITCHVAR S> - 07 SS 00 00 00 00
#define OP_JUMP 0x2A // JUMP <JUMP J> 08 00 00 JJ JJ 00
#define OP_RETURN 0x2B // RETURN < <VALUE V> 09 VV 00 00 00 00
#define OP_RETURNV 0x2C 
#define OP_ALLOC8 0x2D // ALLOC <COUNT CC> - 2D CC 00 00 RR 00
#define OP_ALLOC16 0x2E
#define OP_ALLOC32 0x2F
#define OP_ALLOCP 0x30
#define OP_PSTORE8  0x31 // STORE <SLOT S> <STORE CC> - 02 SS SS 00 CC 00
#define OP_PSTORE16 0x32 
#define OP_PSTORE32 0x33
#define OP_PSTOREP  0x34 
#define OP_OCONST  0x35  // OCONST <X> - 00 XX XX XX RR XX


union MEM_SLOT {
  void* pV;
  int   iV;
  short sV;
  char  bV;
};

union MEM_SLOT vm(char* program, union MEM_SLOT* appendedData, union MEM_SLOT* pars) {

		union MEM_SLOT* memory = malloc((0x100+0x100)*sizeof(union MEM_SLOT));
		int pc = 0;
		
		while(1) {
			int opcode = program[pc]&0xFF;
			
            int index;
			int data;
			int memslot;
			int op1;
			int op2;
			short jumpPosition;
			int stackslot;
			
			data = (program[pc+1]&0xFF)|((program[pc+2]&0xFF)<<8)|((program[pc+3]&0xFF)<<16)|(program[pc+5]<<24);
			op1     = program[pc+1]&0xFF;
			op2     = program[pc+2]&0xFF;
			jumpPosition = (short) ((program[pc+3]&0xFF) | (program[pc+4]<<8));
			memslot = (program[pc+1]&0xFF)|((program[pc+2]&0xFF)<<8);
			stackslot = (program[pc+4]&0xFF);
			
			switch(opcode) {
			case OP_CONST:
				memory[stackslot].iV = data;
				break;
			case OP_LOAD8:
				memory[stackslot].iV = memory[memslot+0x100].bV;
				break;
			case OP_LOAD16:
				memory[stackslot].iV = memory[memslot+0x100].sV;
				break;
			case OP_LOAD32:
				memory[stackslot].iV = memory[memslot+0x100].iV;
				break;
			case OP_LOADP:
				memory[stackslot].pV = memory[memslot+0x100].pV;
				break;
			case OP_PLOAD8:
				memory[stackslot].iV = pars[memslot].bV;
				break;
			case OP_PLOAD16:
				memory[stackslot].iV = pars[memslot].sV;
				break;
			case OP_PLOAD32:
				memory[stackslot].iV = pars[memslot].iV;
				break;
			case OP_PLOADP:
				memory[stackslot].pV = pars[memslot].pV;
				break;
			case OP_STORE8:
				memory[memslot+0x100].iV = (memory[stackslot].iV)&0xFF;
				break;
			case OP_STORE16:
				memory[memslot+0x100].iV = (memory[stackslot].iV)&0xFFFF;
				break;
			case OP_STORE32:
				memory[memslot+0x100].iV = memory[stackslot].iV;
				break;
			case OP_STOREP:
				memory[memslot+0x100].pV = memory[stackslot].pV;
				break;
			case OP_PSTORE8:
				pars[memslot].iV = memory[stackslot].iV&0xFF;
				break;
			case OP_PSTORE16:
				pars[memslot].iV = memory[stackslot].iV&0xFFFF;
				break;
			case OP_PSTORE32:
				pars[memslot].iV = memory[stackslot].iV;
				break;
			case OP_PSTOREP:
				pars[memslot].pV = memory[stackslot].pV;
				break;
			case OP_ALOAD8:
				memory[stackslot].iV = ((char*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOAD16:
				memory[stackslot].iV = ((short*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOAD32:
				memory[stackslot].iV = ((int*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOADP:
				memory[stackslot].pV = ((void**)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ASTORE8:
                ((char*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].bV;
				break;
			case OP_ASTORE16:
				((short*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].sV;
				break;
			case OP_ASTORE32:
				((int*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].iV;
				break;
			case OP_ASTOREP:
				((void**)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].pV;
				break;
			case OP_NOT:
				memory[stackslot].iV = ~(memory[op1].iV);
				break;
			case OP_NEG:
				memory[stackslot].iV = -(memory[op1].iV);
				break;
			case OP_NOP:
				memory[stackslot].iV = (memory[op1].iV);
				break;
			case OP_ADD:
				memory[stackslot].iV = (memory[op1].iV) + (memory[op2].iV);
				break;
			case OP_SUB:
				memory[stackslot].iV = (memory[op1].iV) - (memory[op2].iV);
				break;
			case OP_MUL:
				memory[stackslot].iV = (memory[op1].iV) * (memory[op2].iV);
				break;
			case OP_DIV:
				memory[stackslot].iV = (memory[op1].iV) / (memory[op2].iV);
				break;
			case OP_MOD:
				memory[stackslot].iV = (memory[op1].iV) % (memory[op2].iV);
				break;		
			case OP_AND:
				memory[stackslot].iV = (memory[op1].iV) & (memory[op2].iV);
				break;	
			case OP_OR:
				memory[stackslot].iV = (memory[op1].iV) | (memory[op2].iV);
				break;	
			case OP_XOR:
				memory[stackslot].iV = (memory[op1].iV) ^ (memory[op2].iV);
				break;	
			case OP_SHR:
				memory[stackslot].iV = (memory[op1].iV) >> (memory[op2].iV);
				break;	
			case OP_USHR:
				memory[stackslot].iV = (((unsigned int)memory[op1].iV) >> ((unsigned int)memory[op2].iV));
				break;
			case OP_SHL:
				memory[stackslot].iV = (memory[op1].iV) << (memory[op2].iV);
				break;
			case OP_COMPARE_EQUAL:
				if(memory[op1].iV == memory[op2].iV)
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_NOTEQUAL:
				if(memory[op1].iV != memory[op2].iV)
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_LESSTHAN:
				if((memory[op1].iV) < (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_LESSEQUAL:
				if((memory[op1].iV) <= (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_GREATERTHAN:
				if((memory[op1].iV) > (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_GREATEREQUAL:
				if((memory[op1].iV) >= (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_SWITCH:
				index = pc+6+((memory[op1].iV)*2);
				pc += ((short)((program[index]&0xFF) + (program[index+1]<<8)));
				break;
			case OP_JUMP:
				pc += ((int)jumpPosition-6);
				break;
			case OP_RETURN:
				return (union MEM_SLOT)0;
			case OP_RETURNV:
				return memory[op1];
			case OP_ALLOC8:
				memory[stackslot].pV = alloca(memory[op1].iV * sizeof(char));
				break;
			case OP_ALLOC16:
				memory[stackslot].pV = alloca(memory[op1].iV * sizeof(short));
				break;
			case OP_ALLOC32:
				memory[stackslot].pV = alloca(memory[op1].iV * sizeof(int));
				break;
			case OP_ALLOCP:
				memory[stackslot].pV = alloca(memory[op1].iV * sizeof(void*));
				break;
			case OP_OCONST:
				memory[stackslot].pV = appendedData[memory[op1].iV].pV;
				break;
			default:
                printf("ERROR: Illegal Opcode %02X @ %08X\n", opcode, pc);
				return (union MEM_SLOT)0;
			}
			
			pc += 6;
			
		}
}


int main(int argc, char** argv) {
    if(argc != 2) {
        puts("Usage ./vm <input>");
        return 1;
    }
    
    char* fileName = "verify.vbin";
    
    FILE *filepointer;
    long size;
    char *buffer;

    filepointer = fopen(fileName,"rb");
    if( !filepointer ) {
        printf("Couldn't open the file %s\n", fileName);
        exit(1);
    }

    fseek(filepointer, 0L, SEEK_END);
    size = ftell(filepointer);
    rewind(filepointer);

    buffer = malloc(size+1);
    if( !buffer ) {
        fclose(filepointer);
        puts("Memory allocation failed");
        exit(1);
    }

    if(fread(buffer , size, 1 , filepointer) != 1) {
        fclose(filepointer);
        puts("Reading the file failed");
        exit(1);
    }


    union MEM_SLOT appendedData[] = {};
    union MEM_SLOT parameter[] = {argv[1], (union MEM_SLOT)((int)strlen(argv[1]))};

    int value = vm(buffer, appendedData, parameter).iV;
    printf("=> %d\n", value);

    fclose(filepointer);
    free(buffer);

    
    return 0;
}