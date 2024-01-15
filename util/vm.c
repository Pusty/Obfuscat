#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

//#define DEBUG

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


#define OP_CUSTOM_PREPCALL  0x36  // PREPCALL <X> <X> <X> <X> - 00 XX XX XX RR XX
#define OP_CUSTOM_CALL      0x37  // CALL <X> - 00 XX 00 00 RR 00


union MEM_SLOT {
  void* pV;
  int   iV;
  short sV;
  char  bV;
};

typedef union MEM_SLOT MEM_SLOT;

MEM_SLOT vm(char* program, MEM_SLOT* appendedData, MEM_SLOT* pars) {
		MEM_SLOT* memory = malloc((0x100+0x100)*sizeof(MEM_SLOT));
		int pc = 0;
		while(1) {
			int opcode = program[pc]&0xFF;
            int index;
			int data;
			int memslot;
			int op1;
			int op2;
            int op3;
            int op4;
			short jumpPosition;
			int stackslot;
			
			data = (program[pc+1]&0xFF)|((program[pc+2]&0xFF)<<8)|((program[pc+3]&0xFF)<<16)|(program[pc+5]<<24);
			op1     = program[pc+1]&0xFF;
			op2     = program[pc+2]&0xFF;
			op3     = program[pc+3]&0xFF;
			op4     = program[pc+5]&0xFF;
			jumpPosition = (short) ((program[pc+3]&0xFF) | (program[pc+4]<<8));
			memslot = (program[pc+1]&0xFF)|((program[pc+2]&0xFF)<<8);
			stackslot = (program[pc+4]&0xFF);
			switch(opcode) {
			case OP_CONST:
                #ifdef DEBUG
                    printf("%08X [%d]CONST = %d\n", pc, stackslot, data);
                #endif
				memory[stackslot].iV = data;
				break;
			case OP_LOAD8:
                #ifdef DEBUG
                    printf("%08X [%d]LOAD8 = %d\n", pc, stackslot, memory[memslot+0x100].bV);
                #endif
				memory[stackslot].iV = memory[memslot+0x100].bV;
				break;
			case OP_LOAD16:
                #ifdef DEBUG
                    printf("%08X [%d]LOAD16 = %d\n", pc, stackslot, memory[memslot+0x100].sV);
                #endif
				memory[stackslot].iV = memory[memslot+0x100].sV;
				break;
			case OP_LOAD32:
                #ifdef DEBUG
                    printf("%08X [%d]LOAD32 = %d\n", pc, stackslot, memory[memslot+0x100].iV);
                #endif
				memory[stackslot].iV = memory[memslot+0x100].iV;
				break;
			case OP_LOADP:
                #ifdef DEBUG
                    printf("%08X [%d]LOADP = %p\n", pc, stackslot, memory[memslot+0x100].pV);
                #endif
				memory[stackslot].pV = memory[memslot+0x100].pV;
				break;
			case OP_PLOAD8:
                #ifdef DEBUG
                    printf("%08X [%d]PLOAD8 = %d @ %d\n", pc, stackslot, pars[memslot].bV, memslot);
                #endif
				memory[stackslot].iV = pars[memslot].bV;
				break;
			case OP_PLOAD16:
                #ifdef DEBUG
                    printf("%08X [%d]PLOAD16 = %d @ %d\n", pc, stackslot, pars[memslot].sV, memslot);
                #endif
				memory[stackslot].iV = pars[memslot].sV;
				break;
			case OP_PLOAD32:
                #ifdef DEBUG
                    printf("%08X [%d]PLOAD32 = %d @ %d\n", pc, stackslot, pars[memslot].iV, memslot);
                #endif
				memory[stackslot].iV = pars[memslot].iV;
				break;
			case OP_PLOADP:
                #ifdef DEBUG
                    printf("%08X [%d]PLOADP = %p @ %d\n", pc, stackslot, pars[memslot].pV, memslot);
                #endif
				memory[stackslot].pV = pars[memslot].pV;
				break;
			case OP_STORE8:
                #ifdef DEBUG
                    printf("%08X [%d]STORE8 = %d\n", pc, memslot+0x100, (memory[stackslot].iV)&0xFF);
                #endif
				memory[memslot+0x100].iV = (memory[stackslot].iV)&0xFF;
				break;
			case OP_STORE16:
                #ifdef DEBUG
                    printf("%08X [%d]STORE16 = %d\n", pc, memslot+0x100, (memory[stackslot].iV)&0xFFFF);
                #endif
				memory[memslot+0x100].iV = (memory[stackslot].iV)&0xFFFF;
				break;
			case OP_STORE32:
                #ifdef DEBUG
                    printf("%08X [%d]STORE32 = %d\n", pc, memslot+0x100, memory[stackslot].iV);
                #endif
				memory[memslot+0x100].iV = memory[stackslot].iV;
				break;
			case OP_STOREP:
                #ifdef DEBUG
                    printf("%08X [%d]STOREP = %p\n", pc, memslot+0x100, memory[stackslot].pV);
                #endif
				memory[memslot+0x100].pV = memory[stackslot].pV;
				break;
			case OP_PSTORE8:
                #ifdef DEBUG
                    printf("%08X pars[%d]PSTORE8 = %d\n", pc, memslot, memory[stackslot].iV&0xFF);
                #endif
				pars[memslot].iV = memory[stackslot].iV&0xFF;
				break;
			case OP_PSTORE16:
                #ifdef DEBUG
                    printf("%08X pars[%d]PSTORE16 = %d\n", pc, memslot, memory[stackslot].iV&0xFFFF);
                #endif
				pars[memslot].iV = memory[stackslot].iV&0xFFFF;
				break;
			case OP_PSTORE32:
                #ifdef DEBUG
                    printf("%08X pars[%d]PSTORE32 = %d\n", pc, memslot, memory[stackslot].iV);
                #endif
				pars[memslot].iV = memory[stackslot].iV;
				break;
			case OP_PSTOREP:
                #ifdef DEBUG
                    printf("%08X pars[%d]PSTOREP = %p\n", pc, memslot, memory[stackslot].pV);
                #endif
				pars[memslot].pV = memory[stackslot].pV;
				break;
			case OP_ALOAD8:
                #ifdef DEBUG
                    printf("%08X [%d]ALOAD8 = %d\n", pc, stackslot, ((char*)memory[op1].pV)[(memory[op2].iV)]);
                #endif
				memory[stackslot].iV = ((char*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOAD16:
                #ifdef DEBUG
                    printf("%08X [%d]ALOAD16 = %d\n", pc, stackslot, ((short*)memory[op1].pV)[(memory[op2].iV)]);
                #endif
				memory[stackslot].iV = ((short*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOAD32:
                #ifdef DEBUG
                    printf("%08X [%d]ALOAD32 = %d\n", pc, stackslot, ((int*)memory[op1].pV)[(memory[op2].iV)]);
                #endif
				memory[stackslot].iV = ((int*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOADP:
                #ifdef DEBUG
                    printf("%08X [%d]ALOADP = %p\n", pc, stackslot, ((void**)memory[op1].pV)[(memory[op2].iV)]);
                #endif
				memory[stackslot].pV = ((void**)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ASTORE8:
                #ifdef DEBUG
                    printf("%08X [%p]ASTORE8 = %d\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].bV);
                #endif
                ((char*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].bV;
				break;
			case OP_ASTORE16:
                #ifdef DEBUG
                    printf("%08X [%p]ASTORE16 = %d\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].sV);
                #endif
				((short*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].sV;
				break;
			case OP_ASTORE32:
                #ifdef DEBUG
                    printf("%08X [%p]ASTORE32 = %d\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].iV);
                #endif
				((int*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].iV;
				break;
			case OP_ASTOREP:
                #ifdef DEBUG
                    printf("%08X [%p]ASTOREP = %p\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].pV);
                #endif
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
                #ifdef DEBUG
                    printf("%08X RETURN\n", pc);
                #endif
                free(memory);
				return (MEM_SLOT)0;
			case OP_RETURNV:
                MEM_SLOT retval = memory[op1];
                #ifdef DEBUG
                    printf("%08X RETURNV => %p\n", pc, retval.pV);
                #endif
                free(memory);
				return retval;
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
                #ifdef DEBUG
                    printf("%08X [%d]OCONST = appendedData[%d]\n", pc, stackslot, data);
                #endif
				memory[stackslot].pV = appendedData[data].pV;
				break;
            case OP_CUSTOM_PREPCALL:
                #ifdef DEBUG
                    printf("%08X [%d]CUSTOM_PREPCALL = {%p %p %p %p}\n", pc, stackslot, memory[op1].pV, memory[op2].pV, memory[op3].pV, memory[op4].pV);
                #endif
                MEM_SLOT* buffer = (MEM_SLOT*)alloca(4 * sizeof(MEM_SLOT));
                buffer[0].pV = memory[op1].pV;
                buffer[1].pV = memory[op2].pV;
                buffer[2].pV = memory[op3].pV;
                buffer[3].pV = memory[op4].pV;
                memory[stackslot].pV = buffer;
                break;
            case OP_CUSTOM_CALL:
                #ifdef DEBUG
                    printf("%08X [%d]CUSTOM_CALL = %p @ %d\n", pc, stackslot, memory[op1].pV, op1);
                #endif
                memory[stackslot] = vm(program, appendedData, (MEM_SLOT*)memory[op1].pV);
                break;
			default:
                printf("ERROR: Illegal Opcode %02X @ %08X\n", opcode, pc);
				return (MEM_SLOT)0;
			}
			
			pc += 6;
			
		}
}

        
char data0[] = {-115, 1, 2, 4, 8, 16, 32, 64, -128, 27, 54};
char data1[] = {82, 9, 106, -43, 48, 54, -91, 56, -65, 64, -93, -98, -127, -13, -41, -5, 124, -29, 57, -126, -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, -23, -53, 84, 123, -108, 50, -90, -62, 35, 61, -18, 76, -107, 11, 66, -6, -61, 78, 8, 46, -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 109, -117, -47, 37, 114, -8, -10, 100, -122, 104, -104, 22, -44, -92, 92, -52, 93, 101, -74, -110, 108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 70, 87, -89, -115, -99, -124, -112, -40, -85, 0, -116, -68, -45, 10, -9, -28, 88, 5, -72, -77, 69, 6, -48, 44, 30, -113, -54, 63, 15, 2, -63, -81, -67, 3, 1, 19, -118, 107, 58, -111, 17, 65, 79, 103, -36, -22, -105, -14, -49, -50, -16, -76, -26, 115, -106, -84, 116, 34, -25, -83, 53, -123, -30, -7, 55, -24, 28, 117, -33, 110, 71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 98, 14, -86, 24, -66, 27, -4, 86, 62, 75, -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 90, -12, 31, -35, -88, 51, -120, 7, -57, 49, -79, 18, 16, 89, 39, -128, -20, 95, 96, 81, 127, -87, 25, -75, 74, 13, 45, -27, 122, -97, -109, -55, -100, -17, -96, -32, 59, 77, -82, 42, -11, -80, -56, -21, -69, 60, -125, 83, -103, 97, 23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 20, 99, 85, 33, 12, 125};
char data2[] = {99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118, -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 35, -61, 24, -106, 5, -102, 7, 18, -128, -30, -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, 127, 80, 60, -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, -68, -74, -38, 33, 16, -1, -13, -46, -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115, 96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22};

        

int main(int argc, char** argv) {
    if(argc != 2) {
        puts("Usage ./vm <input>");
        return 1;
    }
    
    char* fileName = "output.bin";
    
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


    //MEM_SLOT appendedData[] = {};
    //union MEM_SLOT parameter[] = {argv[1], (MEM_SLOT)((int)strlen(argv[1]))};
    MEM_SLOT appendedData[] = {data0, data1, data2};
    MEM_SLOT parameter[] = {(MEM_SLOT)((int)0), argv[1], (MEM_SLOT)((int)strlen(argv[1])), 0};

    int value = vm(buffer, appendedData, parameter).iV;
    printf("=> %d\n", value);

    fclose(filepointer);
    free(buffer);

    
    return 0;
}