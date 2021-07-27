package re.bytecode.obfuscat.pass.vm;

import static re.bytecode.obfuscat.pass.vm.VMConst.*;

import java.util.HashMap;
import java.util.Random;

import re.bytecode.obfuscat.dsl.api.ExcludeField;
import re.bytecode.obfuscat.dsl.api.ExcludeMethod;

/**
 * This is a reference implementation for the VMConst Virtual Machine specs
 */
public class VMRefImpl {
	
	@ExcludeField
	private static Random addressRandomiser;
	@ExcludeField
	private static HashMap<Integer, Object> dataMap;
	@ExcludeField
	private static HashMap<Object, Integer> reverseMap;
	
	@ExcludeMethod
	private static void init() {
		if(addressRandomiser != null) return;
		addressRandomiser = new Random();
		dataMap = new HashMap<Integer, Object>();
		reverseMap = new HashMap<Object, Integer>();
	}
	
	@ExcludeMethod
	private static Object native_int2obj(int a) {
		init();
		if(dataMap.containsKey(a)) return dataMap.get(a);
		return a;
		//throw new RuntimeException("Can't convert integer "+a+" to object");
	}
	
	@ExcludeMethod
	private static int native_obj2int(Object o) {
		init();
		
		if(o instanceof Integer) return ((Integer)o).intValue();
		if(o instanceof Byte) return ((Byte)o).intValue();
		if(o instanceof Short) return ((Short)o).intValue();
		if(o instanceof Character) return (int)((Character)o).charValue();
		if(o instanceof Boolean) return ((Boolean)o).booleanValue()?1:0;
		
		if(reverseMap.containsKey(o)) {
			return reverseMap.get(o);
		}else {
			int addr = addressRandomiser.nextInt()&0x7FFFFFF;
			dataMap.put(addr, o);
			reverseMap.put(o, addr);
			return addr;
		}
	}
	
	
	
	// memory + 0x100 = mem
	public static int process(byte[] program, Object[] appendedData, Object[] pars) {
		
		int[] memory = new int[0x100+0x100];
		int pc = 0;
		
		while(true) {
			int opcode = program[pc]&0xFF;
			

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
			
			//System.out.println("Opcode: "+Integer.toHexString(opcode)+" @ "+pc);
			//System.out.println(Arrays.toString(memory));
			
			switch(opcode) {
			case OP_CONST:
				memory[stackslot] = data;
				break;
			case OP_LOAD8:
				memory[stackslot] = (byte)(memory[memslot+0x100]);
				break;
			case OP_LOAD16:
				memory[stackslot] = (short)(memory[memslot+0x100]);
				break;
			case OP_LOAD32:
				memory[stackslot] = memory[memslot+0x100];
				break;
			case OP_LOADP:
				memory[stackslot] = memory[memslot+0x100];
				break;
			case OP_PLOAD8:
				memory[stackslot] = (byte)native_obj2int(pars[memslot]);
				break;
			case OP_PLOAD16:
				memory[stackslot] = (short)native_obj2int(pars[memslot]);
				break;
			case OP_PLOAD32:
				memory[stackslot] = native_obj2int(pars[memslot]);
				break;
			case OP_PLOADP:
				memory[stackslot] = native_obj2int(pars[memslot]);
				break;
			case OP_STORE8:
				memory[memslot+0x100] = (memory[stackslot])&0xFF;
				break;
			case OP_STORE16:
				memory[memslot+0x100] = (memory[stackslot])&0xFFFF;
				break;
			case OP_STORE32:
				memory[memslot+0x100] = memory[stackslot];
				break;
			case OP_STOREP:
				memory[memslot+0x100] = memory[stackslot];
				break;
			case OP_PSTORE8:
				pars[memslot] = native_int2obj(memory[stackslot]&0xFF);
				break;
			case OP_PSTORE16:
				pars[memslot] = native_int2obj(memory[stackslot]&0xFFFF);
				break;
			case OP_PSTORE32:
				pars[memslot] = native_int2obj(memory[stackslot]);
				break;
			case OP_PSTOREP:
				pars[memslot] = native_int2obj(memory[stackslot]);
				break;
			case OP_ALOAD8:
				memory[stackslot] = (int)((byte[])native_int2obj(memory[op1]))[(memory[op2])];
				break;
			case OP_ALOAD16:
				memory[stackslot] = (int)((short[])native_int2obj(memory[op1]))[(memory[op2])];
				break;
			case OP_ALOAD32:
				memory[stackslot] = (int)((int[])native_int2obj(memory[op1]))[(memory[op2])];
				break;
			case OP_ALOADP:
				memory[stackslot] = native_obj2int(((Object[])native_int2obj(memory[op1]))[(memory[op2])]);
				break;
			case OP_ASTORE8:
				((byte[])native_int2obj(memory[op1]))[(memory[op2])] = (byte) (memory[stackslot]);
				break;
			case OP_ASTORE16:
				((short[])native_int2obj(memory[op1]))[(memory[op2])] = (short) (memory[stackslot]);
				break;
			case OP_ASTORE32:
				((int[])native_int2obj(memory[op1]))[(memory[op2])] = (int) (memory[stackslot]);
				break;
			case OP_ASTOREP:
				((Object[])native_int2obj(memory[op1]))[(memory[op2])] = native_int2obj(memory[stackslot]);
				break;
			case OP_NOT:
				memory[stackslot] = ~(memory[op1]);
				break;
			case OP_NEG:
				memory[stackslot] = -(memory[op1]);
				break;
			case OP_NOP:
				memory[stackslot] = (memory[op1]);
				break;
			case OP_ADD:
				memory[stackslot] = (memory[op1]) + (memory[op2]);
				break;
			case OP_SUB:
				memory[stackslot] = (memory[op1]) - (memory[op2]);
				break;
			case OP_MUL:
				memory[stackslot] = (memory[op1]) * (memory[op2]);
				break;
			case OP_DIV:
				memory[stackslot] = (memory[op1]) / (memory[op2]);
				break;
			case OP_MOD:
				memory[stackslot] = (memory[op1]) % (memory[op2]);
				break;		
			case OP_AND:
				memory[stackslot] = (memory[op1]) & (memory[op2]);
				break;	
			case OP_OR:
				memory[stackslot] = (memory[op1]) | (memory[op2]);
				break;	
			case OP_XOR:
				memory[stackslot] = (memory[op1]) ^ (memory[op2]);
				break;	
			case OP_SHR:
				memory[stackslot] = (memory[op1]) >> (memory[op2]);
				break;	
			case OP_USHR:
				memory[stackslot] = (memory[op1]) >>> (memory[op2]);
				break;
			case OP_SHL:
				memory[stackslot] = (memory[op1]) << (memory[op2]);
				break;
			case OP_COMPARE_EQUAL:
				if(memory[op1] == memory[op2])
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_NOTEQUAL:
				if(memory[op1] != memory[op2])
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_LESSTHAN:
				if((memory[op1]) < (memory[op2]))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_LESSEQUAL:
				if((memory[op1]) <= (memory[op2]))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_GREATERTHAN:
				if((memory[op1]) > (memory[op2]))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_GREATEREQUAL:
				if((memory[op1]) >= (memory[op2]))
					pc += ((int)jumpPosition-6);
				break;
			case OP_SWITCH:
				int index = pc+6+((memory[op1])*2);
				pc += ((short)((program[index]&0xFF) + (program[index+1]<<8)));
				break;
			case OP_JUMP:
				pc += ((int)jumpPosition-6);
				break;
			case OP_RETURN:
				return 0;
			case OP_RETURNV:
				return memory[op1];
			case OP_ALLOC8:
				memory[stackslot] = native_obj2int(new byte[memory[op1]]);
				break;
			case OP_ALLOC16:
				memory[stackslot] = native_obj2int(new short[memory[op1]]);
				break;
			case OP_ALLOC32:
				memory[stackslot] = native_obj2int(new int[memory[op1]]);
				break;
			case OP_ALLOCP:
				memory[stackslot] = native_obj2int(new Object[memory[op1]]);
				break;
			case OP_OCONST:
				memory[stackslot] = native_obj2int(appendedData[memory[op1]]);
				break;
			case OP_CUSTOM_PREPCALL:
				memory[stackslot] = native_obj2int(new Object[] {native_int2obj(memory[op1]), native_int2obj(memory[op2]), native_int2obj(memory[op3]), native_int2obj(memory[op4])});
				break;
			case OP_CUSTOM_CALL:
				memory[stackslot] = process(program, appendedData, (Object[])native_int2obj(memory[op1]));
				break;
			default:
				return 0;
			//	throw new RuntimeException("Illegal Opcode "+opcode+" @ "+pc);
			}
			
			pc += 6;
			
		}
		
	}
}
