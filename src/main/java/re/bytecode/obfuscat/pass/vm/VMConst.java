package re.bytecode.obfuscat.pass.vm;

import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.MemorySize;

public class VMConst {

	public static final int OP_CONST   = 0x00; // CONST <X> - 00 XX XX XX RR XX
	
	public static final int OP_LOAD8   = 0x01; // LOAD <SLOT S> - 01 SS SS 00 RR 00
	public static final int OP_LOAD16  = 0x02;
	public static final int OP_LOAD32  = 0x03;
	public static final int OP_LOADP   = 0x04;
	
	public static final int OP_PLOAD8  = 0x05; // parameter load
	public static final int OP_PLOAD16 = 0x06;
	public static final int OP_PLOAD32 = 0x07;
	public static final int OP_PLOADP  = 0x08;
	
	public static final int OP_STORE8  = 0x09; // STORE <SLOT S> <STORE CC> - 02 SS SS 00 CC 00
	public static final int OP_STORE16 = 0x0A; 
	public static final int OP_STORE32 = 0x0B; 
	public static final int OP_STOREP  = 0x0C; 
	
	public static final int OP_ALOAD8 = 0x0D; // ALOAD  <ARRAY A> <INDEX I> - 03 AA II 00 RR 00
	public static final int OP_ALOAD16 = 0x0E;
	public static final int OP_ALOAD32 = 0x0F;
	public static final int OP_ALOADP = 0x10;
	
	public static final int OP_ASTORE8 = 0x11; // ASTORE <ARRAY A> <INDEX I> <DATA D> - 04 AA II 00 DD 00
	public static final int OP_ASTORE16 = 0x12;
	public static final int OP_ASTORE32 = 0x13;
	public static final int OP_ASTOREP = 0x14;
	
	public static final int OP_NOT = 0x15; // MATH <OP1 A> <OP2 B> - 05 AA BB 00 RR 00
	public static final int OP_NEG = 0x16;
	public static final int OP_NOP = 0x17;
	public static final int OP_ADD = 0x18;
	public static final int OP_SUB = 0x19;
	public static final int OP_MUL = 0x1A;
	public static final int OP_DIV = 0x1B;
	public static final int OP_MOD = 0x1C;
	public static final int OP_AND = 0x1D;
	public static final int OP_OR = 0x1E;
	public static final int OP_XOR = 0x1F;
	public static final int OP_SHR = 0x20;
	public static final int OP_USHR = 0x21;
	public static final int OP_SHL = 0x22;
	
	
	public static final int OP_COMPARE_EQUAL = 0x23; // COMPARE <OP1 A> <OP2 B> <CONDITIONALJUMP J> - 06 AA BB JJ JJ 00
	public static final int OP_COMPARE_NOTEQUAL = 0x24;
	public static final int OP_COMPARE_LESSTHAN = 0x25;
	public static final int OP_COMPARE_LESSEQUAL = 0x26;
	public static final int OP_COMPARE_GREATERTHAN = 0x27;
	public static final int OP_COMPARE_GREATEREQUAL = 0x28;

	public static final int OP_SWITCH = 0x29; // SWITCH <SWITCHVAR S> - 07 SS 00 00 00 00
	public static final int OP_JUMP = 0x2A; // JUMP <JUMP J> 08 00 00 JJ JJ 00
	public static final int OP_RETURN = 0x2B; // RETURN < <VALUE V> 09 VV 00 00 00 00
	public static final int OP_RETURNV = 0x2C; 

	public static int size2value(MemorySize size) {
		switch (size) {
		case BYTE:
			return 0;
		case SHORT:
			return 1;
		case INT:
			return 2;
		case POINTER:
			return 3;
		default:
			throw new RuntimeException("Not implemented");
		}
	}

	public static int operation2value(MathOperation op) {
		switch (op) {
		case NOT:
			return 0;
		case NEG:
			return 1;
		case NOP:
			return 2;
		case ADD:
			return 3;
		case SUB:
			return 4;
		case MUL:
			return 5;
		case DIV:
			return 6;
		case MOD:
			return 7;
		case AND:
			return 8;
		case OR:
			return 9;
		case XOR:
			return 10;
		case SHR:
			return 11;
		case USHR:
			return 12;
		case SHL:
			return 13;
		default:
			throw new RuntimeException("Not implemented");
		}
	}

	public static int condition2value(CompareOperation op) {
		switch (op) {
		case EQUAL:
			return 0;
		case NOTEQUAL:
			return 1;
		case LESSTHAN:
			return 2;
		case LESSEQUAL:
			return 3;
		case GREATERTHAN:
			return 4;
		case GREATEREQUAL:
			return 5;
		default:
			throw new RuntimeException("Not implemented");
		}
	}

}
