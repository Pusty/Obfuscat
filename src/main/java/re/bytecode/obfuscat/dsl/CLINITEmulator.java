package re.bytecode.obfuscat.dsl;

import java.util.Arrays;
import java.util.Map;
import java.util.Stack;

import pusty.f0cr.ClassReader;
import pusty.f0cr.attribute.CodeAttribute;
import pusty.f0cr.data.MethodInfo;
import pusty.f0cr.inst.Opcodes;
import pusty.f0cr.inst.types.InstAVar;
import pusty.f0cr.inst.types.InstConst;
import pusty.f0cr.inst.types.InstConvert;
import pusty.f0cr.inst.types.InstMath;
import pusty.f0cr.inst.types.InstStack;
import pusty.f0cr.inst.types.InstVar;
import pusty.f0cr.inst.types.Instruction;
import pusty.f0cr.types.ClassReference;
import pusty.f0cr.types.FieldReference;
import pusty.f0cr.types.NameAndTypeDescriptor;

final class CLINITEmulator {
	
	// CLINIT is emulated statically
	protected static void emulateCLINIT(ClassReader classReader, MethodInfo method, Map<String, Object> globalVariableMap) {
		CodeAttribute code = method.getCode();
		
		if(code == null) throw new RuntimeException("<clinit> exists but has no code");

		Integer[] array;
		array = code.getInst().getInstructionMap().keySet()
				.toArray(new Integer[code.getInst().getInstructionMap().size()]);
		Arrays.sort(array);
		
		
		Stack<Object> stack = new Stack<Object>();
		// iterate instructions
		for (Integer key : array) {
			Instruction instRaw = code.getInst().getInstructionMap().get(key);
			
			if (instRaw instanceof InstConst) {
				InstConst inst = (InstConst) instRaw;
				Object value = inst.getValue();
				if(value.getClass() == Boolean.class)
					stack.push(((Boolean)value)?1:0);
				else if(value.getClass() == Byte.class)
					stack.push(((Byte)value).intValue());
				else if(value.getClass() == Short.class)
					stack.push(((Short)value).intValue());
				else if(value.getClass() == Character.class)
					stack.push((int)((Character)value).charValue());
				else
					stack.push(value);
			} else if (instRaw instanceof InstConvert) {
				InstConvert inst = (InstConvert) instRaw;
				Object val = stack.pop();
				switch (inst.getInstruction() & 0xFF) {
				case Opcodes.I2B:
					stack.push((int)((byte)((Integer)val).intValue()));
					break;
				case Opcodes.I2C:
					stack.push((int)((char)((Integer)val).intValue()));
					break;
				case Opcodes.I2S:
					stack.push((int)((short)((Integer)val).intValue()));
					break;
				default:
					throw new RuntimeException("Not implemented " + inst.getName());
				}

			} else if((instRaw.getInstruction()&0xFF) == Opcodes.NEWARRAY) {
				int arrayType = instRaw.getData()[0];
				int count = (Integer)stack.pop();
				switch(arrayType) {
				case 4: // T_BOOLEAN
					stack.push(new boolean[count]);
					break;
				case 8: // T_BYTE
					stack.push(new byte[count]);
					break;
				case 5: // T_CHAR
					stack.push(new char[count]);
					break;
				case 9: // T_SHORT
					stack.push(new short[count]);
					break;
				case 10: // T_INT
					stack.push(new int[count]);
					break;
				default:
					throw new RuntimeException("NEWARRAY not implemented for type "+arrayType);
				}
			}/*else if((instRaw.getInstruction()&0xFF) == Opcodes.ANEWARRAY) {
				ClassReference cr = (ClassReference) classReader.getPool().get((instRaw.getData()[0]&0xFF << 8) | instRaw.getData()[1]);
				if(!classReader.getPool().get(cr.getIndex()).equals("java/lang/Object"))
					throw new RuntimeException("Not implemented Object Array Creation for classes not Object.class");
				stack.push(new Object[(Integer)stack.pop()]);
			}*/else if (instRaw instanceof InstAVar) {
				InstAVar inst = (InstAVar) instRaw;

				if (inst.isLoad()) {
					int ind = (Integer)stack.pop();
					Object ar = stack.pop();

					if (inst.getType() == int.class)
						stack.push((int)(((int[])ar)[ind]));
					else if (inst.getType() == short.class)
						stack.push((int)(((short[])ar)[ind]));
					else if (inst.getType() == byte.class)
						stack.push((int)(((byte[])ar)[ind]));
					else if (inst.getType() == boolean.class)
						stack.push((((boolean[])ar)[ind])?1:0);
					else if (inst.getType() == char.class)
						stack.push((int)(((short[])ar)[ind]));
					//else if (inst.getType() == Array.class)
					//	stack.push((int)(((Object[])ar)[ind]));
					else
						throw new RuntimeException("Not supported: " + inst.getType());
					
				}
				if (inst.isStore()) {
					Object val = stack.pop();
					int ind = (Integer)stack.pop();
					Object ar = stack.pop();

					if (inst.getType() == int.class)
						((int[])ar)[ind] = (int)((Integer)val).intValue();
					else if (inst.getType() == short.class)
						((short[])ar)[ind] = (short)((Integer)val).intValue();
					else if (inst.getType() == byte.class)
						((byte[])ar)[ind] = (byte)(((Integer)val)).intValue();
					else if (inst.getType() == boolean.class)
						((boolean[])ar)[ind] = (((Integer)val)).intValue()!=0;
					else if (inst.getType() == char.class)
						((char[])ar)[ind] = (char)(((Integer)val)).intValue();
					//else if (inst.getType() == Array.class)
					//	((Object[])ar)[ind] = val;
					else
						throw new RuntimeException("Not supported: " + inst.getType());
				}
			}else if(instRaw instanceof InstVar) {
				InstVar inst = (InstVar)instRaw;
				
				if(!inst.isStatic())
					throw new RuntimeException("Load/Store Operations with Objects are not supported");
				
				
				FieldReference fref = (FieldReference) inst.getConstantPool().get(inst.getIndex());
				NameAndTypeDescriptor nat = (NameAndTypeDescriptor)inst.getConstantPool().get(fref.getNameAndType());
				String type = inst.getConstantPool().get(nat.getEncodedTypeDescriptor()).toString();
				String name = inst.getConstantPool().get(nat.getIdentifier()).toString();
				String identifier = name+type;
			
				if(!inst.getConstantPool().get(((ClassReference)inst.getConstantPool().get(fref.getClassReference())).getIndex()).toString().equals(inst.getConstantPool().get(((ClassReference)inst.getConstantPool().get(classReader.getThisClassIndex())).getIndex()).toString())) {
					// Check that the currently read class matches the class being accessed
					throw new RuntimeException("No external constants may be referenced");
				}
				
				if(inst.isStore()) {
					globalVariableMap.put(identifier, stack.pop());
				}else {
					if(!globalVariableMap.containsKey(identifier))
						throw new RuntimeException("No global variable "+identifier+" found");
					stack.push(globalVariableMap.get(identifier));
				}
				
			} else if (instRaw instanceof InstMath) {
				// parse math instructions
				
				InstMath inst = (InstMath) instRaw;

				if (inst.getOperation().equals("INC")) {
					throw new RuntimeException("INC not supported");
				} else {
					// parse normal math operations
			
					Integer op1;
					Integer op2;
					
					switch (inst.getOperation()) {
					case "ADD":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1+op2);
						break;
					case "SUB":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1-op2);
						break;
					case "MUL":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1*op2);
						break;
					case "DIV":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1/op2);
						break;
					case "REM":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1%op2);
						break;
					case "NEG":
						op1 = ((Integer)stack.pop());
						stack.push(-op1);
						break;
					case "SHL":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1<<op2);
						break;
					case "SHR":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1>>op2);
						break;
					case "USHR":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1>>>op2);
						break;
					case "AND":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1&op2);
						break;
					case "OR":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1|op2);
						break;
					case "XOR":
						op2 = ((Integer)stack.pop());
						op1 = ((Integer)stack.pop());
						stack.push(op1^op2);
						break;
					default:
						throw new RuntimeException("Illegal Instruction");
					}
				}

			} else if (instRaw instanceof InstStack) {			
				// parse stack operations
				InstStack inst = (InstStack) instRaw;
				Object v0;
				Object v1;
				Object v2;
				Object v3;
				switch (inst.getInstruction() & 0xFF) {
				case Opcodes.POP:
					v0 = stack.pop();
					break;
				case Opcodes.POP2:
					v0 = stack.pop();
					v3 = stack.pop();
					break;
				case Opcodes.DUP:
					v0 = stack.pop();
					stack.push(v0);
					stack.push(v0);
					break;
				case Opcodes.DUP_X1:
					v0 = stack.pop();
					v1 = stack.pop();
					stack.push(v0);
					stack.push(v1);
					stack.push(v0);
					break;
				case Opcodes.DUP_X2:
					v2 = stack.pop();
					v1 = stack.pop();
					v0 = stack.pop();
					stack.push(v2);
					stack.push(v1);
					stack.push(v0);
					stack.push(v2);
					break;
				case Opcodes.DUP2:
					v0 = stack.pop();
					v3 = stack.pop();
					stack.push(v3);
					stack.push(v0);
					stack.push(v3);
					stack.push(v0);
					break;
				case Opcodes.DUP2_X1:
					v1 = stack.pop();
					v0 = stack.pop();
					v3 = stack.pop();
					stack.push(v3);
					stack.push(v0);
					stack.push(v1);
					stack.push(v3);
					stack.push(v0);
					break;
				case Opcodes.DUP2_X2:
					v1 = stack.pop();
					v2 = stack.pop();
					v0 = stack.pop();
					v3 = stack.pop();
					stack.push(v3);
					stack.push(v0);
					stack.push(v2);
					stack.push(v1);
					stack.push(v3);
					stack.push(v0);
					break;
				case Opcodes.SWAP:
					v0 = stack.pop();
					v1 = stack.pop();
					stack.push(v0);
					stack.push(v1);
					break;
				default:
					System.out.println("Can't handle stack instruction " + inst.getName());
				}
			}else if((instRaw.getInstruction()&0xFF) == Opcodes.RETURN) {
				return;
			}else
				throw new RuntimeException("Not supported instruction: "+instRaw.getName());

		}
	}
}
