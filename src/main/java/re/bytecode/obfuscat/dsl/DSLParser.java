package re.bytecode.obfuscat.dsl;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Array;
//import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Stack;

import pusty.f0cr.ClassReader;
import pusty.f0cr.attribute.CodeAttribute;
import pusty.f0cr.attribute.RuntimeInvisibleAnnotationsAttribute;
import pusty.f0cr.data.AttributeInfo;
import pusty.f0cr.data.MethodInfo;
import pusty.f0cr.data.RuntimeAnnotations;
import pusty.f0cr.inst.Opcodes;
import pusty.f0cr.inst.types.InstAVar;
import pusty.f0cr.inst.types.InstBranch;
import pusty.f0cr.inst.types.InstConst;
import pusty.f0cr.inst.types.InstConvert;
import pusty.f0cr.inst.types.InstLocalVar;
import pusty.f0cr.inst.types.InstMath;
import pusty.f0cr.inst.types.InstStack;
import pusty.f0cr.inst.types.InstTable;
import pusty.f0cr.inst.types.Instruction;
import pusty.f0cr.types.MethodReference;
import pusty.f0cr.types.NameAndTypeDescriptor;
import pusty.f0cr.util.AccessFlags;
import re.bytecode.obfuscat.dsl.api.ExcludeMethod;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

/*
 * The Languge in use for this project will be a very small subset of the Java Language (or more precise a subset of the JVM Instructions and no JRE functions)
 */

/**
 * Parser for part a selected part of Java Bytecode to the Control Flow Graph Format
 */
public class DSLParser {

	public DSLParser() {
	}

	public Map<String, Function> processFile(byte[] classFile) throws Exception {
		// System.out.println(classFile.length);
		ByteArrayInputStream bis = new ByteArrayInputStream(classFile);
		ClassReader classReader = new ClassReader(bis);
		bis.close();

		// Verify Class (not abstract, interface)

		Map<String, Function> functions = new HashMap<String, Function>();
		
		for (MethodInfo method : classReader.getMethodTable().getIndexes()) {
			if (verifyMethod(classReader, method)) {
				Class<?>[] args = convertFunctionDescriptor(method.getDescriptor());
				String desc = method.getDescriptor().split("\\x29")[1];
				boolean returnValue = convertDescriptor(desc.charAt(0), desc.length()>1?desc.charAt(1):0) != null;
				// System.out.println("Processing: " + method.getName());
				List<BasicBlock> bbs = processMethod(classReader, method);
				// System.out.println(bbs);
				String name = (method.getName()+method.getDescriptor());
				
				// give each function a unique id
				String id = method.getName();
				int ido = 0;
				while(functions.containsKey(id)) {
					id = method.getName()+ido;
					ido++;
				}
					
					
				functions.put(id, new Function(name, bbs, args,
						method.getCode().getLocalVariableTable().getTable().length, returnValue));
			}

			// method.getInfo().printOut();

		}
		return functions;
	}

	// Convert a descriptor character to a class
	private Class<?> convertDescriptor(char desc, char snd) {
		if (desc == 'V')
			return null;
		else if (desc == 'Z')
			return boolean.class;
		else if (desc == 'C')
			return char.class;
		else if (desc == 'B')
			return byte.class;
		else if (desc == 'S')
			return short.class;
		else if (desc == 'I')
			return int.class;
		else if (desc == 'F')
			return float.class;
		else if (desc == 'J')
			return long.class;
		else if (desc == 'D')
			return double.class;
		else if (desc == '[') {
			if(snd == 'B') return byte[].class;
			else if(snd == 'C') return char[].class;
			else if(snd == 'D') return double[].class;
			else if(snd == 'F') return float[].class;
			else if(snd == 'I') return int[].class;
			else if(snd == 'J') return long[].class;
			else if(snd == 'S') return short[].class;
			else if(snd == 'Z') return boolean[].class;
			else return Array.class;
		}else if (desc == 'L')
			return Object.class;
		else
			return null;
	}

	// Convert a method signature to a list of parameters
	private Class<?>[] convertFunctionDescriptor(String desc) {
		String variables = desc.split("\\x28")[1].split("\\x29")[0];
		// String output = desc.split("\\x29")[1];
		ArrayList<Class<?>> list = new ArrayList<Class<?>>();
		for (int i = 0; i < variables.length(); i++) {
			if (variables.charAt(i) == '[') {
				list.add(convertDescriptor(variables.charAt(i), variables.charAt(i+1)));
				if (variables.charAt(i + 1) == 'L') {
					while (variables.charAt(i) != ';')
						i++;
				} else
					i++;
			} else if (variables.charAt(i) == 'L') {
				list.add(convertDescriptor(variables.charAt(i), variables.charAt(i+1)));
				while (variables.charAt(i) != ';')
					i++;
			} else
				list.add(convertDescriptor(variables.charAt(i), (char)0));
		}
		// list.add(convertDescriptor(output.charAt(0)));
		return list.toArray(new Class<?>[list.size()]);
	}

	// verify that this method is suppost to be analyzed
	private boolean verifyMethod(ClassReader classReader, MethodInfo method) throws Exception {

		// Check Method Attributes for special properties
		
		for (AttributeInfo info : method.getInfo().getIndexes()) {

			if (info.getAttribute().equals("RuntimeInvisibleAnnotations")) {

				RuntimeInvisibleAnnotationsAttribute riaa = (RuntimeInvisibleAnnotationsAttribute) info.getInfo();

				// Iterate the annotations
				for (RuntimeAnnotations ra : riaa.getAttributeTable().getIndexes()) {
					String annotationName = classReader.getPool().get(ra.getTypeIndex()).toString();

					// silently ignore methods with the "ExcludeMethod" annotation
					if (annotationName.contains(ExcludeMethod.class.getSimpleName())) {
						return false;
					}

				}

			}
		}

		// ignore non public functions
		//if(!AccessFlags.isPublic(method.getAccessFlags()))
		//	return false;
		
		if (AccessFlags.isAbstract(method.getAccessFlags()))
			throw new Exception("Can't translate abstract method " + method.getName());

		// Constructor is a special case
		if (method.getName().equals("<init>")) {
			if (method.getCode().getCodeLength() > 5) // this is the size of the implicit constructor
				throw new Exception("Can't translate constructor " + method.getName());
			return false;
		} else if (!AccessFlags.isStatic(method.getAccessFlags()))
			throw new Exception("Can't translate non-static method " + method.getName());

		CodeAttribute code = method.getCode();

		if (code == null)
			throw new Exception("No code found in " + method.getName());

		if (code.getExceptionTable() != null && code.getExceptionTable().getIndexes().length > 0)
			throw new Exception("Can't translate exceptions " + method.getName());

		Integer[] array;

		array = code.getInst().getInstructionMap().keySet()
				.toArray(new Integer[code.getInst().getInstructionMap().size()]);
		Arrays.sort(array);

		// for (Integer key : array) {

		// Instruction value = code.getInst().getInstructionMap().get(key);

		// verify instruction is supported
		// }

		return true;
	}

	// Process a analyzable method
	private List<BasicBlock> processMethod(ClassReader classReader, MethodInfo method) {

		CodeAttribute code = method.getCode();

		Integer[] array;

		// Sort the Instructions by "address"
		array = code.getInst().getInstructionMap().keySet()
				.toArray(new Integer[code.getInst().getInstructionMap().size()]);
		Arrays.sort(array);

		// Split the code into basic block boudaries
		List<DSLBasicBlock> blocks = split(code, array);

		// BasicBlock currentBlock = new BasicBlock(array[0]);

		// if(currentBlock != null && currentBlock.isDone()) {
		// currentBlock.setEnd(array[array.length-1]);
		// bbs.add(currentBlock);
		// }

		
		HashMap<Integer, List<BasicBlock>> blockMap = new HashMap<Integer, List<BasicBlock>>();

		// map each internal basic block a real basic block
		for (DSLBasicBlock dslblock : blocks) {
			List<BasicBlock> bbl = new ArrayList<BasicBlock>();
			bbl.add(new BasicBlock());
			blockMap.put(dslblock.getStart(), bbl);
		}

		BasicBlock lastBlock;
		BasicBlock currentBlock = null;
		boolean lastBlockExitBlock = false;
		// this parses a basic block
		// TODO: probably smart to optimize this
		for (DSLBasicBlock dslblock : blocks) {
			lastBlock = currentBlock;
			currentBlock = blockMap.get(dslblock.getStart()).get(0);

			// link sequential blocks together
			if (lastBlock != null && !lastBlockExitBlock && lastBlock.isExitBlock())
				lastBlock.setUnconditionalBranch(currentBlock);

			lastBlockExitBlock = false;
			// int stackDepth = 0;
			// Node[] stack = new Node[code.getMaxStacks()];

			// internal stack to convert from stack based machine
			Stack<Node> stack = new Stack<Node>();

			// iterate instructions
			for (Integer key : array) {
				// if in dslblock
				if (key < dslblock.getStart())
					continue;
				if (key >= dslblock.getEnd())
					continue;

				Instruction instRaw = code.getInst().getInstructionMap().get(key);
				
				// Checkcast can be safely ignored
				if((instRaw.getInstruction()&0xFF) == Opcodes.CHECKCAST) continue;
				
				if (instRaw instanceof InstLocalVar) {
					// parse local variable instruction
					InstLocalVar inst = (InstLocalVar) instRaw;
					
					
					MemorySize localVarSize = MemorySize.POINTER;

					if (inst.getType() == int.class)
						localVarSize = MemorySize.INT;
					else if (inst.getType() == short.class)
						localVarSize = MemorySize.SHORT;
					else if (inst.getType() == byte.class)
						localVarSize = MemorySize.BYTE;
					else if (inst.getType() == boolean.class)
						localVarSize = MemorySize.BYTE;
					else if (inst.getType() == char.class)
						localVarSize = MemorySize.SHORT;
					else if (inst.getType() == Array.class)
						localVarSize = MemorySize.POINTER;
					else
						throw new RuntimeException("Not supported: " + inst.getType());
					
					if (inst.isLoad()) {
						stack.push(new NodeLoad(localVarSize, inst.getVariable()));
					}
					if (inst.isStore()) {
						currentBlock.getNodes().add(new NodeStore(localVarSize, inst.getVariable(), stack.pop()));
					}
				} else if (instRaw instanceof InstConst) {
					// parse constant instructions
					InstConst inst = (InstConst) instRaw;
					Object obj = inst.getValue();
					stack.push(new NodeConst(obj));
				} else if (instRaw instanceof InstConvert) {
					// parse conversion instructions
					InstConvert inst = (InstConvert) instRaw;
					Node value = stack.pop();

					switch (inst.getInstruction() & 0xFF) {
					case Opcodes.I2B:
						// (value & 0x7F) - (value & 0x80)
						stack.push(new NodeMath(MathOperation.SUB, new NodeMath(MathOperation.AND, value, new NodeConst(0x7F)),
								new NodeMath(MathOperation.AND, value, new NodeConst(0x80))));
						break;
					case Opcodes.I2C:
					case Opcodes.I2S:
						stack.push(new NodeMath(MathOperation.SUB, new NodeMath(MathOperation.AND, value, new NodeConst(0x7FFF)),
								new NodeMath(MathOperation.AND, value, new NodeConst(0x8000))));
						break;
					default:
						throw new RuntimeException("Not implemented " + inst.getName());
					}

				} else if (instRaw instanceof InstMath) {
					// parse math instructions
					
					InstMath inst = (InstMath) instRaw;

					if (inst.getOperation().equals("INC")) {
						// INC instructions are split into  load, add, store
						int c = inst.getConstantValue();
						if (c >= 0) {
							currentBlock.getNodes()
									.add(new NodeStore(MemorySize.INT, inst.getLocalVariable(),
											new NodeMath(MathOperation.ADD, new NodeLoad(MemorySize.INT, inst.getLocalVariable()),
													new NodeConst(inst.getConstantValue()))));
						} else {
							currentBlock.getNodes()
									.add(new NodeStore(MemorySize.INT, inst.getLocalVariable(),
											new NodeMath(MathOperation.SUB, new NodeLoad(MemorySize.INT, inst.getLocalVariable()),
													new NodeConst(-inst.getConstantValue()))));
						}

					} else {
						// parse normal math operations
						MathOperation operation;

						switch (inst.getOperation()) {
						case "ADD":
							operation = MathOperation.ADD;
							break;
						case "SUB":
							operation = MathOperation.SUB;
							break;
						case "MUL":
							operation = MathOperation.MUL;
							break;
						case "DIV":
							operation = MathOperation.DIV;
							break;
						case "REM":
							operation = MathOperation.MOD;
							break;
						case "NEG":
							operation = MathOperation.NEG;
							break;
						case "SHL":
							operation = MathOperation.SHL;
							break;
						case "SHR":
							operation = MathOperation.SHR;
							break;
						case "USHR":
							operation = MathOperation.USHR;
							break;
						case "AND":
							operation = MathOperation.AND;
							break;
						case "OR":
							operation = MathOperation.OR;
							break;
						case "XOR":
							operation = MathOperation.XOR;
							break;
						default:
							throw new RuntimeException("Illegal Instruction");
						}

						if (operation.getOperandCount() == 1) {
							Node op1 = stack.pop();
							stack.push(new NodeMath(operation, op1));
						} else if (operation.getOperandCount() == 2) {
							Node op2 = stack.pop();
							Node op1 = stack.pop();
							stack.push(new NodeMath(operation, op1, op2));
						} else
							throw new RuntimeException("Illegal Operant Count");
					}

				} else if (instRaw instanceof InstStack) {
					
					// parse stack operations
					InstStack inst = (InstStack) instRaw;

					Node v0;
					Node v1;
					Node v2;
					Node v3;

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
				} else if (instRaw instanceof InstAVar) {
					
					// handle array based operations
					
					InstAVar inst = (InstAVar) instRaw;

					MemorySize arraySize = MemorySize.POINTER;

					if (inst.getType() == int.class)
						arraySize = MemorySize.INT;
					else if (inst.getType() == short.class)
						arraySize = MemorySize.SHORT;
					else if (inst.getType() == byte.class)
						arraySize = MemorySize.BYTE;
					else if (inst.getType() == boolean.class)
						arraySize = MemorySize.BYTE;
					else if (inst.getType() == char.class)
						arraySize = MemorySize.SHORT;
					else if (inst.getType() == Array.class)
						arraySize = MemorySize.POINTER;
					else
						throw new RuntimeException("Not supported: " + inst.getType());

					if (inst.isLoad()) {
						Node ind = stack.pop();
						Node ar = stack.pop();
						stack.push(new NodeALoad(ar, ind, arraySize));
					}
					if (inst.isStore()) {
						Node val = stack.pop();
						Node ind = stack.pop();
						Node ar = stack.pop();
						currentBlock.getNodes().add(new NodeAStore(ar, ind, val, arraySize));
					}
				}  else if (instRaw instanceof InstTable) {
					
					// handle switches
					
					InstTable inst = (InstTable)instRaw;
					Node op1 = stack.pop();
					Node op2;
					BranchCondition cond;
					int[] branchList = inst.getBranchListInstructionPos();
					boolean addedOne = false;
					for(int i=0;i<branchList.length;i++) {
						
						if(currentBlock.isConditionalBlock()) { // already conditional
							BasicBlock cascadeBlock = new BasicBlock();
							currentBlock.setUnconditionalBranch(cascadeBlock);
							blockMap.get(dslblock.getStart()).add(cascadeBlock);
							currentBlock = cascadeBlock;
							addedOne = true;
						}
						
						op2 = new NodeConst(inst.getBranchIndex()[i]);
						Node op1_clone = op1.clone();
						if (!currentBlock.getNodes().contains(op1_clone))
							currentBlock.getNodes().add(op1_clone);
						if (!currentBlock.getNodes().contains(op2))
							currentBlock.getNodes().add(op2);
						cond = new BranchCondition(currentBlock, op1_clone, op2, CompareOperation.EQUAL);
						currentBlock.setConditionalBranch(blockMap.get(branchList[i]).get(0), cond);
						
						// as the switch cases require context to the switch variable, it needs to be cloned into each block (or stored in a variable)
						// as custom nodes may return values and could be used in switch cases, catch this edge case and complain
						if(addedOne) {
							if(currentBlock.findNodes(new NodeCustom(null)).size() > 0)
								throw new RuntimeException("Custom nodes may not be cloned for switch usage");
						}
					}
					
					currentBlock.setUnconditionalBranch(blockMap.get(inst.getBranchDefaultInstructionPos()).get(0));
					

					
				}  else if (instRaw instanceof InstBranch) {
					
					// handle jumps, calls and return
					
					InstBranch inst = (InstBranch) instRaw;

					// System.out.println(inst + " # " + inst.getBranchInstructionPos());

					CompareOperation operation;
					Node op1;
					Node op2;
					BranchCondition cond;
					String desc;

					switch (inst.getTypeOfBranch()) {
					case InstBranch.BRANCH_CC:
						switch (inst.getInstruction() & 0xFF) {
						case Opcodes.IFEQ:
							operation = CompareOperation.EQUAL;
							break;
						case Opcodes.IFNE:
							operation = CompareOperation.NOTEQUAL;
							break;
						case Opcodes.IFLT:
							operation = CompareOperation.LESSTHAN;
							break;
						case Opcodes.IFGE:
							operation = CompareOperation.GREATEREQUAL;
							break;
						case Opcodes.IFGT:
							operation = CompareOperation.GREATERTHAN;
							break;
						case Opcodes.IFLE:
							operation = CompareOperation.LESSEQUAL;
							break;
						default:
							throw new RuntimeException("Not implemented: " + inst);
						}

						op2 = stack.pop();
						op1 = new NodeConst(0);
						if (!currentBlock.getNodes().contains(op1))
							currentBlock.getNodes().add(op1);
						if (!currentBlock.getNodes().contains(op2))
							currentBlock.getNodes().add(op2);
						cond = new BranchCondition(currentBlock, op1, op2, operation);
						currentBlock.setConditionalBranch(blockMap.get(inst.getBranchInstructionPos()).get(0), cond);
						break;
					case InstBranch.BRANCH_ICMPCC:
						switch (inst.getInstruction() & 0xFF) {
						case Opcodes.IF_ICMPEQ:
							operation = CompareOperation.EQUAL;
							break;
						case Opcodes.IF_ICMPNE:
							operation = CompareOperation.NOTEQUAL;
							break;
						case Opcodes.IF_ICMPLT:
							operation = CompareOperation.LESSTHAN;
							break;
						case Opcodes.IF_ICMPGE:
							operation = CompareOperation.GREATEREQUAL;
							break;
						case Opcodes.IF_ICMPGT:
							operation = CompareOperation.GREATERTHAN;
							break;
						case Opcodes.IF_ICMPLE:
							operation = CompareOperation.LESSEQUAL;
							break;
						default:
							throw new RuntimeException("Not implemented: " + inst);
						}

						op2 = stack.pop();
						op1 = stack.pop();
						if (!currentBlock.getNodes().contains(op1))
							currentBlock.getNodes().add(op1);
						if (!currentBlock.getNodes().contains(op2))
							currentBlock.getNodes().add(op2);
						cond = new BranchCondition(currentBlock, op1, op2, operation);
						currentBlock.setConditionalBranch(blockMap.get(inst.getBranchInstructionPos()).get(0), cond);
						break;
					case InstBranch.BRANCH_GOTO:
						currentBlock.setUnconditionalBranch(blockMap.get(inst.getBranchInstructionPos()).get(0));
						break;
					case InstBranch.BRANCH_RETURN:
						desc = method.getDescriptor().split("\\x29")[1];
						boolean returnValue = convertDescriptor(desc.charAt(0), desc.length()>1?desc.charAt(1):0) != null;

						// if there is suppost to be a return value then pop it from the stack
						if (returnValue) {
							op1 = stack.pop();
							if (!currentBlock.getNodes().contains(op1))
								currentBlock.getNodes().add(op1);
							currentBlock.setExitBlock(op1);
						} else
							currentBlock.setExitBlock(null);
						lastBlockExitBlock = true;
						break;
					case InstBranch.BRANCH_INVOKE:

						
						MethodReference mr = (MethodReference) inst.getConstantPool().get(inst.getPoolIndex());
						NameAndTypeDescriptor natr = (NameAndTypeDescriptor)inst.getConstantPool().get(mr.getNameAndType());
						String name = (String) inst.getConstantPool().get(natr.getIdentifier());
						String type = (String) inst.getConstantPool().get(natr.getEncodedTypeDescriptor());
						
						MethodInfo info = classReader.getMethodTable().getMethod(inst.getConstantPool(), name);
						
						if(info == null) {
							throw new RuntimeException("Method "+name+" not found");
						}
						
						if((inst.getInstruction()&0xFF) != Opcodes.INVOKESTATIC) 
							throw new RuntimeException("Not implemented: " + inst.getName());
						
						
						// NOTE: If the nodes have return values and these are not used / voided , the function call will be optimized out
						// So functions with side effects need to have the void type or be handled carefully
						
						// use "native_" as a method prefix for it to be parsed as a custom node
						//if(!name.startsWith("native_")) throw new RuntimeException("Only 'native' prefix functions supported");
						if(AccessFlags.isPrivate(info.getAccessFlags()) && AccessFlags.isStatic(info.getAccessFlags()) && name.startsWith("native_")) {
							name = name.substring("native_".length());
							
							Class<?>[] args = convertFunctionDescriptor(type);
							Node[] argsNode = new Node[args.length];
							
							// pop the amount of arguments the function has from the stack
							for(int i=0;i<argsNode.length;i++)
								argsNode[argsNode.length-1-i] = stack.pop();
							
							desc = type.split("\\x29")[1];
							boolean returnsSomething = convertDescriptor(desc.charAt(0), desc.length()>1?desc.charAt(1):0) != null;
							
							// add the custom node
							
							Node custom;
							if(name.equals("int2obj") || name.equals("obj2int") ) {
								custom = new NodeMath(MathOperation.NOP, argsNode[0]);
							}else {
								custom = new NodeCustom(name, argsNode);
							}
							
							if(returnsSomething)
								stack.push(custom);
							else
								currentBlock.getNodes().add(custom);
							
						}else if(AccessFlags.isPrivate(info.getAccessFlags()) && AccessFlags.isStatic(info.getAccessFlags())){

							// normal function calls (only works if merged)
							Class<?>[] args = convertFunctionDescriptor(type);
							Node[] argsNode = new Node[args.length+1];
							
							// pop the amount of arguments the function has from the stack
							for(int i=0;i<args.length;i++)
								argsNode[argsNode.length-1-i] = stack.pop();
							
							// function id
							NodeConst functionID = new NodeConst((name+type).hashCode());
							//if (!currentBlock.getNodes().contains(functionID))
							//	currentBlock.getNodes().add(functionID);
							argsNode[0] = functionID;
							
							desc = type.split("\\x29")[1];
							boolean returnsSomething = convertDescriptor(desc.charAt(0), desc.length()>1?desc.charAt(1):0) != null;
							
							
							Node custom;
							custom = new NodeCustom("call_unresolved", argsNode); // this needs to be resolved / replaced by a resolved version by the merger
							
							if(returnsSomething)
								stack.push(custom);
							else
								currentBlock.getNodes().add(custom);
						}else 
							 throw new RuntimeException("Normal Function Calling is not supported");
						
						break;
					default:
						throw new RuntimeException("Not implemented: " + inst.getName());
					}

				}

				else {
					throw new RuntimeException("Not implemented: " + instRaw.getName() + " - " + instRaw);
				}
				
				// DSLTranslater.parse(tC, value);
				// System.out.println(stack);
			}
			
			if(stack.size() != 0)
				throw new RuntimeException("Stack after Basic Block isn't empty "+stack);

			// System.out.println(currentBlock.getNodes());

			// System.out.println(currentBlock.getNodes().get(0).list());

		}

		// System.out.println(blockMap);

		/*
		 * HashMap<Node, String> seq = new HashMap<Node, String>();
		 * 
		 * List<Node> l = emited.get(0).list();
		 * 
		 * int nodeID = 0;
		 * 
		 * for(Node e:l) { if(!seq.containsKey(e)) seq.put(e, "node_"+(nodeID++));
		 * 
		 * Node[] ch = e.children(); if(ch == null)
		 * System.out.println(seq.get(e)+" = "+e); else { String s = ""; for(Node c:ch)
		 * s += seq.get(c)+", "; if(ch.length > 0) s = s.substring(0, s.length()-2);
		 * System.out.println(seq.get(e)+" = "+e.getClass().getSimpleName().substring(
		 * "SSANode".length())+"("+s+")"); } }
		 */
		// System.out.println(tC.getTranslation());

		ArrayList<BasicBlock> returnValue = new ArrayList<BasicBlock>();
		for (DSLBasicBlock dslblock : blocks) {
			for(BasicBlock bb:blockMap.get(dslblock.getStart()))
				returnValue.add(bb);
		}

		return returnValue;
	}

	/**
	 * Split the code into basic blocks
	 */
	public List<DSLBasicBlock> split(CodeAttribute code, Integer[] array) {

		ArrayList<Integer> limiters = new ArrayList<Integer>();

		boolean prime = false;
		for (Integer key : array) {
			Instruction instRaw = code.getInst().getInstructionMap().get(key);
		    // System.out.println(key + " - " + instRaw.getName());
			if (prime) { // if the last instruction causes a basic block split, then add a marker at this basic block
				if (!limiters.contains(key))
					limiters.add(key);
				prime = false; // disable the marker
			}
			if (instRaw instanceof InstBranch) {
				InstBranch inst = (InstBranch) instRaw;
				// invoke doesn't cause a basic block split
				// return and ret don't have branch positions
				if (inst.getTypeOfBranch() != InstBranch.BRANCH_RETURN && inst.getTypeOfBranch() != InstBranch.BRANCH_RET 
						&& inst.getTypeOfBranch() != InstBranch.BRANCH_INVOKE) { 
					int branchPosition = inst.getBranchInstructionPos();
					if (!limiters.contains(branchPosition)) // the branch location is in a new basic block
						limiters.add(branchPosition);
					//System.out.println("=> "+branchPosition);
				}
				if(inst.getTypeOfBranch() != InstBranch.BRANCH_INVOKE) // INVOKE Instructions don't cause a basic block split
					prime = true; // the next instruction is in a new basic block
			} else if (instRaw instanceof InstTable) {	
				InstTable inst = (InstTable)instRaw;
				
				// the default label is in a new basic block
				int defaultPos = inst.getBranchDefaultInstructionPos();
				if (!limiters.contains(defaultPos))
					limiters.add(defaultPos);
				//System.out.println("=> "+inst.getBranchDefault());
				
				// each possible branch is in a new basic block
				int[] branchList = inst.getBranchListInstructionPos();
				for(int i=0;i<inst.getBranchIndex().length;i++) {
					if (!limiters.contains(branchList[i]))
						limiters.add(branchList[i]);
					//System.out.println("=> "+branchList[i]);
				}
				
				// the next instruction is in a new basic block
				prime = true; 
			}
		}
		
		// if not already then the first instruction is in it's own basic block
		if (!limiters.contains(array[0]))
			limiters.add(array[0]);

		// sort the basic block markers
		Collections.sort(limiters);

		
	    // System.out.println(limiters);

		// split the basic blocks
		ArrayList<DSLBasicBlock> list = new ArrayList<DSLBasicBlock>();

		for (int i = 0; i < limiters.size(); i++) {
			int start = limiters.get(i);
			int end = array[array.length - 1] + 1; // +1 so last instruction does get parsed
			if (i + 1 < limiters.size())
				end = limiters.get(i + 1);
			list.add(new DSLBasicBlock(start, end));
		}

		// System.out.println(list);

		return list;

	}



	// Internal Basic Block Format while processing
	private class DSLBasicBlock {
		private int start;
		private int end;

		public DSLBasicBlock(int from, int to) {
			this.start = from;
			this.end = to;
		}

		public int getStart() {
			return start;
		}

		public int getEnd() {
			return end;
		}

		@Override
		public String toString() {
			return "BB(" + start + "," + end + ")";
		}
	}

}
