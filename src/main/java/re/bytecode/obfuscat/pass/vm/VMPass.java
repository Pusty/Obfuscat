package re.bytecode.obfuscat.pass.vm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeAlloc;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;
import re.bytecode.obfuscat.pass.Pass;

import static re.bytecode.obfuscat.cfg.MathOperation.*;
import static re.bytecode.obfuscat.pass.vm.VMConst.*;

/**
 * Create a Virtual Machine, convert the program to static data used in the virtual machine.
 */
public class VMPass extends Pass {

	private static final boolean DEBUG = false;
	
	// This should stay unchanged at 0x100 for slot range 0x00-0xff
	private static final int STACK_SIZE = 0x100;
	private static final int VAR_SIZE   = 0x100;

	public VMPass(Context context) {
		super(context);
	}

	public static byte[] hexStringToByteArray(String hex) {
		int l = hex.length();
		byte[] data = new byte[l / 2];
		for (int i = 0; i < l; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
		}
		return data;
	}
	
	private HashMap<String, byte[]> debugMap = new HashMap<String, byte[]>();
	
	private Node debugNode(Function f, String node, Node... values) {
		Node[] values2 = new Node[values.length+1];
		if(!debugMap.containsKey(node)) {
			byte[] barray = new byte[node.length()+1];
			for(int i=0;i<node.length();i++)
				barray[i] = (byte) node.charAt(i); // convert to ASCII
			f.registerData(barray);
			debugMap.put(node, barray);
		}
		values2[0] = cst(debugMap.get(node));
		for(int i=0;i<values.length;i++)
			values2[1+i] = values[i];
		return new NodeCustom("debugPrint", values2);
	}

	@Override
	protected Function processFunction(Function function, Map<String, Object> args) {
		int[] genIntArray = new VMCodeGenerator(new Context(this.getContext().getInternalSeed()), function).generate();
		
		byte[] vmcode = new byte[genIntArray.length];
		for (int i = 0; i < genIntArray.length; i++) {
			vmcode[i] = (byte) genIntArray[i];
		}
		
		
		ArrayList<BasicBlock> blocks = new ArrayList<BasicBlock>();

		int VARS = function.getArguments().length;
		int index_args = VARS++;
		int index_program = VARS++;
		int index_staticdata = VARS++;
		int index_memory = VARS++; // stack [256 ints] + var memory
		int index_pc = VARS++;
		int index_data = VARS++;
		int index_op1 = VARS++;
		int index_op2 = VARS++;
		int index_jumpPosition = VARS++;
		int index_memslot = VARS++;
		int index_stackslot = VARS++;

		BasicBlock setup = new BasicBlock();
		{
			setup.getNodes().add(new NodeStore(MemorySize.INT, index_pc, cst(0))); // pc = 0;
			setup.getNodes().add(new NodeStore(MemorySize.POINTER, index_program, cst(vmcode)));
			setup.getNodes().add(
					new NodeStore(MemorySize.POINTER, index_memory, new NodeAlloc(MemorySize.POINTER, cst(STACK_SIZE + VAR_SIZE))));

			Node dataArray = new NodeAlloc(MemorySize.POINTER, cst(function.getDataMap().size()));
			Object[] dataArrayValues = function.getData();
			setup.getNodes().add(new NodeStore(MemorySize.POINTER, index_staticdata, dataArray));
			for (int i = 0; i < function.getDataMap().size(); i++) {
				setup.getNodes().add(new NodeAStore(dataArray, cst(i), cst(dataArrayValues[i]), MemorySize.POINTER));
			}

			Node argArray = new NodeAlloc(MemorySize.POINTER, cst(function.getArguments().length));
			Class<?>[] argArrayValues = function.getArguments();
			setup.getNodes().add(new NodeStore(MemorySize.POINTER, index_args, argArray));
			for (int i = 0; i < argArrayValues.length; i++) {
				setup.getNodes()
						.add(new NodeAStore(argArray, cst(i), new NodeLoad(MemorySize.POINTER, i), MemorySize.POINTER));
			}

			blocks.add(setup); // first basic block
		}
		
		//System.out.println(new Function("tmp", Arrays.asList(setup), new
		// Class<?>[] {}, 0, false).statistics());

		BasicBlock dispatcher = new BasicBlock();
		setup.setUnconditionalBranch(dispatcher);

		NodeALoad opcodeBlock;
		{

			// possibly move pc += 6 here
			NodeLoad program = new NodeLoad(MemorySize.POINTER, index_program);
			dispatcher.getNodes().add(program);
			NodeLoad pc = new NodeLoad(MemorySize.INT, index_pc);
			dispatcher.getNodes().add(pc);

			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_data, loadInt(program, pc, 1))); // this is
																											// only used
																											// once,
																											// maybe not
																											// run for
																											// each
																											// handler
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_op1, loadByte(program, pc, 1)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_op2, loadByte(program, pc, 2)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.SHORT, index_jumpPosition, loadShort(program, pc, 3)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_memslot, loadShort(program, pc, 1)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_stackslot, loadByte(program, pc, 4)));

			opcodeBlock = new NodeALoad(program, pc, MemorySize.BYTE);
			dispatcher.getNodes().add(opcodeBlock);
			blocks.add(dispatcher);

			 //if (DEBUG)
			 //dispatcher.getNodes().add(debugNode(function, "Opcode", opcodeBlock));
		}

		ArrayList<BasicBlock> handlers = new ArrayList<BasicBlock>();

		for (int opcode = 0; opcode < 0x38; opcode++) {
			BasicBlock handler = new BasicBlock();
			

			NodeLoad pc = new NodeLoad(MemorySize.INT, index_pc);
			NodeStore addPC6 = new NodeStore(MemorySize.INT, index_pc,
					add(pc, cst(6)));

			NodeLoad program = new NodeLoad(MemorySize.POINTER, index_program);
			NodeLoad memory = new NodeLoad(MemorySize.POINTER, index_memory);
			Node op1 = new NodeLoad(MemorySize.INT, index_op1);
			Node op2 = new NodeLoad(MemorySize.INT, index_op2);
			Node jumpPosition = new NodeLoad(MemorySize.SHORT, index_jumpPosition);
			Node memslot = new NodeLoad(MemorySize.INT, index_memslot);
			Node stackslot = new NodeLoad(MemorySize.INT, index_stackslot);

			Node tmp = null;

			switch (opcode) {
			case OP_CONST: {
				Node data = new NodeLoad(MemorySize.INT, index_data);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "CONST", data));

				// padding
				NodeLoad staticdata = new NodeLoad(MemorySize.POINTER, index_data);
				handler.getNodes().add(staticdata);
				tmp = loadStack(memory, stackslot);
				handler.getNodes().add(tmp);
				tmp = loadStack(memory, stackslot);
				handler.getNodes().add(tmp);
				// end of padding

				handler.getNodes().add(storeStack(memory, stackslot, data));
			}

				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_LOAD8:
				if (tmp == null) {
					tmp = loadData(memory, memslot);
					tmp = sub(and(tmp, cst(0x7F)), and(tmp, cst(0x80)));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "LOAD8", tmp));
				}
			case OP_LOAD16:
				if (tmp == null) {
					tmp = loadData(memory, memslot);
					tmp = sub(and(tmp, new NodeConst(0x7FFF)), and(tmp, new NodeConst(0x8000)));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "LOAD16", tmp));
				}
			case OP_LOAD32:
			case OP_LOADP:
				if (tmp == null) {
					tmp = mul(add(nop(memslot), cst(0)), cst(1));
					tmp = loadData(memory, tmp); // loadData(memory, memslot);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "LOAD32/P", tmp));
				}
				handler.getNodes().add(new NodeLoad(MemorySize.POINTER, index_data)); // padding
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;

			case OP_PLOAD8:
				if (tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = new NodeALoad(arguments, memslot, MemorySize.POINTER);
					tmp = sub(and(tmp, cst(0x7F)), and(tmp, cst(0x80)));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "PLOAD8", tmp));
				}
			case OP_PLOAD16:
				if (tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = new NodeALoad(arguments, memslot, MemorySize.POINTER);
					tmp = sub(and(tmp, new NodeConst(0x7FFF)), and(tmp, new NodeConst(0x8000)));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "PLOAD16", tmp));
				}
			case OP_PLOAD32:
			case OP_PLOADP:
				if (tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = mul(add(nop(memslot), cst(0)), cst(1));
					tmp = new NodeALoad(arguments, tmp, MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "PLOAD32/P", tmp));
				}
				tmp = mul(tmp, cst(1));
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_STORE8:
				if (tmp == null) {
					tmp = and(loadStack(memory, stackslot), cst(0xFF));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "STORE8", tmp));
				}
			case OP_STORE16:
				if (tmp == null) {
					tmp = and(loadStack(memory, stackslot), cst(0xFFFF));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "STORE16", tmp));
				}
			case OP_STORE32:
			case OP_STOREP:
				if (tmp == null) {
					tmp = add(stackslot, cst(0));
					tmp = loadStack(memory, tmp);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "STORE32/P", tmp));
				}
				handler.getNodes().add(new NodeLoad(MemorySize.POINTER, index_data)); // padding
				handler.getNodes().add(storeData(memory, memslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;

			case OP_ALOAD8:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.BYTE);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALOAD8", tmp));
				}
			case OP_ALOAD16:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.SHORT);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALOAD16", tmp));
				}
			case OP_ALOAD32:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.INT);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALOAD32", tmp));
				}
			case OP_ALOADP:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALOADP", tmp));
				}

				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;

			case OP_ASTORE8:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.BYTE);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ASTORE8", loadStack(memory, op1), loadStack(memory, op2)));
				}
			case OP_ASTORE16:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.SHORT);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ASTORE16", loadStack(memory, op1), loadStack(memory, op2)));
				}
			case OP_ASTORE32:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.INT);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ASTORE32", loadStack(memory, op1), loadStack(memory, op2)));
				}
			case OP_ASTOREP:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ASTOREP", loadStack(memory, op1), loadStack(memory, op2)));
				}
				handler.getNodes().add(tmp);
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_NOT:
				if (tmp == null) {
					handler.getNodes().add(loadStack(memory, op2));
					tmp = not(loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "NOT", tmp));
				}
			case OP_NEG:
				if (tmp == null) {
					handler.getNodes().add(loadStack(memory, op2));
					tmp = neg(loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "NEG", tmp));
				}
			case OP_NOP:
				if (tmp == null) {
					handler.getNodes().add(loadStack(memory, op2));
					tmp = nop(loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "NOP", tmp));
				}
			case OP_ADD:
				if (tmp == null) {
					tmp = add(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ADD", tmp));
				}
			case OP_SUB:
				if (tmp == null) {
					tmp = sub(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "SUB", tmp));
				}
			case OP_MUL:
				if (tmp == null) {
					tmp = mul(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "MUL", tmp));
				}
			case OP_DIV:
				if (tmp == null) {
					tmp = div(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "DIV", tmp));
				}
			case OP_MOD:
				if (tmp == null) {
					tmp = mod(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "MOD", tmp));
				}
			case OP_AND:
				if (tmp == null) {
					Node a = loadStack(memory, op1);
					Node b = loadStack(memory, op2);
					tmp = and(a, b);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "AND", a, b, tmp, stackslot));
				}
			case OP_OR:
				if (tmp == null) {
					tmp = or(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "OR", tmp));
				}
			case OP_XOR:
				if (tmp == null) {
					tmp = xor(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "XOR", tmp));
				}
			case OP_SHR:
				if (tmp == null) {
					tmp = shr(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "SHR", tmp));
				}
			case OP_USHR:
				if (tmp == null) {
					tmp = ushr(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "USHR", tmp));
				}
			case OP_SHL:
				if (tmp == null) {
					tmp = shl(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "SHL", tmp));
				}
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_COMPARE_EQUAL: {
				Node op1d = loadStack(memory, op1);
				Node op2d = loadStack(memory, op2);
				Node cmp = and(ushr(not(or(sub(op1d, op2d), sub(op2d, op1d))), cst(31)), cst(1));
				Node jmp = add(mul(cmp, sub(jumpPosition, cst(6))), cst(6));
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "COMPARE_EQUAL", jmp));
				jmp = nop(nop(nop(jmp)));
				handler.getNodes()
						.add(new NodeStore(MemorySize.INT, index_pc, add(new NodeLoad(MemorySize.INT, index_pc), jmp)));
				handler.setUnconditionalBranch(dispatcher);
			}
				break;
			case OP_COMPARE_NOTEQUAL: {
				Node op1d = loadStack(memory, op1);
				Node op2d = loadStack(memory, op2);
				Node cmp = and(ushr(or(sub(op1d, op2d), sub(op2d, op1d)), cst(31)), cst(1));
				Node jmp = add(mul(cmp, sub(jumpPosition, cst(6))), cst(6));
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "COMPARE_NOTEQUAL", jmp));
				jmp = nop(nop(nop(nop(jmp))));
				handler.getNodes()
						.add(new NodeStore(MemorySize.INT, index_pc, add(new NodeLoad(MemorySize.INT, index_pc), jmp)));
				handler.setUnconditionalBranch(dispatcher);
			}
				break;
			case OP_COMPARE_GREATERTHAN:
				tmp = op1;
				op1 = op2;
				op2 = tmp;
			case OP_COMPARE_LESSTHAN: {
				Node op1d = loadStack(memory, op1);
				Node op2d = loadStack(memory, op2);
				Node cmp = and(ushr(xor(sub(op1d, op2d), and(xor(op1d, op2d), xor(sub(op1d, op2d), op1d))), cst(31)),
						cst(1));
				Node jmp = add(mul(cmp, sub(jumpPosition, cst(6))), cst(6));
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "COMPARE_LT/GT", jmp));
				jmp = nop(jmp);
				handler.getNodes()
						.add(new NodeStore(MemorySize.INT, index_pc, add(new NodeLoad(MemorySize.INT, index_pc), jmp)));
				handler.setUnconditionalBranch(dispatcher);
			}
				break;
			case OP_COMPARE_GREATEREQUAL:
				tmp = op1;
				op1 = op2;
				op2 = tmp;
			case OP_COMPARE_LESSEQUAL: {
				Node op1d = loadStack(memory, op1);
				Node op2d = loadStack(memory, op2);
				Node cmp = and(ushr(and(or(op1d, not(op2d)), or(xor(op1d, op2d), not(sub(op2d, op1d)))), cst(31)),
						cst(1));
				Node jmp = add(mul(cmp, sub(jumpPosition, cst(6))), cst(6));
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "COMPARE_LE/GE", jmp));
				handler.getNodes()
						.add(new NodeStore(MemorySize.INT, index_pc, add(new NodeLoad(MemorySize.INT, index_pc), jmp)));
				handler.setUnconditionalBranch(dispatcher);
			}
				break;
			case OP_SWITCH: {
				Node curpc = new NodeLoad(MemorySize.INT, index_pc);
				Node switchVar = loadStack(memory, op1);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "SWTICH", switchVar));
				tmp = loadShort(program, add(curpc, shl(switchVar, cst(1))), 6);
				tmp = sub(and(tmp, new NodeConst(0x7FFF)), and(tmp, new NodeConst(0x8000))); // sign
				handler.getNodes().add(new NodeStore(MemorySize.INT, index_pc, add(add(curpc, cst(6)), tmp)));
				handler.setUnconditionalBranch(dispatcher);
			}

				break;
			case OP_JUMP:
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "JUMP", jumpPosition));
				handler.getNodes().add(new NodeStore(MemorySize.INT, index_pc,
						add(new NodeLoad(MemorySize.INT, index_pc), jumpPosition)));
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_RETURN:
				tmp = loadStack(memory, op1);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "RETURN"));
				handler.getNodes().add(tmp);
				handler.setExitBlock(null);
				break;
			case OP_RETURNV:
				tmp = loadStack(memory, op1);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "RETURNV", tmp));
				handler.getNodes().add(tmp);
				handler.setExitBlock(tmp);
				break;
			case OP_ALLOC8:
				if (tmp == null) {
					tmp = new NodeAlloc(MemorySize.BYTE, loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALLOC8", tmp));
				}
			case OP_ALLOC16:
				if (tmp == null) {
					tmp = new NodeAlloc(MemorySize.SHORT, loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALLOC16", tmp));
				}
			case OP_ALLOC32:
				if (tmp == null) {
					tmp = new NodeAlloc(MemorySize.INT, loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALLOC32", tmp));
				}
			case OP_ALLOCP:
				if (tmp == null) {
					tmp = new NodeAlloc(MemorySize.POINTER, loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "ALLOCP", tmp));
				}
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_PSTORE8:
				if (tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = and(loadStack(memory, stackslot), cst(0xFF));
					tmp = new NodeAStore(arguments, add(memslot, cst(0)), tmp, MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "PSTORE8", tmp));
				}
			case OP_PSTORE16:
				if (tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = and(loadStack(memory, stackslot), cst(0xFFFF));
					tmp = new NodeAStore(arguments, add(memslot, cst(0)), tmp, MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "PSTORE16", tmp));
				}
			case OP_PSTORE32:
			case OP_PSTOREP:
				if (tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = add(stackslot, cst(0));
					tmp = loadStack(memory, tmp);
					tmp = new NodeAStore(arguments, add(memslot, cst(0)), tmp, MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(debugNode(function, "PSTORE32/P", tmp));
				}

				handler.getNodes().add(tmp);
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_OCONST: {
				Node data = new NodeLoad(MemorySize.INT, index_data);
				NodeLoad staticdata = new NodeLoad(MemorySize.POINTER, index_staticdata);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "OCONST", data));
				tmp = new NodeALoad(staticdata, data, MemorySize.POINTER);
			}
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_CUSTOM_PREPCALL: {
				Node s1 = loadStack(memory, op1);
				Node s2 = loadStack(memory, op2);
				Node s3 = loadStack(memory, loadByte(program, pc, 3));
				Node s4 = loadStack(memory, loadByte(program, pc, 5));
				tmp = new NodeCustom("prepare_call", s1, s2, s3, s4);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "CUSTOM_PREPCALL", s1, s2, s3, s4));
			}	
				handler.getNodes().add(storeStack(memory, stackslot, new NodeCustom("call", tmp)));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_CUSTOM_CALL: {
				tmp = loadStack(memory, op1);
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "CUSTOM_CALL", tmp));
			}
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			default:
				if (DEBUG)
					handler.getNodes().add(debugNode(function, "ILLEGAL OPCODE"));
				handler.setExitBlock(null);
			}
			
			//System.out.println(String.format("%02X: ", opcode) + (new Function("tmp", Arrays.asList(handler), new
			// Class<?>[] {}, 0, false)).statistics());
			handlers.add(handler);
			blocks.add(handler);
		}

		dispatcher.setSwitchBlock(handlers, opcodeBlock);
		
		//System.out.println(new Function("tmp", Arrays.asList(dispatcher), new
		// Class<?>[] {}, 0, false).statistics());

	
		Function vmFunction;
		if(function instanceof MergedFunction)
			vmFunction = new MergedFunction(function.getName(), blocks, function.getArguments(), ((MergedFunction) function).getOriginalArguments(), VARS, true);
		else
			vmFunction = new Function(function.getName(), blocks, function.getArguments(), VARS, true);
		
		vmFunction.setDataMap(function.getDataMap());
		vmFunction.registerData(vmcode);

		return vmFunction;
	}

	private static Node storeStack(Node memory, Node stackslot, Node data) {
		return new NodeAStore(memory, stackslot, data, MemorySize.POINTER);
	}

	private static Node loadStack(Node memory, Node stackslot) {
		return new NodeALoad(memory, stackslot, MemorySize.POINTER);
	}

	private static Node storeData(Node memory, Node memslot, Node data) {
		return new NodeAStore(memory, add(memslot, cst(STACK_SIZE)), data, MemorySize.POINTER);
	}

	private static Node loadData(Node memory, Node memslot) {
		return new NodeALoad(memory, add(memslot, cst(STACK_SIZE)), MemorySize.POINTER);
	}

	private static Node loadByte(Node program, Node pc, int offset) {
		return and(new NodeALoad(program, add(pc, cst(offset)), MemorySize.BYTE), cst(0xFF));
	}

	private static Node loadShort(Node program, Node pc, int offset) {
		return or(shl(loadByte(program, pc, offset + 1), cst(8)), loadByte(program, pc, offset));
	}

	private static Node loadInt(Node program, Node pc, int offset) {
		return or(shl(loadByte(program, pc, offset + 4), cst(24)), or(shl(loadByte(program, pc, offset + 2), cst(16)),
				or(shl(loadByte(program, pc, offset + 1), cst(8)), loadByte(program, pc, offset))));
	}

	@Override
	public Map<String, Node> statistics(Map<String, Object> args) {
		Map<String, Node> map = new HashMap<String, Node>();

		// per data entry
		// new NodeAStore(dataArray, cst(i), cst(dataArrayValues[i]),
		// MemorySize.POINTER);

		// per argument entry
		// new NodeAStore(argArray, cst(i), new NodeLoad(MemorySize.POINTER, i),
		// MemorySize.POINTER)

		map.put("const", add(add(cst(155), mul(cst("appendedData"), cst(2))), cst("arguments")));
		map.put("blocks", cst(58));
		map.put("custom", cst(2));
		map.put("store", cst(65));
		map.put("aload", cst(111));
		map.put("conditionalBlocks", cst(0));
		map.put("astore", add(add(cst(46), cst("appendedData")), cst("arguments")));
		map.put("allocate", cst(7));
		map.put("switchBlocks", cst(1));
		map.put("math", cst(236));
		map.put("jumpBlocks", cst(55));
		map.put("load", add(cst(268), cst("arguments")));
		map.put("exitBlocks", cst(2));
		map.put("variables", add(cst(11), cst("arguments")));
		map.put("appendedData", add(cst("appendedData"), cst(1)));

		return map;
	}

	
	private static Node formular(Node initial, int dispatcher, int cst, int load, int store, int aload, int astore, int math, int alloc, int custom, int cond, int jmp, int swit, int exit) {
		return  add(add(
				add(add(add(add(
						add(add(add(add(add(add(initial,
								mul(cst("const"), cst(dispatcher+cst))),
								mul(cst("load"), cst(dispatcher+load))),
								mul(cst("store"), cst(dispatcher+store))),
								mul(cst("aload"), cst(dispatcher+aload))),
								mul(cst("astore"), cst(dispatcher+astore))), 
								mul(cst("math"), cst(dispatcher+math))),
						mul(cst("conditionalBlocks"), cst(dispatcher+cond))), 
						mul(add(cst("jumpBlocks"), cst("conditionalBlocksFalse")), cst(dispatcher+jmp))),
						mul(cst("switchBlocks"), cst(dispatcher+swit))),
						mul(cst("exitBlocks"), cst(dispatcher+exit))),
				mul(cst("allocate"), cst(dispatcher+alloc))),
				mul(cst("custom"), cst(dispatcher+custom)));
	}
	
	@Override
	public Map<String, Node> statisticsRuntime(Map<String, Object> args) {
		Map<String, Node> map = new HashMap<String, Node>();
		
		// TODO: considerations for calls/custom calls are missing here
		// Given how inprecice runtime constrains are anyways, this is not a huge priority [and might not make it into the final release]
		
		map.put("const", formular(add(add(cst(5), cst("arguments")), mul(cst("appendedData"), cst(2))), 27, 1, 4, 3, 1, 1, 1, 1, 0, 4, 0, 9, 0));
		map.put("store", formular(cst(5), 6, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0));
		map.put("aload", formular(cst(0), 12, 2, 1, 1, 3, 3, 2, 1, 0, 2, 0, 3, 1));
		map.put("astore", formular(add(add(cst(0), cst("appendedData")), cst("arguments")), 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0));
		map.put("load", formular(add(cst(0),  cst("arguments")), 2, 5, 5, 5, 5, 5, 5, 4, 0, 5, 2, 4, 2));
		map.put("allocate", formular(cst(3), 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0));
		map.put("math", formular(cst(0), 32, 1, 5, 3, 1, 1, 2, 1, 0, 13, 1, 13, 0));
		map.put("jumpBlocks", formular(cst(1), 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0));
		map.put("switchBlocks", formular(cst(0), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
		map.put("blocks", formular(cst(1), 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
		map.put("conditionalBlocks", cst(0));
		map.put("conditionalBlocksFalse", cst(0));
		map.put("exitBlocks", cst(1));
		map.put("variables", add(cst(11), cst("arguments")));
		map.put("appendedData", add(cst("appendedData"), cst(1)));

		return map;
	}

	public String description() {
		return "Virtualizes the input function";
	}

}
