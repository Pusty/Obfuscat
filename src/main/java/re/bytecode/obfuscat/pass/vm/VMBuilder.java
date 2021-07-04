package re.bytecode.obfuscat.pass.vm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.builder.Builder;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;
import static re.bytecode.obfuscat.cfg.MathOperation.*;
import static re.bytecode.obfuscat.pass.vm.VMConst.*;

/**
 * This a builder for a virtual machine following the VMConst Virtual Machine specs
 * the idea behind this is that each handler has the same format, so that
 * conclusions about runtime behavior can be done
 */
public class VMBuilder extends Builder {

	private static final boolean DEBUG = false;

	public VMBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		ArrayList<BasicBlock> blocks = new ArrayList<BasicBlock>();

		int index_program = 0;
		int index_memory = 1; // stack [256 ints] + var memory
		int index_args = 2;

		int VARS = 3;
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
			blocks.add(setup); // first basic block
		}

		BasicBlock dispatcher = new BasicBlock();
		setup.setUnconditionalBranch(dispatcher);

		NodeALoad opcodeBlock;
		{
			
			// possibly move pc += 6 here
			NodeLoad program = new NodeLoad(MemorySize.POINTER, index_program);
			dispatcher.getNodes().add(program);
			NodeLoad pc = new NodeLoad(MemorySize.INT, index_pc);
			dispatcher.getNodes().add(pc);

			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_data, loadInt(program, pc, 1))); // this is only used once, maybe not run for each handler
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_op1, loadByte(program, pc, 1)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_op2, loadByte(program, pc, 2)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.SHORT, index_jumpPosition, loadShort(program, pc, 3)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_memslot, loadShort(program, pc, 1)));
			dispatcher.getNodes().add(new NodeStore(MemorySize.INT, index_stackslot, loadByte(program, pc, 4)));

			opcodeBlock = new NodeALoad(program, pc, MemorySize.BYTE);
			dispatcher.getNodes().add(opcodeBlock);
			blocks.add(dispatcher);

			//if (DEBUG)
			//	dispatcher.getNodes().add(new NodeCustom("debugPrint", cst("Opcode"), opcodeBlock));
		}

		ArrayList<BasicBlock> handlers = new ArrayList<BasicBlock>();

		for (int opcode = 0; opcode < 0x2D; opcode++) {
			BasicBlock handler = new BasicBlock();

			NodeStore addPC6 = new NodeStore(MemorySize.INT, index_pc,
					add(new NodeLoad(MemorySize.INT, index_pc), cst(6)));

			NodeLoad memory = new NodeLoad(MemorySize.POINTER, index_memory);
			handler.getNodes().add(memory);
			
			Node op1 = new NodeLoad(MemorySize.INT, index_op1);
			Node op2 = new NodeLoad(MemorySize.INT, index_op2);
			Node jumpPosition = new NodeLoad(MemorySize.SHORT, index_jumpPosition);
			Node memslot = new NodeLoad(MemorySize.INT, index_memslot);
			Node stackslot = new NodeLoad(MemorySize.INT, index_stackslot);

			handler.getNodes().add(op1);
			handler.getNodes().add(op2);
			handler.getNodes().add(jumpPosition);
			handler.getNodes().add(memslot);
			handler.getNodes().add(stackslot);

			Node tmp = null;

			
			// TODO: Make sure each handler uses the same amount of nodes, and the same types
			// This will introduce quite the overhead
			
			
			switch (opcode) {
			case OP_CONST:
				Node data = new NodeLoad(MemorySize.INT, index_data);
				if (DEBUG)
					handler.getNodes().add(new NodeCustom("debugPrint", cst("CONST"), data));
				handler.getNodes().add(storeStack(memory, stackslot, data));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_LOAD8:
				if (tmp == null) {
					tmp = loadData(memory, memslot);
					tmp = sub(and(tmp, cst(0x7F)), and(tmp, cst(0x80)));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("LOAD8"), tmp));
				}
			case OP_LOAD16:
				if (tmp == null) {
					tmp = loadData(memory, memslot);
					tmp = sub(and(tmp, new NodeConst(0x7FFF)), and(tmp, new NodeConst(0x8000)));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("LOAD16"), tmp));
				}
			case OP_LOAD32:
			case OP_LOADP:
				if (tmp == null) {
					tmp = loadData(memory, memslot);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("LOAD32/P"), tmp));
				}
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;

			case OP_PLOAD8:
				if(tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = new NodeALoad(arguments, memslot, MemorySize.POINTER);
					tmp = sub(and(tmp, cst(0x7F)), and(tmp, cst(0x80)));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("PLOAD8"), tmp));
				}
			case OP_PLOAD16:
				if(tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = new NodeALoad(arguments, memslot, MemorySize.POINTER);
					tmp = sub(and(tmp, new NodeConst(0x7FFF)), and(tmp, new NodeConst(0x8000)));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("PLOAD16"), tmp));
				}
			case OP_PLOAD32:
			case OP_PLOADP:
				if(tmp == null) {
					NodeLoad arguments = new NodeLoad(MemorySize.POINTER, index_args);
					tmp = new NodeALoad(arguments, memslot, MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("PLOAD32/P"), tmp));
				}
				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_STORE8:
				if (tmp == null) {
					tmp = and(loadStack(memory, stackslot), cst(0xFF));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("STORE8"), tmp));
				}
			case OP_STORE16:
				if (tmp == null) {
					tmp = and(loadStack(memory, stackslot), cst(0xFFFF));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("STORE16"), tmp));
				}
			case OP_STORE32:
			case OP_STOREP:
				if (tmp == null) {
					tmp = loadStack(memory, stackslot);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("STORE32/P"), tmp));
				}
				handler.getNodes().add(storeData(memory, memslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;

			case OP_ALOAD8:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.BYTE);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ALOAD8"), tmp));
				}
			case OP_ALOAD16:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.SHORT);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ALOAD16"), tmp));
				}
			case OP_ALOAD32:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.INT);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ALOAD32"), tmp));
				}
			case OP_ALOADP:
				if (tmp == null) {
					tmp = new NodeALoad(loadStack(memory, op1), loadStack(memory, op2), MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ALOADP"), tmp));
				}

				handler.getNodes().add(storeStack(memory, stackslot, tmp));
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;

			case OP_ASTORE8:
				if (tmp == null) {
					Node op1d = loadStack(memory, op1);
					Node op2d = loadStack(memory, op2);
					tmp = new NodeAStore(op1d, op2d, loadStack(memory, stackslot),
							MemorySize.BYTE);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ASTORE8"), op1d, op2d));
				}
			case OP_ASTORE16:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.SHORT);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ASTORE16"), op1, op2));
				}
			case OP_ASTORE32:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.INT);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ASTORE32"), op1, op2));
				}
			case OP_ASTOREP:
				if (tmp == null) {
					tmp = new NodeAStore(loadStack(memory, op1), loadStack(memory, op2), loadStack(memory, stackslot),
							MemorySize.POINTER);
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ASTOREP"), op1, op2));
				}
				handler.getNodes().add(tmp);
				handler.getNodes().add(addPC6);
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_NOT:
				if (tmp == null) {
					tmp = not(loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("NOT"), tmp));
				}
			case OP_NEG:
				if (tmp == null) {
					tmp = neg(loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("NEG"), tmp));
				}
			case OP_NOP:
				if (tmp == null) {
					tmp = nop(loadStack(memory, op1));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("NOP"), tmp));
				}
			case OP_ADD:
				if (tmp == null) {
					tmp = add(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("ADD"), tmp));
				}
			case OP_SUB:
				if (tmp == null) {
					tmp = sub(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("SUB"), tmp));
				}
			case OP_MUL:
				if (tmp == null) {
					tmp = mul(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("MUL"), tmp));
				}
			case OP_DIV:
				if (tmp == null) {
					tmp = div(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("DIV"), tmp));
				}
			case OP_MOD:
				if (tmp == null) {
					tmp = mod(loadStack(memory, op1), loadStack(memory, op2));
					if (DEBUG)
						handler.getNodes().add(new NodeCustom("debugPrint", cst("MOD"), tmp));
				}
			case OP_AND:
				if (tmp == null) {
					Node a = loadStack(memory, op1);
					Node b = loadStack(memory, op2);
					tmp = and(a, b);
					if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("AND"), a, b, tmp, stackslot));
				}
			case OP_OR:
				if (tmp == null) {
					tmp = or(loadStack(memory, op1), loadStack(memory, op2));
					if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("OR"), tmp));
				}
			case OP_XOR:
				if (tmp == null) {
					tmp = xor(loadStack(memory, op1), loadStack(memory, op2));
					if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("XOR"), tmp));
				}
			case OP_SHR:
				if (tmp == null) {
					tmp = shr(loadStack(memory, op1), loadStack(memory, op2));
					if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("SHR"), tmp));
				}
			case OP_USHR:
				if (tmp == null) {
					tmp = ushr(loadStack(memory, op1), loadStack(memory, op2));
					if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("USHR"), tmp));
				}
			case OP_SHL:
				if (tmp == null) {
					tmp = shl(loadStack(memory, op1), loadStack(memory, op2));
					if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("SHL"), tmp));
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
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("COMPARE_EQUAL"), jmp));
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
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("COMPARE_NOTEQUAL"), jmp));
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
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("COMPARE_LT/GT"), jmp));
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
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("COMPARE_LE/GE"), jmp));
				handler.getNodes()
						.add(new NodeStore(MemorySize.INT, index_pc, add(new NodeLoad(MemorySize.INT, index_pc), jmp)));
				handler.setUnconditionalBranch(dispatcher);
			}
				break;
			case OP_SWITCH: {

				NodeLoad program = new NodeLoad(MemorySize.POINTER, index_program);
				handler.getNodes().add(program);
				Node curpc = new NodeLoad(MemorySize.INT, index_pc);
				Node switchVar = loadStack(memory, op1);
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("SWTICH"), switchVar));
				tmp = loadShort(program, add(curpc, shl(switchVar, cst(1))), 6);
				tmp = sub(and(tmp, new NodeConst(0x7FFF)), and(tmp, new NodeConst(0x8000))); // sign
				handler.getNodes().add(new NodeStore(MemorySize.INT, index_pc, add(add(curpc, cst(6)), tmp)));
				handler.setUnconditionalBranch(dispatcher);
			}

				break;
			case OP_JUMP:
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("JUMP"), jumpPosition));
				handler.getNodes().add(new NodeStore(MemorySize.INT, index_pc,
						add(new NodeLoad(MemorySize.INT, index_pc), jumpPosition)));
				handler.setUnconditionalBranch(dispatcher);
				break;
			case OP_RETURN:
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("RETURN")));
				handler.setExitBlock(null);
				break;
			case OP_RETURNV:
				tmp = loadStack(memory, op1);
				if(DEBUG) handler.getNodes().add(new NodeCustom("debugPrint", cst("RETURNV"), tmp));
				handler.getNodes().add(tmp);
				handler.setExitBlock(tmp);
				break;
			default:
				if (DEBUG)
					handler.getNodes().add(new NodeCustom("debugPrint", cst("ILLEGAL OPCODE")));
				handler.setExitBlock(null);
			}

			handlers.add(handler);
			blocks.add(handler);
		}

		dispatcher.setSwitchBlock(handlers, opcodeBlock);

		Function vmFunction = new Function("vm", blocks, new Class<?>[] { byte[].class, int[].class, Object[].class }, VARS, true);

		return vmFunction;
	}

	private static Node storeStack(Node memory, Node stackslot, Node data) {
		return new NodeAStore(memory, stackslot, data, MemorySize.POINTER);
	}

	private static Node loadStack(Node memory, Node stackslot) {
		return new NodeALoad(memory, stackslot, MemorySize.POINTER);
	}

	private static Node storeData(Node memory, Node memslot, Node data) {
		return new NodeAStore(memory, add(memslot, cst(0x100)), data, MemorySize.POINTER);
	}

	private static Node loadData(Node memory, Node memslot) {
		return new NodeALoad(memory, add(memslot, cst(0x100)), MemorySize.POINTER);
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
	public Map<String, Class<?>> supportedArguments() {
		HashMap<String, Class<?>> supported = new HashMap<String, Class<?>>();
		// supported.put("data", byte[].class);
		return supported;
	}

	@Override
	public Map<String, String> supportedArgumentsHelp() {
		HashMap<String, String> helpInfo = new HashMap<String, String>();
		// helpInfo.put("data", "[Required] The key this function will generate");
		return helpInfo;
	}

	public String description() {
		return "A builder for creating Virtual Machines";
	}
}
