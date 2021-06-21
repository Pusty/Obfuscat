package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

/**
 * The Code Synthesizer for ARMv8 Thumb2 Code
 */
public class ThumbCodeGenerator extends CodeGenerator {

	/**
	 * Create a new ThumbCodeGenerator (recommended way of creating an instance is
	 * through {@link re.bytecode.obfuscat.Obfuscat#generateCode(String, Function)})
	 * 
	 * @param context
	 *            the context of this generator, may be null
	 * @param function
	 *            the function to generate code for
	 */
	public ThumbCodeGenerator(Context context, Function function) {
		super(context, function);
	}

	public String description() {
		return "A code generator for ARMv8 Thumb2 code";
	}

	// Load Node Result from the Stack
	private void loadNode(int[] data, int offset, int register, Node from) {

		int fromID = this.getNodeID(from);

		// ldr r0, [sp, #0x0] - 00 98

		if (fromID > 0xFF)
			throw new RuntimeException("Too high block Node ID " + fromID);

		data[offset] = fromID & 0xFF;

		if (register == 0)
			data[offset + 1] = 0x98;
		else if (register == 1)
			data[offset + 1] = 0x99;
		else if (register == 2)
			data[offset + 1] = 0x9A;
		else if (register == 3)
			data[offset + 1] = 0x9B;
		else if (register == 4)
			data[offset + 1] = 0x9C;
		else if (register == 5)
			data[offset + 1] = 0x9D;
		else if (register == 6)
			data[offset + 1] = 0x9E;
		else if (register == 7)
			data[offset + 1] = 0x9F;
		else
			throw new RuntimeException("Register " + register + " not supported");
	}

	// Store Node Result to the Stack
	private void storeNode(int[] data, int offset, Node from) {

		int fromID = this.getNodeID(from);
		storeSlot(data, offset, fromID, 0);

	}

	// Store Register Value to a stack slot from a given register
	private void storeSlot(int[] data, int offset, int slot, int register) {

		// str r0, [sp, #0x0] - 00 90

		if (slot > 0xFF)
			throw new RuntimeException("Too high block Node ID " + slot);

		data[offset] = slot & 0xFF;

		if (register == 0)
			data[offset + 1] = 0x90;
		else if (register == 1)
			data[offset + 1] = 0x91;
		else if (register == 2)
			data[offset + 1] = 0x92;
		else if (register == 3)
			data[offset + 1] = 0x93;
		else if (register == 4)
			data[offset + 1] = 0x94;
		else if (register == 5)
			data[offset + 1] = 0x95;
		else if (register == 6)
			data[offset + 1] = 0x96;
		else if (register == 7)
			data[offset + 1] = 0x97;
		else
			throw new RuntimeException("Register " + register + " not supported");

	}

	
	private int conditionCode(CompareOperation type) {
		switch (type) {
		case EQUAL:
			return 0;
		case NOTEQUAL:
			return 1;
		case LESSTHAN:
			return 11;
		case LESSEQUAL:
			return 13;
		case GREATERTHAN:
			return 12;
		case GREATEREQUAL:
			return 10;
		default:
			throw new RuntimeException("Not implemented");
		}
	}
	
	// As conditional and unconditional jump encoding is non-trivial
	// This function is here to handle it
	// Implemented based on the encoding specifications of the ARMv8 Thumb Manual
	private void conditionalJump(int[] data, int offset, int position, CompareOperation type) {

		if (position % 2 != 0)
			throw new RuntimeException("Jump position not dividable by 2");

		position = position / 2;

		if (position >= 0x40000)
			throw new RuntimeException("Offset too far away");
		if (position <= -0x40000)
			throw new RuntimeException("Offset too far away");

		// 1 1 1 1 0 S cond != 111x imm6 1 0 J1 0 J2 imm11

		int cond = 0;
		boolean isConditional = true;

		int j1 = 0;
		int j2 = 0;
		int s = 0;

		if (type == null) {
			j1 = 1;
			j2 = 1;
			isConditional = false;
		} else {
			cond = conditionCode(type);
		}

		if (position < 0) {
			j1 = 1;
			j2 = 1;
			s = 1;
			if (!isConditional)
				cond = 15; // 1111 - negative
		}

		data[offset + 0] = ((cond & 0x3) << 6) | (position >> 11) & 0x3F;
		data[offset + 1] = 0xF0 | (s << 2) | ((cond >> 2) & 0x3);
		data[offset + 2] = position & 0xFF;
		data[offset + 3] = 0x80 | ((j1 & 1) << 5) | ((isConditional ? 0 : 1) << 4) | ((j2 & 1) << 3)
				| ((position >> 8) & 0x7);
		// System.out.println(cond+" -> "+Integer.toHexString(data[offset])+"
		// "+Integer.toHexString(data[offset+1])+"
		// "+Integer.toHexString(data[offset+2])+"
		// "+Integer.toHexString(data[offset+3]));
	}

	@Override
	protected void initMapping() {

		// Default case
		codeMapping.put(null, new ThumbNodeCodeGenerator(null) {

			@Override
			public void process(CompiledBasicBlock cbb, Node node) {
				throw new RuntimeException("Not implemented " + node);
			}

			@Override
			public void writeData(Node node, int[] data) {
			}

		});

		// Encode Constants
		codeMapping.put(NodeConst.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeConst);
				NodeConst node = (NodeConst) n;
				Object constObj = node.getObj();
				int value = 0;
				if (constObj instanceof Integer) {
					value = ((Integer) constObj).intValue();
				} else if (constObj instanceof Short) {
					value = ((Short) constObj).intValue();
				} else if (constObj instanceof Byte) {
					value = ((Byte) constObj).intValue();
				} else if (constObj instanceof Character) {
					value = (int) ((Character) constObj).charValue();
				} else {
					throw new RuntimeException("Const type " + constObj.getClass() + " not implemented");
				}

				// MOVW r0, 0x1234 - 41 F2 34 20
				// MOVT r0, 0x5678 - C5 F2 78 60

				data[0] = 0x40 | (value >> 12) & 0xF;
				data[1] = 0xF2 | (((value >> 11) & 1) << 2);
				data[2] = value & 0xFF;
				data[3] = (((value >> 8) & 0x7) << 4);

				value = (value >> 16) & 0xFFFF;

				data[4] = 0xC0 | (value >> 12) & 0xF;
				data[5] = 0xF2 | (((value >> 11) & 1) << 2);
				data[6] = value & 0xFF;
				data[7] = (((value >> 8) & 0x7) << 4);

				storeNode(data, 8, node);

				data[10] = 0x00; // NOP
				data[11] = 0xBF;

				data[12] = 0x00; // NOP
				data[13] = 0xBF;

				data[14] = 0x00; // NOP
				data[15] = 0xBF;

				// 6 Instructions
			}

		});

		// Encode Variable Load Operations
		codeMapping.put(NodeLoad.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeLoad);
				NodeLoad node = (NodeLoad) n;

				int slot = node.getSlot();
				int slotMem = slot * 4;

				if (slotMem >= 8192)
					throw new RuntimeException("Variable slot " + slot + " not supported");

				// The old out-commented versions were smaller, but unsigned which causes wrong
				// results

				switch (node.getLoadSize()) {
				case BYTE:

					// LDRB r0, [r7, #0x0] - 38 78
					// data[0] = 0x38 | ((slot & 3) << 6);
					// data[1] = 0x78 | ((slot & 0x1C) >> 2);

					// LDRSB r0, [r7, #0x4] - 97 F9 04 00
					data[0] = 0x97;
					data[1] = 0xF9;
					data[2] = slotMem & 0xFF;
					data[3] = (slotMem >> 8) & 0x0F;
					break;
				case SHORT:
					// LDRH r0, [r7, #0x0] - 38 88
					// data[0] = 0x38 | ((slot & 3) << 6);
					// data[1] = 0x88 | ((slot & 0x1C) >> 2);

					// LDRSH r0, [r7, #0x4] - B7 F9 04 00
					data[0] = 0xB7;
					data[1] = 0xF9;
					data[2] = slotMem & 0xFF;
					data[3] = (slotMem >> 8) & 0x0F;
					break;
				case INT:
				case POINTER:
					// LDR r0, [r7, #0x0] - 38 68
					// data[0] = 0x38 | ((slot & 3) << 6);
					// data[1] = 0x68 | ((slot & 0x1C) >> 2);

					// LDR r0, [r7, #0x100] - D7 F8 00 01
					data[0] = 0xD7;
					data[1] = 0xF8;
					data[2] = slotMem & 0xFF;
					data[3] = (slotMem >> 8) & 0x0F;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				storeNode(data, 4, node);

				data[6] = 0x00; // NOP
				data[7] = 0xBF;

				data[8] = 0x00; // NOP
				data[9] = 0xBF;

				data[10] = 0x00; // NOP
				data[11] = 0xBF;

				data[12] = 0xAF; // NOP.W
				data[13] = 0xF3;
				data[14] = 0x00;
				data[15] = 0x80;

				// 6 instructions
			}
		});

		// Encode Variable Store Operations
		codeMapping.put(NodeStore.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeStore);
				NodeStore node = (NodeStore) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);

				int slot = node.getSlot();
				int slotMem = slot * 4;

				if (slotMem >= 8192)
					throw new RuntimeException("Variable slot not supported");

				switch (node.getStoreSize()) {
				case BYTE:
					// STRB r0, [r7, #0x100] - 87 F8 00 01
					data[2] = 0x87;
					data[3] = 0xF8;
					data[4] = slotMem & 0xFF;
					data[5] = (slotMem >> 8) & 0x0F;
					break;
				case SHORT:
					// STRH r0, [r7, #0x100] - A7 F8 00 01
					data[2] = 0xA7;
					data[3] = 0xF8;
					data[4] = slotMem & 0xFF;
					data[5] = (slotMem >> 8) & 0x0F;
					break;
				case INT:
				case POINTER:
					// STR r0, [r7, #0x100] - C7 F8 00 01
					data[2] = 0xC7;
					data[3] = 0xF8;
					data[4] = slotMem & 0xFF;
					data[5] = (slotMem >> 8) & 0x0F;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				data[6] = 0x00; // NOP
				data[7] = 0xBF;

				data[8] = 0x00; // NOP
				data[9] = 0xBF;

				data[10] = 0x00; // NOP
				data[11] = 0xBF;

				data[12] = 0xAF; // NOP.W
				data[13] = 0xF3;
				data[14] = 0x00;
				data[15] = 0x80;

				// 6 instructions
			}
		});

		// Encode Array Load Operations
		codeMapping.put(NodeALoad.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeALoad);
				NodeALoad node = (NodeALoad) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 2, 1, children[1]);

				switch (node.getLoadSize()) {
				case BYTE:
					// LDRSB r0, [r0, r1, LSL #0] - 10 F9 01 00
					data[4] = 0x10;
					data[5] = 0xF9;
					data[6] = 0x01;
					data[7] = 0x00;
					break;
				case SHORT:
					// LDRSH r0, [r0, r1, LSL #1] - 30 F9 11 00
					data[4] = 0x30;
					data[5] = 0xF9;
					data[6] = 0x11;
					data[7] = 0x00;
					break;
				case INT:
				case POINTER:
					// LDR r0, [r0, r1, LSL #2] - 50 F8 21 00
					data[4] = 0x50;
					data[5] = 0xF8;
					data[6] = 0x21;
					data[7] = 0x00;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				storeNode(data, 8, node);

				data[10] = 0x00; // NOP
				data[11] = 0xBF;

				data[12] = 0xAF; // NOP.W
				data[13] = 0xF3;
				data[14] = 0x00;
				data[15] = 0x80;

				// 6 instructions

			}
		});

		// Encode Array Store Operations
		codeMapping.put(NodeAStore.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeAStore);
				NodeAStore node = (NodeAStore) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 2, 1, children[1]);
				loadNode(data, 4, 2, children[2]);

				switch (node.getStoreSize()) {
				case BYTE:
					// STRB r2, [r0, r1, LSL #0] - 00 F8 01 20
					data[6] = 0x00;
					data[7] = 0xF8;
					data[8] = 0x01;
					data[9] = 0x20;
					break;
				case SHORT:
					// STRH r2, [r0, r1, LSL #1] - 20 F8 11 20
					data[6] = 0x20;
					data[7] = 0xF8;
					data[8] = 0x11;
					data[9] = 0x20;
					break;
				case INT:
				case POINTER:
					// STR r2, [r0, r1, LSL #2] - 40 F8 21 20
					data[6] = 0x40;
					data[7] = 0xF8;
					data[8] = 0x21;
					data[9] = 0x20;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				data[10] = 0x00; // NOP
				data[11] = 0xBF;

				data[12] = 0xAF; // NOP.W
				data[13] = 0xF3;
				data[14] = 0x00;
				data[15] = 0x80;

				// 6 instructions
			}
		});

		// Encode Math Operations
		codeMapping.put(NodeMath.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeMath);
				NodeMath node = (NodeMath) n;

				Node[] children = node.children();

				if (node.getOperation().getOperandCount() == 1) {
					loadNode(data, 0, 0, children[0]);
					switch (((NodeMath) node).getOperation()) {
					case NOT:
						// mvns r0, r0 - C0 43
						data[2] = 0xC0;
						data[3] = 0x43;
						break;
					case NEG:
						// rsbs r0, r0, #0 - 40 42
						data[2] = 0x40;
						data[3] = 0x42;
						break;
					case NOP:
						// NOP
						data[2] = 0x00;
						data[3] = 0xBF;
						break;
					default:
						throw new RuntimeException("Not implemented");
					}
					storeNode(data, 4, node);

					data[6] = 0xAF; // NOP.W
					data[7] = 0xF3;
					data[8] = 0x00;
					data[9] = 0x80;

					data[10] = 0x00; // NOP
					data[11] = 0xBF;

					data[12] = 0xAF; // NOP.W
					data[13] = 0xF3;
					data[14] = 0x00;
					data[15] = 0x80;

					// 6 instructions
				} else if (node.getOperation().getOperandCount() == 2) {
					for (int i = 0; i < data.length / 2; i++) {
						data[i * 2] = 0x00; // NOP
						data[i * 2 + 1] = 0xBF;
					}

					loadNode(data, 0, 0, children[0]);
					loadNode(data, 2, 1, children[1]);

					data[6] = 0xAF; // NOP.W
					data[7] = 0xF3;
					data[8] = 0x00;
					data[9] = 0x80;

					data[10] = 0xAF; // NOP.W
					data[11] = 0xF3;
					data[12] = 0x00;
					data[13] = 0x80;

					switch (node.getOperation()) {
					case ADD:
						// adds r0, r0, r1 - 40 18
						data[4] = 0x40;
						data[5] = 0x18;

						break;
					case SUB:
						// subs r0, r0, r1 - 40 1A
						data[4] = 0x40;
						data[5] = 0x1A;
						break;
					case MUL:
						// muls r0, r0, r1 - 48 43
						data[4] = 0x48;
						data[5] = 0x43;
						break;
					case DIV:
						// sdiv r0, r0, r1 - 90 fb f1 f0
						data[4] = 0x90;
						data[5] = 0xFB;
						data[6] = 0xF1;
						data[7] = 0xF0;

						data[8] = 0x00; // NOP
						data[9] = 0xBF;

						data[10] = 0xAF; // NOP.W
						data[11] = 0xF3;
						data[12] = 0x00;
						data[13] = 0x80;

						break;
					case MOD:
						// mov r2, r0; sdiv r0, r2, r1; mls r0, r0, r1, r2
						// 02 46 92 fb f1 f0 00 fb 11 20
						data[4] = 0x02;
						data[5] = 0x46;

						data[6] = 0x92;
						data[7] = 0xFB;
						data[8] = 0xF1;
						data[9] = 0xF0;

						data[10] = 0x00;
						data[11] = 0xFB;
						data[12] = 0x11;
						data[13] = 0x20;
						break;
					case AND:
						// ands r0, r0, r1 - 08 40
						data[4] = 0x08;
						data[5] = 0x40;
						break;
					case OR:
						// orrs r0, r0, r1 - 08 43
						data[4] = 0x08;
						data[5] = 0x43;
						break;
					case XOR:
						// eors r0, r0, r1 - 48 40
						data[4] = 0x48;
						data[5] = 0x40;
						break;
					case SHR:
						// asrs r0, r0, r1 - 08 41
						data[4] = 0x08;
						data[5] = 0x41;
						break;
					case USHR:
						// lsrs r0, r0, r1 - C8 40
						data[4] = 0xC8;
						data[5] = 0x40;
						break;
					case SHL:
						// lsls r0, r0, r1 - 88 40
						data[4] = 0x88;
						data[5] = 0x40;
						break;
					default:
						throw new RuntimeException("Not implemented");
					}

					storeNode(data, 14, node);

					// 6 instructions
				} else {
					throw new RuntimeException("Not implemented");
				}
			}

		});

	}

	@Override
	public CompiledBasicBlock generateBlock(BasicBlock block) {

		// Instead of normal CompiledBasicBlocks this provides the ThumbCodeGenerator
		// specific variant
		CompiledBasicBlock cbb = new ThumbCompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	@Override
	public int getNodeSize() {
		return 16; // The largest node is the "NodeMath2@MOD" one which is 16 bytes in size and to
					// my knowledge can't be made smaller with this code synthesis approach
	}

	@Override
	public int getNodeInstCount() {
		return 6;
	}
	
	@Override
	public int getSwitchCaseCount() {
		return 8;
	}

	@Override
	public void link(List<CompiledBasicBlock> blocks) {

		HashMap<BasicBlock, Integer> positionMap = new HashMap<BasicBlock, Integer>();
		int curPos = 0;

		curPos += getNodeSize(); // entry point
		curPos += getNodeSize(); // pretext

		// Map BasicBlocks to their position in compiled format
		for (CompiledBasicBlock cbb : blocks) {
			positionMap.put(cbb.getBlock(), curPos);
			curPos += this.getBlockSize(cbb.getBlock()) * getNodeSize(); // the size for the nodes
			curPos += cbb.getBlock().isConditionalBlock()?getNodeSize():0; // conditional jumps
			
			if(cbb.getBlock().isSwitchCase()) { // switch cases
				int swc = (cbb.getBlock().getSwitchBlocks().size()/getSwitchCaseCount());
				if(cbb.getBlock().getSwitchBlocks().size() % getSwitchCaseCount() != 0)
					swc++;
				curPos += swc * getNodeSize();
			}
			curPos += getNodeSize(); // the size for a unconditional jump or return
		}
		

		// Iterate the basic blocks and add the conditional and unconditional jumps
		for (CompiledBasicBlock cbb : blocks) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			// current position is at the end of this basic block
			int position = positionMap.get(cbb.getBlock()) + this.getBlockSize(cbb.getBlock()) * getNodeSize();

			if(cbb.getBlock().isConditionalBlock()) {
				int[] branches = new int[getNodeSize()];


				// load values to compare
				loadNode(branches, 0, 0, cbb.getBlock().getCondition().getOperant1());
				loadNode(branches, 2, 1, cbb.getBlock().getCondition().getOperant2());

				// cmp r0, r1 - 88 42
				branches[4] = 0x88;
				branches[5] = 0x42;
				
				
				branches[6] = 0x00; // NOP
				branches[7] = 0xBF;
				
				branches[8] = 0xAF; // NOP.W
				branches[9] = 0xF3;
				branches[10] = 0x00;
				branches[11] = 0x80;


				// calculate the actual offset to jump
				int jumpOffsetConditonal = positionMap.get(cbb.getBlock().getConditionalBranch()) - (position + 4 + 12);

				// add the conditional jump
				conditionalJump(branches, 12, jumpOffsetConditonal, cbb.getBlock().getCondition().getOperation());

				// append the compiled conditional jump
				((ThumbCompiledBasicBlock) cbb).appendBytes(branches);
				position += this.getNodeSize(); // add the conditional jump size to the current position
				// 6 instructions
			}
			
			if(cbb.getBlock().isSwitchCase()) {

				int[] switchJump = new int[getNodeSize()];

				// load switch jump value
				loadNode(switchJump, 0, 0, cbb.getBlock().getSwitchNode());
				
				// LSL.W R0, R0, #1 - 4F EA 40 00
				switchJump[2] = 0x4F;
				switchJump[3] = 0xEA;
				switchJump[4] = 0x40;
				switchJump[5] = 0x00;
				
				// add r0, r0, pc - 78 44
				switchJump[6] = 0x78;
				switchJump[7] = 0x44;
				
				// LDRSH r0, [r0, #6] - B0 F9 06 00
				switchJump[8] = 0xB0;
				switchJump[9] = 0xF9;
				switchJump[10] = 0x06;
				switchJump[11] = 0x00;
				
				// ADD r0, r0, pc - 78 44
				switchJump[12] = 0x78;
				switchJump[13] = 0x44;
				
				// BX r0 - 00 47
				switchJump[14] = 0x00;
				switchJump[15] = 0x47;
				
				((ThumbCompiledBasicBlock) cbb).appendBytes(switchJump);
				position += this.getNodeSize(); // add the conditional jump size to the current position
				// 6 instructions
				
				int[] switchEntry = new int[getNodeSize()];
				int switchEntryIndex = 0;
				int switchEntryAppened = 0;
				for(int s=0;s<cbb.getBlock().getSwitchBlocks().size();s++) {
					
					// jump offset
					int offset = (positionMap.get(cbb.getBlock().getSwitchBlocks().get(s)) - (position)) | 1;
					switchEntry[switchEntryIndex] = offset & 0xFF;
					switchEntry[switchEntryIndex+1] = (offset>>8) & 0xFF;
					
					switchEntryIndex+=2;
					if(switchEntryIndex % getNodeSize() == 0) {
						((ThumbCompiledBasicBlock) cbb).appendBytes(switchEntry);
						switchEntry = new int[getNodeSize()];
						switchEntryIndex = 0;
						switchEntryAppened++;
					}
				}
				
				// append unfinished blocks as well
				if(switchEntryIndex != 0) {
					((ThumbCompiledBasicBlock) cbb).appendBytes(switchEntry);
					switchEntryAppened++;
				}
				
				position += switchEntryAppened*getNodeSize();
				
			}else if(cbb.getBlock().isExitBlock()) {
				int[] done = new int[getNodeSize()];
				
				done[0] = 0xAF; // NOP.W
				done[1] = 0xF3;
				done[2] = 0x00;
				done[3] = 0x80;
	
				done[4] = 0x00; // NOP
				done[5] = 0xBF;
				
				// if this is an exit block
				
				// load the return value into r0 before returning if there is a return value
				if (cbb.getBlock().getReturnValue() != null) {
					loadNode(done, 6, 0, cbb.getBlock().getReturnValue());
				} else {
					done[6] = 0x00; // NOP
					done[7] = 0xBF;
				}

				// "free" the stack variables / reset the stack pointer to the original position
				int variableCount = (this.getFunction().getVariables() + getNodeSlotCount());
				if (variableCount >= 256 * 2)
					throw new RuntimeException("Too much stack space reserved");

				int spOffset = variableCount * 4;

				// addw sp, sp, #0x1 - 0D F2 01 0D
				done[8] = 0x0D;
				done[9] = 0xF2;
				done[10] = spOffset & 0xFF;
				done[11] = 0x0D | (((spOffset >> 8) & 0x7) << 4);

				done[12] = 0x00; // NOP
				done[13] = 0xBF;

				// pop {pc, r6, r7} - C0 BD
				done[14] = 0xC0;
				done[15] = 0xBD;
				
				((ThumbCompiledBasicBlock) cbb).appendBytes(done);

				// 6 instructions
			}else {			
				// Normal direct jump	
				int[] done = new int[getNodeSize()];
	
				done[0] = 0xAF; // NOP.W
				done[1] = 0xF3;
				done[2] = 0x00;
				done[3] = 0x80;
	
				done[4] = 0x00; // NOP
				done[5] = 0xBF;

				done[6] = 0x00; // NOP
				done[7] = 0xBF;

				done[8] = 0x00; // NOP
				done[9] = 0xBF;

				done[10] = 0x00; // NOP
				done[11] = 0xBF;

				// if this isn't a returning block unconditionally jump to the next one
				int jumpOffset = positionMap.get(cbb.getBlock().getUnconditionalBranch()) - (position + 4 + 12);
				conditionalJump(done, 12, jumpOffset, null);

				// 6 instructions

			// append the last part of code
			((ThumbCompiledBasicBlock) cbb).appendBytes(done);
			}
		}
		

	}

	@Override
	public int[] finish(List<CompiledBasicBlock> compiledBlocks) {

		List<int[]> l = new ArrayList<int[]>();

		// This entry point code is to streamline MergedFunctions
		int[] entrypoint = new int[getNodeSize()];

		// point r8 to pretext for calls
		// add r8, pc, 13 - 0F F2 0D 08
		entrypoint[0] = 0x0F;
		entrypoint[1] = 0xF2;
		entrypoint[2] = 0x0D;
		entrypoint[3] = 0x08;

		entrypoint[4] = 0xAF; // NOP.W
		entrypoint[5] = 0xF3;
		entrypoint[6] = 0x00;
		entrypoint[7] = 0x80;

		if (this.getFunction() instanceof MergedFunction) {

			// mov r3, r2 - 13 46
			entrypoint[8] = 0x13;
			entrypoint[9] = 0x46;

			// mov r2, r1 - 0A 46
			entrypoint[10] = 0x0A;
			entrypoint[11] = 0x46;

			// mov r1, r0 - 01 46
			entrypoint[12] = 0x01;
			entrypoint[13] = 0x46;

			// merged functions first argument is the function hash, 0 is entry point
			// EORS r0, r0 - 40 40
			entrypoint[14] = 0x40;
			entrypoint[15] = 0x40;

		} else {
			entrypoint[8] = 0x00; // NOP
			entrypoint[9] = 0xBF;

			entrypoint[10] = 0x00; // NOP
			entrypoint[11] = 0xBF;

			entrypoint[12] = 0x00; // NOP
			entrypoint[13] = 0xBF;

			entrypoint[14] = 0x00; // NOP
			entrypoint[15] = 0xBF;
		}

		// 6 instructions

		l.add(entrypoint);

		int[] pretext = new int[getNodeSize()];

		// set r8 = current address

		// push {lr, r6, r7} - C0 B5
		pretext[0] = 0xC0;
		pretext[1] = 0xB5;

		int variableCount = this.getFunction().getVariables();
		if (variableCount >= 256)
			throw new RuntimeException("Too much stack space reserved");

		int nodeCount = getNodeSlotCount();
		if (nodeCount >= 256)
			throw new RuntimeException("Too much stack space reserved " + nodeCount);

		int spOffset = (variableCount + nodeCount) * 4;

		// System.out.println(nodeCount + " - "+ variableCount+ " - "+spOffset);

		// subw sp, sp, #0x1 - AD F2 01 0D
		pretext[2] = 0xAD;
		pretext[3] = 0xF2;
		pretext[4] = spOffset & 0xFF;
		pretext[5] = 0x0D | (((spOffset >> 8) & 0x7) << 4);

		// add r7, sp, #0x3fc - FF AF
		pretext[6] = nodeCount & 0xFF;
		pretext[7] = 0xAF;

		// Copy over arguments from registers to the stack to make them non volatile

		if (getFunction().getArguments().length >= 4) {
			// STRD R0, [SP,#0] - CD E9 00 01
			pretext[8] = 0xC7;
			pretext[9] = 0xE9;
			pretext[10] = 0x00; // to sp, 0
			pretext[11] = 0x01; // r0, r1

			// STR R2, [R7, #0x8] - BA 60
			pretext[12] = 0xBA;
			pretext[13] = 0x60;

			// STR R3, [R7, #0xC] - FB 60
			pretext[14] = 0xFB;
			pretext[15] = 0x60;
		} else if (getFunction().getArguments().length >= 3) {
			// STRD R0, [SP,#0] - CD E9 00 01
			pretext[8] = 0xC7;
			pretext[9] = 0xE9;
			pretext[10] = 0x00; // to sp, 0
			pretext[11] = 0x01; // r0, r1

			// STR R2, [R7, #0x8] - BA 60
			pretext[12] = 0xBA;
			pretext[13] = 0x60;

			pretext[14] = 0x00; // NOP
			pretext[15] = 0xBF;
		} else if (getFunction().getArguments().length >= 2) {
			// STRD R0, [SP,#0] - CD E9 00 01
			pretext[8] = 0xC7;
			pretext[9] = 0xE9;
			pretext[10] = 0x00; // to sp, 0
			pretext[11] = 0x01; // r0, r1

			pretext[12] = 0x00; // NOP
			pretext[13] = 0xBF;

			pretext[14] = 0x00; // NOP
			pretext[15] = 0xBF;
		} else if (getFunction().getArguments().length >= 1) {
			// STR R0, [SP, #0] - CD F8 00 00
			pretext[8] = 0xC7;
			pretext[9] = 0xF8;
			pretext[10] = 0x00; // to sp 0
			pretext[11] = 0x00; // r0

			pretext[12] = 0x00; // NOP
			pretext[13] = 0xBF;

			pretext[14] = 0x00; // NOP
			pretext[15] = 0xBF;
		} else if (getFunction().getArguments().length == 0) {
			pretext[8] = 0xAF; // NOP.W
			pretext[9] = 0xF3;
			pretext[10] = 0x00;
			pretext[11] = 0x80;

			pretext[12] = 0x00; // NOP
			pretext[13] = 0xBF;

			pretext[14] = 0x00; // NOP
			pretext[15] = 0xBF;
		} else
			throw new RuntimeException("Only up to 4 arguments supported");

		// 6 instructions

		l.add(pretext);

		for (CompiledBasicBlock cbb : compiledBlocks) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			l.add(((ThumbCompiledBasicBlock) cbb).getBytes());
		}

		return mapFlat(l);
	}

	// flat map utility function
	private int[] mapFlat(List<int[]> arr) {
		int size = 0;
		for (int[] array : arr)
			size += array.length;

		int[] fullArray = new int[size];

		int curPos = 0;
		for (int[] array : arr) {
			System.arraycopy(array, 0, fullArray, curPos, array.length);
			curPos += array.length;
		}
		return fullArray;
	}

	// Internal CompiledBasicBlock Class
	private class ThumbCompiledBasicBlock extends CompiledBasicBlock {

		List<int[]> dataArray;

		public ThumbCompiledBasicBlock(BasicBlock block) {
			super(block);
			dataArray = new ArrayList<int[]>();
		}

		public void appendBytes(int[] data) {
			dataArray.add(data);
		}

		public int[] getBytes() {
			return mapFlat(dataArray);
		}

		public String toString() {
			StringBuilder sb = new StringBuilder();
			for (int[] arr : dataArray) {
				for (int i = 0; i < arr.length; i++) {
					String st = Integer.toHexString(arr[i]);
					if (st.length() < 1)
						sb.append('0');
					if (st.length() < 2)
						sb.append('0');
					sb.append(st);
				}
				// sb.append('-');
			}
			return sb.toString();
		}

	}

	// Internal NodeCodeGenerator for Thumb Code generation
	// Enforces NodeSize Requirements and NOPS by default, also caches conversions
	private abstract class ThumbNodeCodeGenerator extends NodeCodeGenerator {

		private ThumbNodeCodeGenerator(int[] data) {
			assert (data.length == ThumbCodeGenerator.this.getNodeSize());
		}

		public void process(CompiledBasicBlock cbb, Node node) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			int[] data = new int[ThumbCodeGenerator.this.getNodeSize()];
			writeData(node, data);
			((ThumbCompiledBasicBlock) cbb).appendBytes(data);
		}

		// public int getSize(Node node) {
		// return data.length;
		// }

		/**
		 * Return the compiled bytes for a specific node
		 * 
		 * @param node
		 *            the node to compile
		 * @param data
		 *            the array to write in
		 */
		public abstract void writeData(Node node, int[] data);

	}

	/**
	 * CustomNodeImpl for "readInt" for the Thumb Architecture
	 */
	public static class ThumbNodeReadInt extends CustomNodeImpl {

		public ThumbNodeReadInt(Context context, CodeGenerator generator) {
			super(context, generator);
			assert (generator instanceof ThumbCodeGenerator);
		}

		@Override
		public void process(CompiledBasicBlock cbb, NodeCustom node) {
			assert (cbb instanceof ThumbCompiledBasicBlock);

			int[] data = new int[getGenerator().getNodeSize()];

			((ThumbCodeGenerator) getGenerator()).loadNode(data, 0, 0, node.children()[0]);

			// LDR r0, [r0] - 00 68
			data[2] = 0x00;
			data[3] = 0x68;
			((ThumbCodeGenerator) getGenerator()).storeNode(data, 4, node);

			data[6] = 0xAF; // NOP.W
			data[7] = 0xF3;
			data[8] = 0x00;
			data[9] = 0x80;

			data[10] = 0x00; // NOP
			data[11] = 0xBF;

			data[12] = 0xAF; // NOP.W
			data[13] = 0xF3;
			data[14] = 0x00;
			data[15] = 0x80;

			// 6 instructions

			((ThumbCompiledBasicBlock) cbb).appendBytes(data);
		}

	}

	/**
	 * CustomNodeImpl for "call" for the Thumb Architecture
	 */
	public static class ThumbNodeCall extends CustomNodeImpl {

		public ThumbNodeCall(Context context, CodeGenerator generator) {
			super(context, generator);
			assert (generator instanceof ThumbCodeGenerator);
		}

		@Override
		public void process(CompiledBasicBlock cbb, NodeCustom node) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			if (!(this.getGenerator().getFunction() instanceof MergedFunction))
				throw new RuntimeException("Can't branch in a non merged function");

			int[] data = new int[getGenerator().getNodeSize()];

			Node[] children = node.children();

			if (children.length >= 1) {
				((ThumbCodeGenerator) getGenerator()).loadNode(data, 0, 0, children[0]);
			} else {
				data[0] = 0x00; // NOP
				data[1] = 0xBF;
			}

			if (children.length >= 2) {
				((ThumbCodeGenerator) getGenerator()).loadNode(data, 2, 1, children[1]);
			} else {
				data[2] = 0x00; // NOP
				data[3] = 0xBF;
			}

			if (children.length >= 3) {
				// ((ThumbCodeGenerator) getGenerator()).loadNode(data, 4, 2, children[2]);

				// ldr r2, [sp, #1019] - DD F8 FB 23
				int v = ((ThumbCodeGenerator) getGenerator()).getNodeID(children[2]) * 4;
				data[4] = 0xDD;
				data[5] = 0xF8;
				data[6] = v & 0xFF;
				data[7] = 0x20 | (v >> 8) & 0xF;

			} else {
				data[4] = 0xAF; // NOP.W
				data[5] = 0xF3;
				data[6] = 0x00;
				data[7] = 0x80;
			}

			if (children.length >= 4) {
				// ((ThumbCodeGenerator) getGenerator()).loadNode(data, 6, 3, children[3]);

				// ldr r3, [sp, #1019] - DD F8 FB 23
				int v = ((ThumbCodeGenerator) getGenerator()).getNodeID(children[3]) * 4;
				data[8] = 0xDD;
				data[9] = 0xF8;
				data[10] = v & 0xFF;
				data[11] = 0x30 | (v >> 8) & 0xF;

			} else {
				data[8] = 0xAF; // NOP.W
				data[9] = 0xF3;
				data[10] = 0x00;
				data[11] = 0x80;
			}

			// This requires r8 to point at the address
			// BLX r8 - C0 47
			data[12] = 0xC0;
			data[13] = 0x47;

			((ThumbCodeGenerator) getGenerator()).storeNode(data, 14, node);

			// 6 instructions

			((ThumbCompiledBasicBlock) cbb).appendBytes(data.clone());
		}

	}

}
