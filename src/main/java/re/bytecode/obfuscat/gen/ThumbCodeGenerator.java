package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath1;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

/**
 * The Code Synthesizer for ARMv8 Thumb2 Code
 */
public class ThumbCodeGenerator extends CodeGenerator {
	
	/**
	 * Create a new ThumbCodeGenerator (recommended way of creating an instance is through {@link re.bytecode.obfuscat.Obfuscat#generateCode(String, Function)})
	 * @param context the context of this generator, may be null
	 * @param function the function to generate code for
	 */
	public ThumbCodeGenerator(Context context, Function function) {
		super(context, function);
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
		
		int j1   = 0;
		int j2   = 0;
		int s    = 0;
		
		if (type == null) {
			j1 = 1;
			j2 = 1;
			isConditional = false;
		} else {
			switch (type) {
			case EQUAL:
				cond = 0;
				break;
			case NOTEQUAL:
				cond = 1;
				break;
			case LESSTHAN:
				cond = 11;
				break;
			case LESSEQUAL:
				cond = 13;
				break;
			case GREATERTHAN:
				cond = 12;
				break;
			case GREATEREQUAL:
				cond = 10;
				break;
			default:
				throw new RuntimeException("Not implemented");
			}
		}
		
		if(position < 0) {
			j1 = 1;
			j2 = 1;
			s = 1;
			if(!isConditional)
				cond = 15; // 1111 - negative
		}
		
		data[offset+0] =  ((cond&0x3) << 6) | (position >> 11) & 0x3F;
		data[offset+1] = 0xF0 | (s << 2) | ((cond>>2)&0x3);
		data[offset+2] = position & 0xFF;
		data[offset+3] = 0x80 | ((j1&1)<<5) | ((isConditional?0:1)<<4) | ((j2&1)<<3) | ((position >> 8) & 0x7);	
		// System.out.println(cond+" -> "+Integer.toHexString(data[offset])+" "+Integer.toHexString(data[offset+1])+" "+Integer.toHexString(data[offset+2])+" "+Integer.toHexString(data[offset+3]));
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
			public int[] getBytes(Node node) {
				return null;
			}

		});

		// Encode Constants
		codeMapping.put(NodeConst.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public int[] getBytes(Node n) {
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
				data[1] = 0xF2 | (((value >> 11) & 1) << 2);;
				data[2] = value & 0xFF;
				data[3] = (((value >> 8) & 0x7) << 4);

				value = (value >> 16) & 0xFFFF;

				data[4] = 0xC0 | (value >> 12) & 0xF;
				data[5] = 0xF2 | (((value >> 11) & 1) << 2);
				data[6] = value & 0xFF;
				data[7] = (((value >> 8) & 0x7) << 4);

				storeNode(data, 8, node);
				return data;
			}

		});

		// Encode Variable Load Operations
		codeMapping.put(NodeLoad.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeLoad);
				NodeLoad node = (NodeLoad) n;

				int slot = node.getSlot();
				int slotMem = slot*4;

				if (slotMem >= 8192)
					throw new RuntimeException("Variable slot "+slot+" not supported");

				// The old out-commented versions were smaller, but unsigned which causes wrong results
				
				switch (node.getLoadSize()) {
				case 1:
					
					// LDRB r0, [r7, #0x0] - 38 78
					// data[0] = 0x38 | ((slot & 3) << 6);
					// data[1] = 0x78 | ((slot & 0x1C) >> 2);
					
					// LDRSB r0, [r7, #0x4] - 97 F9 04 00
					data[0] = 0x97;
					data[1] = 0xF9;
					data[2] = slotMem&0xFF;
					data[3] = (slotMem>>8)&0x0F;
					break;
				case 2:
					// LDRH r0, [r7, #0x0] - 38 88
					// data[0] = 0x38 | ((slot & 3) << 6);
					// data[1] = 0x88 | ((slot & 0x1C) >> 2);
					
					// LDRSH r0, [r7, #0x4] - B7 F9 04 00
					data[0] = 0xB7;
					data[1] = 0xF9;
					data[2] = slotMem&0xFF;
					data[3] = (slotMem>>8)&0x0F;
					break;
				case 4:
					// LDR r0, [r7, #0x0] - 38 68
					// data[0] = 0x38 | ((slot & 3) << 6);
					// data[1] = 0x68 | ((slot & 0x1C) >> 2);
					
					// LDR r0, [r7, #0x100] - D7 F8 00 01
					data[0] = 0xD7;
					data[1] = 0xF8;
					data[2] = slotMem&0xFF;
					data[3] = (slotMem>>8)&0x0F;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				storeNode(data, 4, node);
				return data;
			}
		});

		// Encode Variable Store Operations
		codeMapping.put(NodeStore.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeStore);
				NodeStore node = (NodeStore) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);

				int slot = node.getSlot();
				int slotMem = slot*4;
				
				if (slotMem >= 8192)
					throw new RuntimeException("Variable slot not supported");
				

				switch (node.getStoreSize()) {
				case 1:
					// STRB r0, [r7, #0x0] - 38 70
					// data[2] = 0x38 | ((slot & 3) << 6);
					// data[3] = 0x70 | ((slot & 0x1C) >> 2);
					
					//  STRB r0, [r7, #0x100] - 87 F8 00 01
					data[2] = 0x87;
					data[3] = 0xF8;
					data[4] = slotMem&0xFF;
					data[5] = (slotMem>>8)&0x0F;
					break;
				case 2:
					// STRH r0, [r7, #0x0] - 38 80
					// data[2] = 0x38 | ((slot & 3) << 6);
					// data[3] = 0x80 | ((slot & 0x1C) >> 2);
					
					//  STRH r0, [r7, #0x100] - A7 F8 00 01
					data[2] = 0xA7;
					data[3] = 0xF8;
					data[4] = slotMem&0xFF;
					data[5] = (slotMem>>8)&0x0F;
					break;
				case 4:
					// STR r0, [r7, #0x0] - 38 60
					// data[2] = 0x38 | ((slot & 3) << 6);
					// data[3] = 0x60 | ((slot & 0x1C) >> 2);
					
					//  STR r0, [r7, #0x100] - C7 F8 00 01
					data[2] = 0xC7;
					data[3] = 0xF8;
					data[4] = slotMem&0xFF;
					data[5] = (slotMem>>8)&0x0F;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				return data;
			}
		});

		// Encode Array Load Operations
		codeMapping.put(NodeALoad.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeALoad);
				NodeALoad node = (NodeALoad) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 2, 1, children[1]);

				switch (node.getLoadSize()) {
				case 1:
					// LSLS r1, r1, #0; LDRSB r0, [r0, r1] - 09 00 40 56
					//data[4] = 0x09;
					//data[5] = 0x00;
					data[6] = 0x40;
					data[7] = 0x56;
					break;
				case 2:
					// LSLS r1, r1, #1; LDRSH r0, [r0, r1] - 49 00 40 5E
					data[4] = 0x49;
					data[5] = 0x00;
					data[6] = 0x40;
					data[7] = 0x5E;
					break;
				case 4:
					// LSLS r1, r1, #2; LDR r0, [r0, r1] - 89 00 40 58
					data[4] = 0x89;
					data[5] = 0x00;
					data[6] = 0x40;
					data[7] = 0x58;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				storeNode(data, 8, node);

				return data;
			}
		});

		// Encode Array Store Operations
		codeMapping.put(NodeAStore.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeAStore);
				NodeAStore node = (NodeAStore) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 2, 1, children[1]);
				loadNode(data, 4, 2, children[2]);

				switch (node.getStoreSize()) {
				case 1:
					// LSLS r1, r1, #0 ; STRB r2, [r0, r1] - 09 00 42 54
					//data[6] = 0x09;
					//data[7] = 0x00;
					data[8] = 0x42;
					data[9] = 0x54;
					break;
				case 2:
					// LSLS r1, r1, #1 ; STRH r2, [r0, r1] - 49 00 42 52
					data[6] = 0x49;
					data[7] = 0x00;
					data[8] = 0x42;
					data[9] = 0x52;
					break;
				case 4:
					// LSLS r1, r1, #2 ; STR r2, [r0, r1] - 89 00 42 50
					data[6] = 0x89;
					data[7] = 0x00;
					data[8] = 0x42;
					data[9] = 0x50;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				return data;
			}
		});

		// Encode One Operand Math Operations
		codeMapping.put(NodeMath1.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeMath1);
				NodeMath1 node = (NodeMath1) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				switch (((NodeMath1) node).getOperation()) {
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
				default:
					throw new RuntimeException("Not implemented");
				}
				storeNode(data, 4, node);
				return data;
			}

		});

		// Encode Two Operand Math Operations
		codeMapping.put(NodeMath2.class, new ThumbNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeMath2);
				NodeMath2 node = (NodeMath2) n;

				Node[] children = node.children();
				
				for (int i = 0; i < data.length / 2; i++) {
					data[i * 2] = 0x00; // NOP
					data[i * 2 + 1] = 0xBF;
				}

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 2, 1, children[1]);

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

				return data;
			}

		});
		
	}

	@Override
	public CompiledBasicBlock generateBlock(BasicBlock block) {

		// Instead of normal CompiledBasicBlocks this provides the ThumbCodeGenerator specific variant
		CompiledBasicBlock cbb = new ThumbCompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	@Override
	public int getNodeSize() {
		return 16; // The largest node is the "NodeMath2@MOD" one which is 16 bytes in size and to my knowledge can't be made smaller with this code synthesis approach
	}

	@Override
	public void link(List<CompiledBasicBlock> blocks) {

		HashMap<BasicBlock, Integer> positionMap = new HashMap<BasicBlock, Integer>();
		int curPos = 0;

		// Map BasicBlocks to their position in compiled format
		for (CompiledBasicBlock cbb : blocks) {
			positionMap.put(cbb.getBlock(), curPos);
			curPos += this.getBlockSize(cbb.getBlock()) * getNodeSize(); // the size for the nodes
			curPos += cbb.getBlock().getSwitchBlocks().size() * getNodeSize(); // the size for conditional jumps
			curPos += getNodeSize(); // the size for a unconditional jump or return
		}

		// Iterate the basic blocks and add the conditional and unconditional jumps
		for (CompiledBasicBlock cbb : blocks) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			// current position is at the end of this basic block
			int position = positionMap.get(cbb.getBlock()) + this.getBlockSize(cbb.getBlock()) * getNodeSize();
			for (Entry<BranchCondition, BasicBlock> e : cbb.getBlock().getSwitchBlocks().entrySet()) {

				int[] branches = new int[getNodeSize()];

				// nop the block by default
				for (int i = 0; i < branches.length/2; i++) {
					branches[i * 2] = 0x00; // NOP
					branches[i * 2 + 1] = 0xBF;
				}

				// load values to compare
				loadNode(branches, 0, 0, e.getKey().getOperant1());
				loadNode(branches, 2, 1, e.getKey().getOperant2());
				// cmp r0, r1 - 88 42
				branches[4] = 0x88;
				branches[5] = 0x42;

				// calculate the actual offset to jump
				int jumpOffset = positionMap.get(e.getValue()) - (position + 4 + 6);

				// add the conditional jump
				conditionalJump(branches, 6, jumpOffset, e.getKey().getOperation());

				// append the compiled conditional jump
				((ThumbCompiledBasicBlock) cbb).appendBytes(branches);
				position += this.getNodeSize(); // add the conditional jump size to the current position
			}

			int[] done = new int[getNodeSize()];

			// nop the block by default
			for (int i = 0; i < done.length/2; i++) {
				done[i * 2] = 0x00; // NOP
				done[i * 2 + 1] = 0xBF;
			}

			if (!cbb.getBlock().isExitBlock()) {
				// if this isn't a returning block unconditionally jump to the next one
				int jumpOffset = positionMap.get(cbb.getBlock().getUnconditionalBranch()) - (position + 4);
				conditionalJump(done, 0, jumpOffset, null);
			} else {
				// if this is an exit block
				
				// load the return value into r0 before returning if there is a return value
				if (cbb.getBlock().getReturnValue() != null)
					loadNode(done, 0, 0, cbb.getBlock().getReturnValue());
				
				
				// "free" the stack variables / reset the stack pointer to the original position
				int variableCount = (this.getFunction().getVariables() + getNodeSlotCount());
				if(variableCount > 2032) throw new RuntimeException("Too much stack space reserved");
				
				// add sp, 0x40 - 10 B0
				
				done[2] = variableCount&0xFF;
				done[3] = 0xB0;
				
				// pop {pc} - 00 BD
				 
				// return
				done[4] = 0x00;
				done[5] = 0xBD;
			}
			
			// append the last part of code
			((ThumbCompiledBasicBlock) cbb).appendBytes(done);
		}

	}

	@Override
	public int[] finish(List<CompiledBasicBlock> compiledBlocks) {

		List<Integer[]> l = new ArrayList<Integer[]>();

		int[] pretext = new int[getNodeSize()];

		// NOP the pretext by default
		for (int i = 0; i < pretext.length/2; i++) {
			pretext[i * 2] = 0x00; // NOP
			pretext[i * 2 + 1] = 0xBF;
		}
		
		// push {lr} - 00 B5
		pretext[0] = 0x00;
		pretext[1] = 0xB5;
		
		
		int variableCount = this.getFunction().getVariables();
		if(variableCount > 2032) throw new RuntimeException("Too much stack space reserved");
		
		// sub sp, 0x40 - 90 B0
		pretext[2] = 0x80 | (variableCount&0xFF);
		pretext[3] = 0xB0;


		// Copy over arguments from registers to the stack to make them non volatile
		
		if(getFunction().getArguments().length >= 1)
			storeSlot(pretext, 4, 0, 4); // slot 0
		if(getFunction().getArguments().length >= 2)
			storeSlot(pretext, 6, 1, 5); // slot 1
		if(getFunction().getArguments().length >= 3)
			storeSlot(pretext, 8, 2, 6); // slot 2
		if(getFunction().getArguments().length >= 4)
			storeSlot(pretext, 10, 3, 6); // slot 3
		
		// mov r7, sp - 6F 46
		pretext[12] = 0x6F;
		pretext[13] = 0x46;
		
		variableCount = (getNodeSlotCount()*4)/4;
		if(variableCount > 2032) throw new RuntimeException("Too much stack space reserved");
		
		// sub sp, 0x40 - 90 B0
		pretext[14] = 0x80 | (variableCount&0xFF);
		pretext[15] = 0xB0;
		

		// Convert the int[] to an Integer[] 
		l.add(Arrays.stream(pretext).boxed().toArray(Integer[]::new));

		// Convert all the  int[] to an Integer[] 
		for (CompiledBasicBlock cbb : compiledBlocks) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			l.add(((ThumbCompiledBasicBlock) cbb).getBytes());
		}

		// Combine all arrays and output one int[]
		return l.stream().flatMap(Arrays::stream).mapToInt(Integer::intValue).toArray();
	}

	// Internal CompiledBasicBlock Class
	// TODO: The whole converting process is super messy, check for efficency and clean up bottlenecks!
	private class ThumbCompiledBasicBlock extends CompiledBasicBlock {

		List<Integer[]> dataArray;

		public ThumbCompiledBasicBlock(BasicBlock block) {
			super(block);
			dataArray = new ArrayList<Integer[]>();
		}

		public void appendBytes(int[] data) {
			dataArray.add(Arrays.stream(data).boxed().toArray(Integer[]::new));
		}

		public Integer[] getBytes() {
			// int[] resultArray =
			// dataArray.stream().flatMap(Arrays::stream).mapToInt(Integer::intValue).toArray();
			// return resultArray;
			return dataArray.stream().flatMap(Arrays::stream).toArray(Integer[]::new);
		}

		public String toString() {
			StringBuilder sb = new StringBuilder();
			for (Integer[] arr : dataArray) {
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

		protected int[] data;

		private ThumbNodeCodeGenerator(int[] data) {
			assert(data.length == ThumbCodeGenerator.this.getNodeSize());
			this.data = data;
			if (data != null)
				for (int i = 0; i < data.length / 2; i++) {
					data[i * 2] = 0x00; // NOP
					data[i * 2 + 1] = 0xBF;
				}
		}

		public void process(CompiledBasicBlock cbb, Node node) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			((ThumbCompiledBasicBlock) cbb).appendBytes(getBytes(node).clone());
		}

		// public int getSize(Node node) {
		// return data.length;
		// }

		/**
		 * Return the compiled bytes for a specific node
		 * @param node the node to compile
		 * @return the compiled node
		 */
		public abstract int[] getBytes(Node node);

	}
	
	/**
	 * CustomNodeImpl for "readInt" for the Thumb Architecture
	 */
	public static class ThumbNodeReadInt extends CustomNodeImpl {

		private int[] data;
		public ThumbNodeReadInt(Context context, CodeGenerator generator) {
			super(context, generator);
			assert(generator instanceof ThumbCodeGenerator);
			data = new int[getGenerator().getNodeSize()];
			for (int i = 0; i < data.length / 2; i++) {
				data[i * 2] = 0x00; // NOP
				data[i * 2 + 1] = 0xBF;
			}
		}

		@Override
		public void process(CompiledBasicBlock cbb, NodeCustom node) {
			assert (cbb instanceof ThumbCompiledBasicBlock);
			
			((ThumbCodeGenerator) getGenerator()).loadNode(data, 0, 0, node.children()[0]);
			
			// LDR r0, [r0] - 00 68
			data[2] = 0x00;
			data[3] = 0x68;
			((ThumbCodeGenerator) getGenerator()).storeNode(data, 4, node);
			
			((ThumbCompiledBasicBlock) cbb).appendBytes(data.clone());
		}
		
	}


}
