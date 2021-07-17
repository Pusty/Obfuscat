package re.bytecode.obfuscat.pass.vm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeAlloc;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;
import re.bytecode.obfuscat.gen.CodeGenerator;
import re.bytecode.obfuscat.gen.CompiledBasicBlock;
import re.bytecode.obfuscat.gen.NodeCodeGenerator;

import static re.bytecode.obfuscat.pass.vm.VMConst.*;

/**
 * The Code Synthesizer for the VM
 */
public class VMCodeGenerator extends CodeGenerator {

	
	static {
		registerCodegen(VMCodeGenerator.class);
	}
	
	/**
	 * Create a new VMCodeGenerator (recommended way of creating an instance is
	 * through {@link re.bytecode.obfuscat.Obfuscat#generateCode(String, Function)})
	 * 
	 * @param context
	 *            the context of this generator, may be null
	 * @param function
	 *            the function to generate code for
	 */
	public VMCodeGenerator(Context context, Function function) {
		super(context, function);
	}

	public String description() {
		return "A code generator for VM code";
	}
	

	@Override
	protected int countProgramSize() {
		
		int size = 0;
		for (BasicBlock bb : getFunction().getBlocks()) {
			size += getBlockSize(bb) * getNodeSize();
			size += bb.isConditionalBlock()?getNodeSize():0;
			
			if(bb.isSwitchCase()) { // switch cases
				int swc = (bb.getSwitchBlocks().size()/getSwitchCaseCount());
				if(bb.getSwitchBlocks().size() % getSwitchCaseCount() != 0)
					swc++;
				size += swc * getNodeSize();
			}
			size += getNodeSize(); // the size for a unconditional jump or return
		}
		return size;
	}

	@Override
	protected void initMapping() {

		// Default case
		codeMapping.put(null, new VMNodeCodeGenerator(null) {

			@Override
			public void process(CompiledBasicBlock cbb, Node node) {
				throw new RuntimeException("Not implemented " + node);
			}

			@Override
			public void writeData(Node node, int[] data) {
			}

		});

		// Encode Constants
		codeMapping.put(NodeConst.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeConst);
				NodeConst node = (NodeConst) n;
				Object constObj = node.getObj();
				int value = 0;
				boolean offset=false;
				if (constObj instanceof Integer) {
					value = ((Integer) constObj).intValue();
				} else if (constObj instanceof Short) {
					value = ((Short) constObj).intValue();
				} else if (constObj instanceof Byte) {
					value = ((Byte) constObj).intValue();
				} else if (constObj instanceof Boolean) {
					value = ((Boolean) constObj).booleanValue()?1:0;
				}else if (constObj instanceof Character) {
					value = (int) ((Character) constObj).charValue();
				} else if(constObj.getClass().isArray()) {
					Object dataEntry = getFunction().getData(constObj);		
					if(dataEntry == null)
						throw new RuntimeException("Constant array not registered "+constObj);
					value = getAppendedDataOffset(dataEntry);
					offset = true;
					
				} else {
					throw new RuntimeException("Const type " + constObj.getClass() + " not implemented");
				}
				
				if(!offset) {
					data[0] = OP_CONST;
				}else {
					data[0] = OP_OCONST;
				}
				
				data[1] = value&0xFF;
				data[2] = (value>>8)&0xFF;
				data[3] = (value>>16)&0xFF;
				data[4] = getNodeID(node);
				data[5] = (value>>24)&0xFF;
			}

		});

		// Encode Variable Load Operations
		codeMapping.put(NodeLoad.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeLoad);
				NodeLoad node = (NodeLoad) n;
				
				int slot = node.getSlot();
				int args = VMCodeGenerator.this.getFunction().getArguments().length;
				
				if(slot >= args) {
					slot = slot - args;
					data[0] = OP_LOAD8+size2value(node.getLoadSize());
				}else {
					data[0] = OP_PLOAD8+size2value(node.getLoadSize());
				}
				data[1] = slot&0xFF;
				data[2] = (slot>>8)&0xFF;
				data[3] = 0;
				data[4] = getNodeID(node);
				data[5] = 0;
			}
		});

		// Encode Variable Store Operations
		codeMapping.put(NodeStore.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeStore);
				NodeStore node = (NodeStore) n;
				
				int slot = node.getSlot();
				int args = VMCodeGenerator.this.getFunction().getArguments().length;
				
				if(slot >= args) {
					slot = slot - args;
					data[0] = OP_STORE8+size2value(node.getStoreSize());
				}else {
					data[0] = OP_PSTORE8+size2value(node.getStoreSize());
				}

				Node[] children = node.children();
				data[1] = slot&0xFF;
				data[2] = (slot>>8)&0xFF;
				data[3] = 0;
				data[4] = getNodeID(children[0]);
				data[5] = size2value(node.getStoreSize());
			}
		});

		// Encode Array Load Operations
		codeMapping.put(NodeALoad.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeALoad);
				NodeALoad node = (NodeALoad) n;

				Node[] children = node.children();
				
				data[0] = OP_ALOAD8+size2value(node.getLoadSize());
				data[1] = getNodeID(children[0]);
				data[2] = getNodeID(children[1]);
				data[3] = 0;
				data[4] = getNodeID(node);
				data[5] = 0;

			}
		});

		// Encode Array Store Operations
		codeMapping.put(NodeAStore.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeAStore);
				NodeAStore node = (NodeAStore) n;

				Node[] children = node.children();
				
				data[0] = OP_ASTORE8+size2value(node.getStoreSize());
				data[1] = getNodeID(children[0]);
				data[2] = getNodeID(children[1]);
				data[3] = 0;
				data[4] = getNodeID(children[2]);
				data[5] = 0;
			}
		});

		// Encode Math Operations
		codeMapping.put(NodeMath.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeMath);
				NodeMath node = (NodeMath) n;

				Node[] children = node.children();
				
				
				data[0] = OP_NOT + operation2value(node.getOperation());
				data[3] = 0;
				data[4] = getNodeID(node);
				data[5] = 0;
				
				if (node.getOperation().getOperandCount() == 1) {
					
					data[1] = getNodeID(children[0]);
					data[2] = 0;
				} else if (node.getOperation().getOperandCount() == 2) {
					
					data[1] = getNodeID(children[0]);
					data[2] = getNodeID(children[1]);

				} else {
					throw new RuntimeException("Not implemented");
				}
			}

		});

		// Encode Math Operations
		codeMapping.put(NodeAlloc.class, new VMNodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public void writeData(Node n, int[] data) {
				assert (n instanceof NodeAlloc);
				NodeAlloc node = (NodeAlloc) n;

				Node[] children = node.children();
				
				data[0] = OP_ALLOC8 + size2value(node.getAllocationSize());
				data[1] = getNodeID(children[0]);
				data[2] = 0;
				data[3] = 0;
				data[4] = getNodeID(node);
				data[5] = 0;
			
			}

		});

		
	}

	@Override
	public CompiledBasicBlock generateBlock(BasicBlock block) {

		// Instead of normal CompiledBasicBlocks this provides the VMCodeGenerator
		// specific variant
		CompiledBasicBlock cbb = new VMCompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	@Override
	public int getNodeSize() {
		return 6;
	}

	@Override
	public int getNodeInstCount() {
		return 1;
	}
	
	@Override
	public int getSwitchCaseCount() {
		return 3;
	}
	
	@Override
	protected int[] processAppendedData() {
		int size = 0;
		Object[] data = getFunction().getData();
		
		for(int i=0;i<data.length;i++) {
			if(dataOffsetMap.containsKey(data[i])) // this should never occur
				throw new RuntimeException(data[i]+" is registered more than once");
			dataOffsetMap.put(data[i], size);
			size++;
		}
		
		return new int[] {};
	}

	@Override
	protected void link(List<CompiledBasicBlock> blocks) {

		HashMap<BasicBlock, Integer> positionMap = new HashMap<BasicBlock, Integer>();
		int curPos = 0;

		//curPos += getNodeSize(); // entry point
		//curPos += getNodeSize(); // pretext

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
		
		if(curPos != getProgramSize())
			throw new RuntimeException("Actual program size is not equal to calculated program size");

		// Iterate the basic blocks and add the conditional and unconditional jumps
		for (CompiledBasicBlock cbb : blocks) {
			assert (cbb instanceof VMCompiledBasicBlock);
			// current position is at the end of this basic block
			int position = positionMap.get(cbb.getBlock()) + this.getBlockSize(cbb.getBlock()) * getNodeSize();

			if(cbb.getBlock().isConditionalBlock()) {
				int[] branches = new int[getNodeSize()];

				// calculate the actual offset to jump
				int jumpOffsetConditonal = positionMap.get(cbb.getBlock().getConditionalBranch()) - (position);

				branches[0] = OP_COMPARE_EQUAL + condition2value(cbb.getBlock().getCondition().getOperation());
				branches[1] = getNodeID(cbb.getBlock().getCondition().getOperant1());
				branches[2] = getNodeID(cbb.getBlock().getCondition().getOperant2());
				branches[3] = jumpOffsetConditonal&0xFF;
				branches[4] = (jumpOffsetConditonal>>8)&0xFF;
				branches[5] = 0;
				
				// append the compiled conditional jump
				((VMCompiledBasicBlock) cbb).appendBytes(branches);
				position += this.getNodeSize(); // add the conditional jump size to the current position
			}
			
			if(cbb.getBlock().isSwitchCase()) {

				int[] switchJump = new int[getNodeSize()];

				switchJump[0] = OP_SWITCH;
				switchJump[1] = getNodeID(cbb.getBlock().getSwitchNode());
				switchJump[2] = 00;
				switchJump[3] = 00;
				switchJump[4] = 00;
				switchJump[5] = 00;
				
				((VMCompiledBasicBlock) cbb).appendBytes(switchJump);
				position += this.getNodeSize(); // add the conditional jump size to the current position
				// 6 instructions
				
				int[] switchEntry = new int[getNodeSize()];
				int switchEntryIndex = 0;
				int switchEntryAppened = 0;
				for(int s=0;s<cbb.getBlock().getSwitchBlocks().size();s++) {
					
					// jump offset
					int offset = (positionMap.get(cbb.getBlock().getSwitchBlocks().get(s)) - (position));
					switchEntry[switchEntryIndex] = offset & 0xFF;
					switchEntry[switchEntryIndex+1] = (offset>>8) & 0xFF;

					switchEntryIndex+=2;
					if(switchEntryIndex % getNodeSize() == 0) {
						((VMCompiledBasicBlock) cbb).appendBytes(switchEntry);
						switchEntry = new int[getNodeSize()];
						switchEntryIndex = 0;
						switchEntryAppened++;
					}
				}
				
				// append unfinished blocks as well
				if(switchEntryIndex != 0) {
					((VMCompiledBasicBlock) cbb).appendBytes(switchEntry);
					switchEntryAppened++;
				}
				
				position += switchEntryAppened*getNodeSize();
				
			}else if(cbb.getBlock().isExitBlock()) {
				int[] done = new int[getNodeSize()];
				
				if(cbb.getBlock().getReturnValue() == null)
					done[0] = OP_RETURN;
				else
					done[0] = OP_RETURNV;
				done[1] = cbb.getBlock().getReturnValue() == null?0:getNodeID(cbb.getBlock().getReturnValue());
				done[2] = 00;
				done[3] = 00;
				done[4] = 00;
				done[5] = 00;
		
				((VMCompiledBasicBlock) cbb).appendBytes(done);

			}else {			
				// Normal direct jump	
				int[] done = new int[getNodeSize()];
	
				int jumpOffset = positionMap.get(cbb.getBlock().getUnconditionalBranch()) - (position);
				done[0] = OP_JUMP;
				done[1] = 00;
				done[2] = 00;
				done[3] = jumpOffset&0xFF;
				done[4] = (jumpOffset>>8)&0xFF;;
				done[5] = 00;
				// append the last part of code
				((VMCompiledBasicBlock) cbb).appendBytes(done);
			}
		}
		

	}

	@Override
	protected int[] finish(List<CompiledBasicBlock> compiledBlocks) {

		List<int[]> l = new ArrayList<int[]>();

		// This entry point code is to streamline MergedFunctions
		//int[] entrypoint = new int[getNodeSize()];

		//l.add(entrypoint);

		//int[] pretext = new int[getNodeSize()];

		int variableCount = this.getFunction().getVariables();
		if (variableCount >= 256)
			throw new RuntimeException("Too much stack space reserved");

		int nodeCount = getNodeSlotCount();
		if (nodeCount >= 256)
			throw new RuntimeException("Too much stack space reserved " + nodeCount);

		//int spOffset = (variableCount + nodeCount) * 4;

		
		//l.add(pretext);

		for (CompiledBasicBlock cbb : compiledBlocks) {
			assert (cbb instanceof VMCompiledBasicBlock);
			l.add(((VMCompiledBasicBlock) cbb).getBytes());
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
	private class VMCompiledBasicBlock extends CompiledBasicBlock {

		List<int[]> dataArray;

		public VMCompiledBasicBlock(BasicBlock block) {
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

	// Internal NodeCodeGenerator for VM Code generation
	// Enforces NodeSize Requirements and NOPS by default, also caches conversions
	private abstract class VMNodeCodeGenerator extends NodeCodeGenerator {

		private VMNodeCodeGenerator(int[] data) {
			assert (data.length == VMCodeGenerator.this.getNodeSize());
		}

		public void process(CompiledBasicBlock cbb, Node node) {
			assert (cbb instanceof VMCompiledBasicBlock);
			int[] data = new int[VMCodeGenerator.this.getNodeSize()];
			writeData(node, data);
			((VMCompiledBasicBlock) cbb).appendBytes(data);
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


}
