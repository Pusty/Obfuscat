package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map.Entry;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath1;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

// TODO: Implement Function Arguments
// For the sake of the Thumb Generator this is for now depreciated and may be taken on again later (and made more efficent)

@Deprecated
public class x86CodeGenerator extends CodeGenerator {

	public x86CodeGenerator(Context context, Function function) {
		super(context, function);
	}

	private void loadNode(int[] data, int offset, int register, Node from) {
		int fromID = this.getNodeID(from) * 8;

		// 48 8B 84 24 FF FF FF 1F
		// mov rbx, qword ptr [rsp + 0x1FFFFFFF]

		data[offset] = 0x48;
		data[offset + 1] = 0x8B;
		if (register == 0)
			data[offset + 2] = 0x84;
		else if (register == 1)
			data[offset + 2] = 0x9C;
		else if (register == 2)
			data[offset + 2] = 0x8C;
		else
			throw new RuntimeException("Register " + register + " not supported");
		data[offset + 3] = 0x24;
		data[offset + 4] = fromID & 0xFF;
		data[offset + 5] = (fromID >> 8) & 0xFF;
		data[offset + 6] = (fromID >> 16) & 0xFF;
		data[offset + 7] = (fromID >> 24) & 0xFF;

	}

	private void storeNode(int[] data, int offset, Node from) {
		int fromID = this.getNodeID(from) * 8;

		// 48 89 84 24 FF FF FF 1F
		// mov qword ptr [rsp + 0x1FFFFFFF], rax

		data[offset] = 0x48;
		data[offset + 1] = 0x89;
		data[offset + 2] = 0x84;
		data[offset + 3] = 0x24;
		data[offset + 4] = fromID & 0xFF;
		data[offset + 5] = (fromID >> 8) & 0xFF;
		data[offset + 6] = (fromID >> 16) & 0xFF;
		data[offset + 7] = (fromID >> 24) & 0xFF;

	}

	protected void initMapping() {
		
		// Default case
		codeMapping.put(null, new x86NodeCodeGenerator(null) {

			@Override
			public void process(CompiledBasicBlock cbb, Node node) {
				throw new RuntimeException("Not implemented " + node);
			}

			@Override
			public int[] getBytes(Node node) {
				return null;
			}

		});

		codeMapping.put(NodeConst.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeConst);
				NodeConst node = (NodeConst) n;
				Object constObj = node.getObj();
				int value = 0;
				if (constObj instanceof Integer) {
					value = ((Integer) constObj).intValue();
				} else if(constObj instanceof Short) {
					value = ((Short) constObj).intValue();
				} else if(constObj instanceof Byte) {
					value = ((Byte) constObj).intValue();
				}  else if(constObj instanceof Character) {
					value = (int)((Character) constObj).charValue();
				}  else {
					throw new RuntimeException("Const type " + constObj.getClass() + " not implemented");
				}
				
				// B8 78 56 34 12
				// mov eax, 0x12345678
				data[0] = 0xB8;
				data[1] = value & 0xFF;
				data[2] = (value >> 8) & 0xFF;
				data[3] = (value >> 16) & 0xFF;
				data[4] = (value >> 24) & 0xFF;
				
				storeNode(data, 5, node);
				return data;
			}

		});

		codeMapping.put(NodeLoad.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeLoad);
				NodeLoad node = (NodeLoad) n;

				int slot = -(node.getSlot()*8);

				// xor eax, eax
				data[0] = 0x31;
				data[1] = 0xC0;

				switch (node.getLoadSize()) {
				case 1:
					// mov al, [rdi+0x12345678]
					data[2] = 0x8A;
					data[3] = 0x87;
					data[4] = slot & 0xFF;
					data[5] = (slot >> 8) & 0xFF;
					data[6] = (slot >> 16) & 0xFF;
					data[7] = (slot >> 24) & 0xFF;
					data[8] = 0x90;
					break;
				case 2:
					// mov ax, [rdi+0x12345678]
					data[2] = 0x66;
					data[3] = 0x8B;
					data[4] = 0x87;
					data[5] = slot & 0xFF;
					data[6] = (slot >> 8) & 0xFF;
					data[7] = (slot >> 16) & 0xFF;
					data[8] = (slot >> 24) & 0xFF;
					break;
				case 4:
					// mov eax, [rdi+0x12345678]
					data[2] = 0x8B;
					data[3] = 0x87;
					data[4] = slot & 0xFF;
					data[5] = (slot >> 8) & 0xFF;
					data[6] = (slot >> 16) & 0xFF;
					data[7] = (slot >> 24) & 0xFF;
					data[8] = 0x90;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				storeNode(data, 9, node);
				return data;
			}
		});

		codeMapping.put(NodeStore.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeStore);
				NodeStore node = (NodeStore) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);

				int slot = -(node.getSlot()*8);

				switch (node.getStoreSize()) {
				case 1:
					// mov [rdi+0x12345678], al
					data[8] = 0x88;
					data[9] = 0x87;
					data[10] = slot & 0xFF;
					data[11] = (slot >> 8) & 0xFF;
					data[12] = (slot >> 16) & 0xFF;
					data[13] = (slot >> 24) & 0xFF;
					data[14] = 0x90;
					break;
				case 2:
					// mov [rdi+0x12345678], ax
					data[8] = 0x66;
					data[9] = 0x89;
					data[10] = 0x87;
					data[11] = slot & 0xFF;
					data[12] = (slot >> 8) & 0xFF;
					data[13] = (slot >> 16) & 0xFF;
					data[14] = (slot >> 24) & 0xFF;
					break;
				case 4:
					// mov [rdi+0x12345678], eax
					data[8] = 0x89;
					data[9] = 0x87;
					data[10] = slot & 0xFF;
					data[11] = (slot >> 8) & 0xFF;
					data[12] = (slot >> 16) & 0xFF;
					data[13] = (slot >> 24) & 0xFF;
					data[14] = 0x90;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				return data;
			}
		});

		codeMapping.put(NodeALoad.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeALoad);
				NodeALoad node = (NodeALoad) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 8, 0, children[1]);

				switch (node.getLoadSize()) {
				case 1:
					// xor eax, eax; mov al, [rax+rbx] - 31 C0 8A 04 18
					data[16] = 0x31;
					data[17] = 0xC0;
					data[18] = 0x8A;
					data[19] = 0x04;
					data[20] = 0x18;
					data[21] = 0x90;
					break;
				case 2:
					// xor eax, eax; mov ax, [rax+rbx*2] - 31 C0 66 8B 04 58
					data[16] = 0x31;
					data[17] = 0xC0;
					data[18] = 0x66;
					data[19] = 0x8B;
					data[20] = 0x04;
					data[21] = 0x58;
					break;
				case 4:
					// mov eax, [rax+rbx*4] - 8B 04 98
					data[16] = 0x8B;
					data[17] = 0x04;
					data[18] = 0x98;
					data[19] = 0x90;
					data[20] = 0x90;
					data[21] = 0x90;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				storeNode(data, 22, node);

				return data;
			}
		});

		codeMapping.put(NodeAStore.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {
			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeAStore);
				NodeAStore node = (NodeAStore) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 8, 0, children[1]);
				loadNode(data, 16, 0, children[2]);

				switch (node.getStoreSize()) {
				case 1:
					// mov [rax+rbx], cl - 88 0C 18
					data[24] = 0x88;
					data[25] = 0x0C;
					data[26] = 0x18;
					data[27] = 0x90;
					break;
				case 2:
					// mov [rax+rbx*2], cx - 66 89 0C 58
					data[24] = 0x66;
					data[25] = 0x89;
					data[26] = 0x0C;
					data[27] = 0x58;
					break;
				case 4:
					// mov [rax+rbx*4], ecx - 89 0C 98
					data[24] = 0x89;
					data[25] = 0x0C;
					data[26] = 0x98;
					data[27] = 0x90;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				return data;
			}
		});

		codeMapping.put(NodeMath1.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeMath1);
				NodeMath1 node = (NodeMath1) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				switch (((NodeMath1) node).getOperation()) {
				case NOT:
					// not eax F7 D0
					data[8] = 0xF7;
					data[9] = 0xD0;
					break;
				case NEG:
					// neg eax F7 D8
					data[8] = 0xF7;
					data[9] = 0xD8;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				storeNode(data, 10, node);
				return data;
			}

		});

		codeMapping.put(NodeMath2.class, new x86NodeCodeGenerator(new int[getNodeSize()]) {

			@Override
			public int[] getBytes(Node n) {
				assert (n instanceof NodeMath2);
				NodeMath2 node = (NodeMath2) n;

				Node[] children = node.children();

				loadNode(data, 0, 0, children[0]);
				loadNode(data, 8, 1, children[1]);

				int relOffset = 16;

				switch (node.getOperation()) {
				case ADD:
					// add eax, ebx
					data[relOffset] = 0x01;
					data[relOffset + 1] = 0xD8;
					data[relOffset + 2] = 0x90;
					data[relOffset + 3] = 0x90;
					break;
				case SUB:
					// sub eax, ebx
					data[relOffset] = 0x29;
					data[relOffset + 1] = 0xD8;
					data[relOffset + 2] = 0x90;
					data[relOffset + 3] = 0x90;
					break;
				case MUL:
					// imul eax, ebx
					data[relOffset] = 0x0F;
					data[relOffset + 1] = 0xAF;
					data[relOffset + 2] = 0xC3;
					data[relOffset + 3] = 0x90;
					break;
				case DIV:
					// cdq; idiv ebx
					data[relOffset] = 0x99;
					data[relOffset + 1] = 0xF7;
					data[relOffset + 2] = 0xFB;
					data[relOffset + 3] = 0x90;
					break;
				case MOD:
					// cdq; idiv ebx; xchg eax, edx
					data[relOffset] = 0x99;
					data[relOffset + 1] = 0xF7;
					data[relOffset + 2] = 0xFB;
					data[relOffset + 3] = 0x92;
					break;
				case AND:
					// and eax, ebx
					data[relOffset] = 0x21;
					data[relOffset + 1] = 0xD8;
					data[relOffset + 2] = 0x90;
					data[relOffset + 3] = 0x90;
					break;
				case OR:
					// or eax, ebx
					data[relOffset] = 0x09;
					data[relOffset + 1] = 0xD8;
					data[relOffset + 2] = 0x90;
					data[relOffset + 3] = 0x90;
					break;
				case XOR:
					// xor eax, ebx
					data[relOffset] = 0x31;
					data[relOffset + 1] = 0xD8;
					data[relOffset + 2] = 0x90;
					data[relOffset + 3] = 0x90;
					break;
				case SHR:
					// mov cl, bx; sar eax, cl
					data[relOffset] = 0x88;
					data[relOffset + 1] = 0xD9;
					data[relOffset + 2] = 0xD3;
					data[relOffset + 3] = 0xF8;
					break;
				case USHR:
					// mov cl, bx; shr eax, cl
					data[relOffset] = 0x88;
					data[relOffset + 1] = 0xD9;
					data[relOffset + 2] = 0xD3;
					data[relOffset + 3] = 0xE8;
					break;
				case SHL:
					// mov cl, bx; shl eax, cl
					data[relOffset] = 0x88;
					data[relOffset + 1] = 0xD9;
					data[relOffset + 2] = 0xD3;
					data[relOffset + 3] = 0xE0;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}

				storeNode(data, relOffset + 4, node);

				return data;
			}

		});

	}

	public CompiledBasicBlock generateBlock(BasicBlock block) {

		CompiledBasicBlock cbb = new x86CompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	public int getNodeSize() {
		return 32;
	}
	
	public void link(List<CompiledBasicBlock> blocks) {
		
		HashMap<BasicBlock, Integer> positionMap = new HashMap<BasicBlock, Integer>();
		int curPos = 0;
		
		// map assembled sizes
		for(CompiledBasicBlock cbb : blocks) {
			positionMap.put(cbb.getBlock(), curPos);
			curPos += this.getBlockSize(cbb.getBlock())*getNodeSize();
			curPos += cbb.getBlock().getSwitchBlocks().size()*getNodeSize();
			curPos += getNodeSize();
		}
		
		
		for(CompiledBasicBlock cbb : blocks) {
			assert(cbb instanceof x86CompiledBasicBlock);
			int position = positionMap.get(cbb.getBlock()) + this.getBlockSize(cbb.getBlock())*getNodeSize();
			for(Entry<BranchCondition, BasicBlock> e:cbb.getBlock().getSwitchBlocks().entrySet()) {
				
				int[] branches = new int[getNodeSize()];
				
				for (int i = 0; i < branches.length; i++)
					branches[i] = 0x90; // NOP
				
				loadNode(branches, 0, 0, e.getKey().getOperant1());
				loadNode(branches, 8, 1, e.getKey().getOperant2());
				// cmp eax, ebx
				branches[16] = 0x39;
				branches[17] = 0xD8;
				
				int jumpOffset = positionMap.get(e.getValue())-(position+24);
				
				branches[18] = 0x0F;
				switch(e.getKey().getOperation()) {
				case EQUAL:
					//je 0x12345678 - 0F 84 72 56 34 12
					branches[19] = 0x84;
					break;
				case NOTEQUAL:
					//je 0x12345678 - 0F 85 72 56 34 12
					branches[19] = 0x85;
					break;
				case LESSTHAN:
					// jl 0x12345678 - 0F 8C 72 56 34 12
					branches[19] = 0x8C;
					break;
				case LESSEQUAL:
					// jle 0x12345678 - 0F 8E 72 56 34 12
					branches[19] = 0x8E;
					break;
				case GREATERTHAN:
					// jg 0x12345678 - 0F 8F 72 56 34 12
					branches[19] = 0x8F;
					break;
				case GREATEREQUAL:
					// jge 0x12345678 - 0F 8D 72 56 34 12
					branches[19] = 0x8D;
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				
				branches[20] = jumpOffset & 0xFF;
				branches[21] = (jumpOffset >> 8) & 0xFF;
				branches[22] = (jumpOffset >> 16) & 0xFF;
				branches[23] = (jumpOffset >> 24) & 0xFF;
				((x86CompiledBasicBlock)cbb).appendBytes(branches);
				position+=32;
		    }
			
			int[] done = new int[getNodeSize()];
			
			for (int i = 0; i < done.length; i++)
				done[i] = 0x90; // NOP
			
			if(!cbb.getBlock().isExitBlock()) {
				int jumpOffset = positionMap.get(cbb.getBlock().getUnconditionalBranch())-(position+23);
				// jmp 0x12345678 - E9 73 56 34 12
				done[0] = 0xE9;
				done[1] = jumpOffset & 0xFF;
				done[2] = (jumpOffset >> 8) & 0xFF;
				done[3] = (jumpOffset >> 16) & 0xFF;
				done[4] = (jumpOffset >> 24) & 0xFF;
			}else {
				
				if(cbb.getBlock().getReturnValue() != null)
					loadNode(done, 0, 0, cbb.getBlock().getReturnValue());
				// add rsp, 0x140 - 48 81 C4 40 01 00 00
				done[8] = 0x48;
				done[9] = 0x81;
				done[10] = 0xC4;

				int variableCount = (this.getFunction().getVariables()+this.getFunction().getArguments().length)*8+getNodeSlotCount()*8;
				
				done[11] = variableCount & 0xFF;
				done[12] = (variableCount >> 8) & 0xFF;
				done[13] = (variableCount >> 16) & 0xFF;
				done[14] = (variableCount >> 24) & 0xFF;
				
				
				
				// add rsp, nodes * 8
				// add rsp, slots * 8
				// mov rsp, rbp
				// pop rbp
				
				done[15] = 0x48; 
				done[16] = 0x89; 
				done[17] = 0xEC; 
				done[18] = 0x5D; 
				
				done[19] = 0xC3; // ret
			}
			((x86CompiledBasicBlock)cbb).appendBytes(done);
		}
		
		

	}


	public int[] finish(List<CompiledBasicBlock> compiledBlocks) {
		
		
		
		List<Integer[]> l = new ArrayList<Integer[]>();
		
		
		this.getFunction().getArguments();
		this.getFunction().getVariables();
		
		
		// push rbp
		// mov rbp, rsp
		// sub rsp, slots * 8
	
		// xor rax, rax
		
		// arguments slots = stack arguments
		
		// mov [rsp], rax
		// mov [rsp+(slots-1)*8], rax
		// mov rdi, rsp
		// sub rsp, nodes * 8
		
		Integer[] pre = new Integer[getNodeSize()];
		
		for (int i = 0; i < pre.length; i++)
			pre[i] = 0x90; // NOP
		
		
		pre[0] = 0x55; // push rbp
		pre[1] = 0x48; // mov rbp, rsp
		pre[2] = 0x89;
		pre[3] = 0xE5;
		
		pre[4] = 0x48; // lea rdi, [rbp-8]
		pre[5] = 0x8D;
		pre[6] = 0x7D;
		pre[7] = 0xF8;
		
		int variableCount = (this.getFunction().getVariables()+this.getFunction().getArguments().length+this.getNodeSlotCount())*8;
		pre[8] = 0x48; // sub rsp, slots * 8 48 81 EC 40 01 00 00
		pre[9] = 0x81;
		pre[10] = 0xEC;
		pre[11] = variableCount & 0xFF;
		pre[12] = (variableCount >> 8) & 0xFF;
		pre[13] = (variableCount >> 16) & 0xFF;
		pre[14] = (variableCount >> 24) & 0xFF;
		
		
		l.add(pre);
		// mov [rbp-0], rcx
		// mov [rbp-8], rdx
		// mov [rbp-16], r8
		// mov [rbp-24], r9
		

		
		
		for(CompiledBasicBlock cbb : compiledBlocks) {
			assert(cbb instanceof x86CompiledBasicBlock);
			l.add(((x86CompiledBasicBlock) cbb).getBytes());
		}
		
		return l.stream().flatMap(Arrays::stream).mapToInt(Integer::intValue).toArray();
	}

	private class x86CompiledBasicBlock extends CompiledBasicBlock {

		List<Integer[]> dataArray;

		public x86CompiledBasicBlock(BasicBlock block) {
			super(block);
			dataArray = new ArrayList<Integer[]>();
		}

		public void appendBytes(int[] data) {
			dataArray.add(Arrays.stream(data).boxed().toArray( Integer[]::new ));
		}
		
		public Integer[] getBytes() {
			//int[] resultArray = dataArray.stream().flatMap(Arrays::stream).mapToInt(Integer::intValue).toArray();
			//return resultArray;
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

	private abstract class x86NodeCodeGenerator extends NodeCodeGenerator {

		protected int[] data;

		private x86NodeCodeGenerator(int[] data) {
			this.data = data;
			if (data != null)
				for (int i = 0; i < data.length; i++)
					data[i] = 0x90; // NOP
		}

		public void process(CompiledBasicBlock cbb, Node node) {
			assert (cbb instanceof x86CompiledBasicBlock);
			((x86CompiledBasicBlock) cbb).appendBytes(getBytes(node).clone());
		}

		//public int getSize(Node node) {
		//	return data.length;
		//}

		public abstract int[] getBytes(Node node);

	}

	// TODO: not implemented yet
	@Override
	public int getNodeInstCount() {
		return 0;
	}

}
