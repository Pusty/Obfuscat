package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.List;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeAlloc;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;
/**
 * The Graph Synthesizer for Flowgraph
 */
public class FlowgraphCodeGenerator extends CodeGenerator {

	
	static {
		registerCodegen(FlowgraphCodeGenerator.class);
		registerCustomNode(FlowgraphCodeGenerator.class, "readInt", new FlowgraphNodeReadInt());
		registerCustomNode(FlowgraphCodeGenerator.class, "prepare_call", new FlowgraphNodeCall());
		registerCustomNode(FlowgraphCodeGenerator.class, "call", new FlowgraphNodeCall());
	}
	
	
	/**
	 * Create a new FlowgraphCodeGenerator (recommended way of creating an instance is
	 * through {@link re.bytecode.obfuscat.Obfuscat#generateCode(String, Function)})
	 * 
	 * @param context
	 *            the context of this generator, may be null
	 * @param function
	 *            the function to generate code for
	 */
	public FlowgraphCodeGenerator(Context context, Function function) {
		super(context, function);
	}

	public String description() {
		return "A graph generator for Control Flow Graph diagrams";
	}

	private static String addNode(BasicBlock block, Node node, String desc, Node[] children) {
		StringBuilder nodeStr = new StringBuilder();
		nodeStr.append("addNode(o, \"");
		nodeStr.append(block.getName());
		nodeStr.append("\", \"");
		nodeStr.append("N"+node.hashCode());
		nodeStr.append("\", \"");
		nodeStr.append(desc);
		nodeStr.append("\");");
		
		
		for(Node child:children) {
			nodeStr.append(" addChild(o, \"");
			nodeStr.append(block.getName());
			nodeStr.append("\", \"");
			nodeStr.append("N"+node.hashCode());
			nodeStr.append("\", \"");
			nodeStr.append("N"+child.hashCode());
			nodeStr.append("\");");
		}
		
		return nodeStr.toString();
	}
	
	private static String addConditionalBranch(BasicBlock block, Node operant1, Node operant2, CompareOperation operation,
			BasicBlock conditionalBranch, BasicBlock unconditionalBranch) {
		StringBuilder nodeStr = new StringBuilder();
		nodeStr.append("addJump(o, \"");
		nodeStr.append(block.getName());
		nodeStr.append("\", \"");
		nodeStr.append(conditionalBranch.getName());
		nodeStr.append("\");");
		nodeStr.append(" addJump(o, \"");
		nodeStr.append(block.getName());
		nodeStr.append("\", \"");
		nodeStr.append(unconditionalBranch.getName());
		nodeStr.append("\");");
		return nodeStr.toString();
	}
	

	private static String addSwitchJump(BasicBlock block, Node switchNode, List<BasicBlock> switchBlocks) {
		StringBuilder nodeStr = new StringBuilder();
		for(BasicBlock entry:switchBlocks) {
		nodeStr.append("addJump(o, \"");
		nodeStr.append(block.getName());
		nodeStr.append("\", \"");
		nodeStr.append(entry.getName());
		nodeStr.append("\"); ");
		}
		return nodeStr.toString();
	}

	
	private static String addJump(BasicBlock block, BasicBlock unconditionalBranch) {
		StringBuilder nodeStr = new StringBuilder();
		nodeStr.append("addJump(o, \"");
		nodeStr.append(block.getName());
		nodeStr.append("\", \"");
		nodeStr.append(unconditionalBranch.getName());
		nodeStr.append("\");");
		return nodeStr.toString();
	}

	private static String addExitBlock(BasicBlock block, Node returnValue) {
		return "";
	}
	

	@Override
	protected void initMapping() {

		// Default case
		codeMapping.put(null, new FlowgraphNodeCodeGenerator() {

			@Override
			public void process(CompiledBasicBlock cbb, Node node) {
				throw new RuntimeException("Not implemented " + node);
			}

			@Override
			public String writeData(BasicBlock bb, Node n) {
				return null;
			}

		});

		// Encode Constants
		codeMapping.put(NodeConst.class, new FlowgraphNodeCodeGenerator() {

			@Override
			public String writeData(BasicBlock bb, Node n) {
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
				} else if (constObj instanceof Boolean) {
					value = ((Boolean) constObj).booleanValue()?1:0;
				}else if (constObj instanceof Character) {
					value = (int) ((Character) constObj).charValue();
				} else {
					return addNode(bb, n, constObj.toString(), new Node[] {});
					//throw new RuntimeException("Const type " + constObj.getClass() + " not implemented");
				}
				
				return addNode(bb, n, Integer.toString(value), new Node[] {});
			}

		});

		// Encode Variable Load Operations
		codeMapping.put(NodeLoad.class, new FlowgraphNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeLoad);
				NodeLoad node = (NodeLoad) n;
				
				return addNode(bb, n, "Load"+node.getLoadSize()+"("+node.getSlot()+")", new Node[] {});
			}
		});

		// Encode Variable Store Operations
		codeMapping.put(NodeStore.class, new FlowgraphNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeStore);
				NodeStore node = (NodeStore) n;

				Node[] children = node.children();
				
				return addNode(bb, n, "Store"+node.getStoreSize()+"("+node.getSlot()+")", children);
			}
		});

		// Encode Array Load Operations
		codeMapping.put(NodeALoad.class, new FlowgraphNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeALoad);
				NodeALoad node = (NodeALoad) n;

				Node[] children = node.children();

				return addNode(bb, n, "ALoad"+node.getLoadSize(), children);
			}
		});

		// Encode Array Store Operations
		codeMapping.put(NodeAStore.class, new FlowgraphNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeAStore);
				NodeAStore node = (NodeAStore) n;

				Node[] children = node.children();

				return addNode(bb, n, "AStore"+node.getStoreSize(), children);
			}
		});

		// Encode Math Operations
		codeMapping.put(NodeMath.class, new FlowgraphNodeCodeGenerator() {

			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeMath);
				NodeMath node = (NodeMath) n;

				Node[] children = node.children();

				return addNode(bb, n, node.getOperation().toString(), children);
			}

		});
		
		// Encode Math Operations
		codeMapping.put(NodeAlloc.class, new FlowgraphNodeCodeGenerator() {

			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeAlloc);
				NodeAlloc node = (NodeAlloc) n;

				Node[] children = node.children();

				return addNode(bb, n,"Alloc"+node.getAllocationSize(), children);
			}

		});

	}

	@Override
	public CompiledBasicBlock generateBlock(BasicBlock block) {

		// Instead of normal CompiledBasicBlocks this provides the ThumbCodeGenerator
		// specific variant
		CompiledBasicBlock cbb = new FlowgraphCompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	@Override
	public int getNodeSize() {
		return 0;
	}

	@Override
	public int getNodeInstCount() {
		return 0;
	}
	
	@Override
	public int getSwitchCaseCount() {
		return 0;
	}


	@Override
	protected int countProgramSize() {
		return 0;
	}
	
	@Override
	public void link(List<CompiledBasicBlock> blocks) {
	}
	
	@Override
	protected int[] processAppendedData() {
		return new int[] {};
	}



	@Override
	public int[] finish(List<CompiledBasicBlock> compiledBlocks) {

		StringBuilder mapTogether = new StringBuilder();
		for (CompiledBasicBlock cbb : compiledBlocks) {
			assert (cbb instanceof FlowgraphCompiledBasicBlock);
			for(String line:((FlowgraphCompiledBasicBlock) cbb).dataArray) {
				mapTogether.append(line);
				mapTogether.append('\n');
			}
		}
		
		
		// Iterate the basic blocks and add the conditional and unconditional jumps
		for (CompiledBasicBlock cbb : compiledBlocks) {
			assert (cbb instanceof FlowgraphCompiledBasicBlock);
			
			if(cbb.getBlock().isConditionalBlock()) {
				
				String conditional = addConditionalBranch(cbb.getBlock(), cbb.getBlock().getCondition().getOperant1(),  cbb.getBlock().getCondition().getOperant2(), cbb.getBlock().getCondition().getOperation(),  cbb.getBlock().getConditionalBranch(), cbb.getBlock().getUnconditionalBranch());
				mapTogether.append(conditional);
				mapTogether.append('\n');
			}else if(cbb.getBlock().isSwitchCase()) {
				String jumpTable = addSwitchJump(cbb.getBlock(), cbb.getBlock().getSwitchNode(), cbb.getBlock().getSwitchBlocks());
				mapTogether.append(jumpTable);
				mapTogether.append('\n');
			}else if(cbb.getBlock().isExitBlock()) {
				String exitBlock = addExitBlock(cbb.getBlock(), cbb.getBlock().getReturnValue());
				mapTogether.append(exitBlock);
				mapTogether.append('\n');
			}else {			
				String normalJump = addJump(cbb.getBlock(), cbb.getBlock().getUnconditionalBranch());
				mapTogether.append(normalJump);
				mapTogether.append('\n');
			}
		}
		
		
		String res = mapTogether.toString();
		
		int[] intArray = new int[res.length()];
		for(int i=0;i<intArray.length;i++)
			intArray[i] = res.charAt(i);

		return intArray;
	}

	// Internal CompiledBasicBlock Class
	private class FlowgraphCompiledBasicBlock extends CompiledBasicBlock {

		List<String> dataArray;

		public FlowgraphCompiledBasicBlock(BasicBlock block) {
			super(block);
			dataArray = new ArrayList<String>();
		}

		public void appendLine(String data) {
			dataArray.add(data);
		}


		public String toString() {
			StringBuilder sb = new StringBuilder();
			for (String arr : dataArray) {
				sb.append(arr);
				sb.append('\n');
			}
			return sb.toString();
		}

	}

	private abstract class FlowgraphNodeCodeGenerator extends NodeCodeGenerator {

		private FlowgraphNodeCodeGenerator() {
		}

		public void process(CompiledBasicBlock cbb, Node node) {
			assert (cbb instanceof FlowgraphCompiledBasicBlock);
			((FlowgraphCompiledBasicBlock) cbb).appendLine(writeData(cbb.getBlock(), node));
		}

		public abstract String writeData(BasicBlock bb, Node node);

	}

	/**
	 * CustomNodeImpl for "readInt"
	 */
	public static class FlowgraphNodeReadInt extends CustomNodeImpl {

		@Override
		public void process(CodeGenerator generator, CompiledBasicBlock cbb, NodeCustom node) {
			assert (generator instanceof FlowgraphCodeGenerator);
			assert (cbb instanceof FlowgraphCompiledBasicBlock);
			((FlowgraphCompiledBasicBlock) cbb).appendLine(addNode(cbb.getBlock(), node, node.getIdentifier() ,node.children()));
		}

	}

	/**
	 * CustomNodeImpl for "call"
	 */
	public static class FlowgraphNodeCall extends CustomNodeImpl {

		@Override
		public void process(CodeGenerator generator, CompiledBasicBlock cbb, NodeCustom node) {
			assert (generator instanceof FlowgraphCodeGenerator);
			assert (cbb instanceof FlowgraphCompiledBasicBlock);
			//if (!(generator.getFunction() instanceof MergedFunction))
			//	throw new RuntimeException("Can't branch in a non merged function");

			((FlowgraphCompiledBasicBlock) cbb).appendLine(addNode(cbb.getBlock(), node, node.getIdentifier() ,node.children()));
		}

	}


}
