package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;

/**
 * A function to code generator class
 */
public abstract class CodeGenerator {

	protected Map<Class<? extends Node>, NodeCodeGenerator> codeMapping  = new HashMap<Class<? extends Node>, NodeCodeGenerator>();

	private Map<BasicBlock, Integer> numberedBlocks;
	private Map<BasicBlock, Integer> amountBlocks;
	private Map<Node, Integer> numberedNodes;
	private int blockID;
	private int maxNodeID;

	private Function function;
	private int[] data;
	private Context context;

	/**
	 * Create a new code generator given a context and a function to synthesize code for
	 * @param context the context of this generator, may be null
	 * @param function the function to generate code for
	 */
	public CodeGenerator(Context context, Function function) {
		
		if (context == null)
			context = new Context(System.currentTimeMillis()); // if for some reason no context is set, create one
		
		this.context = context;
		
		numberedBlocks = new HashMap<BasicBlock, Integer>();
		amountBlocks = new HashMap<BasicBlock, Integer>();
		numberedNodes = new HashMap<Node, Integer>();
		blockID = 0;
		maxNodeID = 0;
		this.function = function;
		
		// processor for custom node through the Obfuscat main class
		codeMapping.put(NodeCustom.class, new NodeCodeGenerator() {

			// cache implementation instances
			private Map<String, CustomNodeImpl> cache = new HashMap<String, CustomNodeImpl>();
			
			@Override
			public void process(CompiledBasicBlock cbb, Node node) {
				assert(node instanceof NodeCustom);
				NodeCustom custom = (NodeCustom)node;
				if(!cache.containsKey(custom.getIdentifier()))
					cache.put(custom.getIdentifier(), Obfuscat.getCustomNodeImpl(CodeGenerator.this, custom.getIdentifier()));
				cache.get(custom.getIdentifier()).process(cbb, custom);
			}
			
		});
		
		initMapping();
		
	}

	/**
	 * Synthesize data and return it
	 * @return the generated code
	 */
	public int[] generate() {
		this.data = generate(function.getBlocks());
		return this.data;
	}

	/**
	 * Return the context of this code synthesis
	 * @return
	 */
	public Context getContext() {
		return context;
	}

	/**
	 * Return the amount of needed node slots
	 * @return the maximum amount of required node slots by the generated function
	 */
	public int getNodeSlotCount() {
		return maxNodeID;
	}

	/**
	 * Return the amount of basic blocks of the function to generate
	 * @return the amount of basic blocks
	 */
	public int getBlockCount() {
		return blockID;
	}

	/**
	 * Initialize the codeMapping for Nodes -> Code
	 */
	protected abstract void initMapping();

	/**
	 * Return the function to generate code for
	 * @return the internally processed function
	 */
	public Function getFunction() {
		return function;
	}

	/**
	 * Return the generated data (and generate it if not already done)
	 * @return the synthesized data
	 */
	public int[] getData() {
		if (data == null)
			return generate();
		return data;
	}

	/**
	 * Process an individual Node for a given CompiledBasicBlock
	 * @param cbb the basic block this node belongs to
	 * @param node the node to process
	 */
	protected void processNode(CompiledBasicBlock cbb, Node node) {
		if (cbb.getNodes().contains(node)) // check if this node is already processed in this block
			return;
		cbb.getNodes().add(node); // add this node to the processed nodes

		Node[] children = node.children();

		// process the children of this node first if existent
		if (children != null)
			for (int i = 0; i < children.length; i++)
				processNode(cbb, children[i]);

		// process the node
		codeMapping.getOrDefault(node.getClass(), codeMapping.get(null)).process(cbb, node);
	}

	/**
	 * Return the internal used node id for a given node (probably not unique)
	 * @param n the node to lookup the id for
	 * @return the node slot this node belongs into
	 */
	protected int getNodeID(Node n) {
		return numberedNodes.get(n);
	}

	/**
	 * Return the unique basic block id for a given basic block of the processed function
	 * @param bb the basic block to look up the id for
	 * @return the basic block id of the block
	 */
	protected int getBlockID(BasicBlock bb) {
		return numberedBlocks.get(bb);
	}

	/**
	 * Return the amount of processed nodes of a given basic block
	 * @param bb the basic block to look up 
	 * @return the amount of processed nodes
	 */
	protected int getBlockSize(BasicBlock bb) {
		return amountBlocks.get(bb);
	}

	private int nodeID;

	// recursively give ids to the nodes and increase the count of nodes in the block
	private void numberNode(BasicBlock bb, Node node) {
		if (!numberedNodes.containsKey(node)) {
			numberedNodes.put(node, nodeID++);
			amountBlocks.put(bb, amountBlocks.get(bb) + 1);

			Node[] children = node.children();

			if (children != null)
				for (int i = 0; i < children.length; i++)
					numberNode(bb, children[i]);

		}
	}

	// iterate each block and calculate the node is and the maximum needed node slots
	private void iterateBlocks(BasicBlock bb) {

		if (!numberedBlocks.containsKey(bb)) {
			numberedBlocks.put(bb, blockID++);
			amountBlocks.put(bb, 0);

			nodeID = 0;
			for (Node node : bb.getNodes()) {
				numberNode(bb, node);
			}
			if (nodeID > maxNodeID)
				maxNodeID = nodeID;

			for (Entry<BranchCondition, BasicBlock> e : bb.getSwitchBlocks().entrySet()) {
				iterateBlocks(e.getValue());
			}

			if (!bb.isExitBlock())
				iterateBlocks(bb.getUnconditionalBranch());
		}
	}

	/**
	 * Generate a CompiledBasicBlock for a provided BasicBlock
	 * @param block the block to compile
	 * @return the compiled basic block
	 */
	protected CompiledBasicBlock generateBlock(BasicBlock block) {

		CompiledBasicBlock cbb = new CompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	/**
	 * Generate a List of compiled basic blocks and processed basic blocks from a given start block
	 * @param compiledBlocks the output list of compiled basic blocks
	 * @param processedBlocks the internally used already processed basic blocks
	 * @param block the basic block to start synthesis at
	 */
	protected void generateBlockRecursive(List<CompiledBasicBlock> compiledBlocks, List<BasicBlock> processedBlocks,
			BasicBlock block) {

		// check that the block isn't processed already
		if (processedBlocks.contains(block))
			return;
		
		processedBlocks.add(block);
		
		// compile the basic block
		compiledBlocks.add(generateBlock(block));

		// iterate all connected basic blocks
		
		for (Entry<BranchCondition, BasicBlock> e : block.getSwitchBlocks().entrySet()) {
			generateBlockRecursive(compiledBlocks, processedBlocks, e.getValue());
		}

		if (!block.isExitBlock())
			generateBlockRecursive(compiledBlocks, processedBlocks, block.getUnconditionalBranch());

	}

	/**
	 * Generate an array of bytes (in int[] format) for a list of connected basic blocks
	 * @param f the list of connected basic blocks to process
	 * @return the compiled function as a byte array
	 */
	protected int[] generate(List<BasicBlock> f) {
		
		// Number and Count the Blocks and Nodes
		for (BasicBlock bb : f) {
			iterateBlocks(bb);
		}
		
		// The output list of compiled basic blocks
		ArrayList<CompiledBasicBlock> blocks = new ArrayList<CompiledBasicBlock>();
		
		// Compile the basic blocks starting from the first recursively
		generateBlockRecursive(blocks, new ArrayList<BasicBlock>(), f.get(0));
		
		// Link the basic blocks together (add code parts for jumps)
		link(blocks);
		
		// Put everything together and pretext
		return finish(blocks);
	}

	/**
	 * Put all CompiledBasicBlock together, add a pretext, and output it as a combined array of bytes
	 * @param compiledBlocks the compiled basic blocks to fuse together
	 * @return the combined program
	 */
	protected abstract int[] finish(List<CompiledBasicBlock> compiledBlocks);

	/**
	 * Add (relative) jumps to the CompiledBasicBlocks
	 * @param compiledBlocks the compiled basic blocks to link together with jumps
	 */
	protected abstract void link(List<CompiledBasicBlock> compiledBlocks);
	
	/**
	 * The fixed amount of bytes per compiled Node, Conditional Jump and Unconditional Jump/Return and the pretext
	 * @return the exact size of each individual compiled code piece
	 */
	public abstract int getNodeSize();

	/**
	 * The fixed amount of instructions per compiled Node, Conditional Jump and Unconditional Jump/Return and the pretext
	 * @return the exact amount of executed instructions each individual compiled code piece
	 */
	public abstract int getNodeInstCount();
}
