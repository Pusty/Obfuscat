package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;

/**
 * A function to code generator class
 */
public abstract class CodeGenerator {

	protected Map<Class<? extends Node>, NodeCodeGenerator> codeMapping  = new HashMap<Class<? extends Node>, NodeCodeGenerator>();

	protected Map<BasicBlock, Integer> numberedBlocks;
	protected Map<BasicBlock, Integer> amountBlocks;
	protected Map<Node, Integer> numberedNodes;
	private int blockID;
	private int maxNodeID;

	private Function function;
	private int[] data;
	private int[] appenedDataOuput;
	private Context context;
	
	protected Map<Object, Integer> dataOffsetMap;
	private int programSize;

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
		
		dataOffsetMap = new HashMap<Object, Integer>();
		
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
					//cache.put(custom.getIdentifier(), Obfuscat.getCustomNodeImpl(CodeGenerator.this, custom.getIdentifier(), CodeGenerator.this.context));
					cache.put(custom.getIdentifier(), getCustomNodeImpl(custom.getIdentifier()));
				cache.get(custom.getIdentifier()).process(CodeGenerator.this, cbb, custom);
			}
			
		});
		
		initMapping();
		
	}
	
	
	private static Map<Class<?>, Map<String, CustomNodeImpl>> codegenMap = new HashMap<Class<?>, Map<String, CustomNodeImpl>>();
	

	/**
	 * Register a code generator
	 * @param codegenClass the code generator to register
	 */
	public static void registerCodegen(Class<?> codegenClass) {
		codegenMap.put(codegenClass, new HashMap<String, CustomNodeImpl>());
	}
	
	/**
	 * Register a custom node implementation with a specific identifier to a code generator
	 * @param codegenClass the code generator to register this custom node to
	 * @param identifier the identifier of the custom node
	 * @param customNode the custom node implementation handling nodes with the given identifier
	 */
	public static void registerCustomNode(Class<?> codegenClass, String identifier, CustomNodeImpl customNode) {
		codegenMap.get(codegenClass).put(identifier, customNode);
	}
	
	private CustomNodeImpl getCustomNodeImpl(String identifier) {
		if(codegenMap.get(this.getClass()).get(identifier) == null)
			throw new RuntimeException("No implemention for "+identifier+" in "+this.getClass());
		return codegenMap.get(this.getClass()).get(identifier);
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

	private HashMap<Node, Integer> countOccurances;
	
	// recursively count the amount a node is needed, also look for circles
	private void countOccuranceMethod(Node node, List<Node> alreadyPassed) {
		
		if(alreadyPassed.contains(node))
			throw new RuntimeException("Circle found with node in Node "+node);
		
		alreadyPassed = alreadyPassed.stream().collect(Collectors.toList()); // make a shallow copy of the list
		alreadyPassed.add(node);
		
		Node[] children = node.children();
		if (children != null)
			for (int i = 0; i < children.length; i++)
				countOccuranceMethod(children[i], alreadyPassed);
		
		if(!countOccurances.containsKey(node)) {
			countOccurances.put(node, 0);
			if (children != null)
				for (int i = 0; i < children.length; i++) {
					countOccurances.put(children[i], countOccurances.getOrDefault(children[i], 0)+1);
				}
		}
	}
	
	private HashMap<Integer, Node> slots;
	// recursively give ids to the nodes and increase the count of nodes in the block
	protected void numberNodes(Node node) {
		
		if(numberedNodes.containsKey(node)) return;
		
		Node[] children = node.children();
		if (children != null) {
			
			// provide slots for children
			for (int i = 0; i < children.length; i++) {
				numberNodes(children[i]);
			}
			
			// after usage of parameters - clear slots if values are not reused
			for (int i = 0; i < children.length; i++) {
				int occ = countOccurances.get(children[i])-1;
				countOccurances.put(children[i], occ);
				if(occ == 0)
					slots.put(numberedNodes.get(children[i]), null);
			}
		}
		
		boolean foundFreeSlot = false;
		
		int slotSize = slots.size();
		
		// find an empty slot an empty slot
		
		for(int i=0;i<slotSize;i++) {
			if(slots.get(i) == null) {
				slots.put(i, node);
				numberedNodes.put(node, i);
				foundFreeSlot = true;
				break;
			}
		}
		
		// add a new slot if no slot was empty
		if(!foundFreeSlot) {
			slots.put(slotSize, node);
			numberedNodes.put(node, slotSize);
		}

	}
	

	// iterate each block and calculate the node is and the maximum needed node slots
	private void iterateBlocks(BasicBlock bb) {

		if (!numberedBlocks.containsKey(bb)) {
			
			numberedBlocks.put(bb, blockID++);
			
			countOccurances = new HashMap<Node, Integer>();
			
			// circle detection - dependency counting
			for (Node node : bb.getNodes()) {
				List<Node> alreadyPassed = new ArrayList<Node>();
				countOccuranceMethod(node, alreadyPassed);
			}
			
			if(bb.isConditionalBlock()) {
				countOccurances.put(bb.getCondition().getOperant1(), countOccurances.getOrDefault(bb.getCondition().getOperant1(), 0)+1);
				if(bb.getCondition().getOperant2() != bb.getCondition().getOperant1())
					countOccurances.put(bb.getCondition().getOperant2(), countOccurances.getOrDefault(bb.getCondition().getOperant2(), 0)+1);
			}
			

			
			if(bb.getReturnValue() != null)
				countOccurances.put(bb.getReturnValue(), countOccurances.getOrDefault(bb.getReturnValue(), 0)+1);
			
			amountBlocks.put(bb, countOccurances.size());
			
			slots = new HashMap<Integer, Node>();
			
			for (Node node : bb.getNodes()) {
				numberNodes(node);
			}
			
			//System.out.println(slots);

			if (slots.size() > maxNodeID)
				maxNodeID = slots.size();
			
			if(bb.isConditionalBlock()) {
				iterateBlocks(bb.getConditionalBranch());
			}
			
			if(bb.isSwitchCase()) {
				for(BasicBlock c:bb.getSwitchBlocks())
					iterateBlocks(c);
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
		
		if(block.isConditionalBlock()) {
			generateBlockRecursive(compiledBlocks, processedBlocks, block.getConditionalBranch());
		}
		
		if(block.isSwitchCase()) {
			for(BasicBlock c:block.getSwitchBlocks())
				generateBlockRecursive(compiledBlocks, processedBlocks, c);
		}

		if (!block.isExitBlock())
			generateBlockRecursive(compiledBlocks, processedBlocks, block.getUnconditionalBranch());

	}
	
	protected int getAppendedDataOffset(Object o) {
		return dataOffsetMap.get(o);
	}
	
	protected  int getProgramSize() {
		return programSize;
	}
	
	protected abstract int countProgramSize();
	
	protected int[] getAppendedData() {
		return appenedDataOuput;
	}
	
	protected int[] processAppendedData() {
		int size = 0;
		
		Object[] data = function.getData();
		
		// initial alignment
		if(getProgramSize()%4 != 0)
			size += 4-(getProgramSize()%4);
		
		for(int i=0;i<data.length;i++) {
			
			if(dataOffsetMap.containsKey(data[i])) // this should never occur
				throw new RuntimeException(data[i]+" is registered more than once");
			
			dataOffsetMap.put(data[i], size);
			if(data[i] instanceof boolean[])
				size += ((boolean[])data[i]).length;
			else if(data[i] instanceof byte[])
				size += ((byte[])data[i]).length;
			else if(data[i] instanceof short[])
				size += ((short[])data[i]).length*2;
			else if(data[i] instanceof char[])
				size += ((char[])data[i]).length*2;
			else if(data[i] instanceof int[])
				size += ((int[])data[i]).length*4;
			else
				throw new RuntimeException("Unexpected Data of type "+data[i].getClass());
			
			// align by 4 bytes
			if(size%4 != 0)
				size += 4-(size%4);
		}
		
		// padding at the end
		if(getNodeSize() != 0 && size%getNodeSize() != 0)
			size += getNodeSize()-(size%getNodeSize());
		
		
		int[] dataOuput = new int[size];
		
		// Note that this way be overwritten for endian reasons
		int currentPos = 0;
		
		// initial alignment
		if(getProgramSize()%4 != 0)
			currentPos += 4-(getProgramSize()%4);
		
		for(int i=0;i<data.length;i++) {
			if(data[i] instanceof boolean[]) {
				boolean[] a = (boolean[])data[i];
				for(int j=0;j<a.length;j++) {
					dataOuput[currentPos++] = a[j]?1:0;
				}
			}else if(data[i] instanceof byte[]) {
				byte[] a = (byte[])data[i];
				for(int j=0;j<a.length;j++) {
					dataOuput[currentPos++] = a[j]&0xFF;
				}
			}else if(data[i] instanceof short[]) {
				short[] a = (short[])data[i];
				for(int j=0;j<a.length;j++) {
					dataOuput[currentPos++] = a[j]&0xFF;
					dataOuput[currentPos++] = (a[j]>>8)&0xFF;
				}
			}
			else if(data[i] instanceof char[]) {
				char[] a = (char[])data[i];
				for(int j=0;j<a.length;j++) {
					dataOuput[currentPos++] = a[j]&0xFF;
					dataOuput[currentPos++] = (a[j]>>8)&0xFF;
				}
			}else if(data[i] instanceof int[]) {
				int[] a = (int[])data[i];
				for(int j=0;j<a.length;j++) {
					dataOuput[currentPos++] = a[j]&0xFF;
					dataOuput[currentPos++] = (a[j]>>8)&0xFF;
					dataOuput[currentPos++] = (a[j]>>16)&0xFF;
					dataOuput[currentPos++] = (a[j]>>24)&0xFF;
				}
			}else
				throw new RuntimeException("Unexpected Data of type "+data[i].getClass());
			
			
			if(currentPos%4 != 0)
				currentPos += 4-(currentPos%4);
		}
		
		return dataOuput;
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
		
		programSize = countProgramSize();
		appenedDataOuput = processAppendedData();
		
		// The output list of compiled basic blocks
		ArrayList<CompiledBasicBlock> blocks = new ArrayList<CompiledBasicBlock>();
		
		// Compile the basic blocks starting from the first recursively
		//generateBlockRecursive(blocks, new ArrayList<BasicBlock>(), f.get(0));
		
		// Iterative means we can decide the order
		for(BasicBlock bb:f) {
			blocks.add(generateBlock(bb));
		}
		
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
	
	/**
	 * Return a map of supported arguments
	 * @return a map of argument names and their associated types
	 */
	public Map<String, Class<?>> supportedArguments() {
		return new HashMap<String, Class<?>>();
	}
	
	/**
	 * Return a map of supported arguments and their description
	 * @return a map of argument names and their help dialog
	 */
	public Map<String, String> supportedArgumentsHelp() {
		return new HashMap<String, String>();
	}
	
	/**
	 * Return a description of the behavior of this object
	 * @return return a description for the help dialog
	 */
	public abstract String description();
}
