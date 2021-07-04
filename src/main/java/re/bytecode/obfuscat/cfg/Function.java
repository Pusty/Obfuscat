package re.bytecode.obfuscat.cfg;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.cfg.nodes.Node;

/**
 * A function is a collection of basic blocks that may take input, have variables and return values
 */
public class Function implements Serializable {
	
	private static final long serialVersionUID = -1350502203263513629L;
	private String name;
	private List<BasicBlock> blocks;
	private Class<?>[] argumentTypes;
	private int variableSlots; // includes arguments, so: "void a(int a) { int i=a; return i; }" has 2 variableSlots
	private boolean returnsSomething;
	
	/**
	 * Create a function based on a name, the basic blocks, their parameters, the used variables and whether it returns something
	 * @param name the name of this function
	 * @param blocks a list of basic blocks
	 * @param argumentTypes the types of the parameters of this function
	 * @param variableSlots the variables used in this basic block (must include arguments in this number)
	 * @param returnsSomething if this function returns a value
	 */
	public Function(String name, List<BasicBlock> blocks, Class<?>[] argumentTypes, int variableSlots, boolean returnsSomething) {
		this.name = name;
		this.blocks = blocks;
		this.argumentTypes = argumentTypes;
		this.variableSlots = variableSlots;
		this.returnsSomething = returnsSomething;
	}
	
	/**
	 * Returns the name of this function
	 * @return the functions assigned name
	 */
	public String getName() { return name; }
	
	/**
	 * Return the list of basic blocks
	 * @return the internally used list of basic blocks of this function
	 */
	public List<BasicBlock> getBlocks() { return blocks; }
	
	/**
	 * Returns the types of the arguments
	 * @return an array of the types of the arguments
	 */
	public Class<?>[] getArguments() { return argumentTypes; }
	
	/**
	 * Returns the amount of used variables in this function (this includes the existing arguments)
	 * @return the amount of variables in this function
	 */
	public int getVariables() { return variableSlots; }
	public boolean hasReturnValue() { return returnsSomething; }

	
	private void traverseNode(List<Node> already, Node node, Map<String, Integer> map) {
		if(already.contains(node)) return;
		already.add(node);
		
		map.put(node.getNodeIdentifier(), map.getOrDefault(node.getNodeIdentifier(), 0)+1);
		
		Node[] children = node.children();
		if(children != null)
			for(int i=0;i<children.length;i++)
				traverseNode(already, children[i], map);
	}
	
	public Map<String, Integer> statistics() {
		Map<String, Integer> map = new HashMap<String, Integer>();
		
		map.put("blocks", blocks.size());
		
		int conditionalBlocks = 0;
		int switchBlocks = 0;
		int exitBlocks   = 0;
		int jumpBlocks   = 0;

		for(BasicBlock block:blocks) {
			List<Node> already = new ArrayList<Node>();
			for(Node node:block.getNodes()) {
				traverseNode(already, node, map);
			}
			if(block.isConditionalBlock())
				conditionalBlocks++;
			else if(block.isSwitchCase())
				switchBlocks++;
			else if(block.isExitBlock())
				exitBlocks++;
			else if(block.getUnconditionalBranch() != null)
				jumpBlocks++;
		}
		
		map.put("const", map.getOrDefault("const", 0));
		map.put("math", map.getOrDefault("math", 0));
		map.put("store", map.getOrDefault("store", 0));
		map.put("load", map.getOrDefault("load", 0));
		map.put("astore", map.getOrDefault("astore", 0));
		map.put("aload", map.getOrDefault("aload", 0));
		map.put("custom", map.getOrDefault("custom", 0));
		
		map.put("conditionalBlocks", conditionalBlocks);
		map.put("switchBlocks", switchBlocks);
		map.put("exitBlocks", exitBlocks);
		map.put("jumpBlocks", jumpBlocks);
		
		return map;
	}
	
}
