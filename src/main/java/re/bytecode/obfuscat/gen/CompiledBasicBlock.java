package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.List;

import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.nodes.Node;

/**
 * This Class acts as a container and processing class for the code compilation
 */
public class CompiledBasicBlock {
	
	private BasicBlock block;
	private List<Object> generated;
	private List<Node> nodes;
	
	/**
	 * Create a CompiledBasicBlock for a fixed BasicBlock
	 * @param bb the BasicBlock this CompiledBasicBlock belongs to
	 */
	public CompiledBasicBlock(BasicBlock bb) {
		this.block = bb;
		generated = new ArrayList<Object>();
		nodes = new ArrayList<Node>();
	}
	
	/**
	 * Return the associated basic block
	 * @return the basic block this compiled version associates with
	 */
	public BasicBlock getBlock() {
		return block;
	}
	
	/**
	 * Return the list of generated pieces of whatever type
	 * @return the list of generated pieces for the associated basic block
	 */
	public List<Object> getGenerated() {
		return generated;
	}
	
	/**
	 * Return the list of already processed nodes of this compiled version of the assoicated basic block
	 * @return the list of processed nodes
	 */
	public List<Node> getNodes() {
		return nodes;
	}
}