package re.bytecode.obfuscat.cfg;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import re.bytecode.obfuscat.cfg.nodes.Node;

/**
 * A BasicBlock is a sequence of instructions (Nodes) that end at conditional or unconditional control flow changes (jmp, jcc, ret)
 */
public class BasicBlock implements Serializable {

	private static final long serialVersionUID = 4567636696750578172L;

	private BranchCondition conditionalJumpCondition; // if(condition)
	private BasicBlock      conditionalJumpBlock; // if(condition) { # code }
	
	private Node switchNode; // switch case node
	private List<BasicBlock> switchBlocks; // switch case branching
	
	private BasicBlock unconditional; // default branch, null = exitBlock
	
	private List<Node> nodes; // instructions in basic block
	
	private Node returnValue;
	
	/**
	 * Create a BasicBlock
	 */
	public BasicBlock() {
		nodes = new ArrayList<Node>();
		conditionalJumpCondition = null;
		conditionalJumpBlock = null;
		switchNode = null;
		switchBlocks = null;
		unconditional = null;
		returnValue = null;
	}
	
	/**
	 * Does this block have an unconditional following block?
	 * @return whether this block returns out of the function it is in
	 */
	public boolean isExitBlock() { return unconditional == null; }
	
	/**
	 * If this is an exit block return the return value node
	 * @return return the node which values is returned from this function, may be null
	 */
	public Node getReturnValue() {
		if(unconditional != null) return null;
		return returnValue;
	}
	
	/**
	 * Return the unconditional following block (jmp) if there is one
	 * @return the block unconditionally executed after this one, may be null
	 */
	public BasicBlock getUnconditionalBranch() { return unconditional; }
	
	/**
	 * Set the unconditional/default following block 
	 * @param b the block that is following after this one if no conditional branch is taken, may not be null
	 */
	public void setUnconditionalBranch(BasicBlock b) {
		if(b == null) throw new IllegalArgumentException("Unconditional Branch may not be null");
		unconditional = b;
		returnValue = null;
	}
	
	/**
	 * Set this block to be returning out of function block and also provide the return value node
	 * @param returnValue the node which values will be returned, may be null but must be in this basic block already
	 */
	public void setExitBlock(Node returnValue) { 
		unconditional = null; 
		if(returnValue != null && findNodes(returnValue).size() == 0)
			throw new IllegalArgumentException("Return Value is not in Basic Block");
		if(this.isConditionalBlock() || this.isSwitchCase())
			throw new IllegalArgumentException("Neither conditional nor switch blocks may be exit blocks");
		this.returnValue = returnValue;
	}
	
	/**
	 * Return the blocks this basic block can branch to if it is a switch block, null otherwise
	 * @return the switch cases
	 */
	public List<BasicBlock> getSwitchBlocks() { return switchBlocks; }
	
	/**
	 * Return the node that decides which switch case to take, null if not a switch case
	 * @return the node that decides the next block
	 */
	public Node getSwitchNode() { return switchNode; }
	
	/**
	 * Set the switch cases and node which decides the next block
	 * @param bbs the list of possible switch cases
	 * @param sN the node that controls which block to execute next
	 */
	public void setSwitchBlock(List<BasicBlock> bbs, Node sN) {
		if(bbs == null) throw new IllegalArgumentException("Switch Blocks may not be null");
		if(!getNodes().contains(sN)) throw new IllegalArgumentException("Switch Node must be in the basic block");
		if(this.conditionalJumpBlock != null) throw new IllegalArgumentException("Block with conditional jump may not have switch cases");
		if(this.returnValue != null) throw new IllegalArgumentException("Switch block may not return a value directly");
		if(this.unconditional != null) throw new IllegalArgumentException("Switch block may have an unconditional branch");
		switchBlocks = bbs;
		switchNode = sN;
	}

	/**
	 * Return whether this basic block is a switch
	 * @return whether this block is a switch 
	 */
	public boolean isSwitchCase() {
		return switchNode != null;
	}
	
	/**
	 * Return the basic block this block conditionally branches to, null if not a conditional block
	 * @return the next basic block if the branch condition is true
	 */
	public BasicBlock getConditionalBranch() { return conditionalJumpBlock; }
	
	/**
	 * Return the condition this block branches to the conditional branch, null if not a conditional block
	 * @return the condition of branching
	 */
	public BranchCondition getCondition() { return conditionalJumpCondition; }
	
	/**
	 * Change this block to an unconditional block
	 */
	public void unsetConditionalBranch() {
		if(!isConditionalBlock()) throw new IllegalArgumentException("Can't unset a block that isn't a Conditional Block");
		conditionalJumpBlock = null;
		conditionalJumpCondition = null;
	}
	
	/**
	 * Change this block to be a conditional block with a conditional branch and appropiate condition
	 * @param b the new conditional basic block
	 * @param bc the condition of branching to the new basic block
	 */
	public void setConditionalBranch(BasicBlock b, BranchCondition bc) {
		if(b == null) throw new IllegalArgumentException("Conditional Block may not be null");
		if(bc == null) throw new IllegalArgumentException("Conditio may not be null");
		if(switchBlocks != null && switchBlocks.size() > 0) throw new IllegalArgumentException("Block with conditional jump may not have switch cases");
		//if(isExitBlock()) throw new IllegalArgumentException("Conditional Block can not be exit block"); // TODO: Verify somewhere else
		conditionalJumpBlock = b;
		conditionalJumpCondition = bc;
	}
	
	/**
	 * Return whether this basic block ends with a conditional branch
	 * @return whether this basic block is conditional
	 */
	public boolean isConditionalBlock() {
		return conditionalJumpBlock != null;
	}
	
	
	/**
	 * Return the internally used sequential list of instructions / nodes
	 * @return the sequentially used instructions of this block
	 */
	public List<Node> getNodes() { return nodes; }
	
	// internal recursive search for node function
	private void searchNode(Node node, Node template, List<Node> nodeL) {
		
		// if this node fits the template and isn't in the return array, add it
		if(node.equalsSemantics(template) && !nodeL.contains(node))
			nodeL.add(node);
		
		// iterate all children if they exist for the node to replace
		Node[] children = node.children();
		if(children == null) return;
		
		for(Node n:children)
			searchNode(n, template, nodeL);
		
		
	}
	
	/**
	 * Find all nodes in this block matching a template/dummy node 
	 * @param template the template node which may contain null values as wildcards
	 * @return an array containing all unique found nodes
	 */
	public List<Node> findNodes(Node template) {
		
		template.dumify(); // make a template out of the node
		
		List<Node> nodeL = new ArrayList<Node>();
		for(Node node:nodes) {
			searchNode(node, template, nodeL); // search all nodes in this block
		}
		
		return nodeL; // return the array
	}
	
	/**
	 * Replace all occurrences of the node with the new node
	 * @param node
	 * @param newNode
	 */
	public void replace(Node node, Node newNode) {
		
		List<Node> newNodeList = new ArrayList<Node>();
		
		// replace all occurrences of the node in all other nodes
		for(Node n:nodes) {
			newNodeList.add(n.equals(node)?newNode:n.replace(node, newNode));
		}

		// commit the changes to all instructions
		this.nodes.clear();
		this.nodes.addAll(newNodeList);


		if(this.conditionalJumpCondition != null)
			conditionalJumpCondition = conditionalJumpCondition.replace(node, newNode);
		
		if(this.switchNode != null)
			switchNode = switchNode.equals(node)?newNode:switchNode.replace(node, newNode);
		
		if(returnValue != null)
			returnValue = returnValue.equals(node)?newNode:returnValue.replace(node, newNode);
		
	}
	
	
	// when removing a node, check() should be called on all BranchConditions
	
	/**
	 * The name of this basic block for identification
	 * @return an identifier made out of the hashcode
	 */
	public String getName() { return "BB"+this.hashCode(); }
	
	
	@Override
	public String toString() {
		
		// start with the name and opening brackets
		StringBuilder block = new StringBuilder(getName());
		block.append(":[");
		
		// append the nodes
		for(Node n:getNodes()) {
			block.append(n.toString());
			block.append(", ");
		}
		
		// cut out the last comma
		if(getNodes().size() > 0)
			block.setLength(block.length()-2);
		
		// close block brackets
		block.append("]");
		
		// append conditional branching text
		if(isConditionalBlock()) {
			block.append(" if(");
			block.append(conditionalJumpCondition.toString());
			block.append(") -> ");
			block.append(conditionalJumpBlock.getName());
			block.append(" ");
		}
		
		if(this.isSwitchCase()) {
		
			block.append(" [ ");
			block.append(this.getSwitchNode().toString());
			block.append(" ] ");
			
			for(BasicBlock sc:getSwitchBlocks()) {
				block.append(" => ");
				block.append(sc.getName());
				block.append(" ");
			}
			
			// remove the last space
			if(getSwitchBlocks().size() > 0)
				block.setLength(block.length()-1);
		
		}
		
		
		if(isExitBlock()) {
			// if this is an exit block append the return value if existent
			if(this.returnValue != null) {
				block.append(" => exit(");
				block.append(this.returnValue.toString());
				block.append(")");
			} else
				block.append(" => exit()");
		}else {
			// otherwise append the unconditional jump location
			block.append(" => ");
			block.append(getUnconditionalBranch().getName());
		}
		
		return block.toString();
	}
	
	/*
	@Override
	public BasicBlock clone() {
		BasicBlock cloned = new BasicBlock();

		// compressing the graph before would make sense
		
		outer: for(Node node:this.getNodes()) {
			if(getReturnValue() != null && getReturnValue().equalsSemantics(node)) continue;
			for(Entry<BranchCondition, BasicBlock> e:getSwitchBlocks().entrySet()) {
				if(e.getKey().getOperant1().equalsSemantics(node)) continue outer;
				if(e.getKey().getOperant2().equalsSemantics(node)) continue outer;
			}
			cloned.getNodes().add(node.clone());
		}
		
		
		Node returnValue = getReturnValue();
		if(returnValue != null) {
			returnValue = returnValue.clone();
			cloned.getNodes().add(returnValue);
			cloned.setExitBlock(returnValue);
		}else if(this.isExitBlock())
			cloned.setExitBlock(null);
		
		for(Entry<BranchCondition, BasicBlock> e:getSwitchBlocks().entrySet()) {
			Node op1 = e.getKey().getOperant1().clone();
			Node op2 = e.getKey().getOperant2().clone();
			cloned.getSwitchBlocks().put(new BranchCondition(cloned, op1, op2, e.getKey().getOperation()), e.getValue());
		}
		
		return cloned;
	}
	*/
}
