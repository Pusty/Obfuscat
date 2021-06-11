package re.bytecode.obfuscat.cfg;

import java.io.Serializable;

import re.bytecode.obfuscat.cfg.nodes.Node;

/**
 * A Condition for Branching.
 */
public class BranchCondition implements Serializable {
	
	
	private static final long serialVersionUID = 2958687028811699705L;

	private BasicBlock owner;
	
	private Node op1;
	private Node op2;
	
	private CompareOperation operation;
	
	/**
	 * Create a branching condition based on the two things to compare and the operation to apply.
	 * The owner block is required to verify that the operands really appear in the basic block (this may change later).
	 * @param owner the owner basic block of this conditional branch
	 * @param a the first operand of this comparison
	 * @param b the second operand of this comparison
	 * @param op the compare operation
	 */
	public BranchCondition(BasicBlock owner, Node a, Node b, CompareOperation op) {
		
		if(op.getOperandCount() != 2) throw new IllegalArgumentException("Math Operation must have 2 Operands");
		this.owner = owner;
		this.op1 = a;
		this.op2 = b;
		this.operation = op;
		
		// this may be moved to BasicBlock later
		if(!check()) throw new IllegalArgumentException("Operant 1 or 2 didn't appear in the Basic Block");
	}
	
	/**
	 * Return the first operand of this comparison
	 * @return the operand A
	 */
	public Node getOperant1() { return op1; }
	
	
	/**
	 * Return the second operand of this comparison
	 * @return the operand B
	 */
	public Node getOperant2() { return op2; }
	
	
	/**
	 * Replace a reference to a search node with the replace node. Also recursively traverse the nodes for references for the search needle.
	 * @param search the needle to search and replace
	 * @param replace the replacement node
	 * @return this object but updated
	 */
	public BranchCondition replace(Node search, Node replace) {
		this.op1 = op1.equals(search) ? replace : op1.replace(search, replace);
		this.op2 = op2.equals(search) ? replace : op2.replace(search, replace);
		return this;
	}

	/**
	 * Verify that the nodes used in this comparison appear in the basic block (may be moved into BasicBlock later)
	 * @return whether both nodes appear in the owner block
	 */
	public boolean check() {
		return owner.getNodes().contains(op1) && owner.getNodes().contains(op2);
	}
	
	/**
	 * The compare operation to apply to the operands.
	 * @return the comparison to do
	 */
	public CompareOperation getOperation() {
		return this.operation;
	}
	
	@Override
	public String toString() {
		switch(operation) {
			case EQUAL:
				return op1+" == "+op2;
			case NOTEQUAL:
				return op1+" != "+op2;
			case GREATERTHAN:
				return op1+" > "+op2;
			case GREATEREQUAL:
				return op1+" >= "+op2;
			case LESSTHAN:
				return op1+" < "+op2;
			case LESSEQUAL:
				return op1+" <= "+op2;
			default:
				throw new RuntimeException("Not implemented");
		}
	}
	
}
