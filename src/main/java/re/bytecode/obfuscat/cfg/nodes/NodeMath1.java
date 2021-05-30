package re.bytecode.obfuscat.cfg.nodes;

import re.bytecode.obfuscat.cfg.MathOperation;

/**
 * A One Operand Math Operation
 */
public class NodeMath1 extends Node {
	
	private Node op1;
	private MathOperation type;
	
	/**
	 * Create a one operand math operation
	 * @param op1 the one operand to be used in this operation
	 * @param type the operation to be applied
	 */
	public NodeMath1(Node op1, MathOperation type) {
		
		if(type.getOperandCount() != 1) throw new IllegalArgumentException("Math Operation must have 1 Operands");
		this.op1 = op1;
		this.type = type;
		
	}
	
	/**
	 * Return the operation
	 * @return the math operation of this node
	 */
	public MathOperation getOperation() {
		return this.type;
	}
	
	@Override
	public String toString() {
		switch(type) {
			case NOT:
				return "{ !("+op1+") }";
			case NEG:
				return "{ ~("+op1+") }";
			case NOP:
				return "{ "+op1+" }";
			default:
				throw new RuntimeException("Not implemented");
		}
	}
	
	@Override
	public void dumify() {
		
		if (this.op1 == null)
			this.op1 = new NodeDummy();
		else
			this.op1.dumify();

	}
	
	@Override
	public Node replace(Node search, Node replace) {
		this.op1 = op1.equals(search) ? replace : op1.replace(search, replace);
		return this;
	}
	
	@Override
	protected boolean checkCriteria(Node o) { return ((NodeMath1)o).type == this.type || this.type == MathOperation.ANY || ((NodeMath1)o).type == MathOperation.ANY; }
	
	@Override
	public Node[] children() { return new Node[] {op1}; }
	
	@Override
	public Node clone() {
		return new NodeMath1(op1.clone(), type);
	}
}
