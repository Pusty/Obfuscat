package re.bytecode.obfuscat.cfg.nodes;

import re.bytecode.obfuscat.cfg.MathOperation;

/**
 * A Two Operand Math Operation
 */
public class NodeMath2 extends Node {
	
	private Node op1;
	private Node op2;
	private MathOperation type;
	
	/**
	 * Create a two operand math operation
	 * @param op1 the first operand
	 * @param op2 the second operand
	 * @param type the operation
	 */
	public NodeMath2(Node op1, Node op2, MathOperation type) {
		
		if(type.getOperandCount() != 2) throw new IllegalArgumentException("Math Operation must have 2 Operands");
		
		this.op1 = op1;
		this.op2 = op2;
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
			case ADD:
				return "{ "+op1+" + "+op2+" }";
			case SUB:
				return "{ "+op1+" - "+op2+" }";
			case MUL:
				return "{ "+op1+" * "+op2+" }";
			case MOD:
				return "{ "+op1+" % "+op2+" }";
			case DIV:
				return "{ "+op1+" / "+op2+" }";
			case AND:
				return "{ "+op1+" & "+op2+" }";
			case OR:
				return "{ "+op1+" | "+op2+" }";
			case XOR:
				return "{ "+op1+" ^ "+op2+" }";
			case SHR:
				return "{ "+op1+" >> "+op2+" }";
			case USHR:
				return "{ "+op1+" >>> "+op2+" }";
			case SHL:
				return "{ "+op1+" << "+op2+" }";
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
		
		if (this.op2 == null)
			this.op2 = new NodeDummy();
		else
			this.op2.dumify();

	}
	
	@Override
	public Node replace(Node search, Node replace) {
		this.op1 = op1.equals(search) ? replace : op1.replace(search, replace);
		this.op2 = op2.equals(search) ? replace : op2.replace(search, replace);
		return this;
	}
	
	@Override
	protected boolean checkCriteria(Node o) { return ((NodeMath2)o).type == this.type ; }
	
	@Override
	public Node[] children() { return new Node[] {op1, op2}; }
}
