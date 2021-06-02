package re.bytecode.obfuscat.cfg.nodes;

import re.bytecode.obfuscat.cfg.MathOperation;

/**
 * A Math Operation
 */
public class NodeMath extends Node {
	
	private Node[] operands;
	private MathOperation type;
	
	/**
	 * Create a math operation
	 * @param type the operation
	 * @param operands the operands of this math operation
	 */
	public NodeMath(MathOperation type, Node... operands) {
		
		if(type.getOperandCount() != operands.length) throw new IllegalArgumentException("Math Operation "+type+" must have "+type.getOperandCount()+" Operands");
		
		this.operands = operands;
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
				return "{ "+operands[0]+" + "+operands[1]+" }";
			case SUB:
				return "{ "+operands[0]+" - "+operands[1]+" }";
			case MUL:
				return "{ "+operands[0]+" * "+operands[1]+" }";
			case MOD:
				return "{ "+operands[0]+" % "+operands[1]+" }";
			case DIV:
				return "{ "+operands[0]+" / "+operands[1]+" }";
			case AND:
				return "{ "+operands[0]+" & "+operands[1]+" }";
			case OR:
				return "{ "+operands[0]+" | "+operands[1]+" }";
			case XOR:
				return "{ "+operands[0]+" ^ "+operands[1]+" }";
			case SHR:
				return "{ "+operands[0]+" >> "+operands[1]+" }";
			case USHR:
				return "{ "+operands[0]+" >>> "+operands[1]+" }";
			case SHL:
				return "{ "+operands[0]+" << "+operands[1]+" }";
			case NOT:
				return "{ !("+operands[0]+") }";
			case NEG:
				return "{ ~("+operands[0]+") }";
			case NOP:
				return "{ "+operands[0]+" }";
			default:
				throw new RuntimeException("Not implemented");
		}
	}
	

	@Override
	public void dumify() {
		
		for(int i=0;i<type.getOperandCount();i++)
			if(operands[i] == null)
				operands[i] = new NodeDummy();
	}
	
	@Override
	public Node replace(Node search, Node replace) {
		for(int i=0;i<type.getOperandCount();i++)
			operands[i] =  operands[i].equals(search) ? replace : operands[i].replace(search, replace);
		return this;
	}
	
	@Override
	protected boolean checkCriteria(Node o) { return ((NodeMath)o).type == this.type || this.type == MathOperation.ANY || ((NodeMath)o).type == MathOperation.ANY; }
	
	@Override
	public Node[] children() { return operands; }
	
	@Override
	public Node clone() {
		return new NodeMath(type, operands.clone());
	}
	
	@Override
	public String getNodeIdentifier() { return "math"; }
}
