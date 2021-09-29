package re.bytecode.obfuscat.cfg;

import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;

/**
 * An enumeration filled with possible mathematical operations
 */
public enum MathOperation {
	
	/** A + B **/
	ADD(2),
	/** A - B **/
	SUB(2),
	/** A * B **/
	MUL(2),
	/** A / B **/
	DIV(2),
	/** A % B **/
	MOD(2),
	/** A & B **/
	AND(2),
	/** A | B **/
	OR(2),
	/** A ^ B **/
	XOR(2),
	/** A << B **/
	SHL(2),
	/** A >> B **/
	SHR(2),
	/** A >>> B **/
	USHR(2),
	/** -A **/
	NEG(1),
	/** ~A **/
	NOT(1),
	/** NOP **/
	NOP(1),
	/** DUMMY **/
	ANY(0);
	

	// Short forms to create operators
	public static NodeMath add(Node a, Node b) { return new NodeMath(ADD, a, b); }
	public static NodeMath sub(Node a, Node b) { return new NodeMath(SUB, a, b); }
	public static NodeMath mul(Node a, Node b) { return new NodeMath(MUL, a, b); }
	public static NodeMath mod(Node a, Node b) { return new NodeMath(MOD, a, b); }
	public static NodeMath div(Node a, Node b) { return new NodeMath(DIV, a, b); }
	public static NodeMath and(Node a, Node b) { return new NodeMath(AND, a, b); }
	public static NodeMath or(Node a, Node b) { return new NodeMath(OR, a, b); }
	public static NodeMath xor(Node a, Node b) { return new NodeMath(XOR, a, b); }
	public static NodeMath shr(Node a, Node b) { return new NodeMath(SHR, a, b); }
	public static NodeMath ushr(Node a, Node b) { return new NodeMath(USHR, a, b); }
	public static NodeMath shl(Node a, Node b) { return new NodeMath(SHL, a, b); }
	public static NodeMath not(Node a) { return new NodeMath(NOT, a); }
	public static NodeMath neg(Node a) { return new NodeMath(NEG, a); }
	public static NodeMath nop(Node a) { return new NodeMath(NOP, a); }
	public static NodeConst cst(Object o) { return new NodeConst(o); }
	
	private int operands;
	
	private MathOperation(int operands) {
		this.operands = operands;
	}
	
	/**
	 * The amount of operands of the compare operation
	 * @return the amount of operands
	 */
	public int getOperandCount() {
		return operands;
	}
}
