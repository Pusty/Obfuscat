package re.bytecode.obfuscat.cfg;

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
