package re.bytecode.obfuscat.cfg;

/**
 * An enumeration filled with possible comparison operations
 */
public enum CompareOperation {
	
	/** A == B **/
	EQUAL(2),
	/** A != B **/
	NOTEQUAL(2),
	/** A < B **/
	LESSTHAN(2),
	/** A <= B **/
	LESSEQUAL(2),
	/** A > B **/
	GREATERTHAN(2),
	/** A >= B **/
	GREATEREQUAL(2);
	
	private int operands;
	
	private CompareOperation(int operands) {
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
