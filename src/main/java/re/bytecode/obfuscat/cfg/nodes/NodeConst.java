package re.bytecode.obfuscat.cfg.nodes;

/**
 * A Constant Object Operation
 */
public class NodeConst extends Node {
	
	private Object constObj;
	
	/**
	 * Create a constant object operation
	 * @param constObj the constant object of this operation
	 */
	public NodeConst(Object constObj) {
		this.constObj = constObj;
	}
	
	public String toString() {
		return "Const("+constObj+")";
	}
	
	/**
	 * The constant object of this operation
	 * @return the object this operation creates
	 */
	public Object getObj() {
		return constObj;
	}
	
	@Override
	protected boolean checkCriteria(Node o) { return this.constObj == null || ((NodeConst)o).constObj == null ||  constObj.equals(((NodeConst)o).constObj); }

	@Override
	public Node replace(Node search, Node replace) {
		return this;
	}
	
	@Override
	public Node[] children() { return null; }

	@Override
	public void dumify() {
	}
	
	@Override
	public Node clone() {
		return new NodeConst(constObj);
	}
}
