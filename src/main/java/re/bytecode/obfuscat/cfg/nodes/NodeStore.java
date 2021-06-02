package re.bytecode.obfuscat.cfg.nodes;

/**
 * A Variable Store Operation
 */
public class NodeStore extends Node {
	
	private int storeSize;
	private int slot;
	private Node value;
	
	/**
	 * Create a variable store operation of storing value to slot with size storeSize
	 * @param storeSize the size of the value to store
	 * @param slot the variable slot to store to
	 * @param value the node to store
	 */
	public NodeStore(int storeSize, int slot, Node value) {
		this.storeSize = storeSize;
		this.slot = slot;
		this.value = value;
	}
	
	/**
	 * Return the variable slot to store to
	 * @return the variable slot
	 */
	public int getSlot() {
		return slot;
	}
	
	/**
	 * The store size from this array (1 = byte, 2 = short/char, 4 = int/array)
	 * @return the size of data to store in this array
	 */
	public int getStoreSize() {
		return storeSize;
	}
	
	@Override
	public String toString() {
		return "{ Store"+(8*storeSize)+"("+slot+") = "+value+" }";
	}
	
	@Override
	public void dumify() {
		
		if (this.value == null)
			this.value = new NodeDummy();
		else
			this.value.dumify();

	}
	
	@Override
	public Node replace(Node search, Node replace) {
		this.value = value.equals(search) ? replace : value.replace(search, replace);
		return this;
	}
	
	@Override
	protected boolean checkCriteria(Node o) { 
		return (((NodeStore)o).storeSize == this.storeSize || ((NodeStore)o).storeSize == -1 || this.storeSize == -1) && (((NodeStore)o).slot == this.slot  || ((NodeStore)o).slot == -1 || this.slot == -1);
	}
	
	@Override
	public Node[] children() { return new Node[] {value}; }
	
	@Override
	public Node clone() {
		return new NodeStore(storeSize, slot, value.clone());
	}
	
	@Override
	public String getNodeIdentifier() { return "store"; }
}
