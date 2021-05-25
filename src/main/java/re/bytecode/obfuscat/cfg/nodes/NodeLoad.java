package re.bytecode.obfuscat.cfg.nodes;

/**
 * A Variable Load Operation
 */
public class NodeLoad extends Node {
	
	private int loadSize;
	private int slot;
	
	/**
	 * Load a variable with loadSize from slot
	 * @param loadSize the size of the variable to load
	 * @param slot the slot to load from
	 */
	public NodeLoad(int loadSize, int slot) {
		this.loadSize = loadSize;
		this.slot = slot;
	}
	
	/**
	 * Return the variable slot to load from
	 * @return the variable slot
	 */
	public int getSlot() {
		return slot;
	}
	
	/**
	 * The load size from this variable (1 = byte, 2 = short/char, 4 = int/array)
	 * @return the size of data to load from this variable
	 */
	public int getLoadSize() {
		return loadSize;
	}
	
	@Override
	public String toString() {
		return "Load"+(8*loadSize)+"("+slot+")";
	}
	
	@Override
	protected boolean checkCriteria(Node o) { 
		return (((NodeLoad)o).loadSize == this.loadSize || ((NodeLoad)o).loadSize == -1 || this.loadSize == -1) && (((NodeLoad)o).slot == this.slot  || ((NodeLoad)o).slot == -1 || this.slot == -1);
	}

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
		return new NodeLoad(loadSize, slot);
	}
}
