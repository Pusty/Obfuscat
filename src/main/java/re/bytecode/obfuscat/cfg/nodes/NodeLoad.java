package re.bytecode.obfuscat.cfg.nodes;

import re.bytecode.obfuscat.cfg.MemorySize;

/**
 * A Variable Load Operation
 */
public class NodeLoad extends Node {
	
	private static final long serialVersionUID = 9223303537708755992L;
	private MemorySize loadSize;
	private int slot;
	
	/**
	 * Load a variable with loadSize from slot
	 * @param loadSize the size of the variable to load
	 * @param slot the slot to load from
	 */
	public NodeLoad(MemorySize loadSize, int slot) {
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
	 * The load size from this variable
	 * @return the size of data to load from this variable
	 */
	public MemorySize getLoadSize() {
		return loadSize;
	}
	
	@Override
	public String toString() {
		return "Load"+loadSize+"("+slot+")";
	}
	
	@Override
	protected boolean checkCriteria(Node o) { 
		return (((NodeLoad)o).loadSize == this.loadSize || ((NodeLoad)o).loadSize == MemorySize.ANY || this.loadSize == MemorySize.ANY) && (((NodeLoad)o).slot == this.slot  || ((NodeLoad)o).slot == -1 || this.slot == -1);
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
	
	@Override
	public String getNodeIdentifier() { return "load"; }
}
