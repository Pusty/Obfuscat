package re.bytecode.obfuscat.cfg.nodes;

import re.bytecode.obfuscat.cfg.MemorySize;

/**
 * An Memory Allocation Operation
 */
public class NodeAlloc extends Node {
	
	private static final long serialVersionUID = 8217228684790022798L;
	private Node amount;
	private MemorySize allocSize;

	/**
	 * Create a memory allocation operation with a fixed entry size and a variable amount of entries
	 * @param allocSize the size of each entry in the return array
	 * @param amount the amount of entries
	 */
	public NodeAlloc(MemorySize allocSize, Node amount) {
		this.allocSize = allocSize;
		this.amount = amount;
	}

	public MemorySize getAllocationSize() {
		return allocSize;
	}

	@Override
	public String toString() {
		return "Alloc"+allocSize+"(" + amount + ")";
	}

	@Override
	protected boolean checkCriteria(Node o) {
		return ((NodeAlloc) o).allocSize == this.allocSize || this.allocSize == MemorySize.ANY || ((NodeAlloc) o).allocSize == MemorySize.ANY;
	}

	@Override
	public void dumify() {

		if (this.amount == null)
			this.amount = new NodeDummy();
		else
			this.amount.dumify();

	}

	@Override
	public Node[] children() {
		return new Node[] { amount };
	}

	@Override
	public Node replace(Node search, Node replace) {
		this.amount = amount.equals(search) ? replace : amount.replace(search, replace);
		return this;
	}

	@Override
	public Node clone() {
		return new NodeAlloc(allocSize, amount.clone());
	}
	
	@Override
	public String getNodeIdentifier() { return "allocate"; }
}
