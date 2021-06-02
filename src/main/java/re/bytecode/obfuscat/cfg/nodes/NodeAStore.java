package re.bytecode.obfuscat.cfg.nodes;

/**
 * An Array Store Operation
 */
public class NodeAStore extends Node {

	private Node array;
	private Node index;
	private Node value;
	private int storeSize;

	/**
	 * Create an array store operation based on an array, an index and the size to store into.
	 * @param array the array to store to
	 * @param index the index to reference in the array
	 * @param storeSize the size of data stored to the array
	 */
	public NodeAStore(Node array, Node index, Node value, int storeSize) {
		this.array = array;
		this.index = index;
		this.value = value;
		this.storeSize = storeSize;
	}

	/**
	 * The store size to this array (1 = byte, 2 = short/char, 4 = int/array)
	 * @return the size of data to store in this array
	 */
	public int getStoreSize() {
		return storeSize;
	}

	public String toString() {
		return "{ AStore(" + array + ", " + index + ") = " + value + " }";
	}

	@Override
	protected boolean checkCriteria(Node o) {
		return ((NodeAStore) o).storeSize == this.storeSize || this.storeSize == -1 || ((NodeAStore) o).storeSize == -1;
	}

	@Override
	public void dumify() {

		if (this.array == null)
			this.array = new NodeDummy();
		else
			this.array.dumify();

		if (this.index == null)
			this.index = new NodeDummy();
		else
			this.index.dumify();

		if (this.value == null)
			this.value = new NodeDummy();
		else
			this.value.dumify();

	}
	
	@Override
	public Node replace(Node search, Node replace) {
		this.array = array.equals(search) ? replace : array.replace(search, replace);
		this.index = index.equals(search) ? replace : index.replace(search, replace);
		this.value = value.equals(search) ? replace : value.replace(search, replace);
		return this;
	}

	@Override
	public Node[] children() {
		return new Node[] { array, index, value };
	}

	@Override
	public Node clone() {
		return new NodeAStore(array.clone(), index.clone(), value.clone(), storeSize);
	}
	
	@Override
	public String getNodeIdentifier() { return "astore"; }
}
