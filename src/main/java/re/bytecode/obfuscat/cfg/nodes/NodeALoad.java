package re.bytecode.obfuscat.cfg.nodes;

/**
 * An Array Load Operation
 */
public class NodeALoad extends Node {

	private static final long serialVersionUID = -7877480315541802538L;
	private Node array;
	private Node index;
	private int loadSize;

	/**
	 * Create an array load operation based on an array, an index and the size to load from it.
	 * @param array the array to load from
	 * @param index the index to reference in the array
	 * @param loadSize the size of data read from the array
	 */
	public NodeALoad(Node array, Node index, int loadSize) {
		this.array = array;
		this.index = index;
		this.loadSize = loadSize;
	}

	/**
	 * The load size from this array (1 = byte, 2 = short/char, 4 = int/array)
	 * @return the size of data to load from this array
	 */
	public int getLoadSize() {
		return loadSize;
	}

	@Override
	public String toString() {
		return "ALoad(" + array + ", " + index + ")";
	}

	@Override
	protected boolean checkCriteria(Node o) {
		return ((NodeALoad) o).loadSize == this.loadSize || this.loadSize == -1 || ((NodeALoad) o).loadSize == -1;
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

	}

	@Override
	public Node[] children() {
		return new Node[] { array, index };
	}

	@Override
	public Node replace(Node search, Node replace) {
		this.array = array.equals(search) ? replace : array.replace(search, replace);
		this.index = index.equals(search) ? replace : index.replace(search, replace);
		return this;
	}
	
	@Override
	public Node clone() {
		return new NodeALoad(array.clone(), index.clone(), loadSize);
	}
	
	@Override
	public String getNodeIdentifier() { return "aload"; }
}
