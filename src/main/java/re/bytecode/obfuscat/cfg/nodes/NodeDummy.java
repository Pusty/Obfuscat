package re.bytecode.obfuscat.cfg.nodes;

/**
 * Dummy Node. Used indirectly for wildcard operation when searching and replacing.
 */
public class NodeDummy extends Node {
	protected NodeDummy() {
	}

	@Override
	public void dumify() {
	}

	@Override
	public Node replace(Node search, Node replace) {
		return this;
	}
	
	@Override
	public Node clone() {
		return new NodeDummy();
	}
}
