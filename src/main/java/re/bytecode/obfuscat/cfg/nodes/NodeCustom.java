package re.bytecode.obfuscat.cfg.nodes;

import java.util.Arrays;

import re.bytecode.obfuscat.Obfuscat;

/**
 * A Custom Operation. See {@link Obfuscat}.registerCustomNode for more information
 */
public class NodeCustom extends Node {

	private static final long serialVersionUID = -7666453126576386252L;
	private String identifier;
	private Node[] args;

	/**
	 * Create a custom operation based on an identifier and arguments
	 * @param identifier the custom identifier
	 * @param args the arguments for this custom node
	 */
	public NodeCustom(String identifier, Node... args) {
		this.identifier = identifier;
		this.args = args;
	}

	/**
	 * Return the custom node identifier of this node
	 * @return the identifier of this node
	 */
	public String getIdentifier() {
		return identifier;
	}
	
	@Override
	public String toString() {
		return "Custom["+identifier+"]"+Arrays.toString(args);
	}

	@Override
	public boolean checkCriteria(Node o) {
		return ((NodeCustom) o).identifier.equals(identifier);
	}

	@Override
	public void dumify() {
		for(int i=0;i<args.length;i++)
			if(this.args[i] == null)
				this.args[i] = new NodeDummy();
	}

	@Override
	public Node[] children() {
		return args.clone();
	}

	@Override
	public Node replace(Node search, Node replace) {
		for(int i=0;i<args.length;i++)
			args[i] = args[i].equals(search) ? replace : args[i].replace(search, replace);
		return this;
	}

	@Override
	public Node clone() {
		Node[] argsCopy = new Node[args.length];
		for(int i=0;i<args.length;i++)
			argsCopy[i] = args[i].clone();
		return new NodeCustom(identifier, argsCopy);
	}
	
	@Override
	public String getNodeIdentifier() { return "custom-"+identifier; }
}
