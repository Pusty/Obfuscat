package re.bytecode.obfuscat.gen;

import re.bytecode.obfuscat.cfg.nodes.Node;

/**
 * Classes extending NodeCodeGenerator process Code Generation for Classes extending from {@link re.bytecode.obfuscat.cfg.nodes.Node}
 */
public abstract class NodeCodeGenerator {

	/**
	 * Process the Nodes redirected to this implementation
	 * @param cbb the CompiledBasicBlock the handled node belongs to
	 * @param node the node to process
	 */
	public abstract void process(CompiledBasicBlock cbb, Node node);
	
}