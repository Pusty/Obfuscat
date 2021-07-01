package re.bytecode.obfuscat.gen;

import re.bytecode.obfuscat.cfg.nodes.NodeCustom;

/**
 * Classes extending from CustomNodeImpl act as handlers for CustomNodes during the code generation process.
 * They are bound to specific CodeGenerator's and Identifiers using the {@link re.bytecode.obfuscat.Obfuscat#registerCustomNode(String, String, Class)} interface
 */
public abstract class CustomNodeImpl {
	
	/**
	 * Create a specific custom node implementation instance
	 */
	public CustomNodeImpl() {}
	
	/**
	 * Process the CustomNode's redirected to this implementation
	 * @param gen the associated code generator
	 * @param cbb the CompiledBasicBlock the handled node belongs to
	 * @param node the node to process
	 */
	public abstract void process(CodeGenerator gen, CompiledBasicBlock cbb, NodeCustom node);
	
}
