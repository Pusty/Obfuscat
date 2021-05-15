package re.bytecode.obfuscat.gen;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;

/**
 * Classes extending from CustomNodeImpl act as handlers for CustomNodes during the code generation process.
 * They are bound to specific CodeGenerator's and Identifiers using the {@link re.bytecode.obfuscat.Obfuscat#registerCustomNode(String, String, Class)} interface
 */
public abstract class CustomNodeImpl {
	
	private Context context;
	private CodeGenerator generator;
	
	/**
	 * Create a specific custom node implementation instance for a given compilation context and code generator instance
	 * @param context the context of this interpretation
	 * @param gen the associated code generator
	 */
	public CustomNodeImpl(Context context, CodeGenerator gen) {
		this.context = context;
		this.generator = gen;
	}
	
	/**
	 * Process the CustomNode's redirected to this implementation
	 * @param cbb the CompiledBasicBlock the handled node belongs to
	 * @param node the node to process
	 */
	public abstract void process(CompiledBasicBlock cbb, NodeCustom node);
	
	/**
	 * Return the current context of this operation
	 * @return the context of this compilation process
	 */
	public Context getContext() { return context; }
	
	/**
	 * Return the code generator instance this implementation instance is linked to
	 * @return the code generator for which CustomNodes are handled
	 */
	public CodeGenerator getGenerator() { return generator; }
}
