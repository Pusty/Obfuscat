package re.bytecode.obfuscat.pass;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.exception.PassArgumentException;

/***
 * A Pass is an Obfuscation Pass that can be applied to a function. The provided formulas describe the changes that it can produce.
 */
public abstract class Pass {
	
	private Context context;
	
	protected Pass(Context context) {
		this.context = context;
	}
	
	/**
	 * The Context of this obfuscation pass
	 * @return the context of this instance
	 */
	public Context getContext() {
		return context;
	}
	
	
	/**
	 * Apply this obfuscation technique on the input function
	 * @param inputFunction the input function
	 * @param args the arguments given to the obfuscation pass
	 * @return the output function with the pass applied
	 */
	public Function obfuscate(Function inputFunction, Map<String, Object> args) {
		
		// verify arguments
		if(args == null) throw new PassArgumentException("Argument Map may not be null");
		Map<String, Class<?>> supported = supportedArguments();
		for(Entry<String, Object> e:args.entrySet()) {
			// Check if the arguments provided are all supported (possibly want to ignore or warn for not supported instead)
			if(!supported.containsKey(e.getKey())) throw new PassArgumentException(this.getClass()+" doesn't supported argument '"+e.getKey()+"'");
			// Check if the provided arguments type is derivable from the specified parameter type
			//if(!supported.get(e.getKey()).isAssignableFrom(e.getValue().getClass())) throw new PassArgumentException("Argument "+e.getKey()+" has wrong type "+e.getValue().getClass()+" which should be "+supported.get(e.getKey()));
			// ^ this check is correct but causes some errors in GWT compilation, do in CLI instead
		}
		
		return processFunction(inputFunction, args);
	}
	
	/**
	 * Process a function
	 * @param function the function to process
	 * @param args the arguments given to the obfuscation pass
	 * @return the processed output function
	 */
	protected Function processFunction(Function function, Map<String, Object> args) {
		for(BasicBlock block:function.getBlocks())
			processBlock(function, block, args);
		return function;
	}
	
	/**
	 * Process a basic block of a given function
	 * @param function the function the basic block to process is in
	 * @param block the basic block to process
	 * @param args the arguments given to the obfuscation pass
	 */
	protected void processBlock(Function function, BasicBlock block, Map<String, Object> args) {
		
	}
	
	/**
	 * Return the size formulas of this obfuscation pass
	 * @param args the arguments given to the obfuscation pass
	 * @return the size formulas
	 */
	public abstract Map<String, Node> statistics(Map<String, Object> args);
	
	/**
	 * Return the runtime formulas of this obfuscation pass
	 * @param args the arguments given to the obfuscation pass
	 * @return the runtime formulas
	 */
	public Map<String, Node> statisticsRuntime(Map<String, Object> args) {
		return statistics(args);
	}
	
	
	/**
	 * Return a map of supported arguments
	 * @return a map of argument names and their associated types
	 */
	public Map<String, Class<?>> supportedArguments() {
		return new HashMap<String, Class<?>>();
	}
	
	/**
	 * Return a map of supported arguments and their description
	 * @return a map of argument names and their help dialog
	 */
	public Map<String, String> supportedArgumentsHelp() {
		return new HashMap<String, String>();
	}
	
	/**
	 * Return a description of the behavior of this object
	 * @return return a description for the help dialog
	 */
	public abstract String description();
}
