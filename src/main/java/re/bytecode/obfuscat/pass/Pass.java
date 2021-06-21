package re.bytecode.obfuscat.pass;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.exception.PassArgumentException;

// TODO: Not done yet
public abstract class Pass {
	
	private Context context;
	
	public Pass(Context context) {
		this.context = context;
	}
	
	public Context getContext() {
		return context;
	}
	
	
	public Function obfuscate(Function inputFunction, Map<String, Object> args) {
		
		// verify arguments
		if(args == null) throw new PassArgumentException("Argument Map may not be null");
		Map<String, Class<?>> supported = supportedArguments();
		for(Entry<String, Object> e:args.entrySet()) {
			// Check if the arguments provided are all supported (possibly want to ignore or warn for not supported instead)
			if(!supported.containsKey(e.getKey())) throw new PassArgumentException(this.getClass()+" doesn't supported argument '"+e.getKey()+"'");
			// Check if the provided arguments type is derivable from the specified parameter type
			if(!supported.get(e.getKey()).isAssignableFrom(e.getValue().getClass())) throw new PassArgumentException("Argument "+e.getKey()+" has wrong type "+e.getValue().getClass()+" which should be "+supported.get(e.getKey()));
		}
		
		return processFunction(inputFunction, args);
	}
	
	protected Function processFunction(Function function, Map<String, Object> args) {
		for(BasicBlock block:function.getBlocks())
			processBlock(function, block, args);
		return function;
	}
	
	protected void processBlock(Function function, BasicBlock block, Map<String, Object> args) {
		
	}
	
	public abstract Map<String, Node> statistics();
	
	public Map<String, Node> statisticsRuntime() {
		return statistics();
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
