package re.bytecode.obfuscat.builder;

import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.Function;

/**
 * A Builder is a Class that creates Functions based on a set of parameters
 */
public abstract class Builder {
	
	private Context context;
	
	/**
	 * Create a Builder based on a context
	 * @param context the context of this builder, should not be null
	 */
	public Builder(Context context) {
		this.context = context;
	}
	
	/**
	 * The Context of this Building Process
	 * @return the context
	 */
	protected Context getContext() { return context; }
	
	/**
	 * Generate a function based on the map of Arguments, checks the argument map, argument and their types
	 * @param args the map of argument values
	 * @return the generated function
	 */
	public Function generate(Map<String, Object> args) {
		
		
		if(args == null) throw new IllegalArgumentException("Argument Map may not be null");
		
		Map<String, Class<?>> supported = supportedArguments();
		for(Entry<String, Object> e:args.entrySet()) {
			// Check if the arguments provided are all supported (possibly want to ignore or warn for not supported instead)
			if(!supported.containsKey(e.getKey())) throw new IllegalArgumentException(this.getClass()+" doesn't supported argument '"+e.getKey()+"'");
			// Check if the provided arguments type is derivable from the specified parameter type
			if(!supported.get(e.getKey()).isAssignableFrom(e.getValue().getClass())) throw new IllegalArgumentException("Argument "+e.getKey()+" has wrong type "+e.getValue().getClass()+" which should be "+supported.get(e.getKey()));
		}
		
		return generateFunction(args);
	}
	
	/**
	 * Generate a function based on the map of Arguments
	 * @param args the map of argument values
	 * @return the generated function
	 */
	protected abstract Function generateFunction(Map<String, Object> args);
	
	/**
	 * Return a map of supported arguments
	 * @return a map of argument names and their associated types
	 */
	public abstract Map<String, Class<?>> supportedArguments();
}
