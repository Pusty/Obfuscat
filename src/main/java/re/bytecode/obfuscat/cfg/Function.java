package re.bytecode.obfuscat.cfg;

import java.util.List;

/**
 * A function is a collection of basic blocks that may take input, have variables and return values
 */
public class Function {
	
	private String name;
	private List<BasicBlock> blocks;
	private Class<?>[] argumentTypes;
	private int variableSlots; // includes arguments, so: "void a(int a) { int i=a; return i; }" has 2 variableSlots
	private boolean returnsSomething;
	
	/**
	 * Create a function based on a name, the basic blocks, their parameters, the used variables and whether it returns something
	 * @param name the name of this function
	 * @param blocks a list of basic blocks
	 * @param argumentTypes the types of the parameters of this function
	 * @param variableSlots the variables used in this basic block (must include arguments in this number)
	 * @param returnsSomething if this function returns a value
	 */
	public Function(String name, List<BasicBlock> blocks, Class<?>[] argumentTypes, int variableSlots, boolean returnsSomething) {
		this.name = name;
		this.blocks = blocks;
		this.argumentTypes = argumentTypes;
		this.variableSlots = variableSlots;
		this.returnsSomething = returnsSomething;
	}
	
	/**
	 * Returns the name of this function
	 * @return the functions assigned name
	 */
	public String getName() { return name; }
	
	/**
	 * Return the list of basic blocks
	 * @return the internally used list of basic blocks of this function
	 */
	public List<BasicBlock> getBlocks() { return blocks; }
	
	/**
	 * Returns the types of the arguments
	 * @return an array of the types of the arguments
	 */
	public Class<?>[] getArguments() { return argumentTypes; }
	
	/**
	 * Returns the amount of used variables in this function (this includes the existing arguments)
	 * @return the amount of variables in this function
	 */
	public int getVariables() { return variableSlots; }
	public boolean hasReturnValue() { return returnsSomething; }

	
}
