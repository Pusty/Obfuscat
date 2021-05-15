package re.bytecode.obfuscat;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

import re.bytecode.obfuscat.builder.Builder;
import re.bytecode.obfuscat.builder.HWKeyBuilder;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.gen.CodeGenerator;
import re.bytecode.obfuscat.gen.ThumbCodeGenerator;
import re.bytecode.obfuscat.gen.x86CodeGenerator;
import re.bytecode.obfuscat.pass.EncodeArithmeticPass;
import re.bytecode.obfuscat.pass.Pass;
import re.bytecode.obfuscat.gen.CustomNodeImpl;

/** Main Class */
public class Obfuscat {
	
	
	private static Map<String, Class<? extends Builder>> builders = new HashMap<String, Class<? extends Builder>>();
	
	
	private static Map<String, Class<? extends CodeGenerator>> generators = new HashMap<String, Class<? extends CodeGenerator>>();
	
	private static Map<Class<? extends CodeGenerator>, Map<String, Class<? extends CustomNodeImpl>>> customNodes = new HashMap<Class<? extends CodeGenerator>, Map<String, Class<? extends CustomNodeImpl>>>();

	private static Map<String, Class<? extends Pass>> passes = new HashMap<String, Class<? extends Pass>>();
	
	
	static {
		registerGenerator("x86", x86CodeGenerator.class);
		
		
		registerGenerator("Thumb", ThumbCodeGenerator.class);
		registerCustomNode("Thumb", "readInt", ThumbCodeGenerator.ThumbNodeReadInt.class);
		
		registerPass("EncodeArithmetic", EncodeArithmeticPass.class);
		
		registerBuilder("HWKeyBuilder", HWKeyBuilder.class);
	}
	
	/**
	 * Register a new builder to a specific name
	 * @param name the name of the registered builder
	 * @param cl the builder class to register
	 */
	public static void registerBuilder(String name, Class<? extends Builder> cl) {
		if(name == null || cl == null) throw new IllegalArgumentException("The builder can't be null");
		if(builders.containsKey(name)) throw new IllegalArgumentException("A Builder with the name '"+name+"' is already registered");
		builders.put(name, cl);
	}
	
	/**
	 * Register a new code generator to a specific name
	 * @param name the name of the code generator
	 * @param cl the code generator class
	 */
	public static void registerGenerator(String name, Class<? extends CodeGenerator> cl) {
		if(name == null || cl == null) throw new IllegalArgumentException("The code generator can't be null");
		if(generators.containsKey(name)) throw new IllegalArgumentException("A Code Generator with the name '"+name+"' is already registered");
		generators.put(name, cl);
		customNodes.put(cl, new HashMap<String, Class<? extends CustomNodeImpl>>());
	}
	
	/**
	 * Register a new code obfuscation pass to a specific name
	 * @param name the tag of the obfuscation pass
	 * @param cl the class of the added obfuscation pass
	 */
	public static void registerPass(String name, Class<? extends Pass> cl) {
		if(name == null || cl == null) throw new IllegalArgumentException("The pass can't be null");
		if(passes.containsKey(name)) throw new IllegalArgumentException("A Pass with the name '"+name+"' is already registered");
		passes.put(name, cl);
	}
	
	/**
	 * Register a custom node implementation for a specific generator
	 * @param generatorName generator to register the node implementation to
	 * @param nodeName the custom node to to implement
	 * @param customImpl the implementation
	 */
	public static void registerCustomNode(String generatorName, String nodeName,  Class<? extends CustomNodeImpl> customImpl) {
		if(generatorName == null) throw new IllegalArgumentException("The generator can't be null");
		if(!generators.containsKey(generatorName))  throw new IllegalArgumentException("The generator with name '"+generatorName+"' isn't registered");
		if(nodeName == null || customImpl == null) throw new IllegalArgumentException("The custom node can't be null");
		Map<String, Class<? extends CustomNodeImpl>> map = customNodes.get(generators.get(generatorName));
		if(map.containsKey(nodeName)) throw new IllegalArgumentException("A CustomNode Implementation  with the tag '"+nodeName+"' is already registered in "+generatorName);
		map.put(nodeName, customImpl);
	}
	
	/**
	 * Create a generator instance for a given generator tag and function input
	 * @param generatorName the generate to generate code from
	 * @param function the function to generate code from
	 * @return a processed code generator
	 */
	public static CodeGenerator generateCode(String generatorName, Function function) {
		
		if(generatorName == null) throw new IllegalArgumentException("The generator can't be null");
		if(function == null) throw new IllegalArgumentException("The function can't be null");
		if(!generators.containsKey(generatorName))  throw new IllegalArgumentException("The generator with name '"+generatorName+"' isn't registered");
		
		Context context = new Context(System.currentTimeMillis());
		CodeGenerator generator;
		try {
			Constructor<? extends CodeGenerator> c = generators.get(generatorName).getConstructor(Context.class, Function.class);
			generator = c.newInstance(context, function);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException("Constructor for generator not found", e);
		} catch (Exception e) {
			throw new RuntimeException("Generator Construction Exception", e);
		}
		generator.generate();
		return generator;
		
	}
	
	/**
	 * Create a function from a function builder with given arguments
	 * @param builderName the builder to use
	 * @param args the arguments given to the builder
	 * @return the build function
	 */
	public static Function buildFunction(String builderName, Map<String, Object> args) {
		if(builderName == null) throw new IllegalArgumentException("The builder can't be null");
		if(!builders.containsKey(builderName)) throw new IllegalArgumentException("The builder with name '"+builderName+"' isn't registered");
		
		Context context = new Context(System.currentTimeMillis());
		Builder builder;
		try {
			Constructor<? extends Builder> c = builders.get(builderName).getConstructor(Context.class);
			builder = c.newInstance(context);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException("Constructor for Builder not found", e);
		} catch (Exception e) {
			throw new RuntimeException("Builder Construction Exception", e);
		}
		return builder.generate(args);
	}
	
	/**
	 * Get a custom node implementation by code generator and custom node identifier
	 * @param generator the generator for the custom node implementation
	 * @param nodeName the custom node identifier
	 * @return the custom node implementation for this identifier
	 */
	public static CustomNodeImpl getCustomNodeImpl(CodeGenerator generator, String nodeName) {
		if(generator == null) throw new IllegalArgumentException("The generator can't be null");
		if(nodeName == null) throw new IllegalArgumentException("The node can't be null");
		if(!generators.containsValue(generator.getClass()))  throw new IllegalArgumentException("The generator "+generator+" isn't registered");
		Map<String, Class<? extends CustomNodeImpl>> map = customNodes.get(generator.getClass());
		if(!map.containsKey(nodeName)) throw new IllegalArgumentException("The custom node '"+nodeName+"' is not part of generator "+generator);
		
		Context context = new Context(System.currentTimeMillis());
		try {
			Constructor<? extends CustomNodeImpl> c = map.get(nodeName).getConstructor(Context.class, CodeGenerator.class);
			return c.newInstance(context, generator);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException("Constructor for CustomNodeImpl not found", e);
		} catch (Exception e) {
			throw new RuntimeException("CustomNodeImpl Construction Exception", e);
		}
	}
	
}