package re.bytecode.obfuscat;

import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

import re.bytecode.obfuscat.builder.Builder;
import re.bytecode.obfuscat.builder.HWKeyBuilder;
import re.bytecode.obfuscat.builder.KeyBuilder;
import re.bytecode.obfuscat.builder.TestBuilder;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.gen.CodeGenerator;
import re.bytecode.obfuscat.gen.ThumbCodeGenerator;
import re.bytecode.obfuscat.pass.Pass;
import re.bytecode.obfuscat.pass.VariableEncodePass;
import re.bytecode.obfuscat.pass.FakeDependencyPass;
import re.bytecode.obfuscat.pass.FlatteningPass;
import re.bytecode.obfuscat.pass.LiteralEncodePass;
import re.bytecode.obfuscat.pass.OperationEncodePass;
import re.bytecode.obfuscat.gen.CustomNodeImpl;

/** Main Class */
public class Obfuscat {
	
	
	protected static Map<String, Class<? extends Builder>> builders = new HashMap<String, Class<? extends Builder>>();
	
	
	protected static Map<String, Class<? extends CodeGenerator>> generators = new HashMap<String, Class<? extends CodeGenerator>>();
	
	protected static Map<Class<? extends CodeGenerator>, Map<String, Class<? extends CustomNodeImpl>>> customNodes = new HashMap<Class<? extends CodeGenerator>, Map<String, Class<? extends CustomNodeImpl>>>();

	protected static Map<String, Class<? extends Pass>> passes = new HashMap<String, Class<? extends Pass>>();
	
	
	static {
		
		
		registerGenerator("Thumb", ThumbCodeGenerator.class);
		registerCustomNode("Thumb", "readInt", ThumbCodeGenerator.ThumbNodeReadInt.class);
		registerCustomNode("Thumb", "call", ThumbCodeGenerator.ThumbNodeCall.class);
		
		registerPass("OperationEncode", OperationEncodePass.class);
		registerPass("LiteralEncode", LiteralEncodePass.class);
		registerPass("VariableEncode", VariableEncodePass.class);
		registerPass("FakeDependency", FakeDependencyPass.class);
		registerPass("Flatten", FlatteningPass.class);
		
		registerBuilder("HWKeyBuilder", HWKeyBuilder.class);
		registerBuilder("KeyBuilder", KeyBuilder.class);
		registerBuilder("Test", TestBuilder.class);
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
	
	public static Function applyPass(Function f, String passName) {
		return applyPass(f, passName, new HashMap<String, Object>());
	}
	
	public static Function applyPass(Function f, String passName, Map<String, Object> args) {
		if(f == null) throw new IllegalArgumentException("The function can't be null");
		return getPass(passName).obfuscate(f, args);
	}
	
	
	public static Pass getPass(String passName) {
		return getPass(passName, System.currentTimeMillis());
	}
	public static Pass getPass(String passName, long seed) {
		if(passName == null) throw new IllegalArgumentException("The pass can't be null");
		if(!passes.containsKey(passName)) throw new IllegalArgumentException("A Pass with the name '"+passName+"' is not registered");
		
		Context context = new Context(seed);
		Pass pass;
		try {
			Constructor<? extends Pass> c = passes.get(passName).getConstructor(Context.class);
			pass = c.newInstance(context);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException("Constructor for pass not found", e);
		} catch (Exception e) {
			throw new RuntimeException("Pass Construction Exception", e);
		}
		return pass;
	}
	
	public static Map<String, Node> getPassStatistics(String passName) {
		return getPass(passName).statistics();
	}
	
	public static Map<String, Node> getPassRuntimeStatistics(String passName) {
		return getPass(passName).statisticsRuntime();
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
	public static CodeGenerator getGenerator(String generatorName, Function function) {
		return getGenerator(generatorName, function, System.currentTimeMillis());
	}
	
	public static CodeGenerator getGenerator(String generatorName, Function function, long seed) {
		
		if(generatorName == null) throw new IllegalArgumentException("The generator can't be null");
		//if(function == null) throw new IllegalArgumentException("The function can't be null");
		if(!generators.containsKey(generatorName))  throw new IllegalArgumentException("The generator with name '"+generatorName+"' isn't registered");
		
		Context context = new Context(seed);
		CodeGenerator generator;
		try {
			Constructor<? extends CodeGenerator> c = generators.get(generatorName).getConstructor(Context.class, Function.class);
			generator = c.newInstance(context, function);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException("Constructor for generator not found", e);
		} catch (Exception e) {
			throw new RuntimeException("Generator Construction Exception", e);
		}
		//generator.generate();
		return generator;
		
	}
	
	/**
	 * Create a function from a function builder with given arguments
	 * @param builderName the builder to use
	 * @param args the arguments given to the builder
	 * @return the build function
	 */
	public static Function buildFunction(String builderName, Map<String, Object> args) {
		return buildFunction(builderName, args, System.currentTimeMillis());
	}
	
	public static Function buildFunction(String builderName, Map<String, Object> args, long seed) {
		return getBuilder(builderName, seed).generate(args);
	}
	
	public static Builder getBuilder(String builderName) {
		return getBuilder(builderName, System.currentTimeMillis());
	}
	
	public static Builder getBuilder(String builderName, long seed) {
		if(builderName == null) throw new IllegalArgumentException("The builder can't be null");
		if(!builders.containsKey(builderName)) throw new IllegalArgumentException("The builder with name '"+builderName+"' isn't registered");
		
		Context context = new Context(seed);
		Builder builder;
		try {
			Constructor<? extends Builder> c = builders.get(builderName).getConstructor(Context.class);
			builder = c.newInstance(context);
		} catch (NoSuchMethodException e) {
			throw new RuntimeException("Constructor for Builder not found", e);
		} catch (Exception e) {
			throw new RuntimeException("Builder Construction Exception", e);
		}
		return builder;
	}
	
	/**
	 * Get a custom node implementation by code generator and custom node identifier
	 * @param generator the generator for the custom node implementation
	 * @param nodeName the custom node identifier
	 * @return the custom node implementation for this identifier
	 */
	public static CustomNodeImpl getCustomNodeImpl(CodeGenerator generator, String nodeName, Context parentContext) {
		if(generator == null) throw new IllegalArgumentException("The generator can't be null");
		if(nodeName == null) throw new IllegalArgumentException("The node can't be null");
		if(!generators.containsValue(generator.getClass()))  throw new IllegalArgumentException("The generator "+generator+" isn't registered");
		Map<String, Class<? extends CustomNodeImpl>> map = customNodes.get(generator.getClass());
		if(!map.containsKey(nodeName)) throw new IllegalArgumentException("The custom node '"+nodeName+"' is not part of generator "+generator);
		
		Context context = new Context(parentContext.getInternalSeed());
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
