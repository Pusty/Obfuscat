package re.bytecode.obfuscat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.InvalidPathException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.builder.Builder;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.exception.BuilderArgumentException;
import re.bytecode.obfuscat.exception.GeneratorArgumentException;
import re.bytecode.obfuscat.exception.PassArgumentException;
import re.bytecode.obfuscat.gen.CodeGenerator;
import re.bytecode.obfuscat.pass.Pass;

public class CLI {

	// ./CLI build <Builder Name> [builder args]
	// ./CLI obfuscate <Obfuscator> [obfuscator args]
	// ./CLI compile <Platform> [compile args]

	
	/*public static void main(String[] args) {
		main2(new String[] { "builder", "KeyBuilder", "-data", "'test'" });
		main2(new String[] { "emulate", "'0000'", "-input", "build.fbin" });
		main2(new String[] { "obfuscate", "Flatten" });
		main2(new String[] { "compile", "Thumb" });
		//main2(new String[] { "help", "info", "KeyBuilder" });
		main2(new String[] { "emulate", "'0000'" });
	}*/
	
	//TODO: rewrite how arrays are parsed

	public static void main(String[] args) {

		// Parse Arguments		
		if (args.length == 0) {
			System.out.println("Usage ./CLI <command>");
			return;
		}

		String command = args[0];
		
		if(command.equals("help")) {
			commandHelp(args);
			return;
		}
		
		Obfuscat.setReadFileFunction(readFile);

		Map<String, List<String>> argumentMap = parseCommandLine(args);

		if (argumentMap == null) {
			System.out.println("Error parsing arguments");
			return;
		}
		

		switch (command) {
		case "builder":
			commandBuild(argumentMap);
			return;
		case "obfuscate":
			commandObfuscate(argumentMap);
			return;
		case "compile":
			commandCompile(argumentMap);
			return;
		case "emulate":
			commandEmulate(argumentMap);
			return;
		case "info":
			commandInfo(argumentMap);
			return;
		case "appended":
			commandAppended(argumentMap);
			return;
		default:
			System.out.println("Unknown command '" + command + "', try help for information");
			return;
		}

	}
	
	
	
	private static java.util.function.Function<String, byte[]> readFile = (path) -> {
		File file = new File(path);

		try {
			file.toPath(); // this fails if the path is invalid
		} catch (InvalidPathException ipe) {
			throw new IllegalArgumentException("The input path is invalid");
		}

		if (!file.exists()) {
			throw new IllegalArgumentException("The input file does not exist");
		}

		if (file.isDirectory()) {
			throw new IllegalArgumentException("The input path is a directory");
		}

		if (!file.canRead()) {
			throw new IllegalArgumentException("The input file is not readable");
		}

		byte[] data;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			data = new byte[fis.available()];
			fis.read(data);
			fis.close();
		} catch (Exception ex) {
			throw new IllegalArgumentException("Reading input failed", ex);
		}
		
		return data;
	};

	private static Map<String, List<String>> parseCommandLine(String[] args) {

		Map<String, List<String>> argumentMap = new HashMap<String, List<String>>();

		// ./CLI <command> <taget> [args]
		if (args.length >= 1)
			argumentMap.put("command", Arrays.asList(new String[] { args[0] }));

		String tag = "arguments";
		List<String> tagData = new ArrayList<String>();
		for (int argI = 1; argI < args.length; argI++) {
			args[argI] = args[argI].trim();
			if (args[argI].startsWith("--")) {
				if (tag != null)
					argumentMap.put(tag, tagData); // add last tag
				tag = args[argI].substring(2);
				tagData = new ArrayList<String>();
			} else if (args[argI].startsWith("-")) {
				if (tag != null)
					argumentMap.put(tag, tagData); // add last tag
				tag = args[argI].substring(1);
				tagData = new ArrayList<String>();
			} else {
				if (tag == null) { // a tag needs to be specified before data can be added to it
					System.out.println("Need to specify argument before data");
					return null;
				}
				tagData.add(args[argI]);
			}

			if (tag.startsWith(" ")) { // abort if tag starts with whitespace
				System.out.println("Argument can't start with whitespace");
				return null;
			}

		}
		if (tag != null)
			argumentMap.put(tag, tagData); // add last tag

		return argumentMap;
	}

	private static Object parseTo(String dataStr, Class<?> type) {

		try {

			if (type.equals(Integer.class) || type.equals(int.class)) {
				return Integer.parseInt(dataStr);
			} else if (type.equals(Long.class) || type.equals(long.class)) {
				return Long.parseLong(dataStr);
			} else if (type.equals(Short.class) || type.equals(short.class)) {
				return Short.parseShort(dataStr);
			} else if (type.equals(Byte.class) || type.equals(byte.class)) {
				return Byte.parseByte(dataStr);
			} else if (type.equals(Character.class) || type.equals(char.class)) {
				if (dataStr.length() < 0 || dataStr.length() > 1) {
					System.out.println("Builder expected argument of type " + type);
					return null;
				}
				return dataStr.charAt(0);
			} else if (type.equals(Float.class) || type.equals(float.class)) {
				return Float.parseFloat(dataStr);
			} else if (type.equals(Double.class) || type.equals(double.class)) {
				return Double.parseDouble(dataStr);
			} else if (type.equals(Boolean.class) || type.equals(boolean.class)) {
				return Boolean.parseBoolean(dataStr);
			} else if (type.equals(String.class)) {
				if (dataStr.startsWith("\"") && dataStr.endsWith("\"")) {
					return dataStr.substring(1, dataStr.length() - 1);
				}
				if (dataStr.startsWith("'") && dataStr.endsWith("'")) {
					return dataStr.substring(1, dataStr.length() - 1);
				}
				return dataStr;
			} else {
				System.out.println("Unsupported argument type " + type + " expected");
				return null;
			}

		} catch (NumberFormatException nfe) {
			System.out.println("Exception while casting argument '" + dataStr + "' to " + type);
			return null;
		}
	}
	
	private static Object parseArray(List<String> data, Class<?> type) {

		// 0 data either means toggle
		if (data.size() == 0) {
			if (type.equals(Boolean.class)) { // no argument = True for toggles
				return Boolean.valueOf(true);
			} else {
				System.out.println("Builder expected argument of type " + type);
				return null;
			}
		} else if (data.size() == 1 && !type.isArray()) {
			Object o = parseTo(data.get(0), type);
			if (o == null) {
				System.out.println("Error while processing Builder arguments");
				return null;
			}
			return o;
		} else {

			if (!type.isArray()) {
				System.out.println("Builder expected argument of type " + type + " and not an array");
				return null;
			}
			Class<?> comp = type.getComponentType();
			List<Object> dataArray = new ArrayList<Object>();

			// special case to allow string parameters for short, char and byte arrays
			if (data.size() == 1 && !comp.equals(String.class)
					&& ((data.get(0).startsWith("\"") && data.get(0).endsWith("\""))
							|| (data.get(0).startsWith("'") && data.get(0).endsWith("'")))) {
				String d = (String) parseTo(data.get(0), String.class);

				if (comp.equals(Short.class) || comp.equals(short.class)) {
					for (char c : d.toCharArray()) {
						dataArray.add((short) c);
					}
				} else if (comp.equals(Character.class) || comp.equals(char.class)) {
					for (char c : d.toCharArray()) {
						dataArray.add(c);
					}
				} else if (comp.equals(Byte.class) || comp.equals(byte.class)) {
					for (char c : d.toCharArray()) {
						dataArray.add((byte) c);
					}
				} else {
					System.out.println("Argument " + data + " is compatible with String casting for type " + type);
					return null;
				}

			} else {
				for (String ds : data) {
					Object o = parseTo(ds, comp);
					if (o == null) {
						System.out.println("Error while processing Builder arguments");
						return null;
					}
					dataArray.add(o);
				}
			}

			// special cases for base types
			if (comp.equals(int.class)) {
				int[] arr = new int[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Integer.valueOf((Integer) dataArray.get(i));
				return arr;
			} else if (comp.equals(long.class)) {
				long[] arr = new long[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Long.valueOf((Long) dataArray.get(i));
				return arr;
			} else if (comp.equals(short.class)) {
				short[] arr = new short[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Short.valueOf((Short) dataArray.get(i));
				return arr;
			} else if (comp.equals(char.class)) {
				char[] arr = new char[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Character.valueOf((Character) dataArray.get(i));
				return arr;
			} else if (comp.equals(byte.class)) {
				byte[] arr = new byte[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Byte.valueOf((Byte) dataArray.get(i));
				return arr;
			} else if (comp.equals(float.class)) {
				float[] arr = new float[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Float.valueOf((Float) dataArray.get(i));
				return arr;
			} else if (comp.equals(double.class)) {
				double[] arr = new double[dataArray.size()];
				for (int i = 0; i < arr.length; i++)
					arr[i] = Double.valueOf((Double) dataArray.get(i));
				return arr;
			} else {
				// normal types can just be converted directly
				return dataArray.toArray();
			}
		}
	}

	private static Map<String, Object> parsedArgs(Map<String, List<String>> argsRaw, Map<String, Class<?>> supportedArgs) {
		Map<String, Object> actualArgs = new HashMap<String, Object>();
		for (String key : argsRaw.keySet()) {

			if (key.equals("command"))
				continue;
			if (key.equals("arguments"))
				continue;
			if (key.equals("output"))
				continue; // global argument for file output
			if (key.equals("input"))
				continue; // global argument for file input
			if (key.equals("seed"))
				continue; // global argument for random seed
			if (!supportedArgs.containsKey(key)) {
				System.out.println("Unknown argument " + key + ", ignored");
				continue;
			}

			Class<?> type = supportedArgs.get(key);
			List<String> data =  argsRaw.get(key);

			Object res = parseArray(data, type);
			
			if(res == null) return null;
			
			actualArgs.put(key, res);
			
		}
		return actualArgs;
	}

	private static boolean writeOutput(Map<String, List<String>> args, Object data, String defaultName) {
		if (args.containsKey("output")) {
			List<String> outputList = args.get("output");
			if (outputList.size() != 1) {
				System.out.println("Output argument requires exactly one file");
				return false;
			}
			String pathStr = (String) parseTo(outputList.get(0), String.class);

			if (pathStr == null) {
				System.out.println("Argument parsing for output failed");
				return false;
			}

			defaultName = pathStr;
		}

		File file = new File(defaultName);
		try {
			file.toPath(); // this fails if the path is invalid
		} catch (InvalidPathException ipe) {
			System.out.println("The output path is invalid");
			return false;
		}
		if (file.exists() && !file.canWrite()) {
			System.out.println("The output path is not writeable");
			return false;
		}
		if (file.exists() && file.isDirectory()) {
			System.out.println("The output path is a directory");
			return false;
		}
		if (file.getParentFile() != null && !file.getParentFile().exists() && !file.getParentFile().mkdirs()) {
			System.out.println("Creating the folders for the output failed");
			return false;
		}

		if (data.getClass() == int[].class) {
			FileOutputStream fos = null;
			try {
				int[] inpdata = (int[]) data;
				byte[] inpdataArray = new byte[inpdata.length];
				for(int i=0;i<inpdata.length;i++)
					inpdataArray[i] = (byte) inpdata[i];
				fos = new FileOutputStream(file);
				fos.write(inpdataArray);
				fos.close();
			} catch (Exception ex) {
				System.out.println("Saving output failed");
				ex.printStackTrace();
				return false;
			}
		} else {
			FileOutputStream fos = null;
			ObjectOutputStream out = null;
			try {
				fos = new FileOutputStream(file);
				out = new ObjectOutputStream(fos);
				out.writeObject(data);
				out.close();
			} catch (Exception ex) {
				System.out.println("Saving output failed");
				ex.printStackTrace();
				return false;
			}
		}
		// System.out.println("File was created");
		return true;
	}

	public static Object readInput(Map<String, List<String>> args, String defaultName) {
		if (args.containsKey("input")) {
			List<String> outputList = args.get("input");
			if (outputList.size() != 1) {
				System.out.println("Input argument requires exactly one file");
				return null;
			}
			String pathStr = (String) parseTo(outputList.get(0), String.class);

			if (pathStr == null) {
				System.out.println("Argument parsing for input failed");
				return null;
			}

			defaultName = pathStr;
		}

		File file = new File(defaultName);

		try {
			file.toPath(); // this fails if the path is invalid
		} catch (InvalidPathException ipe) {
			System.out.println("The input path is invalid");
			return null;
		}

		if (!file.exists()) {
			System.out.println("The input file does not exist");
			return false;
		}

		if (file.isDirectory()) {
			System.out.println("The input path is a directory");
			return false;
		}

		if (!file.canRead()) {
			System.out.println("The input file is not readable");
			return false;
		}

		Object o;
		FileInputStream fis = null;
		ObjectInputStream oit = null;
		try {
			fis = new FileInputStream(file);
			oit = new ObjectInputStream(fis);
			o = oit.readObject();
			oit.close();
		} catch (Exception ex) {
			System.out.println("Reading input failed");
			ex.printStackTrace();
			return null;
		}
		return o;
	}
	
	private static long getSeed(Map<String, List<String>> argsRaw) {
		long seed = System.currentTimeMillis();
		if (argsRaw.containsKey("seed")) {
			List<String> data = argsRaw.get("seed");
			if(data.size() != 1) {
				System.out.println("The seed needs to be a single long");
				return -1;
			}
			seed = Long.valueOf(((Long)parseTo(data.get(0), Long.class)));
		}
		if(seed == -1) seed++;
		return seed;
	}

	private static void commandBuild(Map<String, List<String>> argsRaw) {

		if (!argsRaw.containsKey("arguments") || argsRaw.get("arguments").size() != 1) {
			System.out.println("No Builder specified. Usage ./CLI builder <builder> [args] [-output filename]");
			return;
		}
		Builder builder;
		
		long seed = getSeed(argsRaw);
		if(seed == -1) return;

		try {
			builder = Obfuscat.getBuilder(argsRaw.get("arguments").get(0), seed);
		} catch (IllegalArgumentException iae) {
			System.out.println(iae.getMessage());
			return;
		}

		Map<String, Class<?>> actualArgsTypes = builder.supportedArguments();
		Map<String, Object> args = parsedArgs(argsRaw, actualArgsTypes);

		if (args == null) {
			System.out.println("Argument parsing failed");
			return;
		}

		Function f;
		try {
			f = builder.generate(args);
		} catch (BuilderArgumentException bae) {
			System.out.println("Failed to build: " + bae);
			if(bae.getCause() != null)
				bae.getCause().printStackTrace();
			return;
		}

		if (writeOutput(argsRaw, f, "build.fbin"))
			System.out.println("Build was successful");

	}

	private static void commandObfuscate(Map<String, List<String>> argsRaw) {

		if (!argsRaw.containsKey("arguments") || argsRaw.get("arguments").size() != 1) {
			System.out.println(
					"No Builder specified. Usage ./CLI obfuscate <pass> [args]  [-input filename] [-output filename]");
			return;
		}

		
		long seed = getSeed(argsRaw);
		if(seed == -1) return;
		
		Pass pass;

		try {
			pass = Obfuscat.getPass(argsRaw.get("arguments").get(0), seed);
		} catch (IllegalArgumentException iae) {
			System.out.println(iae.getMessage());
			return;
		}

		Map<String, Class<?>> actualArgsTypes = pass.supportedArguments();
		Map<String, Object> args = parsedArgs(argsRaw, actualArgsTypes);

		if (args == null) {
			System.out.println("Argument parsing failed");
			return;
		}

		Object rI = readInput(argsRaw, "build.fbin");

		if (rI == null) {
			System.out.println("Reading the input file failed");
			return;
		}

		if (!(rI instanceof Function)) {
			System.out.println("The read file object has the wrong type " + rI.getClass());
			return;
		}

		Function f = (Function) rI;

		try {
			f = pass.obfuscate(f, args);
		} catch (PassArgumentException bae) {
			System.out.println("Failed to obfuscate: " + bae.getMessage());
			return;
		}

		if (writeOutput(argsRaw, f, "obfuscated.fbin"))
			System.out.println("Obfuscate was successful");

	}

	private static void commandCompile(Map<String, List<String>> argsRaw) {

		if (!argsRaw.containsKey("arguments") || argsRaw.get("arguments").size() != 1) {
			System.out.println(
					"No Builder specified. Usage ./CLI obfuscate <pass> [args]  [-input filename] [-output filename]");
			return;
		}
		

		Object rI = readInput(argsRaw, "obfuscated.fbin");

		if (rI == null) {
			System.out.println("Reading the input file failed");
			return;
		}

		if (!(rI instanceof Function)) {
			System.out.println("The read file object has the wrong type " + rI.getClass());
			return;
		}
		
		long seed = getSeed(argsRaw);
		if(seed == -1) return;

		Function f = (Function) rI;
		CodeGenerator generator;

		try {
			generator = Obfuscat.getGenerator(argsRaw.get("arguments").get(0), f, seed);
		} catch (IllegalArgumentException iae) {
			System.out.println(iae.getMessage());
			return;
		}

		Map<String, Class<?>> actualArgsTypes = generator.supportedArguments();
		Map<String, Object> args = parsedArgs(argsRaw, actualArgsTypes);

		if (args == null) {
			System.out.println("Argument parsing failed");
			return;
		}

		int[] data;
		try {
			data = generator.generate();
		} catch (GeneratorArgumentException bae) {
			System.out.println("Failed to compile: " + bae.getMessage());
			return;
		}

		if (writeOutput(argsRaw, data, "output.bin"))
			System.out.println("Compilation was successful");

	}
	
	
	private static void commandEmulate(Map<String, List<String>> argsRaw) {

		Object rI = readInput(argsRaw, "obfuscated.fbin");

		if (rI == null) {
			System.out.println("Reading the input file failed");
			return;
		}
		
		if(rI instanceof Boolean) {
			return;
		}

		if (!(rI instanceof Function)) {
			System.out.println("The read file object has the wrong type " + rI.getClass());
			return;
		}

		Function f = (Function) rI;
		
		EmulateFunction ef = new EmulateFunction(f);
		
		Class<?>[] expectedArgs = f.getArguments();
		List<String> actualArgs = argsRaw.get("arguments");
		

		if(f instanceof MergedFunction) { // the initial 0 does not need to be provided
			Class<?>[] argsAfter = new Class<?>[expectedArgs.length - 1];
			for (int i = 0; i < argsAfter.length; i++)
				argsAfter[i] = expectedArgs[i+1];
			expectedArgs = argsAfter;
		}
		
		Object[] args = new Object[expectedArgs.length];
		
		if(((actualArgs == null || actualArgs.size() == 0) && args.length > 0) || (actualArgs != null && actualArgs.size() != args.length)) {
			System.out.println("The function expects arguments: "+Arrays.toString(expectedArgs));
			return;
		}
		
		for(int i=0;i<args.length;i++) {
			Object res = parseArray(Arrays.asList(new String[] { actualArgs.get(i) }), expectedArgs[i]);
			if(res == null) {
				System.out.println("Error casting argument '"+actualArgs.get(i)+"' to "+expectedArgs[i]);
				return;
			}
			args[i] = res;
		}

		Object val = null;
		try {
			val = ef.run(-1, args);
		}catch(Exception ex) {
			ex.printStackTrace();
			return;
		}
		
		if(f.hasReturnValue())
			System.out.println("Execution ended: "+val);
		else
			System.out.println("Execution ended.");
		
		System.out.println("Function Statistics: "+f.statistics());
		System.out.println("Execution Statistics: "+ef.statistics());
		
		StringBuilder formatOutput = new StringBuilder("=> ");
		for(Object arg:args) {
			if(arg.getClass() == byte[].class)
				formatOutput.append(Arrays.toString((byte[])arg));
			else if(arg.getClass() == short[].class)
				formatOutput.append(Arrays.toString((short[])arg));
			else if(arg.getClass() == char[].class)
				formatOutput.append(Arrays.toString((char[])arg));
			else if(arg.getClass() == int[].class)
				formatOutput.append(Arrays.toString((int[])arg));
			else if(arg.getClass() == long[].class)
				formatOutput.append(Arrays.toString((long[])arg));
			else if(arg.getClass() == double[].class)
				formatOutput.append(Arrays.toString((double[])arg));
			else if(arg.getClass() == float[].class)
				formatOutput.append(Arrays.toString((float[])arg));
			else if(arg.getClass().isArray())
				formatOutput.append(Arrays.toString((Object[])arg));
			else
				formatOutput.append(arg.toString());
			formatOutput.append(' ');
		}
		System.out.println(formatOutput.toString());

	}
	
	private static void commandInfo(Map<String, List<String>> argsRaw) {

		Object rI = readInput(argsRaw, "obfuscated.fbin");

		if (rI == null) {
			System.out.println("Reading the input file failed");
			return;
		}
		
		if(rI instanceof Boolean) {
			return;
		}

		if (!(rI instanceof Function)) {
			System.out.println("The read file object has the wrong type " + rI.getClass());
			return;
		}

		Function f = (Function) rI;
		System.out.println("Function Statistics: "+f.statistics());
		
	}
	
	private static void commandAppended(Map<String, List<String>> argsRaw) {

		Object rI = readInput(argsRaw, "obfuscated.fbin");

		if (rI == null) {
			System.out.println("Reading the input file failed");
			return;
		}
		
		if(rI instanceof Boolean) {
			return;
		}

		if (!(rI instanceof Function)) {
			System.out.println("The read file object has the wrong type " + rI.getClass());
			return;
		}

		Function f = (Function) rI;
		System.out.println("Function Appended Information: "+Arrays.deepToString(f.getData()));
		
	}
	
	

	private static void commandHelp(String[] args) {
		if(args.length == 2 && args[1].equals("builder")) {
			for(String key:Obfuscat.builders.keySet()) {
				System.out.println(key+" : "+Obfuscat.getBuilder(key).description());
			}
		}else if(args.length == 2 && args[1].equals("obfuscate")) {
			for(String key:Obfuscat.passes.keySet()) {
				System.out.println(key+" : "+Obfuscat.getPass(key).description());
			}
		}else if(args.length == 2 && args[1].equals("compile")) {
			for(String key:Obfuscat.generators.keySet()) {
				System.out.println(key+" : "+Obfuscat.getGenerator(key, null).description());
			}
		}else if(args.length == 3 && args[1].equals("info")) {
			String target = args[2];
			boolean found = false;
			Map<String, String> supportedArgs = null;
			String description = null;
			try {
				Builder builder = Obfuscat.getBuilder(target);
				supportedArgs = builder.supportedArgumentsHelp();
				description = builder.description();
				found = true;
			} catch (IllegalArgumentException iae) {
			}

			if (!found) {
				try {
					Pass pass = Obfuscat.getPass(target);
					supportedArgs = pass.supportedArgumentsHelp();
					description = pass.description();
					found = true;
				} catch (IllegalArgumentException iae) {
				}
			}

			if (!found) {
				try {
					CodeGenerator gen = Obfuscat.getGenerator(target, null);
					supportedArgs = gen.supportedArgumentsHelp();
					description = gen.description();
					found = true;
				} catch (IllegalArgumentException iae) {
				}
			}

			if (!found) {
				System.out.println(
						"No builder, pass or generator found with name '" + target + "'");
				return;
			}
			
			System.out.println(description);
			System.out.println();
			if(supportedArgs.size() > 0) {
				System.out.println("Supported Arguments:");
				
				for(Entry<String, String> e:supportedArgs.entrySet()) {
					System.out.println(e.getKey()+" : "+e.getValue());
				}
			}
			
		}else {
			System.out.println("Supported commands:");
			System.out.println(
					"    builder <builder> [args] [-output filename] [-seed someseed] - Run a builder with the provided arguments");
			System.out.println(
					"    obfuscate <pass> [args]  [-input filename] [-output filename] [-seed someseed] - Run an obfuscation pass with the provided arguments");
			System.out.println(
					"    compile <compile> [args]  [-input filename] [-output filename] [-seed someseed] - Compile for a platform with the provided arguments");
			System.out.println(
					"    emulate [args]  [-input filename] - Emulate the input function and print statistics");
			System.out.println(
					"    info [args] [-input filename] - Print statistics about the input function");
			System.out.println(
					"    appended [args] [-input filename] - Print statistics about the appended data of the input function");
			System.out.println("    help - Provide an overview over supported commands");
			System.out.println("    help builder - List all registered builders");
			System.out.println("    help obfuscate - List all registered obfuscation passes");
			System.out.println("    help compile - List all registered generators");
			System.out.println("    help info <builder/pass/generator> - List information for the provided builder/pass or generator");
		}
	}
}
