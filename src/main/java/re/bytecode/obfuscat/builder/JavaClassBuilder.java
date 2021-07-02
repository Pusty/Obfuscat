package re.bytecode.obfuscat.builder;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.InvalidPathException;
import java.util.HashMap;
import java.util.Map;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.exception.BuilderArgumentException;

/**
 * This Builder creates a function that fills a provided array with a hardcoded key
 * <br>
 * Supported Arguments: <br>
 * data -> byte[]: The key to produce
 */
public class JavaClassBuilder extends Builder {

	public JavaClassBuilder(Context context) {
		super(context);
	}
	
	
	private byte[] readClassFile(String path) {
		
		File file = new File(path);

		try {
			file.toPath(); // this fails if the path is invalid
		} catch (InvalidPathException ipe) {
			throw new BuilderArgumentException("The input path is invalid");
		}

		if (!file.exists()) {
			throw new BuilderArgumentException("The input file does not exist");
		}

		if (file.isDirectory()) {
			throw new BuilderArgumentException("The input path is a directory");
		}

		if (!file.canRead()) {
			throw new BuilderArgumentException("The input file is not readable");
		}

		byte[] data;
		FileInputStream fis = null;
		try {
			fis = new FileInputStream(file);
			data = new byte[fis.available()];
			fis.read(data);
			fis.close();
		} catch (Exception ex) {
			throw new BuilderArgumentException("Reading input failed", ex);
		}
		
		return data;
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {


		String path = (String)args.get("path");
		if(path == null) throw new BuilderArgumentException("Path to java class file must be provided");


		String entry = (String)args.get("entry");
		if(entry == null) throw new BuilderArgumentException("The entry function name must be provided");
		
		boolean merge = args.containsKey("merge") ? (Boolean)args.get("merge") : false;

		byte[] data = readClassFile(path);
		DSLParser p = new DSLParser();
		Map<String, Function> fs;
		try {
			fs = p.processFile(data);
		} catch (Exception e) {
			throw new BuilderArgumentException("Error processing class file", e);
		}
		
		if(!fs.containsKey(entry)) {
			throw new BuilderArgumentException(entry+" function is not in "+fs.keySet());
		}
		
		if(!merge) {
			return fs.get(entry);
		}else {
			return MergedFunction.mergeFunctions(fs, entry);
		}
	}

	@Override
	public Map<String, Class<?>> supportedArguments() {
		HashMap<String, Class<?>> supported = new HashMap<String, Class<?>>();
		supported.put("path", String.class);
		supported.put("entry", String.class);
		supported.put("merge", Boolean.class);
		return supported;
	}

	@Override
	public Map<String, String> supportedArgumentsHelp() {
		HashMap<String, String> helpInfo = new HashMap<String, String>();
		helpInfo.put("path", "[Required] The path to the class file to process");
		helpInfo.put("entry", "[Required] The name of the entry function");
		helpInfo.put("merge", "A toggle whether to merge all class file functions");
		return helpInfo;
	}

	public String description() {
		return "A builder to lift java class files into functions";
	}
}