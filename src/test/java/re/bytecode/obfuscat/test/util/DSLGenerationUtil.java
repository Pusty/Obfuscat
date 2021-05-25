package re.bytecode.obfuscat.test.util;

import java.util.Map;

import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.dsl.DSLParser;

public class DSLGenerationUtil {
	
	public static EmulateFunction generateCode(byte[] data, String name) throws Exception {
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(data);
		Function f = fs.get(name);
		//assertEquals("Name of parsed function doesn't match", f.getName(), name);
		EmulateFunction gen = new EmulateFunction(f);
		return gen;
	}
	
	public static EmulateFunction generateCodeMerged(byte[] data, String name) throws Exception {
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(data);
		Function f = MergedFunction.mergeFunctions(fs, name);
		//assertEquals("Name of parsed function doesn't match", f.getName(), name);
		EmulateFunction gen = new EmulateFunction(f);
		return gen;
	}
	
}
