package re.bytecode.obfuscat.test.util;

import static org.junit.Assert.assertEquals;

import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;

public class DSLGenerationUtil {
	
	public static EmulateFunction generateCode(byte[] data, String name) throws Exception {
		DSLParser p = new DSLParser();
		Function f = p.processFile(data);
		assertEquals("Name of parsed function doesn't match", f.getName(), name);
		EmulateFunction gen = new EmulateFunction(f);
		return gen;
	}
	
}
