package re.bytecode.obfuscat.test.util;

import static org.junit.Assert.assertEquals;

import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.ThumbCodeGenerator;

public class ThumbGenerationUtil {
	
	public static int[] generateCode(byte[] data, String name) throws Exception {
		DSLParser p = new DSLParser();
		Function f = p.processFile(data);
		assertEquals("Name of parsed function doesn't match", f.getName(), name);
		ThumbCodeGenerator gen = new ThumbCodeGenerator(null, f);
		return gen.getData();
	}
	
}
