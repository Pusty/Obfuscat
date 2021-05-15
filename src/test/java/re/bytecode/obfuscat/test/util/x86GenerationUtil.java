package re.bytecode.obfuscat.test.util;

import static org.junit.Assert.assertEquals;

import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.x86CodeGenerator;

public class x86GenerationUtil {
	
	public static int[] generateCode(byte[] data, String name) throws Exception {
		DSLParser p = new DSLParser();
		Function f = p.processFile(data);
		assertEquals("Name of parsed function doesn't match", f.getName(), name);
		x86CodeGenerator gen = new x86CodeGenerator(null, f);
		return gen.getData();
	}
	
}
