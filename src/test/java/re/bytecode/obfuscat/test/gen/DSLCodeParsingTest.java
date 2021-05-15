package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;

import org.junit.Test;

import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.test.util.DSLGenerationUtil;
import re.bytecode.obfuscat.test.util.JavaGenerationUtil;
import re.bytecode.obfuscat.test.util.SampleLoader;

public class DSLCodeParsingTest {
	
	public void runTest(String fileName, String functionName, Object... args) throws Exception {			
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName, args);
		Integer fun = (Integer) m.invoke(null, args);

		EmulateFunction code = DSLGenerationUtil.generateCode(data, functionName);
	
		Integer res = (Integer) code.run(-1, args);
		assertEquals("Java and DSL Parsing Result don't match", fun.intValue(), res.intValue());
	}
	
	@Test
	public void testDSL() throws Exception {
		runTest("Sample1", "entry");
		runTest("Sample2", "entry");
		runTest("Sample3", "entry");
		runTest("Sample4", "crc32", new byte[] {0x12, 0x23, 0x45, 0x67, (byte) 0x89}, 5);
		runTest("Sample5", "entry"); // WIDE isn't properly implemented yet
	}
}
