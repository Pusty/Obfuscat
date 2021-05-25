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
	
	public int runTestMerged(String fileName, String functionName, Object... args) throws Exception {			
		
		byte[] data = SampleLoader.loadFile(fileName);
		EmulateFunction code = DSLGenerationUtil.generateCodeMerged(data, functionName);
		
		Object[] argsAfter = new Object[args.length+1];
		for(int i=0;i<args.length;i++)
			argsAfter[i+1] = args[i];
		argsAfter[0] = 0;
	
		Integer res = (Integer) code.run(-1, argsAfter);
		return res == null? -1 : res.intValue();
	}
	
	@Test
	public void testDSL() throws Exception {
		runTest("Sample1", "entry");
		runTest("Sample2", "entry");
		runTest("Sample3", "entry");
		runTest("Sample4", "crc32", new byte[] {0x12, 0x23, 0x45, 0x67, (byte) 0x89}, 5);
		runTest("Sample5", "entry"); 
	}
	
	@Test
	public void testMergedDSL() throws Exception {
		byte[] res = new byte[] {-108, -110, -121, -119, -108, -16, -89, 2};
		byte[] encoded = new byte[] {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
		runTestMerged("Sample7", "rc4", new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, encoded, new byte[256]);
		for(int i=0;i<encoded.length;i++)
			assertEquals("RC4 didn't work", encoded[i], res[i]);
	}
}
