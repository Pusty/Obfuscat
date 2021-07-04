package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.junit.Test;

import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.test.util.DSLGenerationUtil;
import re.bytecode.obfuscat.test.util.JavaGenerationUtil;
import re.bytecode.obfuscat.test.util.SampleLoader;
import re.bytecode.obfuscat.test.util.VMGenerationUtil;

public class DSLCodeParsingTest {
	
	public static EmulateFunction runTest(String fileName, String functionName, String[] passes, Object... args) throws Exception {			
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName, args);
		Integer fun = (Integer) m.invoke(null, args);

		EmulateFunction code = DSLGenerationUtil.generateCode(data, functionName, passes);
	
		Integer res = (Integer) code.run(-1, args);
		assertEquals("Java and DSL Parsing Result don't match", fun.intValue(), res.intValue());
		return code;
	}
	
	
	public static EmulateFunction runTestMerged(String fileName, String functionName, String[] passes, Object... args) throws Exception {			
		
		byte[] data = SampleLoader.loadFile(fileName);
		EmulateFunction code = DSLGenerationUtil.generateCodeMerged(data, functionName, passes);
	
		//Integer res = (Integer)
		code.run(-1, args);
		return code;
	}
	
	
	public static List<EmulateFunction> normalTestCases(String[] passes) throws Exception {
		List<EmulateFunction> ef = new ArrayList<EmulateFunction>();
		ef.add(runTest("Sample1", "entry", passes));
		ef.add(runTest("Sample2", "entry", passes));
		ef.add(runTest("Sample3", "entry", passes));
		ef.add(runTest("Sample4", "crc32", passes, new byte[] {0x12, 0x23, 0x45, 0x67, (byte) 0x89}, 5));
		ef.add(runTest("Sample5", "entry", passes)); 
		ef.add(runTest("Sample8", "entry", passes, new Object[] { new Object[]{ new int[] {1, 2, 3, 4}, new int[] {4, 3, 2, 1}}}));
		return ef;
	}
	
	public static void runTestVM(String fileName, String functionName, String[] passes, Object... args) throws Exception {
		
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName, args);
		Integer fib = (Integer) m.invoke(null, args);

		byte[] vmcode = VMGenerationUtil.generateCode(data, functionName, passes);
		
		EmulateFunction code = new EmulateFunction(VMGenerationUtil.generateVM());
		Integer res = (Integer) code.run(-1, new Object[] {vmcode, new int[0x100 + 0x100], args});
		assertEquals("Java and Thumb Result don't match", fib.intValue(), res.intValue());
	}
	
	public static void runTestVMinVM(String fileName, String functionName, String[] passes, Object... args) throws Exception {
		
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName, args);
		Integer fib = (Integer) m.invoke(null, args);

		byte[] codeofvm = VMGenerationUtil.generateCode(VMGenerationUtil.generateVM(), passes);
		byte[] vmcode = VMGenerationUtil.generateCode(data, functionName, passes);
		
		EmulateFunction code = new EmulateFunction(VMGenerationUtil.generateVM());
		
		Integer res = (Integer) code.run(-1, new Object[] {codeofvm, new int[0x100 + 0x100], new Object[] {vmcode, new int[0x100 + 0x100], args}});
		assertEquals("Java and Thumb Result don't match", fib.intValue(), res.intValue());
	}
	
	@Test
	public void testVM() throws Exception {
		String[] passes = new String[0];
		runTestVM("Sample1", "entry", passes);
		runTestVM("Sample2", "entry", passes);
		runTestVM("Sample3", "entry", passes);
		runTestVM("Sample4", "crc32", passes, new byte[] { 0x12, 0x23, 0x45, 0x67, (byte) 0x89 }, 5);
		runTestVM("Sample5", "entry", passes);
		runTestVM("Sample8", "entry", passes, new Object[] { new Object[]{ new int[] {1, 2, 3, 4}, new int[] {4, 3, 2, 1}}});
		
		runTestVMinVM("Sample1", "entry", passes);
		//runTestVMinVM("Sample2", "entry", passes); // this just takes too long
		runTestVMinVM("Sample3", "entry", passes);
		runTestVMinVM("Sample4", "crc32", passes, new byte[] { 0x12, 0x23, 0x45, 0x67, (byte) 0x89 }, 5);
		runTestVMinVM("Sample5", "entry", passes);
		runTestVMinVM("Sample8", "entry", passes, new Object[] { new Object[]{ new int[] {1, 2, 3, 4}, new int[] {4, 3, 2, 1}}});
		
	}
	
	public static List<EmulateFunction> mergedTestCases(String[] passes) throws Exception {
		
		List<EmulateFunction> ef = new ArrayList<EmulateFunction>();
		
		byte[] res = new byte[] {-108, -110, -121, -119, -108, -16, -89, 2};
		byte[] encoded = new byte[] {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
		ef.add(runTestMerged("Sample7", "rc4" , passes, new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, encoded, new byte[256]));
		for(int i=0;i<encoded.length;i++)
			assertEquals("RC4 didn't work "+Arrays.toString(encoded), res[i], encoded[i]);
		
		return ef;
	}
	
	

	public static void evaluteSizeAndSpeed(List<List<EmulateFunction>> listOfList) {
		
		for(int i=0;i<listOfList.get(0).size();i++) {
			
			List<Integer> sizeList = new ArrayList<Integer>();
			List<Integer> execList = new ArrayList<Integer>();
			
			for(int j=0;j<listOfList.size();j++) {
				EmulateFunction ef = listOfList.get(j).get(i);
				Function f = ef.getFunction();
				int blocksOverall = 0;
				for(BasicBlock bb:f.getBlocks()) {
					blocksOverall += bb.getNodes().size();
					//if(bb.isSwitchCase())
					//blocksOverall += bb.getSwitchBlocks().size();
				}
				sizeList.add(blocksOverall);
				execList.add(ef.getExecutedNodes());
			}
			
			assertTrue("Changes in size "+sizeList, sizeList.stream().distinct().count() == 1);
			assertTrue("Changes in executed instructions "+execList, execList.stream().distinct().count() == 1);
		}
	}
	
	public static void compareSizeAndSpeed(List<EmulateFunction> listNormal, List<EmulateFunction> listPass, List<Map<String, Node>> stats, List<Map<String, Node>> statsRuntime) {
		
		
		for(int i=0;i<listNormal.size();i++) {
			
			// Verify node count and size expectations are fulfilled
			{
				
				Map<String, Integer> base = listNormal.get(i).getFunction().statistics();
				Map<String, Integer> changed = listPass.get(i).getFunction().statistics();
				
				// apply expected pass modifications
				for(int j=0;j<stats.size();j++) {
					Map<String, Integer> newbase = new HashMap<String, Integer>();
					newbase.putAll(base);
					for(Entry<String, Node> e:stats.get(j).entrySet()) {
						newbase.put(e.getKey(), EmulateFunction.eval(e.getValue(), base));
					}
					base = newbase; // commit changes after pass
				}
				
				for(String key:base.keySet()) {
					assertEquals(key+": Size values don't match up with expected values ", base.get(key), changed.get(key));
				}
			
			}
			
			// Verify runtime behavior expectations are fulfilled
			// TODO: Verifying runtime behavior for control flow changes differs from direct changes
			{
				
				Map<String, Integer> base = listNormal.get(i).statistics();
				Map<String, Integer> changed = listPass.get(i).statistics();
				
				// apply expected pass modifications
				for(int j=0;j<stats.size();j++) {
					Map<String, Integer> newbase = new HashMap<String, Integer>();
					newbase.putAll(base);
					for(Entry<String, Node> e:statsRuntime.get(j).entrySet()) {
						newbase.put(e.getKey(), EmulateFunction.eval(e.getValue(), base));
					}
					base = newbase; // commit changes after pass
				}
				
				for(String key:base.keySet()) {
					assertEquals(key+" @ Nr. "+(i)+" Speed values don't match up with expected values ", base.get(key), changed.get(key));
				}
			
			}
			
		}
		
	}
	
	@Test
	public void testDSL() throws Exception {
		normalTestCases(null);
	}
	
	@Test
	public void testMergedDSL() throws Exception {
		mergedTestCases(null);
	}
}
