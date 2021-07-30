package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import java.lang.reflect.Method;
import java.security.MessageDigest;
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
		return normalTestCases(passes, new ArrayList<Integer>());
	}
	
	public static List<EmulateFunction> normalTestCases(String[] passes, List<Integer> exclude) throws Exception {
		List<EmulateFunction> ef = new ArrayList<EmulateFunction>();
		if(!exclude.contains(1))
			ef.add(runTest("Sample1", "entry", passes));
		if(!exclude.contains(2))
			ef.add(runTest("Sample2", "entry", passes));
		if(!exclude.contains(3))
			ef.add(runTest("Sample3", "entry", passes));
		if(!exclude.contains(4))
			ef.add(runTest("Sample4", "crc32", passes, new byte[] {0x12, 0x23, 0x45, 0x67, (byte) 0x89}, 5));
		if(!exclude.contains(5))
			ef.add(runTest("Sample5", "entry", passes)); 
		if(!exclude.contains(6))
			ef.add(runTest("Sample8", "entry", passes, new Object[] { new Object[]{ new int[] {1, 2, 3, 4}, new int[] {4, 3, 2, 1}}}));
		return ef;
	}

	
	public static List<EmulateFunction> mergedTestCases(String[] passes) throws Exception {
		return mergedTestCases(passes, new ArrayList<Integer>());
	}
	
	public static List<EmulateFunction> mergedTestCases(String[] passes, List<Integer> exclude) throws Exception {
		
		List<EmulateFunction> ef = new ArrayList<EmulateFunction>();
		
		if(!exclude.contains(7)) {
			byte[] res = new byte[] {-108, -110, -121, -119, -108, -16, -89, 2};
			byte[] encoded = new byte[] {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
			ef.add(runTestMerged("Sample7", "rc4" , passes, new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, encoded, new byte[256]));
			for(int i=0;i<encoded.length;i++)
				assertEquals("RC4 didn't work "+Arrays.toString(encoded), res[i], encoded[i]);
		}
		
		if(!exclude.contains(9)) {
			byte[] decryptMe = new byte[]{0x3d, 0x67, 0x33, (byte)0xe2, 0x34, 0x1d, 0x59, (byte)0xbc, (byte)0xdd, 0x23, 0x07, 0x72, (byte)0xa7, (byte)0xe8, 0x12, 0x43};
			byte[] aesKey    = {0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae, (byte)0xd2, (byte)0xa6, (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, 0x09, (byte)0xcf, 0x4f, 0x3c};
			String decrypted = "Hello World /o/ ";
			ef.add(runTestMerged("Sample9", "entry" , passes, aesKey, decryptMe));
			
			for(int i=0;i<decryptMe.length;i++)
				assertEquals("AES128 didn't work "+Arrays.toString(decryptMe), decrypted.charAt(i)&0xFF, decryptMe[i]);
		}
		
		if(!exclude.contains(10)) {
			
			byte[] byteHash = new byte[20];
			byte[] byteHashReference = null;
			String hashString = "POTATO";
			
			ef.add(runTestMerged("Sample10", "hash" , passes, byteHash, hashString.getBytes(), hashString.length()));
			try {
	            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
	            sha1.update(hashString.getBytes());
	            byteHashReference = sha1.digest();
	            sha1.reset();
	        } catch (Exception e) {
	            System.err.println("getHashedValue failed: " + e.getMessage());
	        }

			for(int i=0;i<byteHash.length;i++)
				assertEquals("SHA1 didn't work "+Arrays.toString(byteHash), byteHash[i], byteHashReference[i]);
		}
		
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
				
				//System.out.println("=============");
				for(String key:base.keySet()) {
					assertEquals(key+" @ Nr. "+(i)+" Speed values don't match up with expected values ", base.get(key), changed.get(key));
					//System.out.println(key+" @ Nr. "+(i)+" Speed values don't match up with expected values "+ base.get(key) +" "+ changed.get(key));
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
