package re.bytecode.obfuscat.samples.benchmark;

import java.util.Random;

import re.bytecode.obfuscat.test.gen.ThumbCodeGenerationTest;

public class Benchmark {
	
	public static void main(String[] args) {
		
		try {
			
			byte[] input;
			int[] SIZES = {8, 64, 128, 256, 512, 1024};
			String[] TECHNIQUES = {null, "OperationEncode", "LiteralEncode", "VariableEncode", "FakeDependency", "Flatten", "Bogus", "Virtualize"};
			String[] FILES = { "CRC32", "RC4", "SHA1" };
			
			for(String FILE:FILES) {
				for(String TECHNIQUE:TECHNIQUES) {
					for(int SIZE:SIZES) { 
					input = new byte[SIZE];
					new Random().nextBytes(input);
	
					String[] t;
					if(TECHNIQUE == null) t = new String[] {};
					else t = new String[] { TECHNIQUE };
					
					if(FILE.equals("CRC32")) {
					ThumbCodeGenerationTest.runTest("benchmark/"+FILE, "entry", t, input, input.length);
					}else {
						ThumbCodeGenerationTest.runTestMerged("benchmark/"+FILE, "entry", t, input, input.length);
					}
					System.out.println(FILE+"-"+TECHNIQUE+"-"+SIZE+", "+ThumbCodeGenerationTest.INST_COUNT+", "+ThumbCodeGenerationTest.INST_SIZE);
					}
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
}
