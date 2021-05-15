package re.bytecode.obfuscat.test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import re.bytecode.obfuscat.dsl.api.ExcludeMethod;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.CFGTOFLOW;
import re.bytecode.obfuscat.gen.ThumbCodeGenerator;
import re.bytecode.obfuscat.gen.x86CodeGenerator;

public class TestAlgorithm {
	
	/*public static void encrypt(byte[] input, byte[] output, int length) {
		
		for(int j=0;j<5;j++)
			for(int i=0;i<length;i++) {
				if(i == 5)
					output[i] = 3;
				output[i] = (byte) (input[i] ^ 0x12);
			}
	}*/
	
	public static int entry() {
		
		int n = 28; // 7th fib number
		
		int n1 = 0;
		int n2 = 1;
		int n3 = 0;
		
		if(n == 0) return n1;
		
		for(int i=2;i<=n;i++) {
			n3 = n1 + n2;
			n1 = n2;
			n2 = n3;
		}
		
		return n2;
		/*int n = 3; // 27th prime

		primeLoop: for (int c = 2;true; c++) {
			for (int i = c - 1; i > 1; i--)
				if (c % i == 0)
					continue primeLoop;
			n--;
			if(n == 0) return c;
		}*/
		
	}
	
	//public static void decrypt(byte[] input, byte[] output, int length) {
	//	for(int i=0;i<length;i++)
	//		output[i] = (byte) (input[i] ^ 0x12);
	//}
	
	
	@ExcludeMethod
    public static void main(String[] args) throws Exception {
    	byte[] fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/re/bytecode/obfuscat/test/TestAlgorithm.class").toURI()));
    	
    	DSLParser p = new DSLParser();
    	Function function = p.processFile(fileData);
    	//x86CodeGenerator.generate(function);
    	
    	//CFGTOFLOW.generate(function.getBlocks().get(0));
    	
		EmulateFunction ef = new EmulateFunction(function);
		
		ThumbCodeGenerator tcg = new ThumbCodeGenerator(null, function);
		
		System.out.println(" => "+ef.run(-1));
		
		int[] code = tcg.getData();
		
		System.out.println();
		for(int i=0;i<code.length;i++) {
			System.out.print(String.format("%02X", code[i]));
		}
		System.out.println();
		
    }
    
}
