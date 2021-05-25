package re.bytecode.obfuscat.test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.dsl.api.ExcludeMethod;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.CFGTOFLOW;
import re.bytecode.obfuscat.gen.ThumbCodeGenerator;
import re.bytecode.obfuscat.gen.x86CodeGenerator;

public class TestAlgorithm {
	

	/*public static int entry() {
		
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
		
	}*/
	
	
	/*
	private static int prime(int n) {
		primeLoop: for (int c = 2;true; c++) {
			for (int i = c - 1; i > 1; i--)
				if (c % i == 0)
					continue primeLoop;
			n--;
			if(n == 0) return c;
		}
	}
	*/
	
	private static void ohno(int i) {
		i *= 3;
	}
	
	public static int entry() {
		ohno(1);
		ohno(2);
		ohno(3);
		return 4;
	}
	
	

	
	
	@ExcludeMethod
    public static void main(String[] args) throws Exception {
    	byte[] fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/re/bytecode/obfuscat/test/TestAlgorithm.class").toURI()));
    	
    	DSLParser p = new DSLParser();
    	Map<String, Function> functions = p.processFile(fileData);
    	
    	
    	
    	//Function function = functions.get("entry");
    	
    	Function function = MergedFunction.mergeFunctions(functions, "entry");
    	System.out.println(function.getBlocks());
    	//x86CodeGenerator.generate(function);
    	
    	//CFGTOFLOW.generate(function.getBlocks().get(0));
    	
		EmulateFunction ef = new EmulateFunction(function);
		
		//ThumbCodeGenerator tcg = new ThumbCodeGenerator(null, function);
		
		System.out.println(" => "+ef.run(-1, 0));
		
		//int[] code = tcg.getData();
		
		//System.out.println();
		//for(int i=0;i<code.length;i++) {
		//	System.out.print(String.format("%02X", code[i]));
		//}
		//System.out.println();
		
		
    }
    
}
