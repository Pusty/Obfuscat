package re.bytecode.obfuscat.test.util;

import java.util.Map;

import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.ThumbCodeGenerator;

public class ThumbGenerationUtil {
	
	//private static Function lastFunc;
	public static int[] generateCode(byte[] data, String name, String[] passes) throws Exception {
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(data);
		Function f = fs.get(name);
		
		if(passes != null) {
			for(String pass:passes)
				f = Obfuscat.applyPass(f, pass);
		}
		
		//assertEquals("Name of parsed function doesn't match", f.getName(), name);
		ThumbCodeGenerator gen = new ThumbCodeGenerator(null, f);
		//lastFunc = f;
		return gen.getData();
	}

	
	public static int[] generateCodeMerged(byte[] data, String name, String[] passes) throws Exception {
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(data);
		Function f = MergedFunction.mergeFunctions(fs, name);
		
		if(passes != null) {
			for(String pass:passes)
				f = Obfuscat.applyPass(f, pass);
		}
		
		//assertEquals("Name of parsed function doesn't match", f.getName(), name);
		ThumbCodeGenerator gen = new ThumbCodeGenerator(null, f);
		//lastFunc = f;
		return gen.getData();
	}
	
	private static final ThumbCodeGenerator tcg = new ThumbCodeGenerator(null, null);
	
	public static int getCodeSize() {
		return tcg.getNodeSize();
	}
	
	public static int getCodeInstCount() {
		return tcg.getNodeInstCount();
	}
	
	
}
