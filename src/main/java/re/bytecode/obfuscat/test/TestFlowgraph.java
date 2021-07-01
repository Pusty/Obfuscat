package re.bytecode.obfuscat.test;

import java.util.HashMap;
import re.bytecode.obfuscat.dsl.api.ExcludeMethod;
import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.Function;

public class TestFlowgraph {
	
	@ExcludeMethod
    public static void main(String[] args) throws Exception {

		
    	//byte[] fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/test/re/bytecode/obfuscat/samples/Sample1.class").toURI()));
    	
    	//DSLParser p = new DSLParser();
    	//Map<String, Function> functions = p.processFile(fileData);
    	
    	
		HashMap<String, Object> map = new HashMap<String, Object>();
		map.put("data", new byte[] { 1, 2, 3, 4 });
		Function f = Obfuscat.buildFunction("KeyBuilder", map );
    	
    	//Function f = functions.get("entry");
    	
		int[] gen = Obfuscat.getGenerator("Flowgraph", f).generate();
		
		StringBuilder sb = new StringBuilder();
		for(int i=0;i<gen.length;i++)
			sb.append((char)(gen[i]));
		
		System.out.println(sb.toString());
		
		System.out.println("=========================================");
		
		f = Obfuscat.applyPass(f, "Flatten");
		
		gen = Obfuscat.getGenerator("Flowgraph", f).generate();
		
		sb = new StringBuilder();
		for(int i=0;i<gen.length;i++)
			sb.append((char)(gen[i]));
		
		System.out.println(sb.toString());
    }
    
}
