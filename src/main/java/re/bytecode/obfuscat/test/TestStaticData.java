package re.bytecode.obfuscat.test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.dsl.api.ExcludeMethod;

public class TestStaticData {
	
	
	public static final int[] array = {5};
	
	public static int entry() {
		return array[0];
	}
	
	@ExcludeMethod
    public static void main(String[] args) throws Exception {


    	byte[] fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/main/re/bytecode/obfuscat/test/TestStaticData.class").toURI()));
    	DSLParser p = new DSLParser();
    	Map<String, Function> functions = p.processFile(fileData);
    	Function refF = functions.get("entry");
    	
		System.out.println("=========================================");

		
		
		
		EmulateFunction eFRef = new EmulateFunction(refF);
		System.out.println("Emulated Reference => "+eFRef.run(-1));
		
		

    }
    
}
