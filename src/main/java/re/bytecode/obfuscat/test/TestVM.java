package re.bytecode.obfuscat.test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import re.bytecode.obfuscat.pass.vm.VMBuilder;
import re.bytecode.obfuscat.pass.vm.VMCodeGenerator;
import re.bytecode.obfuscat.pass.vm.VMRefImpl;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;

public class TestVM {
	
    public static void main(String[] args) throws Exception {

		
    	//byte[] fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/test/re/bytecode/obfuscat/samples/Sample5.class").toURI()));
    	
    	byte[] fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/main/re/bytecode/obfuscat/pass/vm/VMRefImpl.class").toURI()));
    	DSLParser p = new DSLParser();
    	Map<String, Function> functions = p.processFile(fileData);
    	Function refF = functions.get("process");
    	
    	
    	
    	//fileData = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/test/re/bytecode/obfuscat/samples/Sample1.class").toURI()));
    	//p = new DSLParser();
        //functions = p.processFile(fileData);
    	//Function f = functions.get("entry");
    	
		//HashMap<String, Object> map = new HashMap<String, Object>();
		//Function f = Obfuscat.buildFunction("Test", map);
    	
    	
		HashMap<String, Object> map = new HashMap<String, Object>();
		map.put("data", new byte[] { 1, 2, 3, 4 });
		Function f = Obfuscat.buildFunction("KeyBuilder", map );
		
    	f = Obfuscat.applyPass(f, "Flatten");
		f = Obfuscat.applyPass(f, "OperationEncode");
		
		int[] gen = new VMCodeGenerator(new Context(System.currentTimeMillis()), f).generate();

		byte[] vmcode = new byte[gen.length];
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < gen.length; i++) {
			sb.append(String.format("%02X", gen[i] & 0xFF));
			vmcode[i] = (byte) gen[i];
		}

		System.out.println(sb.toString());

		System.out.println("=========================================");

		
		
		VMBuilder vmb = new VMBuilder(new Context(System.currentTimeMillis()));
		
		HashMap<String, Object> vmMap = new HashMap<String, Object>();
		Function vm = vmb.generate(vmMap);
		
		EmulateFunction eFB = new EmulateFunction(f);
		byte[] arr = new byte[] {0, 0, 0, 0};
		System.out.println("Emulate Original => "+eFB.run(-1, arr));
		System.out.println(Arrays.toString(arr));
		
		EmulateFunction eF = new EmulateFunction(vm);
		arr = new byte[] {0, 0, 0, 0};
		System.out.println("Emulate Generated VM => "+eF.run(-1, gen, new int[0x100+0x100], new Object[] {arr}));
		System.out.println(Arrays.toString(arr));
		
		
		arr = new byte[] {0, 0, 0, 0};
		System.out.println("Java Reference => "+VMRefImpl.process(vmcode, new int[0x100+0x100], new Object[]{arr}));
		System.out.println(Arrays.toString(arr));
		
		EmulateFunction eFRef = new EmulateFunction(refF);
		arr = new byte[] {0, 0, 0, 0};
		System.out.println("Emulated Reference => "+eFRef.run(-1, gen, new int[0x100+0x100], new Object[] {arr}));
		System.out.println(Arrays.toString(arr));
		
		
		
		int[] data = Obfuscat.getGenerator("Thumb", vm).generate();
		sb = new StringBuilder();
		for (int i = 0; i < data.length; i++) {
			sb.append(String.format("%02X", data[i] & 0xFF));
		}
		System.out.println(sb.toString().substring(0, 10000));
		System.out.println(sb.toString().substring(10000));
		
		System.out.println("=========================================");

    }
    
}
