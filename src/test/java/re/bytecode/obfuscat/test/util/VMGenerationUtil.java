package re.bytecode.obfuscat.test.util;

import java.util.HashMap;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.pass.vm.VMBuilder;
import re.bytecode.obfuscat.pass.vm.VMCodeGenerator;

public class VMGenerationUtil {

	public static Function generateVM() {
		VMBuilder builder = new VMBuilder(new Context(System.currentTimeMillis()));
		Map<String, Object> args = new HashMap<String, Object>();
		return builder.generate(args);
	}
	
	public static byte[] generateCode(byte[] data, String name, String[] passes) throws Exception {
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(data);
		Function f = fs.get(name);
		return generateCode(f, passes);
	}
	
	public static byte[] generateCode(Function f, String[] passes) throws Exception  {
		if(passes != null) {
			for(String pass:passes)
				f = Obfuscat.applyPass(f, pass);
		}
		
		VMCodeGenerator gen = new VMCodeGenerator(null, f);
		
		int[] idata = gen.getData();
		
		byte[] bdata = new byte[idata.length];
		for(int i=0;i<idata.length;i++)
			bdata[i] = (byte) idata[i];
		
		return bdata;
	}
	
}
