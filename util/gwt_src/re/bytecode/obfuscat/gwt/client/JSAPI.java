package re.bytecode.obfuscat.gwt.client;

import java.util.HashMap;
import java.util.Map;

import com.google.gwt.core.client.GWT;
import com.google.gwt.resources.client.ClientBundle;
import com.google.gwt.resources.client.TextResource;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.builder.KeyBuilder;
import re.bytecode.obfuscat.builder.VerifyBuilder;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.CodeGenerator;
import re.bytecode.obfuscat.gen.FlowgraphCodeGenerator;

public class JSAPI {
	
	protected static java.util.function.Function<String, byte[]> readFile = (path) -> {
		String content;
		if(path.equals("Sample1"))
			content = Resources.INSTANCE.sample1().getText();
		else if(path.equals("Sample2"))
			content = Resources.INSTANCE.sample2().getText();
		else if(path.equals("Sample3"))
			content = Resources.INSTANCE.sample3().getText();
		else if(path.equals("Sample4"))
			content = Resources.INSTANCE.sample4().getText();
		else if(path.equals("Sample5"))
			content = Resources.INSTANCE.sample5().getText();
		else if(path.equals("Sample6"))
			content = Resources.INSTANCE.sample6().getText();
		else if(path.equals("Sample7"))
			content = Resources.INSTANCE.sample7().getText();
		else
			throw new IllegalArgumentException("Unknown file "+path);
			
		content = content.replace("\n", "");
		content = content.replace("\r", "");
		
		return Base64Utils.fromBase64(content);
	};
	
	
	public static String generate(int seed, Function f) {
		CodeGenerator generator = new FlowgraphCodeGenerator(new Context(seed), f);
		int[] gen = generator.generate();
		StringBuilder sb = new StringBuilder();
		for(int i=0;i<gen.length;i++)
			sb.append((char)(gen[i]));
		
		return sb.toString();
	}
	
	static native void consoleLog(String message) /*-{
	console.log( message );
	}-*/;
	
	public static Function buildSample(String file, String entry, boolean merged) {
	
		byte[] data = readFile.apply(file);
		
		Map<String, Function> functions;
		try {
			DSLParser p = new DSLParser();
			functions = p.processFile(data);
		} catch (Exception e) {
		    StringBuilder sb = new StringBuilder();
		    sb.append(e.getMessage());
		    sb.append("\n");
		    for (StackTraceElement element : e.getStackTrace()) {
		        sb.append(element.toString());
		        sb.append("\n");
		    }
			consoleLog("Some exception: "+sb.toString());
			consoleLog(e+"");
			return null;
		}
		
		
		Function f;
		if(merged)
			f = MergedFunction.mergeFunctions(functions, entry);
		else
			f = functions.get(entry);
		
		return f;
	}
	
	public static Function buildKeyBuilder(int seed, String data) {
		HashMap<String, Object> map = new HashMap<String, Object>();
		byte[] dataArray = new byte[data.length()];
		for(int i=0;i<dataArray.length;i++)
			dataArray[i] = (byte) (data.charAt(i));
		map.put("data", dataArray);
		Function f = new KeyBuilder(new Context(seed)).generate(map);
		return f;
	}
	
	public static Function buildVerifyBuilder(int seed, String data) {
		HashMap<String, Object> map = new HashMap<String, Object>();
		byte[] dataArray = new byte[data.length()];
		for(int i=0;i<dataArray.length;i++)
			dataArray[i] = (byte) (data.charAt(i));
		map.put("data", dataArray);
		Function f = new VerifyBuilder(new Context(seed)).generate(map);
		return f;
	}
	
	public static Function obfuscate(int seed, String obf, Function f) {
		HashMap<String, Object> map = new HashMap<String, Object>();
		return Obfuscat.getPass(obf, seed).obfuscate(f, map);
	}
	
	
}


interface Resources extends ClientBundle {
	  Resources INSTANCE = GWT.create(Resources.class);

	  @Source("samples/Sample1.b64")
	  TextResource sample1();
	  
	  @Source("samples/Sample2.b64")
	  TextResource sample2();
	  
	  @Source("samples/Sample3.b64")
	  TextResource sample3();
	  
	  @Source("samples/Sample4.b64")
	  TextResource sample4();
	  
	  @Source("samples/Sample5.b64")
	  TextResource sample5();
	  
	  @Source("samples/Sample6.b64")
	  TextResource sample6();
	  
	  @Source("samples/Sample7.b64")
	  TextResource sample7();

}
