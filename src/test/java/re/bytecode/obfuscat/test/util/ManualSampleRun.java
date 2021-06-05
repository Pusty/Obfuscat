package re.bytecode.obfuscat.test.util;

import java.util.HashMap;

import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.Function;

public class ManualSampleRun {
	
	private static final String[] passNames = new String[] {"LiteralEncode", "FakeDependency", "VariableEncode" /*, "OperationEncode"*/};
	
	
	
	
	
	public static void main(String[] argsMain) throws Exception {
		
		
		/*
		String fileName = "Sample6";
		String functionName = "entry";
		
		byte[] data = SampleLoader.loadFile(fileName);
		int[] code = ThumbGenerationUtil.generateCode(data, functionName, passNames);
		*/
		
		byte[] constKey = "POTATO".getBytes();
		HashMap<String, Object> args = new HashMap<String, Object>();
		args.put("data", constKey);

		
		Function func = Obfuscat.buildFunction("KeyBuilder", args);

		for (String pass : passNames)
			func = Obfuscat.applyPass(func, pass);

		int[] code = Obfuscat.generateCode("Thumb", func).getData();
		
		System.out.println(code.length);
		

		System.out.println();
		for (int i = 0; i < code.length; i++) {
			System.out.print(String.format("%02X", code[i]));
		}
		System.out.println();

		//List<List<int[]>> listOfList = new ArrayList<List<int[]>>();
		//listOfList.add(ThumbCodeGenerationTest.normalTestCases(passNames));
		//ThumbCodeGenerationTest.evaluteSizeAndSpeed(listOfList);
		
		
		//System.out.println(Arrays.toString(ThumbCodeGenerationTest.normalTestCases(null).stream().map(arr -> arr[1]).toArray()));
		// System.out.println("[2718, 308298, 348, 5670, 2292, 24]");
		// [116154, 27294678, 15696, 561390, 300588, 2028]
		// System.out.println(Arrays.toString(listOfList.get(0).stream().map(arr -> arr[1]).toArray()));
	}
}
