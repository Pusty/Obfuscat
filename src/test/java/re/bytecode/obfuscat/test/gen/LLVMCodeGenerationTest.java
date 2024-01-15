package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.dsl.DSLParser;
import re.bytecode.obfuscat.gen.llvm.LLVMCodeGenerator;
import re.bytecode.obfuscat.test.util.JavaGenerationUtil;
import re.bytecode.obfuscat.test.util.SampleLoader;

public class LLVMCodeGenerationTest {

	@Rule
	public TemporaryFolder folder = new TemporaryFolder();




	private static String dumpValue(String name, int index, String arrayType, String arrayTypeAtom, String valueType,
			String align) {
		StringBuilder sb = new StringBuilder();
		sb.append('%');
		sb.append(name);
		sb.append(".format.geptr.");
		sb.append(index);
		sb.append(" = getelementptr inbounds ");
		sb.append(arrayType);
		sb.append(", ");
		sb.append(arrayType);
		sb.append("* @");
		sb.append(name);
		sb.append(", i32 0, i32 ");
		sb.append(index);
		sb.append('\n');

		sb.append('%');
		sb.append(name);
		sb.append(".format.load.");
		sb.append(index);
		sb.append(" = load ");
		sb.append(arrayTypeAtom);
		sb.append(", ");
		sb.append(arrayTypeAtom);
		sb.append("* %");
		sb.append(name);
		sb.append(".format.geptr.");
		sb.append(index);
		sb.append(align);
		sb.append('\n');

		String castedRef = null;

		if (valueType.equals(arrayTypeAtom) && valueType.equals("i32")) {
			castedRef = "%" + name + ".format.load." + index;
		} else if (valueType.equals(arrayTypeAtom)) {
			sb.append('%');
			sb.append(name);
			sb.append(".format.cast.");
			sb.append(index);

			sb.append(" = zext ");
			sb.append(arrayTypeAtom);
			sb.append(" %");
			sb.append(name);
			sb.append(".format.load.");
			sb.append(index);
			sb.append(" to i32\n");
			castedRef = "%" + name + ".format.cast." + index;
		} else if (valueType.equals(arrayTypeAtom)) {
			sb.append('%');
			sb.append(name);
			sb.append(".format.cast.");
			sb.append(index);
			sb.append(" = ptrtoint ");
			sb.append(arrayTypeAtom);
			sb.append(" %");
			sb.append(name);
			sb.append(".format.load.");
			sb.append(index);
			sb.append(" to ");
			sb.append(valueType);
			sb.append("\n");

			if (valueType.equals("i32")) {
				castedRef = "%" + name + ".format.cast." + index;
			} else {
				sb.append('%');
				sb.append(name);
				sb.append(".format.cast2.");
				sb.append(index);
				sb.append(" = zext ");
				sb.append(valueType);
				sb.append(" %");
				sb.append(name);
				sb.append(".format.cast.");
				sb.append(index);
				sb.append(" to i32\n");
				castedRef = "%" + name + ".format.cast2." + index;
			}
		}

		sb.append('%');
		sb.append(name);
		sb.append(".format.");
		sb.append(index);
		sb.append(
				" = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.format, i32 0, i32 0), i32 ");
		sb.append(castedRef);
		sb.append(")\n");
		return sb.toString();
	}

	private static String convertArgumentOutput(String name, Object arg) {

		Class<?> argT = arg.getClass();
		if (argT == Integer.class) {
			return "";
		} else if (argT == Short.class) {
			return "";
		} else if (argT == Character.class) {
			return "";
		} else if (argT == Byte.class) {
			return "";
		} else if (argT == Boolean.class) {
			return "";
		} else if (argT.isArray()) {
			if (argT == byte[].class) {
				byte[] ba = ((byte[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < ba.length; i++)
					sb.append(dumpValue(name, i, LLVMCodeGenerator.convertObjectToType(arg), "i8", "i8", ", align 1"));
				return sb.toString();
			} else if (argT == boolean[].class) {

				boolean[] ba = ((boolean[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < ba.length; i++)
					sb.append(dumpValue(name, i, LLVMCodeGenerator.convertObjectToType(arg), "i8", "i8", ", align 1"));
				return sb.toString();
			} else if (argT == short[].class) {
				short[] sa = ((short[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < sa.length; i++)
					sb.append(dumpValue(name, i, LLVMCodeGenerator.convertObjectToType(arg), "i16", "i16", ", align 2"));
				return sb.toString();
			} else if (argT == char[].class) {
				char[] ca = ((char[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < ca.length; i++)
					sb.append(dumpValue(name, i, LLVMCodeGenerator.convertObjectToType(arg), "i16", "i16", ", align 2"));
				return sb.toString();
			} else if (argT == int[].class) {
				int[] ia = ((int[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < ia.length; i++)
					sb.append(dumpValue(name, i, LLVMCodeGenerator.convertObjectToType(arg), "i32", "i32", ", align 4"));
				return sb.toString();
			} else if (argT == Object[].class) {
				Object[] ooa = ((Object[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < ooa.length; i++) {
					if (ooa[i].getClass().isArray())
						sb.append(convertArgumentOutput(name + "." + i, ooa[i]));
					else
						sb.append(dumpValue(name, i, LLVMCodeGenerator.convertObjectToType(ooa), "i8*", LLVMCodeGenerator.convertObjectToType(ooa[i]),
								", align 4"));
				}

				return sb.toString();
			} else
				throw new RuntimeException("Array type not supported " + arg.getClass());

		} else {
			throw new RuntimeException("Can't convert argument of type " + arg.getClass());
		}
	}

	private static int PROGOUTPUT_INDEX;

	private static void compareOutput(Object arg, String[] progOutput) {
		Class<?> argT = arg.getClass();
		if (argT == Integer.class) {
			assertTrue("Integer Output doesn't match reference value",
					((Integer) arg).intValue() == Integer.parseInt(progOutput[PROGOUTPUT_INDEX++].strip()));
		} else if (argT == Short.class) {
			assertTrue("Short Output doesn't match reference value",
					(((Short) arg).intValue() & 0xFFFF) == Integer.parseInt(progOutput[PROGOUTPUT_INDEX++].strip()));
		} else if (argT == Character.class) {
			assertTrue("Character Output doesn't match reference value",
					(((Character) arg).charValue() & 0xFFFF) == Integer
							.parseInt(progOutput[PROGOUTPUT_INDEX++].strip()));
		} else if (argT == Byte.class) {
			assertTrue("Byte Output doesn't match reference value",
					(((Byte) arg).intValue() & 0xFF) == Integer.parseInt(progOutput[PROGOUTPUT_INDEX++].strip()));
		} else if (argT == Boolean.class) {
			assertTrue("Boolean Output doesn't match reference value",
					(((Boolean) arg).booleanValue() ? 1 : 0) == Integer
							.parseInt(progOutput[PROGOUTPUT_INDEX++].strip()));
		} else if (argT.isArray()) {
			if (argT == byte[].class) {
				byte[] ba = ((byte[]) arg);
				for (int i = 0; i < ba.length; i++) {
					compareOutput(ba[i], progOutput);
				}
			} else if (argT == boolean[].class) {
				boolean[] ba = ((boolean[]) arg);
				for (int i = 0; i < ba.length; i++) {
					compareOutput(ba[i], progOutput);
				}
			} else if (argT == short[].class) {
				short[] sa = ((short[]) arg);
				for (int i = 0; i < sa.length; i++) {
					compareOutput(sa[i], progOutput);
				}
			} else if (argT == char[].class) {
				char[] ca = ((char[]) arg);
				for (int i = 0; i < ca.length; i++) {
					compareOutput(ca[i], progOutput);
				}
			} else if (argT == int[].class) {
				int[] ia = ((int[]) arg);
				for (int i = 0; i < ia.length; i++) {
					compareOutput(ia[i], progOutput);
				}
			} else if (argT == Object[].class) {
				Object[] ooa = ((Object[]) arg);
				for (int i = 0; i < ooa.length; i++) {
					compareOutput(ooa[i], progOutput);
				}
			} else
				throw new RuntimeException("Array type not supported " + arg.getClass());

		} else {
			throw new RuntimeException("Can't convert argument of type " + arg.getClass());
		}
	}

	public static void compareOutput(Object[] args, Integer retValue, String[] progOutput) {
		int retValueInt = retValue==null?0:retValue.intValue();
		//System.out.println(retValue+" - "+Arrays.toString(args));
		//System.out.println(Arrays.toString(progOutput));
		assertTrue("LLVM Output doesn't match reference value", retValueInt == Integer.parseInt(progOutput[0].strip()));
		PROGOUTPUT_INDEX = 1;
		for (int i = 0; i < args.length; i++) {
			if (args[i].getClass().isArray())
				compareOutput(args[i], progOutput);
		}
	}
	
	public String[] runTest(Function f, String fileName, String functionName, String[] passes, Object... args) throws Exception {

		if (passes != null) {
			for (String pass : passes)
				f = Obfuscat.applyPass(f, pass);
		}

		LLVMCodeGenerator gen = new LLVMCodeGenerator(null, f);
		int[] genData = gen.getData();

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < genData.length; i++)
			sb.append((char) (genData[i]));
		

		sb.append('\n');
		sb.append("define dso_local i32 @main(i32 %0, i8** %1, i8** %2) #0 {\n");

		if(f.hasReturnValue()) {
			sb.append("%v0 = call i8* ");
		}else {
			sb.append("%v0 = bitcast i8* null to i8*\n");
			sb.append("call void ");
		}
		
		if (args.length > 0) {
			sb.append("(");
			for (int i = 0; i < args.length; i++) {
				sb.append("i8*");
				if (i != args.length - 1)
					sb.append(", ");
			}
			sb.append(")");
		}
		sb.append(" @");
		sb.append(functionName);
		sb.append("(");
		for (int i = 0; i < args.length; i++) {
			sb.append(LLVMCodeGenerator.convertObjectToCast("arg" + i, args[i], "i8*"));
			if (i != args.length - 1)
				sb.append(", ");
		}
		sb.append(")\n");
		sb.append("%v0.conv = ptrtoint i8* %v0 to i32\n");
		sb.append("%v1 = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([4 x i8], [4 x i8]* @.str.format, i32 0, i32 0), i32 %v0.conv)\n");

		for (int i = 0; i < args.length; i++) {
			sb.append(convertArgumentOutput("arg" + i, args[i]));
		}

		sb.append("ret i32 0\n");
		sb.append("}\n");
		sb.append("@.str.format = private unnamed_addr constant [4 x i8] c\"%d\\0A\\00\", align 1\n");
		sb.append("@.debug.format.0 = private unnamed_addr constant [8 x i8] c\"%s => \\0A\\00\", align 1\n");
		sb.append("@.debug.format.1 = private unnamed_addr constant [10 x i8] c\"%s => %p\\0A\\00\", align 1\n");
		sb.append("@.debug.format.2 = private unnamed_addr constant [13 x i8] c\"%s => %p %p\\0A\\00\", align 1\n");
		sb.append("@.debug.format.3 = private unnamed_addr constant [16 x i8] c\"%s => %p %p %p\\0A\\00\", align 1\n");
		sb.append("@.debug.format.4 = private unnamed_addr constant [19 x i8] c\"%s => %p %p %p %p\\0A\\00\", align 1\n");

		for (int i = 0; i < args.length; i++) {
			sb.append(LLVMCodeGenerator.convertObjectToGlobal("arg" + i, args[i]));
		}

		sb.append("declare i32 @printf(i8*, ...)\n");

		//System.out.println(sb.toString());
		
		try {
			String workingFileName = fileName +"-"+passes.hashCode()+"-"+args.hashCode();
			File ll = folder.newFile(workingFileName + ".ll");
			BufferedWriter writer = new BufferedWriter(new FileWriter(ll));
			writer.write(sb.toString());
			writer.close();

			Process compileProcess = Runtime.getRuntime()
					.exec(String.format("bash -c 'clang %s.ll -o %s'", workingFileName, workingFileName), null, folder.getRoot());

			BufferedReader reader = new BufferedReader(new InputStreamReader(compileProcess.getErrorStream()));

			sb = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				sb.append(line);
				sb.append('\n');
			}

			String stderr = sb.toString();

			System.out.println(stderr);

			assertTrue("ERROR DURING LLVM COMPILATION: " + stderr, !stderr.contains("error"));

			Process runProcess = Runtime.getRuntime().exec(String.format("bash -c '%s'", "./" + workingFileName), null,
					folder.getRoot());

			reader = new BufferedReader(new InputStreamReader(runProcess.getInputStream()));

			sb = new StringBuilder();
			while ((line = reader.readLine()) != null) {
				sb.append(line);
				sb.append('\n');
				// System.out.println("READ: "+line);
			}
			return sb.toString().split("\n");
		}catch (IOException ioe) {
			System.err.println("error creating temporary test file in " + this.getClass().getSimpleName());
			return null;
		}
		
	}

	public void runTest(String fileName, String functionName, String[] passes, Object... args) throws Exception {
		byte[] d = SampleLoader.loadFile(fileName);
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(d);
		Function f = fs.get(functionName);
		
		String[] output = runTest(f, fileName, functionName, passes, args);


		Method m = JavaGenerationUtil.loadSample(d, fileName, functionName, args);
		Integer out = (Integer) m.invoke(null, args);

		compareOutput(args, out, output);

	}
	
	public void runTestMerged(String fileName, String functionName, String[] passes, Object... args) throws Exception {
		byte[] d = SampleLoader.loadFile(fileName);
		DSLParser p = new DSLParser();
		Map<String, Function> fs = p.processFile(d);
		
		Function f = MergedFunction.mergeFunctions(fs, functionName);
		
		String[] output = runTest(f, fileName, f.getName(), passes, args);


		Method m = JavaGenerationUtil.loadSample(d, fileName, functionName, args);
		Integer out = (Integer) m.invoke(null, args);

		compareOutput(args, out, output);

	}
	
	public void runTestBuilder(String builder, Map<String, Object> pars, String[] passes, Object... args) throws Exception {
		Function f = Obfuscat.buildFunction(builder, pars);
		
		String[] output = runTest(f, builder, f.getName(), passes, args);

		EmulateFunction code = new EmulateFunction(f);
		Integer out =  (Integer)  code.run(-1, args);

		compareOutput(args, out, output);

	}

	public List<int[]> normalTestCases(String[] passes) throws Exception {
		return normalTestCases(passes, new ArrayList<Integer>());
	}

	public List<int[]> normalTestCases(String[] passes, List<Integer> exclude) throws Exception {
		List<int[]> data = new ArrayList<int[]>();

		if (!exclude.contains(1)) {
			runTest("Sample1", "entry", passes);
			//data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if (!exclude.contains(2)) {
			runTest("Sample2", "entry", passes);
			// data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if (!exclude.contains(3)) {
			runTest("Sample3", "entry", passes);
			// data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if (!exclude.contains(4)) {
			runTest("Sample4", "crc32", passes, new byte[] { 0x12, 0x23, 0x45, 0x67, (byte) 0x89 }, 5);
			// data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if (!exclude.contains(5)) {
			runTest("Sample5", "entry", passes);
			// data.add(new int[] { INST_SIZE, INST_COUNT });
		}

		return data;
	}
	
	public List<int[]> mergedTestCases(String[] passes, List<Integer> exclude) throws Exception {
		List<int[]> data = new ArrayList<int[]>();
		if(!exclude.contains(7)) {
			byte[] res = new byte[] { -108, -110, -121, -119, -108, -16, -89, 2 };
			byte[] encoded = new byte[] { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
			runTestMerged("Sample7", "rc4", passes, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }, encoded, new byte[256]);
			for (int i = 0; i < encoded.length; i++)
				assertEquals("RC4 didn't work", res[i], encoded[i]);
			//data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		
		if(!exclude.contains(9)) {
			byte[] decryptMe = new byte[]{0x3d, 0x67, 0x33, (byte)0xe2, 0x34, 0x1d, 0x59, (byte)0xbc, (byte)0xdd, 0x23, 0x07, 0x72, (byte)0xa7, (byte)0xe8, 0x12, 0x43};
			byte[] aesKey    = {0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae, (byte)0xd2, (byte)0xa6, (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, 0x09, (byte)0xcf, 0x4f, 0x3c};
			String decrypted = "Hello World /o/ ";
			runTestMerged("Sample9", "entry" , passes, aesKey, decryptMe);
			
			for(int i=0;i<decryptMe.length;i++)
				assertEquals("AES128 didn't work "+Arrays.toString(decryptMe), decrypted.charAt(i)&0xFF, decryptMe[i]);
			//data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		
		if(!exclude.contains(10)) {
			
			byte[] byteHash = new byte[20];
			byte[] byteHashReference = null;
			String hashString = "POTATO";
			
			runTestMerged("Sample10", "hash" , passes, byteHash, hashString.getBytes(), hashString.length());
			try {
	            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
	            sha1.update(hashString.getBytes());
	            byteHashReference = sha1.digest();
	            sha1.reset();
	        } catch (Exception e) {
	            System.err.println("getHashedValue failed: " + e.getMessage());
	        }

			for(int i=0;i<byteHash.length;i++)
				assertEquals("SHA1 didn't work "+Arrays.toString(byteHash), byteHash[i], byteHashReference[i]);
			//data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		
		return data;
	}
	
	public List<int[]> mergedTestCases(String[] passes) throws Exception {
		return mergedTestCases(passes, new ArrayList<Integer>());
	}

	// Note:
	// This test executes shell commands and runs programs, specifically clang and
	// the compiled test binaries
	@Test
	public void testLLVM() throws Exception {
		
		
		String[] passes = new String[] {};
		normalTestCases(passes);
		mergedTestCases(passes);
		
		
		passes = new String[] {"OperationEncode"};
		normalTestCases(passes);
		mergedTestCases(passes);
		
		passes = new String[] {"LiteralEncode"};
		normalTestCases(passes);
		mergedTestCases(passes);
		
		// VariableEncode skipped because of assumptions that pointer size == int size
		
		passes = new String[] {"FakeDependency"};
		normalTestCases(passes);
		mergedTestCases(passes);
		
		passes = new String[] {"Flatten"};
		normalTestCases(passes);
		mergedTestCases(passes);
		
		passes = new String[] {"Bogus"};
		normalTestCases(passes);
		mergedTestCases(passes);
		
		passes = new String[] {"Virtualize"};
		normalTestCases(passes);
		mergedTestCases(passes);
		
	}
	
	

	/*@Test
	public void test() throws Exception {
		
		// "Flatten", "LiteralEncode", "FakeDependency"
		// "Virtualize", "OperationEncode"
		// 
		String[] passes = new String[] {"LiteralEncode", "Flatten", "Virtualize", "Bogus", "Flatten", "OperationEncode"}; // new String[] {"Virtualize"};
	}*/
	
	
	//@Test
	public void testReuseBuilder() throws Exception {
		//HashMap<String, Object> args = new HashMap<String, Object>();
		//runTestBuilder("Test", args, null, new byte[] {5});
	}
	


}
