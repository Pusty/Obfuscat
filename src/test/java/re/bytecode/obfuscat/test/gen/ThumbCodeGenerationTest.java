package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.test.util.JavaGenerationUtil;
import re.bytecode.obfuscat.test.util.SampleLoader;
import re.bytecode.obfuscat.test.util.ThumbGenerationUtil;
import unicorn.CodeHook;
import unicorn.EventMemHook;
import unicorn.Unicorn;
import unicorn.UnicornException;

public class ThumbCodeGenerationTest {

	// Toggle machine code & name dumping
	private static final boolean VERBOSE = false;
	
	
	// memory address where emulation starts
	private static final int ADDRESS = 0x1000000;
	// memory address where the heap starts
	private static final int HEAP = 0x2000000;

	// address reached at end of execution
	private static final int DEAD_ADDRESS = 0xDEADC0DE;

	// current position in heap for arrays
	private static int HEAP_POSITION = HEAP;

	private static class MyWriteInvalidHook implements EventMemHook {
		public boolean hook(Unicorn u, long address, int size, long value, Object user) {
			throw new RuntimeException(
					String.format(">>> Missing memory is being WRITE at 0x%x, data size = %d, data value = 0x%x\n",
							address, size, value));
			// return false;
		}
	}

	private static class MyReadInvalidHook implements EventMemHook {
		public boolean hook(Unicorn u, long address, int size, long value, Object user) {
			throw new RuntimeException(
					String.format(">>> Missing memory is being READ at 0x%x, data size = %d, data value = 0x%x\n",
							address, size, value));
			// return false;
		}
	}

	private static int INST_COUNT;
	private static int INST_SIZE;

	private static class InstructionCountHook implements CodeHook {
		public void hook(Unicorn u, long address, int size, Object user_data) {
			
			
			/*{
			Long r_pc = (Long) u.reg_read(Unicorn.UC_ARM_REG_PC);
				
				System.out.printf(">>> PC is 0x%x 0x%x\n", r_pc.intValue(), INST_COUNT);
				
				
				if(r_pc.intValue()%0x10 == 0 && INST_COUNT % 6 != 0) {
					System.out.println(Arrays.toString(u.mem_read(r_pc.longValue(), 8)));
					System.out.println("^^^^^^^^^^^^^^^^");
				}
			}*/
			
			INST_COUNT++;

			/*{
				Long r_pc = (Long) u.reg_read(Unicorn.UC_ARM_REG_PC);
				Long r_r0 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R0);
				Long r_r1 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R1);
				Long r_r2 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R2);
				Long r_r6 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R6);
				Long r_r7 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R7);
				// System.out.printf(">>> Tracing instruction at 0x%x\n", address);
				System.out.printf(">>> PC is 0x%x - R0 0x%x R1 0x%x R2 0x%x R7 0x%x R6 0x%x \n", r_pc.intValue(),
						r_r0.intValue(), r_r1.intValue(), r_r2.intValue(), r_r7.intValue(), r_r6.intValue());

			}*/
		}
	}

	// Convert Arguments to Unicorn Register values
	private static long convertArgument(Unicorn unicorn, Object arg, boolean write) {

		long returnValue = 0;

		Class<?> argT = arg.getClass();
		if (argT == Integer.class) {
			returnValue = ((Integer) arg).intValue();
		} else if (argT == Short.class) {
			returnValue = (((Short) arg).intValue() & 0xFFFF);
		} else if (argT == Character.class) {
			returnValue = (long) (((Character) arg).charValue() & 0xFFFF);
		} else if (argT == Byte.class) {
			returnValue = (long) (((Byte) arg).intValue() & 0xFF);
		} else if (argT == Boolean.class) {
			returnValue = (long) (((Boolean) arg).booleanValue()?1:0);
		} else if (argT.isArray()) {

			returnValue = (long) HEAP_POSITION;

			if (argT == byte[].class) {

				byte[] ba = ((byte[]) arg);

				if (write) {
					byte[] data = unicorn.mem_read(HEAP_POSITION, ba.length);
					for (int j = 0; j < ba.length; j++)
						ba[j] = data[j];
				} else
					unicorn.mem_write(HEAP_POSITION, ba);

				HEAP_POSITION += ba.length;
			} else if (argT == boolean[].class) {
				
				boolean[] ba = ((boolean[]) arg);
				if (write) {
					byte[] data = unicorn.mem_read(HEAP_POSITION, ba.length);
					for (int j = 0; j < ba.length; j++)
						ba[j] = data[j]!=0;
				} else {
					byte[] oa = new byte[ba.length];
					for(int j=0;j<ba.length;j++)
						oa[j] = (byte) (ba[j]?1:0);
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += ba.length;
			}  else if (argT == short[].class) {
				short[] sa = ((short[]) arg);
				if (write) {
					byte[] oa = unicorn.mem_read(HEAP_POSITION, sa.length * 2);
					for (int j = 0; j < sa.length; j++)
						sa[j] = (short) ((oa[j * 2] & 0xFF) | ((oa[j * 2 + 1] & 0xFF) << 8));
				} else {
					byte[] oa = new byte[sa.length * 2];
					for (int j = 0; j < sa.length; j++) {
						oa[j * 2] = (byte) (sa[j] & 0xFF);
						oa[j * 2 + 1] = (byte) ((sa[j] >> 8) & 0xFF);
					}
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += sa.length * 2;
			} else if (argT == char[].class) {
				char[] ca = ((char[]) arg);
				if (write) {
					byte[] oa = unicorn.mem_read(HEAP_POSITION, ca.length * 2);
					for (int j = 0; j < ca.length; j++)
						ca[j] = (char) ((oa[j * 2] & 0xFF) | ((oa[j * 2 + 1] & 0xFF) << 8));
				} else {
					byte[] oa = new byte[ca.length * 2];
					for (int j = 0; j < ca.length; j++) {
						oa[j * 2] = (byte) (ca[j] & 0xFF);
						oa[j * 2 + 1] = (byte) ((ca[j] >> 8) & 0xFF);
					}
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += ca.length * 2;
			} else if (argT == int[].class) {
				int[] ia = ((int[]) arg);
				if (write) {
					byte[] oa = unicorn.mem_read(HEAP_POSITION, ia.length * 4);
					for (int j = 0; j < ia.length; j++)
						ia[j] = ((oa[j * 2] & 0xFF) | ((oa[j * 2 + 1] & 0xFF) << 8) | ((oa[j * 2 + 2] & 0xFF) << 16)
								| ((oa[j * 2 + 3] & 0xFF) << 24));
				} else {
					byte[] oa = new byte[ia.length * 4];
					for (int j = 0; j < ia.length; j++) {
						oa[j * 4] = (byte) (ia[j] & 0xFF);
						oa[j * 4 + 1] = (byte) ((ia[j] >> 8) & 0xFF);
						oa[j * 4 + 2] = (byte) ((ia[j] >> 16) & 0xFF);
						oa[j * 4 + 3] = (byte) ((ia[j] >> 24) & 0xFF);
					}
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += ia.length * 4;
			} else if (argT == Object[].class) {
				
				Object[] ooa = ((Object[]) arg);
				int curheappos = HEAP_POSITION;
				HEAP_POSITION += ooa.length * 4;
				
				if (write) {
					//byte[] oa = unicorn.mem_read(curheappos, ooa.length * 4);
					// the assumption is that the host array can't be edited
					/*
					for (int j = 0; j < ooa.length; j++) {
						long address = ((oa[j * 2] & 0xFFL) | ((oa[j * 2 + 1] & 0xFFL) << 8L) | ((oa[j * 2 + 2] & 0xFFL) << 16L)
								| ((oa[j * 2 + 3] & 0xFFL) << 24L));
						
					}*/
					
					for (int j = 0; j < ooa.length; j++) {
						convertArgument(unicorn, ooa[j], write);
					}
					
				} else {
					byte[] oa = new byte[ooa.length * 4];
					for (int j = 0; j < ooa.length; j++) {
						long ia = convertArgument(unicorn, ooa[j], write);
						oa[j * 4] = (byte) (ia & 0xFF);
						oa[j * 4 + 1] = (byte) ((ia >> 8) & 0xFF);
						oa[j * 4 + 2] = (byte) ((ia >> 16) & 0xFF);
						oa[j * 4 + 3] = (byte) ((ia >> 24) & 0xFF);
					}
					unicorn.mem_write(curheappos, oa);
				}

			} else
				throw new RuntimeException("Array type not supported " + arg.getClass());

			HEAP_POSITION += HEAP_POSITION % 4; // align
		} else {
			throw new RuntimeException("Can't convert argument of type " + arg.getClass());
		}

		return returnValue;

	}
	
	// otherwise this might crash in the library
	private static Unicorn globalUnicorn;
	static {
		// Initialize emulator in ARM Thumb mode
		globalUnicorn = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_THUMB);

		// Map 1024 bytes at address 0 for system registers
		globalUnicorn.mem_map(0, 1024, Unicorn.UC_PROT_ALL);
		// map 2MB memory for this emulation
		globalUnicorn.mem_map(ADDRESS, 0x200000, Unicorn.UC_PROT_ALL);
		// map 1MB memory for arrays
		globalUnicorn.mem_map(HEAP, 0x10000, Unicorn.UC_PROT_ALL);
		
		// intercept invalid memory events
		globalUnicorn.hook_add(new MyWriteInvalidHook(), Unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, null);
		globalUnicorn.hook_add(new MyReadInvalidHook(), Unicorn.UC_HOOK_MEM_READ_UNMAPPED, null);

		// tracing all instruct
		
		globalUnicorn.hook_add(new InstructionCountHook(), 1, 0, null);
	}

	static long test_thumb(int[] code, Object... args) {

		// r4 - r7 arguments
		long r0 = 0xfd49d41dL;
		long r1 = 0x7f133ddbL;
		long r2 = 0xd8afc461L;
		long r3 = 0x4a733f01L;

		long r4 = 0x717ea358L;
		long r5 = 0x2771ce96L;
		long r6 = 0x02b9ab1fL;
		long r7 = 0x8eb618c1L;

		HEAP_POSITION = HEAP;
		long sp = ADDRESS + 0x200000;

		// System.out.print("Emulate ARM Thumb code\n");



		if (args.length > 4)
			throw new RuntimeException("Thumb can't handle more than 4 arguments"); 
		if (args.length >= 1)
			r0 = convertArgument(globalUnicorn, args[0], false);
		if (args.length >= 2)
			r1 = convertArgument(globalUnicorn, args[1], false);
		if (args.length >= 3)
			r2 = convertArgument(globalUnicorn, args[2], false);
		if (args.length >= 4)
			r3 = convertArgument(globalUnicorn, args[3], false);

		writeSystemRegisters(globalUnicorn);

		byte[] codeData = new byte[code.length];
		for (int i = 0; i < code.length; i++) {
			codeData[i] = (byte) code[i];
			if(VERBOSE) System.out.print(String.format("%02X", codeData[i]));
		}
		if(VERBOSE) System.out.println();
		INST_SIZE = code.length;

		// write machine code to be emulated to memory
		globalUnicorn.mem_write(ADDRESS, codeData);

		// initialize machine registers
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_LR, Long.valueOf(DEAD_ADDRESS));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_SP, Long.valueOf(sp));

		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R0, Long.valueOf(r0));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R1, Long.valueOf(r1));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R2, Long.valueOf(r2));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R3, Long.valueOf(r3));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R4, Long.valueOf(r4));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R5, Long.valueOf(r5));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R6, Long.valueOf(r6));
		globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R7, Long.valueOf(r7));

		// r8 = function address - this would be annoying to do in C
		// globalUnicorn.reg_write(Unicorn.UC_ARM_REG_R8, new Long(ADDRESS | 1));

		
		INST_COUNT = 0;
		

		// emulate machine code in infinite time (last param = 0), or when
		// finishing all the code.
		try {
			globalUnicorn.emu_start(ADDRESS | 1, ADDRESS + codeData.length, 0, 0);
		} catch (UnicornException ue) {
			// ue.getMessage().contains("UC_ERR_FETCH_UNMAPPED") &&
			if (((Long) globalUnicorn.reg_read(Unicorn.UC_ARM_REG_PC)).intValue() == DEAD_ADDRESS) {
				// program ended normally
			} else {
				throw new RuntimeException("@ "+Long.toHexString((Long)globalUnicorn.reg_read(Unicorn.UC_ARM_REG_PC)), ue);
			}
		}

		// INST_COUNT now contains instruction cound

		// now print out some registers
		// System.out.print(">>> Emulation done. Below is the CPU context\n");

		Long r_r0 = (Long) globalUnicorn.reg_read(Unicorn.UC_ARM_REG_R0);

		HEAP_POSITION = HEAP;
		if (args.length >= 1)
			convertArgument(globalUnicorn, args[0], true);
		if (args.length >= 2)
			convertArgument(globalUnicorn, args[1], true);
		if (args.length >= 3)
			convertArgument(globalUnicorn, args[2], true);
		if (args.length >= 4)
			convertArgument(globalUnicorn, args[3], true);

		/*
		 * Long r_r0 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R0); Long r_r1 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R1); Long r_r2 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R2); Long r_r3 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R3); Long r_r4 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R4); Long r_r5 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R5); Long r_r6 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R6); Long r_r7 = (Long)
		 * u.reg_read(Unicorn.UC_ARM_REG_R7);
		 */

		/*
		 * System.out.printf(">>> R0 = 0x%x\n", r_r0.intValue());
		 * System.out.printf(">>> R1 = 0x%x\n", r_r1.intValue());
		 * System.out.printf(">>> R2 = 0x%x\n", r_r2.intValue());
		 * System.out.printf(">>> R3 = 0x%x\n", r_r3.intValue());
		 * System.out.printf(">>> R4 = 0x%x\n", r_r4.intValue());
		 * System.out.printf(">>> R5 = 0x%x\n", r_r5.intValue());
		 * System.out.printf(">>> R6 = 0x%x\n", r_r6.intValue());
		 * System.out.printf(">>> R7 = 0x%x\n", r_r7.intValue());
		 */

		//globalUnicorn.close();
		

		assertTrue("Binary Size is not multiple of Generator " + INST_SIZE,
				(INST_SIZE % ThumbGenerationUtil.getCodeSize()) == 0);
		assertTrue("Instruction Executed is not multiple of Generator " + INST_COUNT,
			(INST_COUNT % ThumbGenerationUtil.getCodeInstCount()) == 0);

		return r_r0.intValue();
	}

	private static int testData123 = 0xBEEFBEEF;

	private static void writeSystemRegisters(Unicorn u) {
		u.mem_write(0x123, new byte[] { (byte) (testData123 & 0xFF), (byte) ((testData123 >> 8) & 0xFF),
				(byte) ((testData123 >> 16) & 0xFF), (byte) ((testData123 >> 24) & 0xFF) });
	}
	
	public static void evaluteSizeAndSpeed(List<List<int[]>> listOfList) {
		
		for(int i=0;i<listOfList.get(0).size();i++) {
			
			List<Integer> sizeList = new ArrayList<Integer>();
			List<Integer> execList = new ArrayList<Integer>();
			
			for(int j=0;j<listOfList.size();j++) {
				int[] ef = listOfList.get(j).get(i);
				sizeList.add(ef[0]);
				execList.add(ef[1]);
			}
			
			assertTrue("Changes in size "+sizeList+" @ Nr. "+(i+1), sizeList.stream().distinct().count() == 1);
			assertTrue("Changes in executed instructions "+execList+" @ Nr. "+(i+1), execList.stream().distinct().count() == 1);
		}
	}
	

	public static void runTest(String fileName, String functionName, String[] passes, Object... args) throws Exception {
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName, args);
		Integer fib = (Integer) m.invoke(null, args);

		if(VERBOSE) System.out.println("Testing: "+fileName+"."+functionName+(passes==null?"":" with "+Arrays.toString(passes)));
		
		int[] code = ThumbGenerationUtil.generateCode(data, functionName, passes);

		// private static int INST_COUNT;
		// private static int INST_SIZE;
		long returnValue = test_thumb(code, args);
		assertEquals("Java and Thumb Result don't match", fib.intValue(), returnValue);
	}

	public static long runTestBuilder(String builder, Map<String, Object> pars, String[] passes, Object... args)
			throws Exception {
		Function func = Obfuscat.buildFunction(builder, pars);

		if(VERBOSE) System.out.println("Testing: "+builder+(passes==null?"":" with "+Arrays.toString(passes)));
		
		if (passes != null) {
			for (String pass : passes)
				func = Obfuscat.applyPass(func, pass);
		}

		int[] code = Obfuscat.getGenerator("Thumb", func).getData();
		long v = test_thumb(code, args);
		return v;
	}

	public static long runTestMerged(String fileName, String functionName, String[] passes, Object... args)
			throws Exception {
		byte[] data = SampleLoader.loadFile(fileName);
		
		if(VERBOSE) System.out.println("Testing Merged: "+fileName+"."+functionName+(passes==null?"":" with "+Arrays.toString(passes)));
		
		int[] code = ThumbGenerationUtil.generateCodeMerged(data, functionName, passes);

		long returnValue = test_thumb(code, args);
		// System.out.println("Return Value: "+returnValue);
		return returnValue;
	}
	
	public static List<int[]> normalTestCases(String[] passes) throws Exception {
		return normalTestCases(passes, new ArrayList<Integer>());
	}

	public static List<int[]> normalTestCases(String[] passes, List<Integer> exclude) throws Exception {
		List<int[]> data = new ArrayList<int[]>();
		if(!exclude.contains(1)) {
			runTest("Sample1", "entry", passes);
			data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if(!exclude.contains(2)) {
		runTest("Sample2", "entry", passes);
		data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if(!exclude.contains(3)) {
		runTest("Sample3", "entry", passes);
		data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if(!exclude.contains(4)) {
		runTest("Sample4", "crc32", passes, new byte[] { 0x12, 0x23, 0x45, 0x67, (byte) 0x89 }, 5);
		data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if(!exclude.contains(5)) {
		runTest("Sample5", "entry", passes);
		data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if(!exclude.contains(6)) {
		runTest("Sample6", "entry", passes);
		data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		if(!exclude.contains(8)) {
		runTest("Sample8", "entry", passes, new Object[] { new Object[]{ new int[] {1, 2, 3, 4}, new int[] {4, 3, 2, 1}}});
		data.add(new int[] { INST_SIZE, INST_COUNT });
		}
		return data;
	}

	@Test
	public void testARMThumb() throws Exception {
		normalTestCases(null);
	}
	

	@Test
	public void testHWKeyBuilder() throws Exception {

		HashMap<String, Object> args = new HashMap<String, Object>();
		args.put("length", 7);
		byte[] byteArray = new byte[] { 0, 0, 0, 0, 0, 0, 0, 12 };
		runTestBuilder("HWKeyBuilder", args, null, byteArray);

		byte[] byteArray2 = new byte[] { 0, 0, 0, 0, 0, 0, 0, 12 };
		runTestBuilder("HWKeyBuilder", args, null, byteArray2);

		for (int i = 0; i < 7; i++) {
			assertNotEquals("Byte Array Generation Failed", byteArray[i], byteArray2[i]);
		}
		assertEquals("Byte Array Generation Processed Too Much", byteArray[7], byteArray2[7]);

	}
	
	//@Test
	public void testReuseBuilder() throws Exception {
		HashMap<String, Object> args = new HashMap<String, Object>();
		runTestBuilder("Test", args, null, 5);
	}
	

	@Test
	public void testKeyBuilder() throws Exception {

		byte[] constKey = "POTATO".getBytes();
		HashMap<String, Object> args = new HashMap<String, Object>();
		args.put("data", constKey);

		byte[] byteArray = new byte[constKey.length];
		runTestBuilder("KeyBuilder", args, null, byteArray);

		for (int i = 0; i < byteArray.length; i++) {
			assertEquals("Byte Array Generation Failed", constKey[i], byteArray[i]);
		}
	}

	@Test
	public void testMerged() throws Exception {
		byte[] res = new byte[] { -108, -110, -121, -119, -108, -16, -89, 2 };
		byte[] encoded = new byte[] { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
		runTestMerged("Sample7", "rc4", null, new byte[] { 0, 1, 2, 3, 4, 5, 6, 7 }, encoded, new byte[256]);
		for (int i = 0; i < encoded.length; i++)
			assertEquals("RC4 didn't work", res[i], encoded[i]);
	}
}
