package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.lang.reflect.Method;
import java.util.HashMap;
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

	// memory address where emulation starts
	public static final int ADDRESS = 0x1000000;
	// memory address where the heap starts
	public static final int HEAP = 0x2000000;
	
	public static final int DEAD_ADDRESS = 0xDEADC0DE;
	
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

	// callback for tracing instruction
	@SuppressWarnings("unused")
	private static class MyCodeHook implements CodeHook {
		public void hook(Unicorn u, long address, int size, Object user_data) {

			 byte[] data = u.mem_read(address, 2);

			 if ((data[1] & 0xFF) == 0x90 ) {
				Long r_pc = (Long) u.reg_read(Unicorn.UC_ARM_REG_PC);
				Long r_r0 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R0);
				Long r_r1 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R1);
				Long r_r2 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R2);
				Long r_r3 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R3);
				Long r_r4 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R4);
				// System.out.printf(">>> Tracing instruction at 0x%x\n", address);
				System.out.printf(">>> PC is 0x%x - R0 0x%x R1 0x%x R2 0x%x R3 0x%x R4 0x%x \n", r_pc.intValue(), r_r0.intValue(),
						r_r1.intValue(), r_r2.intValue(), r_r3.intValue(), r_r4.intValue());

			}

			// if((data[0]&0xFF) == 0x00 && (data[1]&0xFF) == 0xBD) u.emu_stop(); // stop at
			// ret
		}
	}

	
	// Convert Arguments to Unicorn Register values
	private static long convertArgument(Unicorn unicorn, Object arg, boolean write) {
		
		long returnValue = 0;
		
		
		
		Class<?> argT = arg.getClass();
		if(argT == Integer.class) {
			returnValue = ((Integer)arg).intValue();
		}else if(argT == Short.class) {
			returnValue = (((Short)arg).intValue()&0xFFFF);
		}else if(argT == Character.class) {
			returnValue = (long)(((Character)arg).charValue()&0xFFFF);
		}else if(argT == Byte.class) {
			returnValue = (long)(((Byte)arg).intValue()&0xFF);;
		}else if(argT.isArray()) {
			
			returnValue = (long)HEAP_POSITION;
			
			if(argT == byte[].class) {
				
				byte[] ba = ((byte[])arg);
				
				if(write) {
					byte[] data = unicorn.mem_read(HEAP_POSITION, ba.length);
					for(int j=0;j<ba.length;j++)
						ba[j] = data[j];
				}else
					unicorn.mem_write(HEAP_POSITION, ba);
				
				HEAP_POSITION += ba.length;
			}else if(argT == short[].class) {
				short[] sa = ((short[])arg);
				if(write) {
					byte[] oa = unicorn.mem_read(HEAP_POSITION, sa.length*2);
					for(int j=0;j<sa.length;j++)
						sa[j] = (short)((oa[j*2]&0xFF) | ((oa[j*2+1]&0xFF)<<8));
				}else {
					byte[] oa = new byte[sa.length*2];
					for(int j=0;j<sa.length;j++) {
						oa[j*2] = (byte)(sa[j]&0xFF);
						oa[j*2+1] = (byte)((sa[j]>>8)&0xFF);
					}
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += sa.length*2;
			}else if(argT == char[].class) {
				char[] ca = ((char[])arg);
				if(write) {
					byte[] oa = unicorn.mem_read(HEAP_POSITION, ca.length*2);
					for(int j=0;j<ca.length;j++)
						ca[j] = (char)((oa[j*2]&0xFF) | ((oa[j*2+1]&0xFF)<<8));
				}else {
					byte[] oa = new byte[ca.length*2];
					for(int j=0;j<ca.length;j++) {
						oa[j*2] = (byte)(ca[j]&0xFF);
						oa[j*2+1] = (byte)((ca[j]>>8)&0xFF);
					}
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += ca.length*2;
			}else if(argT == int[].class) {
				int[] ia = ((int[])arg);
				if(write) {
					byte[] oa = unicorn.mem_read(HEAP_POSITION, ia.length*4);
					for(int j=0;j<ia.length;j++)
						ia[j] = ((oa[j*2]&0xFF) | ((oa[j*2+1]&0xFF)<<8) | ((oa[j*2+2]&0xFF)<<16) | ((oa[j*2+13]&0xFF)<<24));
				}else {
					byte[] oa = new byte[ia.length*4];
					for(int j=0;j<ia.length;j++) {
						oa[j*4] = (byte)(ia[j]&0xFF);
						oa[j*4+1] = (byte)((ia[j]>>8)&0xFF);
						oa[j*4+2] = (byte)((ia[j]>>16)&0xFF);
						oa[j*4+3] = (byte)((ia[j]>>24)&0xFF);
					}
					unicorn.mem_write(HEAP_POSITION, oa);
				}
				HEAP_POSITION += ia.length*4;
			}else
				throw new RuntimeException("Array type not supported "+arg.getClass());
			
			HEAP_POSITION += HEAP_POSITION%4; // align
		}else {
			throw new RuntimeException("Can't convert argument of type "+arg.getClass());
		}
		

		
		return returnValue;

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

		// Initialize emulator in ARM Thumb mode
		Unicorn u = new Unicorn(Unicorn.UC_ARCH_ARM, Unicorn.UC_MODE_THUMB);

		// Map 1024 bytes at address 0 for system registers
		u.mem_map(0, 1024, Unicorn.UC_PROT_ALL);
		// map 2MB memory for this emulation
		u.mem_map(ADDRESS, 0x200000, Unicorn.UC_PROT_ALL);
		// map 1MB memory for arrays
		u.mem_map(HEAP, 0x10000, Unicorn.UC_PROT_ALL);
		
		if(args.length > 4) throw new RuntimeException("Thumb can't handle more than 4 arguments"); // TODO: add this to the thumb code generator as well
		if(args.length >= 1) r4 = convertArgument(u, args[0], false);
		if(args.length >= 2) r5 = convertArgument(u, args[1], false);
		if(args.length >= 3) r6 = convertArgument(u, args[2], false);
		if(args.length >= 4) r7 = convertArgument(u, args[3], false);
		
		writeSystemRegisters(u);

		System.out.println();
		byte[] codeData = new byte[code.length];
		for (int i = 0; i < code.length; i++) {
			codeData[i] = (byte) code[i];
			System.out.print(String.format("%02X", codeData[i]));
		}
		System.out.println();

		// write machine code to be emulated to memory
		u.mem_write(ADDRESS, codeData);

		// initialize machine registers
		u.reg_write(Unicorn.UC_ARM_REG_LR, new Long(DEAD_ADDRESS));
		u.reg_write(Unicorn.UC_ARM_REG_SP, new Long(sp));

		u.reg_write(Unicorn.UC_ARM_REG_R0, new Long(r0));
		u.reg_write(Unicorn.UC_ARM_REG_R1, new Long(r1));
		u.reg_write(Unicorn.UC_ARM_REG_R2, new Long(r2));
		u.reg_write(Unicorn.UC_ARM_REG_R3, new Long(r3));
		u.reg_write(Unicorn.UC_ARM_REG_R4, new Long(r4));
		u.reg_write(Unicorn.UC_ARM_REG_R5, new Long(r5));
		u.reg_write(Unicorn.UC_ARM_REG_R6, new Long(r6));
		u.reg_write(Unicorn.UC_ARM_REG_R7, new Long(r7));

		// intercept invalid memory events
		u.hook_add(new MyWriteInvalidHook(), Unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, null);
		u.hook_add(new MyReadInvalidHook(), Unicorn.UC_HOOK_MEM_READ_UNMAPPED, null);

		// tracing all instructions
		// u.hook_add(new MyCodeHook(), 1, 0, null);

		// emulate machine code in infinite time (last param = 0), or when
		// finishing all the code.
		try {
			u.emu_start(ADDRESS | 1, ADDRESS + codeData.length, 0, 0);
		} catch (UnicornException ue) {
			// ue.getMessage().contains("UC_ERR_FETCH_UNMAPPED") && 
			if (((Long)u.reg_read(Unicorn.UC_ARM_REG_PC)).intValue() == DEAD_ADDRESS) {
				// program ended normally
			} else
				throw ue;
		}

		// now print out some registers
		// System.out.print(">>> Emulation done. Below is the CPU context\n");

		Long r_r0 = (Long) u.reg_read(Unicorn.UC_ARM_REG_R0);
		
		HEAP_POSITION = HEAP;
		if(args.length >= 1) convertArgument(u, args[0], true);
		if(args.length >= 2) convertArgument(u, args[1], true);
		if(args.length >= 3) convertArgument(u, args[2], true);
		if(args.length >= 4) convertArgument(u, args[3], true);

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

		u.close();
		return r_r0.intValue();
	}


	private static int testData123 = 0xBEEFBEEF;
	private static void writeSystemRegisters(Unicorn u) {
		u.mem_write(0x123, new byte[] { (byte) (testData123&0xFF), (byte) ((testData123>>8)&0xFF), (byte) ((testData123>>16)&0xFF), (byte) ((testData123>>24)&0xFF) });
	}

	public void runTest(String fileName, String functionName, Object... args) throws Exception {
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName, args);
		Integer fib = (Integer) m.invoke(null, args);

		int[] code = ThumbGenerationUtil.generateCode(data, functionName);

		long returnValue = test_thumb(code, args);
		assertEquals("Java and Thumb Result don't match", fib.intValue(), returnValue);
	}
	
	public long runTestBuilder(String builder, Map<String, Object> pars,  Object... args) throws Exception {
		Function func = Obfuscat.buildFunction(builder, pars);
		int[] code = Obfuscat.generateCode("Thumb", func).getData();
		return test_thumb(code, args);
	}


	@Test
	public void testARMThumb() throws Exception {
		runTest("Sample1", "entry");
		runTest("Sample2", "entry");
		runTest("Sample3", "entry");
		runTest("Sample4", "crc32", new byte[] {0x12, 0x23, 0x45, 0x67, (byte) 0x89}, 5);
		runTest("Sample5", "entry");
		runTest("Sample6", "entry");

	}
	
	@Test
	public void testHWKeyBuilder() throws Exception {
		
		HashMap<String,Object> args = new HashMap<String,Object>();
		args.put("length", 7);
		byte[] byteArray =  new byte[] {0, 0, 0, 0, 0, 0, 0, 12};
		runTestBuilder("HWKeyBuilder", args, byteArray);
		
		byte[] byteArray2 = new byte[] {0, 0, 0, 0, 0, 0, 0, 12};
		runTestBuilder("HWKeyBuilder", args, byteArray2);
		
		for(int i=0;i<7;i++) {
			assertNotEquals("Byte Array Generation Failed", byteArray[i], byteArray2[i]);
		}
		assertEquals("Byte Array Generation Processed Too Much", byteArray[7], byteArray2[7]);
		
	}
	
	@Test
	public void testKeyBuilder() throws Exception {
		
		byte[] constKey = "POTATO".getBytes();
		HashMap<String,Object> args = new HashMap<String,Object>();
		args.put("data",constKey);
		
		byte[] byteArray =  new byte[constKey.length];
		runTestBuilder("KeyBuilder", args, byteArray);
		
		for(int i=0;i<byteArray.length;i++) {
			assertEquals("Byte Array Generation Failed", byteArray[i], constKey[i]);
		}
	}
}
