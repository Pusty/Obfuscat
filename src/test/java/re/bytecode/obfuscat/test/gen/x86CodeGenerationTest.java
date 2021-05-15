package re.bytecode.obfuscat.test.gen;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import org.junit.Test;

import re.bytecode.obfuscat.test.util.JavaGenerationUtil;
import re.bytecode.obfuscat.test.util.SampleLoader;
import re.bytecode.obfuscat.test.util.x86GenerationUtil;
import unicorn.CodeHook;
import unicorn.EventMemHook;
import unicorn.Unicorn;

public class x86CodeGenerationTest {

	// memory address where emulation starts
	public static final int ADDRESS = 0x1000000;
	   
	
	private static class MyWriteInvalidHook implements EventMemHook {
		public boolean hook(Unicorn u, long address, int size, long value, Object user) {
			throw new RuntimeException(String.format(">>> Missing memory is being WRITE at 0x%x, data size = %d, data value = 0x%x\n", address,
					size, value));
			//return false;
		}
	}
	
	private static class MyReadInvalidHook implements EventMemHook {
		public boolean hook(Unicorn u, long address, int size, long value, Object user) {
			throw new RuntimeException(String.format(">>> Missing memory is being READ at 0x%x, data size = %d, data value = 0x%x\n", address,
					size, value));
			//return false;
		}
	}	
	
	   // callback for tracing instruction
	   private static class MyCode64Hook implements CodeHook {
	      public void hook(Unicorn u, long address, int size, Object user_data) {      
	         //Long r_rip = (Long)u.reg_read(Unicorn.UC_X86_REG_RIP);
	         //System.out.printf(">>> Tracing instruction at 0x%x, instruction size = 0x%x\n", address, size);
	         //System.out.printf(">>> RIP is 0x%x\n", r_rip.longValue());
	         if(size == 1 && (u.mem_read(address, 1)[0]&0xFF) == 0xC3) u.emu_stop(); // stop at ret
	      }
	   }

	      
	
	   
	static long test_x86_64(int[] code) {
		
		long rax = 0x71f3029efd49d41dL;
		long rbx = 0xd87b45277f133ddbL;
		long rcx = 0xab40d1ffd8afc461L;
		long rdx = 0x919317b4a733f01L;
		long rsi = 0x4c24e753a17ea358L;
		long rdi = 0xe509a57d2571ce96L;
		long r8  = 0xea5b108cc2b9ab1fL;
		long r9  = 0x19ec097c8eb618c1L;
		long r10 = 0xec45774f00c5f682L;
		long r11 = 0xe17e9dbec8c074aaL;
		long r12 = 0x80f86a8dc0f6d457L;
		long r13 = 0x48288ca5671c5492L;
		long r14 = 0x595f72f6e4017f6eL;
		long r15 = 0x1efd97aea331ccccL;

		long rsp = ADDRESS + 0x200000;

		//System.out.print("Emulate x86_64 code\n");

		// Initialize emulator in X86-64bit mode
		Unicorn u = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_64);

		// map 2MB memory for this emulation
		u.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);

		
		//System.out.println();
		byte[] codeData = new byte[code.length];
		for(int i=0;i<code.length;i++) {
			codeData[i] = (byte) code[i];
		//	System.out.print(String.format("%02X", codeData[i]));
		}
		//System.out.println();
		
		// write machine code to be emulated to memory
		u.mem_write(ADDRESS, codeData);

		// initialize machine registers

		
		u.mem_write(new Long(rsp-8), new byte[] {0, 0, 0, 0, 0, 0, 0, 0});
		u.reg_write(Unicorn.UC_X86_REG_RSP, new Long(rsp-16));

		u.reg_write(Unicorn.UC_X86_REG_RAX, new Long(rax));
		u.reg_write(Unicorn.UC_X86_REG_RBX, new Long(rbx));
		u.reg_write(Unicorn.UC_X86_REG_RCX, new Long(rcx));
		u.reg_write(Unicorn.UC_X86_REG_RDX, new Long(rdx));
		u.reg_write(Unicorn.UC_X86_REG_RSI, new Long(rsi));
		u.reg_write(Unicorn.UC_X86_REG_RDI, new Long(rdi));
		u.reg_write(Unicorn.UC_X86_REG_R8, new Long(r8));
		u.reg_write(Unicorn.UC_X86_REG_R9, new Long(r9));
		u.reg_write(Unicorn.UC_X86_REG_R10, new Long(r10));
		u.reg_write(Unicorn.UC_X86_REG_R11, new Long(r11));
		u.reg_write(Unicorn.UC_X86_REG_R12, new Long(r12));
		u.reg_write(Unicorn.UC_X86_REG_R13, new Long(r13));
		u.reg_write(Unicorn.UC_X86_REG_R14, new Long(r14));
		u.reg_write(Unicorn.UC_X86_REG_R15, new Long(r15));
		
	    // intercept invalid memory events
	    u.hook_add(new MyWriteInvalidHook(), Unicorn.UC_HOOK_MEM_WRITE_UNMAPPED, null);
	    u.hook_add(new MyReadInvalidHook(),  Unicorn.UC_HOOK_MEM_READ_UNMAPPED, null);
       // tracing all instructions
       u.hook_add(new MyCode64Hook(), 1, 0, null);
       
		// emulate machine code in infinite time (last param = 0), or when
		// finishing all the code.
       
		u.emu_start(ADDRESS, ADDRESS + codeData.length, 0, 0);

		// now print out some registers
		// System.out.print(">>> Emulation done. Below is the CPU context\n");

		Long r_rax = (Long) u.reg_read(Unicorn.UC_X86_REG_RAX);
		
		/*
		Long r_rbx = (Long) u.reg_read(Unicorn.UC_X86_REG_RBX);
		Long r_rcx = (Long) u.reg_read(Unicorn.UC_X86_REG_RCX);
		Long r_rdx = (Long) u.reg_read(Unicorn.UC_X86_REG_RDX);
		Long r_rsi = (Long) u.reg_read(Unicorn.UC_X86_REG_RSI);
		Long r_rdi = (Long) u.reg_read(Unicorn.UC_X86_REG_RDI);
		Long r_r8 = (Long) u.reg_read(Unicorn.UC_X86_REG_R8);
		Long r_r9 = (Long) u.reg_read(Unicorn.UC_X86_REG_R9);
		Long r_r10 = (Long) u.reg_read(Unicorn.UC_X86_REG_R10);
		Long r_r11 = (Long) u.reg_read(Unicorn.UC_X86_REG_R11);
		Long r_r12 = (Long) u.reg_read(Unicorn.UC_X86_REG_R12);
		Long r_r13 = (Long) u.reg_read(Unicorn.UC_X86_REG_R13);
		Long r_r14 = (Long) u.reg_read(Unicorn.UC_X86_REG_R14);
		Long r_r15 = (Long) u.reg_read(Unicorn.UC_X86_REG_R15);
		*/

		/*
		System.out.printf(">>> RAX = 0x%x\n", r_rax.longValue());
		System.out.printf(">>> RBX = 0x%x\n", r_rbx.longValue());
		System.out.printf(">>> RCX = 0x%x\n", r_rcx.longValue());
		System.out.printf(">>> RDX = 0x%x\n", r_rdx.longValue());
		System.out.printf(">>> RSI = 0x%x\n", r_rsi.longValue());
		System.out.printf(">>> RDI = 0x%x\n", r_rdi.longValue());
		System.out.printf(">>> R8 = 0x%x\n", r_r8.longValue());
		System.out.printf(">>> R9 = 0x%x\n", r_r9.longValue());
		System.out.printf(">>> R10 = 0x%x\n", r_r10.longValue());
		System.out.printf(">>> R11 = 0x%x\n", r_r11.longValue());
		System.out.printf(">>> R12 = 0x%x\n", r_r12.longValue());
		System.out.printf(">>> R13 = 0x%x\n", r_r13.longValue());
		System.out.printf(">>> R14 = 0x%x\n", r_r14.longValue());
		System.out.printf(">>> R15 = 0x%x\n", r_r15.longValue());
		*/

		u.close();
		return r_rax.longValue();
	}

	public void runTestNoParameters(String fileName, String functionName) throws Exception {
		byte[] data = SampleLoader.loadFile(fileName);
		Method m = JavaGenerationUtil.loadSample(data, fileName, functionName);
		Integer fib = (Integer) m.invoke(null);

		int[] code = x86GenerationUtil.generateCode(data, functionName);
	
		long returnValue = test_x86_64(code);
		
		assertEquals("Java and x86 Result don't match",fib.intValue(), returnValue);
	}
	
	@Test
	public void testx86() throws Exception {
		runTestNoParameters("Sample1", "entry");
		runTestNoParameters("Sample2", "entry");
		runTestNoParameters("Sample3", "entry");
	}
}
