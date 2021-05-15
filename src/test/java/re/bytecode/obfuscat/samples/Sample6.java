package re.bytecode.obfuscat.samples;

import re.bytecode.obfuscat.dsl.api.ExcludeMethod;

/**
 * Internal Function Use Sample
 */
public class Sample6 {

	@ExcludeMethod
	private static int native_readInt(int address) { return 0xBEEFBEEF; } // mock function with mock result for tests
	
	public static int entry() {
		return native_readInt(0x123);
	}
	
	

}
