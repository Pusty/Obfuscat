package re.bytecode.obfuscat.samples;

/**
 * Test Array of Arrays
 */
public class Sample8 {

	
	public static int entry(Object[] array) {
		return ((int[])array[0])[2] +  ((int[])array[1])[3];
	}
	
}
