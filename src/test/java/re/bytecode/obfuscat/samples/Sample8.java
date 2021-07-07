package re.bytecode.obfuscat.samples;

/**
 * Test Array of Arrays
 */
public class Sample8 {

	
	public static int entry(Object[] array) {
		Object[] data = new Object[5];
		data[3] = new int[2];
		((int[])data[3])[1] = 5;
		return ((int[])data[3])[1];
		//return ((int[])array[0])[2] +  ((int[])array[1])[3];
	}
	
}
