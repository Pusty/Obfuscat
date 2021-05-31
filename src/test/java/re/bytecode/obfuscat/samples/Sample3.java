package re.bytecode.obfuscat.samples;

/**
 * Math Operation Test Sample
 */
public class Sample3 {

	public static int entry() {
		int a = 1;
		int b = 7;
		int c = 235;
		int d = -9999;
		return (a*b)+(a*d)+(c/d)+(b/c)+(a-b)+(c-d)+(b&c)+(c|d)+(d^b)+(~d)+(-d)-(a*b % c);
	}

}
