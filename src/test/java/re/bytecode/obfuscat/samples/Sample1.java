package re.bytecode.obfuscat.samples;

/**
 * Fibonacci Number calculation Sample
 */
public class Sample1 {

	
	public static int entry() {
		
		int n = 28; // 28th fib number
		
		int n1 = 0;
		int n2 = 1;
		int n3 = 0;
		
		if(n == 0) return n1;
		
		for(int i=2;i<=n;i++) {
			n3 = n1 + n2;
			n1 = n2;
			n2 = n3;
		}
		
		return n2;
		
	}
	
}
