package re.bytecode.obfuscat.samples;

/**
 * Prime Number Calculation Sample
 */
public class Sample2 {

	
	public static int entry() {
		int n = 28; // 27th prime

		primeLoop: for (int c = 2;true; c++) {
			for (int i = c - 1; i > 1; i--)
				if (c % i == 0)
					continue primeLoop;
			n--;
			if(n == 0) return c;
		}
	}
	
}
