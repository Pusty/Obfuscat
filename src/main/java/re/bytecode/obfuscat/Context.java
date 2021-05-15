package re.bytecode.obfuscat;

import java.util.Random;

/**
 * This is meant to be used internally in Builder, Generator, Custom Node Implementations and Passes to access
 * the processing pipeline (e.g. seeded random, already run passes etc.)
 */
public class Context {
	
	private Random random;
	
	public Context(long seed) {
		random = new Random(seed);
	}
	
	/**
	 * Return a random number
	 * @return random.nextInt()
	 */
	public int rand() {
		return random.nextInt();
	}
	
	/**
	 * Return the internal random
	 * @return random
	 */
	public Random random() {
		return random;
	}
	
}
