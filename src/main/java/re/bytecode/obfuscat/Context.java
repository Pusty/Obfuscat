package re.bytecode.obfuscat;

import java.util.Random;

/**
 * This is meant to be used internally in Builder, Generator, Custom Node Implementations and Passes to access
 * the processing pipeline (e.g. seeded random, already run passes etc.)
 */
public class Context {
	
	private Random random;
	private long globalSeed;
	private long seed;
	
	/**
	 * Create a new context
	 * @param seed the seed of the context
	 */
	public Context(long seed) {
		this.seed = seed;
		random = new Random(seed);
		globalSeed = random.nextLong();
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
	
	/**
	 * Generate a random value that is deterministic per Context for a any given seed
	 * @param seed the seed to use for a random value
	 * @return a random int
	 */
	public int seededRand(long seed) {
		return new Random(seed^globalSeed).nextInt();
	}
	
	/**
	 * Return the seed of this context
	 * @return the seed
	 */
	public long getInternalSeed() {
		return seed;
	}
	
}
