package re.bytecode.obfuscat.samples;

/**
 * Switch case example
 */
public class Sample5 {

	public static int entry() {
		int v = 0;
		for (int i = 0; i <= 10; i++) {
			switch (i * i) {
			case 81:
				v += 81;
				break;
			case 64:
				v *= 4;
			case 49:
				v += 49;
			case 36:
				v *= 2;
				break;
			case 25:
				v -= 3;
			case 16:
				v += 32;
				break;
			case 9:
				v += 9;
			case 4:
				v += 4;
				break;	
			case 1:
				v += 1337;
			default:
				v += 42;
				break;
			}
		}
		return v;
		
	}
	
	

}
