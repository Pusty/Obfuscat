package re.bytecode.obfuscat.samples;

/**
 * RC4 Implementation - Merged Functions Example
 */
public class Sample7 {

	private static void swap(byte[] array, int a, int b) {
		byte tmp = array[a];
		array[a] = array[b];
		array[b] = tmp;
	}

	private static void KSA(byte[] key, byte[] S) {

	    int len_key = 8;
	    int j = 0;

	    for(int i = 0; i < 256; i++)
	        S[i] = (byte) i;

	    for(int i = 0; i < 256; i++) {
	        j = (j + (S[i]&0xFF) + (key[i % len_key]&0xFF)) % 256;

	        swap(S, i, j);
	    }
	}

	private static void PRGA(byte[] S, byte[] plaintext) {

	    int i = 0;
	    int j = 0;
	    
	    int len_plaintext = 8;

	    for(int n = 0, len = len_plaintext; n < len; n++) {
	        i = (i + 1) % 256;
	        j = (j + (S[i]&0xFF)) % 256;

	        swap(S, i, j);
	        int rnd = S[((S[i]&0xFF) + (S[j]&0xFF)) % 256];

	        plaintext[n] = (byte) (rnd ^ plaintext[n]);

	    }

	}
	
	// key len = 8, plaintext len = 8, buffer len = 256
	public static void rc4(byte[] key, byte[] plaintext, byte[] buffer) {
	    KSA(key, buffer);
	    PRGA(buffer, plaintext);
	    return;
	}

	/*
	public static void main(String[] args) {
		byte[] encoded = new byte[] {0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48};
		entry(new byte[] {0, 1, 2, 3, 4, 5, 6, 7}, encoded, new byte[256]);
		System.out.println(Arrays.toString(encoded));
	}
	*/
}
