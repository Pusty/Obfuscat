package re.bytecode.obfuscat.samples.benchmark;

/**
 * RC4 Implementation - Merged Functions Example
 */
public class RC4 {
    
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

	private static void PRGA(byte[] S, byte[] plaintext, int len) {

	    int i = 0;
	    int j = 0;

	    for(int n = 0; n < len; n++) {
	        i = (i + 1) % 256;
	        j = (j + (S[i]&0xFF)) % 256;
            
	        swap(S, i, j);
	        int rnd = S[((S[i]&0xFF) + (S[j]&0xFF)) % 256];
            
	        plaintext[n] = (byte) (rnd ^ plaintext[n]);

	    }

	}
	
	// key len = 8
	private static void rc4(byte[] key, byte[] plaintext, int len) {
		byte[] buffer = new byte[256];
	    KSA(key, buffer);
	    PRGA(buffer, plaintext, len);
	    return;
	}
    
    public static int entry(byte[] data, int len) {
        byte[] key = new byte[8];
        key[0] = 0x01;
        key[1] = 0x02;
        key[2] = 0x03;
        key[3] = 0x04;
        key[4] = 0x05;
        key[5] = 0x06;
        key[6] = 0x07;
        key[7] = 0x08;
        
        byte[] tmp = new byte[len];
        for(int i=0;i<len;i++)
            tmp[i] = data[i];
        
        rc4(key, tmp, len);
        return tmp[0]&0xFF;
    }
    
}