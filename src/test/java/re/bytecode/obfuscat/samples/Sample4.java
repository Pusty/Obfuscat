package re.bytecode.obfuscat.samples;

/**
 * CRC32 Implementation Sample
 */
public class Sample4 {
	
	// https://introcs.cs.princeton.edu/java/61data/CRC32.java.html
	public static int crc32(byte[] message, int len) {
		int crc = 0xFFFFFFFF;
		
		for(int i=0;i<len;i++) {
            int temp = (crc ^ message[i]) & 0xff;
            for (int j = 0; j < 8; j++) {
                if ((temp & 1) == 1)
                	temp = (temp >>> 1) ^ 0xEDB88320;
                else               
                	temp = (temp >>> 1);
            }
            crc = (crc >>> 8) ^ temp;
		}
		return ~crc;
	}

}
