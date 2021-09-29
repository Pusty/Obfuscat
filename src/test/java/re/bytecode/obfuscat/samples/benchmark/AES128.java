package re.bytecode.obfuscat.samples.benchmark;

// AES-128
public class AES128 {

	// Original Version from
	// Ported and modified from C
	// https://github.com/kokke/tiny-AES-c/blob/master/aes.c

	private static final int Nb = 4;
	private static final int Nk = 4;
	private static final int Nr = 10;

	private static final byte sbox[] = {
			// 0 1 2 3 4 5 6 7 8 9 A B C D E F
			0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe,
			(byte) 0xd7, (byte) 0xab, 0x76, (byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47,
			(byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72,
			(byte) 0xc0, (byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34,
			(byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15, 0x04, (byte) 0xc7, 0x23, (byte) 0xc3,
			0x18, (byte) 0x96, 0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2,
			0x75, 0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6, (byte) 0xb3,
			0x29, (byte) 0xe3, 0x2f, (byte) 0x84, 0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1,
			0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf, (byte) 0xd0, (byte) 0xef,
			(byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c,
			(byte) 0x9f, (byte) 0xa8, 0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5,
			(byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2, (byte) 0xcd, 0x0c,
			0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
			0x73, 0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee,
			(byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb, (byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24,
			0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79, (byte) 0xe7,
			(byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56, (byte) 0xf4, (byte) 0xea,
			0x65, 0x7a, (byte) 0xae, 0x08, (byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6,
			(byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a, 0x70, 0x3e, (byte) 0xb5,
			0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d,
			(byte) 0x9e, (byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94,
			(byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf, (byte) 0x8c, (byte) 0xa1,
			(byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54,
			(byte) 0xbb, 0x16 };

	private static final byte rsbox[] = { 0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38, (byte) 0xbf,
			0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb, 0x7c, (byte) 0xe3, 0x39,
			(byte) 0x82, (byte) 0x9b, 0x2f, (byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43, 0x44, (byte) 0xc4,
			(byte) 0xde, (byte) 0xe9, (byte) 0xcb, 0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2, 0x23, 0x3d,
			(byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42, (byte) 0xfa, (byte) 0xc3, 0x4e, 0x08, 0x2e, (byte) 0xa1, 0x66,
			0x28, (byte) 0xd9, 0x24, (byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d, (byte) 0x8b, (byte) 0xd1, 0x25,
			0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68, (byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c,
			(byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92, 0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed,
			(byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84,
			(byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7,
			(byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3, 0x45, 0x06, (byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f,
			(byte) 0xca, 0x3f, 0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, 0x03, 0x01, 0x13, (byte) 0x8a, 0x6b,
			0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf,
			(byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, 0x73, (byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7,
			(byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75, (byte) 0xdf, 0x6e,
			0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5, (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e,
			(byte) 0xaa, 0x18, (byte) 0xbe, 0x1b, (byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2, 0x79, 0x20,
			(byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4, 0x1f, (byte) 0xdd,
			(byte) 0xa8, 0x33, (byte) 0x88, 0x07, (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27, (byte) 0x80,
			(byte) 0xec, 0x5f, 0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d, 0x2d, (byte) 0xe5, 0x7a,
			(byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef, (byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d,
			(byte) 0xae, 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, 0x3c, (byte) 0x83, 0x53,
			(byte) 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26, (byte) 0xe1, 0x69, 0x14,
			0x63, 0x55, 0x21, 0x0c, 0x7d };

	private static final byte Rcon[] = { (byte) 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, (byte) 0x80, 0x1b,
			0x36 };

	private static byte getSBoxValue(byte num) {
		return sbox[num & 0xFF];
	}

	private static void KeyExpansion(byte[] RoundKey, byte[] Key) {
		int i, j, k;
		byte[] tempa = new byte[4]; // Used for the column/row operations

		// The first round key is the key itself.
		for (i = 0; i < Nk; ++i) {
			RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
			RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
			RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
			RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
		}

		// All other round keys are found from the previous round keys.
		for (i = Nk; i < Nb * (Nr + 1); ++i) {
			{
				k = (i - 1) * 4;
				tempa[0] = RoundKey[k + 0];
				tempa[1] = RoundKey[k + 1];
				tempa[2] = RoundKey[k + 2];
				tempa[3] = RoundKey[k + 3];

			}

			if (i % Nk == 0) {

				{
					byte u8tmp = tempa[0];
					tempa[0] = tempa[1];
					tempa[1] = tempa[2];
					tempa[2] = tempa[3];
					tempa[3] = u8tmp;
				}

				{
					tempa[0] = getSBoxValue(tempa[0]);
					tempa[1] = getSBoxValue(tempa[1]);
					tempa[2] = getSBoxValue(tempa[2]);
					tempa[3] = getSBoxValue(tempa[3]);
				}

				tempa[0] = (byte) (tempa[0] ^ Rcon[i / Nk]);
			}

			j = i * 4;
			k = (i - Nk) * 4;
			RoundKey[j + 0] = (byte) (RoundKey[k + 0] ^ tempa[0]);
			RoundKey[j + 1] = (byte) (RoundKey[k + 1] ^ tempa[1]);
			RoundKey[j + 2] = (byte) (RoundKey[k + 2] ^ tempa[2]);
			RoundKey[j + 3] = (byte) (RoundKey[k + 3] ^ tempa[3]);
		}
	}

	private static void AES_init_ctx(byte[] RoundKey, byte[] key) {
		KeyExpansion(RoundKey, key);
	}

	private static void AddRoundKey(byte round, byte[] state, byte[] RoundKey) {
		int i, j;
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				state[i * 4 + j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
			}
		}
	}

	private static void SubBytes(byte[] state) {
		int i, j;
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				state[i * 4 + j] = getSBoxValue(state[i * 4 + j]);
			}
		}
	}

	private static void ShiftRows(byte[] state) {
		byte temp;
		temp = state[0 * 4 + 1];
		state[0 * 4 + 1] = state[1 * 4 + 1];
		state[1 * 4 + 1] = state[2 * 4 + 1];
		state[2 * 4 + 1] = state[3 * 4 + 1];
		state[3 * 4 + 1] = temp;
		temp = state[0 * 4 + 2];
		state[0 * 4 + 2] = state[2 * 4 + 2];
		state[2 * 4 + 2] = temp;
		temp = state[1 * 4 + 2];
		state[1 * 4 + 2] = state[3 * 4 + 2];
		state[3 * 4 + 2] = temp;
		temp = state[0 * 4 + 3];
		state[0 * 4 + 3] = state[3 * 4 + 3];
		state[3 * 4 + 3] = state[2 * 4 + 3];
		state[2 * 4 + 3] = state[1 * 4 + 3];
		state[1 * 4 + 3] = temp;
	}

	private static byte xtime(byte x) {
		return (byte) ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
	}

	private static void MixColumns(byte[] state) {
		int i;
		byte Tmp, Tm, t;
		for (i = 0; i < 4; ++i) {
			t = state[i * 4 + 0];
			Tmp = (byte) (state[i * 4 + 0] ^ state[i * 4 + 1] ^ state[i * 4 + 2] ^ state[i * 4 + 3]);
			Tm = (byte) (state[i * 4 + 0] ^ state[i * 4 + 1]);
			Tm = xtime(Tm);
			state[i * 4 + 0] ^= Tm ^ Tmp;
			Tm = (byte) (state[i * 4 + 1] ^ state[i * 4 + 2]);
			Tm = xtime(Tm);
			state[i * 4 + 1] ^= Tm ^ Tmp;
			Tm = (byte) (state[i * 4 + 2] ^ state[i * 4 + 3]);
			Tm = xtime(Tm);
			state[i * 4 + 2] ^= Tm ^ Tmp;
			Tm = (byte) (state[i * 4 + 3] ^ t);
			Tm = xtime(Tm);
			state[i * 4 + 3] ^= Tm ^ Tmp;
		}
	}

	private static byte Multiply(byte x, byte y) {
		return (byte) (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x)))
				^ ((y >> 3 & 1) * xtime(xtime(xtime(x))))
				^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
	}

	private static byte getSBoxInvert(byte num) {
		return rsbox[num & 0xFF];
	}

	// MixColumns function mixes the columns of the state matrix.
	// The method used to multiply may be difficult to understand for the
	// inexperienced.
	// Please use the references to gain more information.
	private static void InvMixColumns(byte[] state) {
		int i;
		byte a, b, c, d;
		for (i = 0; i < 4; ++i) {
			a = state[i * 4 + 0];
			b = state[i * 4 + 1];
			c = state[i * 4 + 2];
			d = state[i * 4 + 3];

			state[i * 4 + 0] = (byte) (Multiply(a, (byte) 0x0e) ^ Multiply(b, (byte) 0x0b) ^ Multiply(c, (byte) 0x0d)
					^ Multiply(d, (byte) 0x09));
			state[i * 4 + 1] = (byte) (Multiply(a, (byte) 0x09) ^ Multiply(b, (byte) 0x0e) ^ Multiply(c, (byte) 0x0b)
					^ Multiply(d, (byte) 0x0d));
			state[i * 4 + 2] = (byte) (Multiply(a, (byte) 0x0d) ^ Multiply(b, (byte) 0x09) ^ Multiply(c, (byte) 0x0e)
					^ Multiply(d, (byte) 0x0b));
			state[i * 4 + 3] = (byte) (Multiply(a, (byte) 0x0b) ^ Multiply(b, (byte) 0x0d) ^ Multiply(c, (byte) 0x09)
					^ Multiply(d, (byte) 0x0e));
		}
	}

	// The SubBytes Function Substitutes the values in the
	// state matrix with values in an S-box.
	private static void InvSubBytes(byte[] state) {
		int i, j;
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				state[j * 4 + i] = getSBoxInvert(state[j * 4 + i]);
			}
		}
	}

	private static void InvShiftRows(byte[] state) {
		byte temp;

		temp = state[3 * 4 + 1];
		state[3 * 4 + 1] = state[2 * 4 + 1];
		state[2 * 4 + 1] = state[1 * 4 + 1];
		state[1 * 4 + 1] = state[0 * 4 + 1];
		state[0 * 4 + 1] = temp;

		temp = state[0 * 4 + 2];
		state[0 * 4 + 2] = state[2 * 4 + 2];
		state[2 * 4 + 2] = temp;

		temp = state[1 * 4 + 2];
		state[1 * 4 + 2] = state[3 * 4 + 2];
		state[3 * 4 + 2] = temp;

		temp = state[0 * 4 + 3];
		state[0 * 4 + 3] = state[1 * 4 + 3];
		state[1 * 4 + 3] = state[2 * 4 + 3];
		state[2 * 4 + 3] = state[3 * 4 + 3];
		state[3 * 4 + 3] = temp;
	}

	private static void Cipher(byte[] state, byte[] RoundKey) {
		int round = 0;
		AddRoundKey((byte) 0, state, RoundKey);
		for (round = 1;; ++round) {
			SubBytes(state);
			ShiftRows(state);
			if (round == Nr) {
				break;
			}
			MixColumns(state);
			AddRoundKey((byte) round, state, RoundKey);
		}
		// Add round key to last round
		AddRoundKey((byte) Nr, state, RoundKey);
	}

	private static void InvCipher(byte[] state, byte[] RoundKey) {
		int round = 0;
		AddRoundKey((byte) Nr, state, RoundKey);

		for (round = (Nr - 1);; --round) {
			InvShiftRows(state);
			InvSubBytes(state);
			AddRoundKey((byte) round, state, RoundKey);
			if (round == 0) {
				break;
			}
			InvMixColumns(state);
		}

	}

	private static void AES_ECB_encrypt(byte[] RoundKey, byte[] buf) {
		Cipher(buf, RoundKey);
	}

	private static void AES_ECB_decrypt(byte[] RoundKey, byte[] buf) {
		InvCipher(buf, RoundKey);
	}

	public static int entry(byte[] message, int len) {
        byte[] key = new byte[16];
        for(int i=0;i<16;i++)
            key[i] = (byte)i;


		byte[] roundKey = new byte[176];
		AES_init_ctx(roundKey, key);
        
        
        int res = 0;
        byte[] data = new byte[16];
        for(int i=0;i<len;i+=16) {
            for(int j=0;j<16;j++)
                data[j] = 0;
            for(int j=0;j<16 && j<(len-i);j++)
                data[j] = message[i+j];
            
            AES_ECB_encrypt(roundKey, data); // reencrypt it to test
            AES_ECB_decrypt(roundKey, data); // if encrypt and decryption is symmetric
            
            res ^= data[0];
        }
        
        return res;
	}

}
