package re.bytecode.obfuscat.samples;

// SHA-1
public class Sample10 {

	// Original Version from
	// Ported and modified from C
	// https://github.com/983/SHA1/blob/master/sha1.hpp

	private static final int c0 = 0x5a827999;
	private static final int c1 = 0x6ed9eba1;
	private static final int c2 = 0x8f1bbcdc;
	private static final int c3 = 0xca62c1d6;

	private static int rol32(int x, int n) {
		return (x << n) | (x >>> (32 - n));
	}

	private static void process_block(int[] state, byte[] buf, int offset) {
		int a = state[0];
		int b = state[1];
		int c = state[2];
		int d = state[3];
		int e = state[4];

		int w[] = new int[16];

		for (int i = offset; i < offset + 16; i++)
			w[i] = ((int) (buf[i * 4 + 0] & 0xFF) << 3 * 8) | ((int) (buf[i * 4 + 1] & 0xFF) << 2 * 8)
					| ((int) (buf[i * 4 + 2] & 0xFF) << 1 * 8) | ((int) (buf[i * 4 + 3] & 0xFF) << 0 * 8);

		e += ((b & (c ^ d)) ^ d) + w[0 & 15] + c0 + rol32(a, 5);
		b = rol32(b, 30);
		d += ((a & (b ^ c)) ^ c) + w[1 & 15] + c0 + rol32(e, 5);
		a = rol32(a, 30);
		c += ((e & (a ^ b)) ^ b) + w[2 & 15] + c0 + rol32(d, 5);
		e = rol32(e, 30);
		b += ((d & (e ^ a)) ^ a) + w[3 & 15] + c0 + rol32(c, 5);
		d = rol32(d, 30);
		a += ((c & (d ^ e)) ^ e) + w[4 & 15] + c0 + rol32(b, 5);
		c = rol32(c, 30);
		e += ((b & (c ^ d)) ^ d) + w[5 & 15] + c0 + rol32(a, 5);
		b = rol32(b, 30);
		d += ((a & (b ^ c)) ^ c) + w[6 & 15] + c0 + rol32(e, 5);
		a = rol32(a, 30);
		c += ((e & (a ^ b)) ^ b) + w[7 & 15] + c0 + rol32(d, 5);
		e = rol32(e, 30);
		b += ((d & (e ^ a)) ^ a) + w[8 & 15] + c0 + rol32(c, 5);
		d = rol32(d, 30);
		a += ((c & (d ^ e)) ^ e) + w[9 & 15] + c0 + rol32(b, 5);
		c = rol32(c, 30);
		e += ((b & (c ^ d)) ^ d) + w[10 & 15] + c0 + rol32(a, 5);
		b = rol32(b, 30);
		d += ((a & (b ^ c)) ^ c) + w[11 & 15] + c0 + rol32(e, 5);
		a = rol32(a, 30);
		c += ((e & (a ^ b)) ^ b) + w[12 & 15] + c0 + rol32(d, 5);
		e = rol32(e, 30);
		b += ((d & (e ^ a)) ^ a) + w[13 & 15] + c0 + rol32(c, 5);
		d = rol32(d, 30);
		a += ((c & (d ^ e)) ^ e) + w[14 & 15] + c0 + rol32(b, 5);
		c = rol32(c, 30);
		e += ((b & (c ^ d)) ^ d) + w[15 & 15] + c0 + rol32(a, 5);
		b = rol32(b, 30);
		w[16 & 15] = rol32(w[(16 + 13) & 15] ^ w[(16 + 8) & 15] ^ w[(16 + 2) & 15] ^ w[16 & 15], 1);
		d += ((a & (b ^ c)) ^ c) + w[16 & 15] + c0 + rol32(e, 5);
		a = rol32(a, 30);
		w[17 & 15] = rol32(w[(17 + 13) & 15] ^ w[(17 + 8) & 15] ^ w[(17 + 2) & 15] ^ w[17 & 15], 1);
		c += ((e & (a ^ b)) ^ b) + w[17 & 15] + c0 + rol32(d, 5);
		e = rol32(e, 30);
		w[18 & 15] = rol32(w[(18 + 13) & 15] ^ w[(18 + 8) & 15] ^ w[(18 + 2) & 15] ^ w[18 & 15], 1);
		b += ((d & (e ^ a)) ^ a) + w[18 & 15] + c0 + rol32(c, 5);
		d = rol32(d, 30);
		w[19 & 15] = rol32(w[(19 + 13) & 15] ^ w[(19 + 8) & 15] ^ w[(19 + 2) & 15] ^ w[19 & 15], 1);
		a += ((c & (d ^ e)) ^ e) + w[19 & 15] + c0 + rol32(b, 5);
		c = rol32(c, 30);
		w[20 & 15] = rol32(w[(20 + 13) & 15] ^ w[(20 + 8) & 15] ^ w[(20 + 2) & 15] ^ w[20 & 15], 1);
		e += (b ^ c ^ d) + w[20 & 15] + c1 + rol32(a, 5);
		b = rol32(b, 30);
		w[21 & 15] = rol32(w[(21 + 13) & 15] ^ w[(21 + 8) & 15] ^ w[(21 + 2) & 15] ^ w[21 & 15], 1);
		d += (a ^ b ^ c) + w[21 & 15] + c1 + rol32(e, 5);
		a = rol32(a, 30);
		w[22 & 15] = rol32(w[(22 + 13) & 15] ^ w[(22 + 8) & 15] ^ w[(22 + 2) & 15] ^ w[22 & 15], 1);
		c += (e ^ a ^ b) + w[22 & 15] + c1 + rol32(d, 5);
		e = rol32(e, 30);
		w[23 & 15] = rol32(w[(23 + 13) & 15] ^ w[(23 + 8) & 15] ^ w[(23 + 2) & 15] ^ w[23 & 15], 1);
		b += (d ^ e ^ a) + w[23 & 15] + c1 + rol32(c, 5);
		d = rol32(d, 30);
		w[24 & 15] = rol32(w[(24 + 13) & 15] ^ w[(24 + 8) & 15] ^ w[(24 + 2) & 15] ^ w[24 & 15], 1);
		a += (c ^ d ^ e) + w[24 & 15] + c1 + rol32(b, 5);
		c = rol32(c, 30);
		w[25 & 15] = rol32(w[(25 + 13) & 15] ^ w[(25 + 8) & 15] ^ w[(25 + 2) & 15] ^ w[25 & 15], 1);
		e += (b ^ c ^ d) + w[25 & 15] + c1 + rol32(a, 5);
		b = rol32(b, 30);
		w[26 & 15] = rol32(w[(26 + 13) & 15] ^ w[(26 + 8) & 15] ^ w[(26 + 2) & 15] ^ w[26 & 15], 1);
		d += (a ^ b ^ c) + w[26 & 15] + c1 + rol32(e, 5);
		a = rol32(a, 30);
		w[27 & 15] = rol32(w[(27 + 13) & 15] ^ w[(27 + 8) & 15] ^ w[(27 + 2) & 15] ^ w[27 & 15], 1);
		c += (e ^ a ^ b) + w[27 & 15] + c1 + rol32(d, 5);
		e = rol32(e, 30);
		w[28 & 15] = rol32(w[(28 + 13) & 15] ^ w[(28 + 8) & 15] ^ w[(28 + 2) & 15] ^ w[28 & 15], 1);
		b += (d ^ e ^ a) + w[28 & 15] + c1 + rol32(c, 5);
		d = rol32(d, 30);
		w[29 & 15] = rol32(w[(29 + 13) & 15] ^ w[(29 + 8) & 15] ^ w[(29 + 2) & 15] ^ w[29 & 15], 1);
		a += (c ^ d ^ e) + w[29 & 15] + c1 + rol32(b, 5);
		c = rol32(c, 30);
		w[30 & 15] = rol32(w[(30 + 13) & 15] ^ w[(30 + 8) & 15] ^ w[(30 + 2) & 15] ^ w[30 & 15], 1);
		e += (b ^ c ^ d) + w[30 & 15] + c1 + rol32(a, 5);
		b = rol32(b, 30);
		w[31 & 15] = rol32(w[(31 + 13) & 15] ^ w[(31 + 8) & 15] ^ w[(31 + 2) & 15] ^ w[31 & 15], 1);
		d += (a ^ b ^ c) + w[31 & 15] + c1 + rol32(e, 5);
		a = rol32(a, 30);
		w[32 & 15] = rol32(w[(32 + 13) & 15] ^ w[(32 + 8) & 15] ^ w[(32 + 2) & 15] ^ w[32 & 15], 1);
		c += (e ^ a ^ b) + w[32 & 15] + c1 + rol32(d, 5);
		e = rol32(e, 30);
		w[33 & 15] = rol32(w[(33 + 13) & 15] ^ w[(33 + 8) & 15] ^ w[(33 + 2) & 15] ^ w[33 & 15], 1);
		b += (d ^ e ^ a) + w[33 & 15] + c1 + rol32(c, 5);
		d = rol32(d, 30);
		w[34 & 15] = rol32(w[(34 + 13) & 15] ^ w[(34 + 8) & 15] ^ w[(34 + 2) & 15] ^ w[34 & 15], 1);
		a += (c ^ d ^ e) + w[34 & 15] + c1 + rol32(b, 5);
		c = rol32(c, 30);
		w[35 & 15] = rol32(w[(35 + 13) & 15] ^ w[(35 + 8) & 15] ^ w[(35 + 2) & 15] ^ w[35 & 15], 1);
		e += (b ^ c ^ d) + w[35 & 15] + c1 + rol32(a, 5);
		b = rol32(b, 30);
		w[36 & 15] = rol32(w[(36 + 13) & 15] ^ w[(36 + 8) & 15] ^ w[(36 + 2) & 15] ^ w[36 & 15], 1);
		d += (a ^ b ^ c) + w[36 & 15] + c1 + rol32(e, 5);
		a = rol32(a, 30);
		w[37 & 15] = rol32(w[(37 + 13) & 15] ^ w[(37 + 8) & 15] ^ w[(37 + 2) & 15] ^ w[37 & 15], 1);
		c += (e ^ a ^ b) + w[37 & 15] + c1 + rol32(d, 5);
		e = rol32(e, 30);
		w[38 & 15] = rol32(w[(38 + 13) & 15] ^ w[(38 + 8) & 15] ^ w[(38 + 2) & 15] ^ w[38 & 15], 1);
		b += (d ^ e ^ a) + w[38 & 15] + c1 + rol32(c, 5);
		d = rol32(d, 30);
		w[39 & 15] = rol32(w[(39 + 13) & 15] ^ w[(39 + 8) & 15] ^ w[(39 + 2) & 15] ^ w[39 & 15], 1);
		a += (c ^ d ^ e) + w[39 & 15] + c1 + rol32(b, 5);
		c = rol32(c, 30);
		w[40 & 15] = rol32(w[(40 + 13) & 15] ^ w[(40 + 8) & 15] ^ w[(40 + 2) & 15] ^ w[40 & 15], 1);
		e += (((b | c) & d) | (b & c)) + w[40 & 15] + c2 + rol32(a, 5);
		b = rol32(b, 30);
		w[41 & 15] = rol32(w[(41 + 13) & 15] ^ w[(41 + 8) & 15] ^ w[(41 + 2) & 15] ^ w[41 & 15], 1);
		d += (((a | b) & c) | (a & b)) + w[41 & 15] + c2 + rol32(e, 5);
		a = rol32(a, 30);
		w[42 & 15] = rol32(w[(42 + 13) & 15] ^ w[(42 + 8) & 15] ^ w[(42 + 2) & 15] ^ w[42 & 15], 1);
		c += (((e | a) & b) | (e & a)) + w[42 & 15] + c2 + rol32(d, 5);
		e = rol32(e, 30);
		w[43 & 15] = rol32(w[(43 + 13) & 15] ^ w[(43 + 8) & 15] ^ w[(43 + 2) & 15] ^ w[43 & 15], 1);
		b += (((d | e) & a) | (d & e)) + w[43 & 15] + c2 + rol32(c, 5);
		d = rol32(d, 30);
		w[44 & 15] = rol32(w[(44 + 13) & 15] ^ w[(44 + 8) & 15] ^ w[(44 + 2) & 15] ^ w[44 & 15], 1);
		a += (((c | d) & e) | (c & d)) + w[44 & 15] + c2 + rol32(b, 5);
		c = rol32(c, 30);
		w[45 & 15] = rol32(w[(45 + 13) & 15] ^ w[(45 + 8) & 15] ^ w[(45 + 2) & 15] ^ w[45 & 15], 1);
		e += (((b | c) & d) | (b & c)) + w[45 & 15] + c2 + rol32(a, 5);
		b = rol32(b, 30);
		w[46 & 15] = rol32(w[(46 + 13) & 15] ^ w[(46 + 8) & 15] ^ w[(46 + 2) & 15] ^ w[46 & 15], 1);
		d += (((a | b) & c) | (a & b)) + w[46 & 15] + c2 + rol32(e, 5);
		a = rol32(a, 30);
		w[47 & 15] = rol32(w[(47 + 13) & 15] ^ w[(47 + 8) & 15] ^ w[(47 + 2) & 15] ^ w[47 & 15], 1);
		c += (((e | a) & b) | (e & a)) + w[47 & 15] + c2 + rol32(d, 5);
		e = rol32(e, 30);
		w[48 & 15] = rol32(w[(48 + 13) & 15] ^ w[(48 + 8) & 15] ^ w[(48 + 2) & 15] ^ w[48 & 15], 1);
		b += (((d | e) & a) | (d & e)) + w[48 & 15] + c2 + rol32(c, 5);
		d = rol32(d, 30);
		w[49 & 15] = rol32(w[(49 + 13) & 15] ^ w[(49 + 8) & 15] ^ w[(49 + 2) & 15] ^ w[49 & 15], 1);
		a += (((c | d) & e) | (c & d)) + w[49 & 15] + c2 + rol32(b, 5);
		c = rol32(c, 30);
		w[50 & 15] = rol32(w[(50 + 13) & 15] ^ w[(50 + 8) & 15] ^ w[(50 + 2) & 15] ^ w[50 & 15], 1);
		e += (((b | c) & d) | (b & c)) + w[50 & 15] + c2 + rol32(a, 5);
		b = rol32(b, 30);
		w[51 & 15] = rol32(w[(51 + 13) & 15] ^ w[(51 + 8) & 15] ^ w[(51 + 2) & 15] ^ w[51 & 15], 1);
		d += (((a | b) & c) | (a & b)) + w[51 & 15] + c2 + rol32(e, 5);
		a = rol32(a, 30);
		w[52 & 15] = rol32(w[(52 + 13) & 15] ^ w[(52 + 8) & 15] ^ w[(52 + 2) & 15] ^ w[52 & 15], 1);
		c += (((e | a) & b) | (e & a)) + w[52 & 15] + c2 + rol32(d, 5);
		e = rol32(e, 30);
		w[53 & 15] = rol32(w[(53 + 13) & 15] ^ w[(53 + 8) & 15] ^ w[(53 + 2) & 15] ^ w[53 & 15], 1);
		b += (((d | e) & a) | (d & e)) + w[53 & 15] + c2 + rol32(c, 5);
		d = rol32(d, 30);
		w[54 & 15] = rol32(w[(54 + 13) & 15] ^ w[(54 + 8) & 15] ^ w[(54 + 2) & 15] ^ w[54 & 15], 1);
		a += (((c | d) & e) | (c & d)) + w[54 & 15] + c2 + rol32(b, 5);
		c = rol32(c, 30);
		w[55 & 15] = rol32(w[(55 + 13) & 15] ^ w[(55 + 8) & 15] ^ w[(55 + 2) & 15] ^ w[55 & 15], 1);
		e += (((b | c) & d) | (b & c)) + w[55 & 15] + c2 + rol32(a, 5);
		b = rol32(b, 30);
		w[56 & 15] = rol32(w[(56 + 13) & 15] ^ w[(56 + 8) & 15] ^ w[(56 + 2) & 15] ^ w[56 & 15], 1);
		d += (((a | b) & c) | (a & b)) + w[56 & 15] + c2 + rol32(e, 5);
		a = rol32(a, 30);
		w[57 & 15] = rol32(w[(57 + 13) & 15] ^ w[(57 + 8) & 15] ^ w[(57 + 2) & 15] ^ w[57 & 15], 1);
		c += (((e | a) & b) | (e & a)) + w[57 & 15] + c2 + rol32(d, 5);
		e = rol32(e, 30);
		w[58 & 15] = rol32(w[(58 + 13) & 15] ^ w[(58 + 8) & 15] ^ w[(58 + 2) & 15] ^ w[58 & 15], 1);
		b += (((d | e) & a) | (d & e)) + w[58 & 15] + c2 + rol32(c, 5);
		d = rol32(d, 30);
		w[59 & 15] = rol32(w[(59 + 13) & 15] ^ w[(59 + 8) & 15] ^ w[(59 + 2) & 15] ^ w[59 & 15], 1);
		a += (((c | d) & e) | (c & d)) + w[59 & 15] + c2 + rol32(b, 5);
		c = rol32(c, 30);
		w[60 & 15] = rol32(w[(60 + 13) & 15] ^ w[(60 + 8) & 15] ^ w[(60 + 2) & 15] ^ w[60 & 15], 1);
		e += (b ^ c ^ d) + w[60 & 15] + c3 + rol32(a, 5);
		b = rol32(b, 30);
		w[61 & 15] = rol32(w[(61 + 13) & 15] ^ w[(61 + 8) & 15] ^ w[(61 + 2) & 15] ^ w[61 & 15], 1);
		d += (a ^ b ^ c) + w[61 & 15] + c3 + rol32(e, 5);
		a = rol32(a, 30);
		w[62 & 15] = rol32(w[(62 + 13) & 15] ^ w[(62 + 8) & 15] ^ w[(62 + 2) & 15] ^ w[62 & 15], 1);
		c += (e ^ a ^ b) + w[62 & 15] + c3 + rol32(d, 5);
		e = rol32(e, 30);
		w[63 & 15] = rol32(w[(63 + 13) & 15] ^ w[(63 + 8) & 15] ^ w[(63 + 2) & 15] ^ w[63 & 15], 1);
		b += (d ^ e ^ a) + w[63 & 15] + c3 + rol32(c, 5);
		d = rol32(d, 30);
		w[64 & 15] = rol32(w[(64 + 13) & 15] ^ w[(64 + 8) & 15] ^ w[(64 + 2) & 15] ^ w[64 & 15], 1);
		a += (c ^ d ^ e) + w[64 & 15] + c3 + rol32(b, 5);
		c = rol32(c, 30);
		w[65 & 15] = rol32(w[(65 + 13) & 15] ^ w[(65 + 8) & 15] ^ w[(65 + 2) & 15] ^ w[65 & 15], 1);
		e += (b ^ c ^ d) + w[65 & 15] + c3 + rol32(a, 5);
		b = rol32(b, 30);
		w[66 & 15] = rol32(w[(66 + 13) & 15] ^ w[(66 + 8) & 15] ^ w[(66 + 2) & 15] ^ w[66 & 15], 1);
		d += (a ^ b ^ c) + w[66 & 15] + c3 + rol32(e, 5);
		a = rol32(a, 30);
		w[67 & 15] = rol32(w[(67 + 13) & 15] ^ w[(67 + 8) & 15] ^ w[(67 + 2) & 15] ^ w[67 & 15], 1);
		c += (e ^ a ^ b) + w[67 & 15] + c3 + rol32(d, 5);
		e = rol32(e, 30);
		w[68 & 15] = rol32(w[(68 + 13) & 15] ^ w[(68 + 8) & 15] ^ w[(68 + 2) & 15] ^ w[68 & 15], 1);
		b += (d ^ e ^ a) + w[68 & 15] + c3 + rol32(c, 5);
		d = rol32(d, 30);
		w[69 & 15] = rol32(w[(69 + 13) & 15] ^ w[(69 + 8) & 15] ^ w[(69 + 2) & 15] ^ w[69 & 15], 1);
		a += (c ^ d ^ e) + w[69 & 15] + c3 + rol32(b, 5);
		c = rol32(c, 30);
		w[70 & 15] = rol32(w[(70 + 13) & 15] ^ w[(70 + 8) & 15] ^ w[(70 + 2) & 15] ^ w[70 & 15], 1);
		e += (b ^ c ^ d) + w[70 & 15] + c3 + rol32(a, 5);
		b = rol32(b, 30);
		w[71 & 15] = rol32(w[(71 + 13) & 15] ^ w[(71 + 8) & 15] ^ w[(71 + 2) & 15] ^ w[71 & 15], 1);
		d += (a ^ b ^ c) + w[71 & 15] + c3 + rol32(e, 5);
		a = rol32(a, 30);
		w[72 & 15] = rol32(w[(72 + 13) & 15] ^ w[(72 + 8) & 15] ^ w[(72 + 2) & 15] ^ w[72 & 15], 1);
		c += (e ^ a ^ b) + w[72 & 15] + c3 + rol32(d, 5);
		e = rol32(e, 30);
		w[73 & 15] = rol32(w[(73 + 13) & 15] ^ w[(73 + 8) & 15] ^ w[(73 + 2) & 15] ^ w[73 & 15], 1);
		b += (d ^ e ^ a) + w[73 & 15] + c3 + rol32(c, 5);
		d = rol32(d, 30);
		w[74 & 15] = rol32(w[(74 + 13) & 15] ^ w[(74 + 8) & 15] ^ w[(74 + 2) & 15] ^ w[74 & 15], 1);
		a += (c ^ d ^ e) + w[74 & 15] + c3 + rol32(b, 5);
		c = rol32(c, 30);
		w[75 & 15] = rol32(w[(75 + 13) & 15] ^ w[(75 + 8) & 15] ^ w[(75 + 2) & 15] ^ w[75 & 15], 1);
		e += (b ^ c ^ d) + w[75 & 15] + c3 + rol32(a, 5);
		b = rol32(b, 30);
		w[76 & 15] = rol32(w[(76 + 13) & 15] ^ w[(76 + 8) & 15] ^ w[(76 + 2) & 15] ^ w[76 & 15], 1);
		d += (a ^ b ^ c) + w[76 & 15] + c3 + rol32(e, 5);
		a = rol32(a, 30);
		w[77 & 15] = rol32(w[(77 + 13) & 15] ^ w[(77 + 8) & 15] ^ w[(77 + 2) & 15] ^ w[77 & 15], 1);
		c += (e ^ a ^ b) + w[77 & 15] + c3 + rol32(d, 5);
		e = rol32(e, 30);
		w[78 & 15] = rol32(w[(78 + 13) & 15] ^ w[(78 + 8) & 15] ^ w[(78 + 2) & 15] ^ w[78 & 15], 1);
		b += (d ^ e ^ a) + w[78 & 15] + c3 + rol32(c, 5);
		d = rol32(d, 30);
		w[79 & 15] = rol32(w[(79 + 13) & 15] ^ w[(79 + 8) & 15] ^ w[(79 + 2) & 15] ^ w[79 & 15], 1);
		a += (c ^ d ^ e) + w[79 & 15] + c3 + rol32(b, 5);
		c = rol32(c, 30);
		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;
		state[4] += e;
	}

	private static void init(int[] state) {
		state[0] = 0x67452301;
		state[1] = 0xEFCDAB89;
		state[2] = 0x98BADCFE;
		state[3] = 0x10325476;
		state[4] = 0xC3D2E1F0;
	}

	public static void hash(byte[] output, byte[] buffer, int length) {

		int[] states = new int[5];
		
		init(states);
		
		byte[] buf = new byte[64];
		
		
		int i = 0;
		int n_bits = 0;
		
		
		for (int indx = 0; indx < length; indx++) {
			buf[i++] = buffer[indx];
			n_bits += 8;
			if (i >= 64) {
				i = 0;
				process_block(states, buf, 0);
			}
		}
		
		buf[i++] = (byte) 0x80;
		if (i >= 64) {
			i = 0;
			process_block(states, buf, 0);
		}
		
		
		while (i % 64 != (56+4)) {
			buf[i++] = 0x00;
			if (i >= 64) {
				i = 0;
				process_block(states, buf, 0);
			}
		}
		
		buf[i++] = (byte) (n_bits >>> 24);
		buf[i++] = (byte) (n_bits >>> 16);
		buf[i++] = (byte) (n_bits >>> 8);
		buf[i++] = (byte) (n_bits);
		
		i = 0;
		process_block(states, buf, 0);
		
		
		for(int o=0;o<5;o++)
			for(int j=0;j<4;j++)
				output[o*4+j] = (byte) (states[o]>>>(8*(3-j)));
		
		
	}
	

}