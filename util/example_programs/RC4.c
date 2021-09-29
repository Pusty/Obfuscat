/*
 * RC4 Implementation - Merged Functions Example
 * https://gist.github.com/rverton/a44fc8ca67ab9ec32089
 */

void swap(unsigned char* array, unsigned int a, unsigned int b) {
    unsigned char tmp = array[a];
    array[a] = array[b];
    array[b] = tmp;
}

void KSA(unsigned char* key, unsigned char* S) {

    unsigned int len_key = 8;
    unsigned int j = 0;

    for(unsigned int i = 0; i < 256; i++)
        S[i] = i&0xFF;

    for(unsigned int i = 0; i < 256; i++) {
        j = (j + (S[i]&0xFF) + (key[i % len_key]&0xFF)) % 256;
        swap(S, i, j);
    }
}

void PRGA(unsigned char* S, unsigned char* plaintext, unsigned int len) {

    unsigned int i = 0;
    unsigned int j = 0;

    for(unsigned int n = 0; n < len; n++) {
        i = (i + 1) % 256;
        j = (j + (S[i]&0xFF)) % 256;
        
        swap(S, i, j);
        unsigned int rnd = S[((S[i]&0xFF) + (S[j]&0xFF)) % 256]&0xFF;
        
        plaintext[n] = (unsigned char) (rnd ^ plaintext[n])&0xFF;

    }

}

// key len = 8
void rc4(unsigned char* key, unsigned char* plaintext, unsigned int len) {
    unsigned char buffer[256];
    KSA(key, buffer);
    PRGA(buffer, plaintext, len);
    return;
}

unsigned int _binary___program_bin_start(unsigned char* data, unsigned int len)  {
    unsigned char key[8];
    unsigned char tmp[len];

    key[0] = 0x01;
    key[1] = 0x02;
    key[2] = 0x03;
    key[3] = 0x04;
    key[4] = 0x05;
    key[5] = 0x06;
    key[6] = 0x07;
    key[7] = 0x08;
    
    for(unsigned int i=0;i<len;i++)
        tmp[i] = data[i]&0xFF;
    
    rc4(key, tmp, len);
    return tmp[0]&0xFF;
}