/*
 * Copyright 2010 Google Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package java.io;

import java.io.DataInput;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UTFDataFormatException;

public class DataInputStream extends InputStream implements DataInput {

  private final InputStream is;
  
  public DataInputStream(final InputStream is) {
    this.is = is;
  }
  
  @Override
  public int read() throws IOException {
    return is.read();
  }

  public boolean readBoolean() throws IOException {
      int ch = is.read();
      if (ch < 0)
          throw new EOFException();
      return (ch != 0);
  }

  public byte readByte() throws IOException {
      int ch = is.read();
      if (ch < 0)
          throw new EOFException();
      return (byte)(ch);
  }

  public char readChar() throws IOException {
    int a = is.read();
    int b = readUnsignedByte();
    return (char) ((a << 8) | b);
  }

  public double readDouble() throws IOException {
    throw new RuntimeException("readDouble");
  }

  public float readFloat() throws IOException {
	 throw new RuntimeException("readFloat");
  }

  public void readFully(byte[] b) throws IOException {
    readFully(b, 0, b.length);
  }

  public void readFully(byte[] b, int off, int len) throws IOException {
      if (len < 0)
          throw new IndexOutOfBoundsException();
      int n = 0;
      while (n < len) {
          int count = is.read(b, off + n, len - n);
          if (count < 0)
              throw new EOFException();
          n += count;
      }
  }

  public int readInt() throws IOException {
      int ch1 = is.read();
      int ch2 = is.read();
      int ch3 = is.read();
      int ch4 = is.read();
      if ((ch1 | ch2 | ch3 | ch4) < 0)
          throw new EOFException();
      return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4 << 0));
  }

  public String readLine() throws IOException {
    throw new RuntimeException("readline NYI");
  }

  public long readLong() throws IOException {
    long a = readInt();
    long b = readInt() & 0xffffffffL;
    return (a << 32) | b;
  }

  public short readShort() throws IOException {
      int ch1 = is.read();
      int ch2 = is.read();
      if ((ch1 | ch2) < 0)
          throw new EOFException();
      return (short)((ch1 << 8) | ch2);
  }

  public String readUTF() throws IOException {
    int bytes = readUnsignedShort();
    StringBuilder sb = new StringBuilder();
    
    while (bytes > 0) {
      bytes -= readUtfChar(sb);
    }
    
    return sb.toString();
  }

  private int readUtfChar(StringBuilder sb) throws IOException {
    int a = readUnsignedByte();
    if ((a & 0x80) == 0) {
      sb.append((char) a);
      return 1;
    }
    if ((a & 0xe0) == 0xb0) {
      int b = readUnsignedByte();
      sb.append((char)(((a& 0x1F) << 6) | (b & 0x3F)));
      return 2;
    }
    if ((a & 0xf0) == 0xe0) {
      int b = is.read();
      int c = readUnsignedByte();
      sb.append((char)(((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F)));
      return 3;
    }
    throw new UTFDataFormatException();
  }

  public int readUnsignedByte() throws IOException {
    int i = read();
    if (i == -1) {
      throw new EOFException();
    }
    return i&0xFF;
  }

  public int readUnsignedShort() throws IOException {
    int a = is.read();
    int b = readUnsignedByte();
    return ((a << 8) | b);
  }

  public int skipBytes(int n) throws IOException {
    // note: This is actually a valid implementation of this method, rendering it quite useless...
    return 0;
  }
  
  @Override
  public int available() throws IOException {
      return is.available();
  }
  
  @Override
  public void close() throws IOException {
	  is.close();
  }
  
  @Override
  public long skip(long byteCount) throws IOException {
	  return is.skip(byteCount);
  }
  
  @Override
  public void reset() throws IOException {
	  is.reset();
  }
  
  
  @Override
  public int read(byte[] buffer, int byteOffset, int byteCount) throws IOException {
	  return is.read(buffer, byteOffset, byteCount);
  }
  
  @Override
  public boolean markSupported() {
      return is.markSupported();
  }
  
  @Override
  public void mark(int readlimit) {
      is.mark(readlimit);
  }

}
