package re.bytecode.obfuscat.test.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SampleLoader {

	public static byte[] loadFile(String name) throws IOException {
    	byte[] fileData  = Files.readAllBytes(Paths.get(new File(System.getProperty("user.dir")+"/bin/re/bytecode/obfuscat/samples/"+name+".class").toURI()));
    	return fileData;
	}

}
