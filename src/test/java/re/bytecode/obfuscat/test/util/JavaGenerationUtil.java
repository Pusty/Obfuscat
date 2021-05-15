package re.bytecode.obfuscat.test.util;

import java.lang.reflect.Method;
import java.util.HashMap;

public class JavaGenerationUtil {
	
	public static Method loadSample(byte[] classData, String name, String functionName, Object... args) throws ClassNotFoundException, NoSuchMethodException, SecurityException {

		// Change Type from Boxed Versions
		Class<?>[] parameters = new Class<?>[args.length];
		for(int i=0;i<args.length;i++) {
			if(args[i].getClass() == Integer.class) parameters[i] = int.class;
			else if(args[i].getClass() == Short.class) parameters[i] = short.class;
			else if(args[i].getClass() == Byte.class) parameters[i] = byte.class;
			else if(args[i].getClass() == Character.class) parameters[i] = char.class;
			else
				parameters[i] = args[i].getClass();
		}
		
		ByteClassLoader byteClassLoader = new ByteClassLoader(JavaGenerationUtil.class.getClassLoader());
		
		byteClassLoader.loadDataInBytes(classData, "re.bytecode.obfuscat.samples."+name);

		Class<?> sampleClass = byteClassLoader.loadClass("re.bytecode.obfuscat.samples."+name);
		
		return sampleClass.getDeclaredMethod(functionName, parameters);
	}
}

//Define Custom ClassLoader
class ByteClassLoader extends ClassLoader {
	private HashMap<String, byte[]> byteDataMap = new HashMap<>();

	public ByteClassLoader(ClassLoader parent) {
		super(parent);
	}

	public void loadDataInBytes(byte[] byteData, String resourcesName) {
		byteDataMap.put(resourcesName, byteData);
	}

	@Override
	protected Class<?> findClass(String className) throws ClassNotFoundException {
		if (byteDataMap.isEmpty())
			throw new ClassNotFoundException("byte data is empty");
		
		String filePath = className.replaceAll("\\.", "/").concat(".class");
		byte[] extractedBytes = byteDataMap.get(filePath);
		if (extractedBytes == null)
			throw new ClassNotFoundException("Cannot find " + filePath + " in bytes");
		
		return defineClass(className, extractedBytes, 0, extractedBytes.length);
	}
}
