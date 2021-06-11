package re.bytecode.obfuscat.exception;

public class GeneratorArgumentException extends IllegalArgumentException {

	private static final long serialVersionUID = 9079935705853201125L;

	public GeneratorArgumentException() {
		super();
	}
	
	public GeneratorArgumentException(String s) {
		super(s);
	}

	public GeneratorArgumentException(String s, Throwable t) {
		super(s, t);
	}
	

}
