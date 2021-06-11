package re.bytecode.obfuscat.exception;

public class PassArgumentException extends IllegalArgumentException {

	private static final long serialVersionUID = 1407507494426901182L;

	public PassArgumentException() {
		super();
	}
	
	public PassArgumentException(String s) {
		super(s);
	}

	public PassArgumentException(String s, Throwable t) {
		super(s, t);
	}
	

}
