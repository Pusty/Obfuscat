package re.bytecode.obfuscat.exception;

public class BuilderArgumentException extends IllegalArgumentException {

	private static final long serialVersionUID = 660203182922233571L;
	
	public BuilderArgumentException() {
		super();
	}
	
	public BuilderArgumentException(String s) {
		super(s);
	}

	public BuilderArgumentException(String s, Throwable t) {
		super(s, t);
	}
	

}
