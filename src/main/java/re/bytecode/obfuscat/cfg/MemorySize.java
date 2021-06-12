package re.bytecode.obfuscat.cfg;

/** Enum for MemorySizes of variable and array operations */
public enum MemorySize {
	BYTE("8"),
	SHORT("16"),
	INT("32"),
	POINTER("*"),
	ANY("?"); // ANY is for dummy operations
	
	
	private String sizeName;
	
	private MemorySize(String sizeName) {
		this.sizeName = sizeName;
	}
	
	@Override
	public String toString() {
		return sizeName;
	}
}
