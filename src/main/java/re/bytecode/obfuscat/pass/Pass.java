package re.bytecode.obfuscat.pass;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;

// TODO: Not done yet
public abstract class Pass {
	
	private Context context;
	
	public Pass(Context context) {
		this.context = context;
	}
	
	public Context getContext() {
		return context;
	}
	
	public void processFunction(Function function) {
		for(BasicBlock block:function.getBlocks())
			processBlock(block);
	}
	
	public void processBlock(BasicBlock block) {
		
	}
	
}
