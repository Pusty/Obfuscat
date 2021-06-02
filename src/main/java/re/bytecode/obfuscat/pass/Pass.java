package re.bytecode.obfuscat.pass;

import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.nodes.Node;

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
	
	public abstract Map<String, Node> statistics();
}
