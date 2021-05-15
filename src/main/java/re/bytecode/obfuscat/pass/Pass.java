package re.bytecode.obfuscat.pass;

import java.util.List;

import re.bytecode.obfuscat.cfg.BasicBlock;

// TODO: Not done yet
public abstract class Pass {
	
	public void processBlocks(List<BasicBlock> blocks) {
		for(BasicBlock block:blocks)
			processBlock(block);
	}
	
	public void processBlock(BasicBlock block) {
		
	}
	
}
