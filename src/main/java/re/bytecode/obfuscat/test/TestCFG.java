package re.bytecode.obfuscat.test;

import re.bytecode.obfuscat.cfg.*;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;

public class TestCFG {
	public static void main(String[] args) {
		
		
		BasicBlock b1 = new BasicBlock();
		
		NodeConst c1 = new NodeConst(new Integer(3));
		NodeConst c2 = new NodeConst(new Integer(5));
		
		NodeMath a1 = new NodeMath(MathOperation.ADD, c1, c2);
		
		b1.getNodes().add(a1);
		
		BranchCondition bc = new BranchCondition(b1, a1, a1, CompareOperation.EQUAL);
		

		b1.getSwitchBlocks().put(bc, b1);
		
		
		//CFGTOJS.generate(b1);
	}
}
