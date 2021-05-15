package re.bytecode.obfuscat.test;

import re.bytecode.obfuscat.cfg.*;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;
import re.bytecode.obfuscat.gen.x86CodeGenerator;

public class TestCFG {
	public static void main(String[] args) {
		
		
		BasicBlock b1 = new BasicBlock();
		
		NodeConst c1 = new NodeConst(new Integer(3));
		NodeConst c2 = new NodeConst(new Integer(5));
		
		NodeMath2 a1 = new NodeMath2(c1, c2, MathOperation.ADD);
		
		b1.getNodes().add(a1);
		
		BranchCondition bc = new BranchCondition(b1, a1, a1, CompareOperation.EQUAL);
		

		b1.getSwitchBlocks().put(bc, b1);
		
		
		//CFGTOJS.generate(b1);
	}
}
