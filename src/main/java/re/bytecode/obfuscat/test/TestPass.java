package re.bytecode.obfuscat.test;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.*;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;
import re.bytecode.obfuscat.pass.OperationEncodePass;

public class TestPass {
	public static void main(String[] args) throws Exception {
		
		
		BasicBlock b2 = new BasicBlock();
		
		b2.getNodes().add(new NodeStore(4, 0, new NodeConst(1)));
		
		BasicBlock b3 = new BasicBlock();
		
		b3.getNodes().add(new NodeStore(4, 0, new NodeConst(0)));
		
		
		BasicBlock b1 = new BasicBlock();
		
		NodeConst c1 = new NodeConst(new Integer(3));
		NodeConst c2 = new NodeConst(new Integer(5));
		
		NodeMath a1 = new NodeMath(MathOperation.ADD, c1, c2);
		
		b1.getNodes().add(a1);
		
		
		NodeConst c3 = new NodeConst(new Integer(12));
		NodeConst c4 = new NodeConst(new Integer(4));
		
		NodeMath a2 = new NodeMath(MathOperation.SUB, c3, c4);
		
		b1.getNodes().add(a2);
		
		BranchCondition bc = new BranchCondition(b1, a1, a2, CompareOperation.EQUAL);
		b1.getSwitchBlocks().put(bc, b2);
		b1.setUnconditionalBranch(b3);
		
		
		OperationEncodePass eap = new OperationEncodePass(new Context(System.currentTimeMillis()));
		eap.processBlock(b1);
		
		System.out.println(b1);
		//CFGTOJS.generate(b1);
	}
}
