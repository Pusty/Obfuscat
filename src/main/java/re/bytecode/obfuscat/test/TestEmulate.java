package re.bytecode.obfuscat.test;

import java.util.Arrays;

import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;

public class TestEmulate {
	public static void main(String[] args) {
		
		
		BasicBlock b1 = new BasicBlock();
		
		NodeConst c1 = new NodeConst(new Integer(3));
		NodeConst c2 = new NodeConst(new Integer(5));
		
		NodeMath2 a1 = new NodeMath2(c1, c2, MathOperation.ADD);
		
		b1.getNodes().add(a1);
		
		BranchCondition bc = new BranchCondition(b1, a1, a1, CompareOperation.EQUAL);
		

		b1.getSwitchBlocks().put(bc, b1);
		
		EmulateFunction ef = new EmulateFunction(new Function("test", Arrays.asList(b1), new Class<?>[] {}, 0, false));
		
		ef.run(5);

	}
}
