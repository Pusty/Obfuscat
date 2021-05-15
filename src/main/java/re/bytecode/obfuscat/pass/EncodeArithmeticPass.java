package re.bytecode.obfuscat.pass;

import java.util.List;

import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeMath1;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;

// TODO: Currently only a PoC, next weeks work will be focused on this
public class EncodeArithmeticPass extends Pass {

	@Override
	public void processBlock(BasicBlock block) {
		
		
		List<Node> addOps = block.findNodes(new NodeMath2(null, null, MathOperation.ADD));
		
		//  Implementation of  b + c = -(-b + (-c))
		for(Node adds:addOps) {
			Node[] children = adds.children();
			NodeMath1 n1 = new NodeMath1(children[1],  MathOperation.NEG);
			NodeMath1 n2 = new NodeMath1(children[0],  MathOperation.NEG);
			NodeMath2 a1 = new NodeMath2(n1, n2, MathOperation.ADD);
			NodeMath1 o1 = new NodeMath1(a1, MathOperation.NEG);
			block.replace(adds, o1);
		}
		
		List<Node> subOps = block.findNodes(new NodeMath2(null, null, MathOperation.SUB));
		//  Implementation of b - c = b + (-c)
		for(Node subs:subOps) {
			Node[] children = subs.children();
			NodeMath1 n1 = new NodeMath1(children[1],  MathOperation.NEG);
			NodeMath2 a1 = new NodeMath2(children[0], n1, MathOperation.ADD);
			block.replace(subs, a1);
		}

	}
	
	

}
