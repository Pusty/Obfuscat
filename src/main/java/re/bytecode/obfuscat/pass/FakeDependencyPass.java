package re.bytecode.obfuscat.pass;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;

import static re.bytecode.obfuscat.cfg.MathOperation.*;


/** Inject fake dependencies between constants and parameters / variables **/
public class FakeDependencyPass extends Pass {

	public FakeDependencyPass(Context context) {
		super(context);
	}

    // https://gitlab.com/eshard/d810/-/blob/master/d810/optimizers/instructions/pattern_matching/rewrite_predicates.py
	
	private Node ident0(Node x, Node fake) {
		return add(and(x, fake), and(x, not(fake))); // 4m
	}
	
	private Node ident1(Node x, Node fake) {
		return xor(and(x, fake), and(x, not(fake))); // 4m
	}
	
	private Node ident2(Node x, Node fake) {
		return and(and(x, x), or(x, not(fake))); // 4m
	}
	
	@Override
	protected void processBlock(Function function, BasicBlock block, Map<String, Object> args) {
		List<Node> constOps = block.findNodes(new NodeConst(null));
		
		for(Node nodeRaw:constOps) {
			NodeConst node = (NodeConst)nodeRaw;
			
			Object constObj = node.getObj();
			Node x = cst(constObj);
			Node fake;
			int vars = function.getVariables();
			
			if(vars > 0)
				fake = new NodeLoad(MemorySize.INT, (getContext().rand()&0xFFFF)%vars); // the size might not match the actual variable, but it doesn't matter
			else
				fake = new NodeLoad(MemorySize.INT, 0); // this will be a random spot on the stack but that is fine as it doesn't matter anyways
			
			Node res;
			
			switch((getContext().rand()&0xFFFF)%3) {
			case 0:
				res = ident0(x, fake);
				break;
			case 1:
				res = ident1(x, fake);
				break;
			case 2:
				res = ident2(x, fake);
				break;
			default: throw new RuntimeException("Unexpected Error");
			}
			
			block.replace(node, res);
		}
	
		
	}
	
	public Map<String, Node> statistics() {
		
		Map<String, Node> map = new HashMap<String, Node>();
		
		map.put("math",  add(cst("math"),  mul(cst("const"), cst(4))));
		map.put("load",  add(cst("load"),  mul(cst("const"), cst(1))));
		
		return map;
	}
	
	public String description() {
		return "Inject fake dependencies to function parameters into constants";
	}
}

