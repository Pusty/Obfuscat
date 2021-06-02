package re.bytecode.obfuscat.pass;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;

import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;

import static re.bytecode.obfuscat.cfg.MathOperation.*;


// as per Collberg  - http://tigress.cs.arizona.edu/transformPage/docs/encodeArithmetic/index.html
// https://github.com/obfuscator-llvm/obfuscator/blob/clang-425.0.24/lib/Transforms/Obfuscation/SubstitutionFunction.cpp

// https://github.com/RolfRolles/SynesthesiaYS
// https://gitlab.com/eshard/d810/-/tree/master/
// https://github.com/softsec-unh/MBA-Solver/tree/main/full-dataset


/*
 * #define GET_IDENT0_PASS(x_0, x_1) ((x_0 & x_1) + (x_0 & ~(x_1)))
#define GET_IDENT1_PASS(x_0, x_1) ((x_0 & x_1) ^ (x_0 & ~(x_1)))
#define GET_IDENT2_PASS(x_0, x_1) (x_0 & (x_0 | x_1))
 */

public class OperationEncodePass extends Pass {

	// Important here is that each operation always uses the same amount of nodes per operation
	
	
	public OperationEncodePass(Context context) {
		super(context);
	}
	
	private Node replaceAdd(Node[] x, int seed) {
		seed = seed % 3;
		switch(seed) {
		case 0: 
			return sub(x[0], add(not(x[1]), cst(1))); // 3 m 1 c
		case 1:
			return sub(add(or(x[0], x[1]), and(x[0], x[1])), cst(0)); // 4m 1c
		case 2:
			return add(xor(x[0], x[1]), mul(cst(2), and(x[0], x[1]))); // 4m 1c
		default: throw new RuntimeException("Not handled");
		}
	}

	private Node replaceSub(Node[] x, int seed) {
		seed = seed % 4;
		switch(seed) {
		case 0:
			return add(x[0], add(not(x[1]), cst(1))); // 3m 1c
		case 1:
			return sub(xor(x[0], x[1]), mul(cst(2), and(not(x[0]), x[1]))); // 5m 1c
		case 2:
			return add(sub(and(x[0], not(x[1])), and(not(x[0]), x[1])), cst(0)); // 6m 1c
		case 3:
			return sub(mul(cst(2), and(x[0], not(x[1]))), xor(x[0], x[1])); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceMul(Node[] x, int seed) {
		seed = seed % 1;
		switch(seed) {
		case 0:
			return mul(add(mul(or(x[0], x[1]), and(x[0], x[1])), mul(and(x[0], not(x[1])), and(x[1], not(x[0])))), cst(1)); //  10m 1c
		//case 1: // removed because too long
		//	return sub(add(mul(or(x[0], x[1]), and(x[0], x[1])), mul(not(or(x[0], not(x[1]))), and(x[0], not(x[1])))), cst(0)); // 11m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceXor(Node[] x, int seed) {
		seed = seed % 4;
		switch(seed) {
		case 0:
			return mul(sub(or(x[0], x[1]), and(x[0], x[1])), cst(1)); // 4m 1c
		case 1:
			return sub(mul(cst(2), or(x[0], x[1])), add(x[0], x[1])); //4m 1c
		case 2:
			return sub(or(and(x[0], not(x[1])), and(not(x[0]), x[1])), cst(0)); // 6m 1c
		case 3:
			return mul(xor(and(x[0], x[1]), or(x[0], x[1])), cst(1)); // 4m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceAnd(Node[] x, int seed) {
		seed = seed % 4;
		switch(seed) {
		case 0:
			return sub(sub(or(not(x[0]), x[1]), not(x[0])), cst(0)); // 5m 1c
		case 1:
			return add(or(not(x[0]), x[1]), add(x[0], cst(1))); // 4m 1c
		case 2:
			return add(sub(add(x[0], x[1]), or(x[0], x[1])),cst(0)); // 4m 1c
		case 3:
			return mul(sub(or(x[0], x[1]), xor(x[0], x[1])), cst(1)); // 4m 1c
		
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceOr(Node[] x, int seed) {
		seed = seed % 3;
		switch(seed) {
		case 0:
			return sub(add(and(x[0], not(x[1])), x[1]), cst(0)); // 4m 1c
		case 1:
			return add(sub(add(x[0], x[1]), and(x[0], x[1])), cst(0)); // 4m 1c
		case 2:
			return mul(or(and(not(x[0]), x[1]), x[0]), cst(1)); // 4m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	
	// These are more or less place holders
	
	private Node replaceShr(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return shr(add(and(x[0], not(c)), c), sub(x[1], c)); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceUShr(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return ushr(add(and(x[0], not(c)), c), sub(x[1], c)); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceShl(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return add(and(shl(x[0], sub(x[1], c)), not(c)), c); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	
	private Node replaceNot(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return add(and(not(x[0]), not(c)), c); // 4m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	
	private Node replaceNeg(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return neg(add(and(x[0], not(c)), c)); // 4m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceNop(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return add(and(neg(not(x[0])), not(c)), c); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	
	// Division by Invariant Multiplication maybe?
	
	private Node replaceDiv(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return add(and(div(x[0], sub(x[1], c)), not(c)), c); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceMod(Node[] x, int seed) {
		seed = seed % 1;
		Node c = cst(0);
		switch(seed) {
		case 0:
			return add(and(mod(x[0], sub(x[1], c)), not(c)), c); // 5m 1c
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node pad(Node node, int beforeUnique) {
		int afterUnique = node.countUnique();
		
		int added = afterUnique-beforeUnique;
		
		final int GOAL = 10;
		
		// add overall -  GOAL
		if(added >  GOAL)
			throw new RuntimeException("Added too many Operations: "+added);

		Node cur = node;
		for(int i=added;i<GOAL;i++)
			cur =  new NodeMath(NOP, cur);
		
		return cur;
	}
	
	


	@Override
	public void processBlock(BasicBlock block) {

		
		List<Node> addOps = block.findNodes(new NodeMath(ADD, new Node[] {null, null}));
		List<Node> subOps = block.findNodes(new NodeMath(SUB, new Node[] {null, null}));
		List<Node> mulOps = block.findNodes(new NodeMath(MUL, new Node[] {null, null}));

		List<Node> orOps = block.findNodes(new NodeMath(OR, new Node[] {null, null}));
		List<Node> andOps = block.findNodes(new NodeMath(AND, new Node[] {null, null}));
		List<Node> xorOps = block.findNodes(new NodeMath(XOR, new Node[] {null, null}));
		
		List<Node> modOps = block.findNodes(new NodeMath(MOD, new Node[] {null, null}));
		List<Node> divOps = block.findNodes(new NodeMath(DIV, new Node[] {null, null}));
		List<Node> shrOps = block.findNodes(new NodeMath(SHR, new Node[] {null, null}));
		List<Node> ushrOps = block.findNodes(new NodeMath(USHR, new Node[] {null, null}));
		List<Node> shlOps = block.findNodes(new NodeMath(SHL, new Node[] {null, null}));
		List<Node> notOps = block.findNodes(new NodeMath(NOT, new Node[] {null}));
		List<Node> negOps = block.findNodes(new NodeMath(NEG, new Node[] {null}));
		List<Node> nopOps = block.findNodes(new NodeMath(NOP, new Node[] {null}));
		
		for(Node node:addOps) {
			Node gen = replaceAdd(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:subOps) {
			Node gen = replaceSub(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:mulOps) {
			Node gen = replaceMul(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:xorOps) {
			Node gen = replaceXor(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:orOps) {
			Node gen = replaceOr(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
	
		for(Node node:andOps) {
			Node gen = replaceAnd(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		
		// basically nops - no smart MBA expressions found as of now - TODO
		
		for(Node node:divOps) {
			Node gen = replaceDiv(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
	
		for(Node node:modOps) {
			Node gen = replaceMod(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:shrOps) {
			Node gen = replaceShr(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:ushrOps) {
			Node gen = replaceUShr(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:shlOps) {
			Node gen = replaceShl(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:negOps) {
			Node gen = replaceNeg(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:notOps) {
			Node gen = replaceNot(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
		for(Node node:nopOps) {
			Node gen = replaceNop(node.children(), getContext().rand()&0xFFFF);
			block.replace(node, pad(gen, node.countUnique()));
		}
		
	}
	
	
	public Map<String, Node> statistics() {
		
		Map<String, Node> map = new HashMap<String, Node>();
		
		map.put("math", mul(cst("math"), cst(10)));
		map.put("const", add(cst("const"), mul(cst("math"), cst(1))));
		
		return map;
	}
	

}
