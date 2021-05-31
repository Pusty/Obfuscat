package re.bytecode.obfuscat.pass;

import java.util.List;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;

import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath1;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;

import static re.bytecode.obfuscat.cfg.MathOperation.*;


// as per Collberg  - http://tigress.cs.arizona.edu/transformPage/docs/encodeArithmetic/index.html
// https://github.com/obfuscator-llvm/obfuscator/blob/clang-425.0.24/lib/Transforms/Obfuscation/SubstitutionFunction.cpp

// https://github.com/RolfRolles/SynesthesiaYS
// https://gitlab.com/eshard/d810/-/tree/master/

/*
 * return (x_0 ^ (~(x_0)&x_1)); OR
return (x_0 - ((0x2 * (x_1 & ~((x_0 ^ x_1)))) - x_1)); XOR
return op_sub(op_add(x_0, x_1), op_or(x_0, x_1)); AND
op_add(((x_0 | x_1) * (x_0 & x_1)), ((x_0 & bnot_x_1) * (x_1 & bnot_x_0))); MUL
return (x_0 + (~(x_1) + 0x1)); SUB
return ((2 * (x_1 | x_0)) - (x_0 ^ x_1)); ADD
 */


/*
 * #define GET_IDENT0_PASS(x_0, x_1) ((x_0 & x_1) + (x_0 & ~(x_1)))
#define GET_IDENT1_PASS(x_0, x_1) ((x_0 & x_1) ^ (x_0 & ~(x_1)))
#define GET_IDENT2_PASS(x_0, x_1) (x_0 & (x_0 | x_1))
 */

public class SimpleArithmeticEncodePass extends Pass {

	
	//  a + b = -(-a + (-b))
	//  a - b = a + (-b)
	//  a 
	
	// Important here is that each operation always uses the same amount of nodes per operation
	
	
	
	public SimpleArithmeticEncodePass(Context context) {
		super(context);
	}
	
	
	private static NodeMath2 add(Node a, Node b) { return new NodeMath2(a, b, ADD); }
	private static NodeMath2 sub(Node a, Node b) { return new NodeMath2(a, b, SUB); }
	private static NodeMath2 mul(Node a, Node b) { return new NodeMath2(a, b, MUL); }
	private static NodeMath2 mod(Node a, Node b) { return new NodeMath2(a, b, MOD); }
	private static NodeMath2 div(Node a, Node b) { return new NodeMath2(a, b, DIV); }
	private static NodeMath2 and(Node a, Node b) { return new NodeMath2(a, b, AND); }
	private static NodeMath2 or(Node a, Node b) { return new NodeMath2(a, b, OR); }
	private static NodeMath2 xor(Node a, Node b) { return new NodeMath2(a, b, XOR); }
	private static NodeMath2 shr(Node a, Node b) { return new NodeMath2(a, b, SHR); }
	private static NodeMath2 ushr(Node a, Node b) { return new NodeMath2(a, b, USHR); }
	private static NodeMath2 shl(Node a, Node b) { return new NodeMath2(a, b, SHL); }
	private static NodeMath1 not(Node a) { return new NodeMath1(a, NOT); }
	//private static NodeMath1 neg(Node a) { return new NodeMath1(a, NEG); }
	private static NodeConst cst(Object o) { return new NodeConst(o); }
	
	private Node replaceAdd(Node[] x, int seed) {
		seed = seed % 3;
		switch(seed) {
		case 0: 
			// a + b =  a - (!(b)-1)
			return sub(x[0], add(not(x[1]), cst(1)));
		case 1:
			// a + b = (a | b) + (a & b)
			return add(or(x[0], x[1]), and(x[0], x[1]));
		case 2:
			// a + b = (a ^ b) + 2*(a&b)
			return add(xor(x[0], x[1]), mul(cst(2), and(x[0], x[1])));
		default: throw new RuntimeException("Not handled");
		}
	}

	private Node replaceSub(Node[] x, int seed) {
		seed = seed % 4;
		switch(seed) {
		case 0:
			return add(x[0], add(not(x[1]), cst(1)));
		case 1:
			return sub(xor(x[0], x[1]), mul(cst(2), and(not(x[0]), x[1])));
		case 2:
			return sub(and(x[0], not(x[1])), and(not(x[0]), x[1]));
		case 3:
			return sub(mul(cst(2), and(x[0], not(x[1]))), xor(x[0], x[1]));
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceMul(Node[] x, int seed) {
		seed = seed % 2;
		switch(seed) {
		case 0:
			return add(mul(or(x[0], x[1]), and(x[0], x[1])), mul(and(x[0], not(x[1])), and(x[1], not(x[0]))));
		case 1:
			return add(mul(or(x[0], x[1]), and(x[0], x[1])), mul(not(or(x[0], not(x[1]))), and(x[0], not(x[1]))));
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceXor(Node[] x, int seed) {
		seed = seed % 4;
		switch(seed) {
		case 0:
			return sub(or(x[0], x[1]), and(x[0], x[1]));
		case 1:
			return sub(mul(cst(2), or(x[0], x[1])), add(x[0], x[1]));
		case 2:
			return or(and(x[0], not(x[1])), and(not(x[0]), x[1]));
		case 3:
			return xor(and(x[0], x[1]), or(x[0], x[1]));
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceAnd(Node[] x, int seed) {
		seed = seed % 4;
		switch(seed) {
		case 0:
			return sub(or(not(x[0]), x[1]), not(x[0]));
		case 1:
			return add(or(not(x[0]), x[1]), add(x[0], cst(1)));
		case 2:
			return sub(add(x[0], x[1]), or(x[0], x[1]));
		case 3:
			return sub(or(x[0], x[1]), xor(x[0], x[1]));
		
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node replaceOr(Node[] x, int seed) {
		seed = seed % 3;
		switch(seed) {
		case 0:
			return add(and(x[0], not(x[1])), x[1]);
		case 1:
			return sub(add(x[0], x[1]), and(x[0], x[1]));
		case 2:
			return or(and(not(x[0]), x[1]), x[0]);
		default: throw new RuntimeException("Not handled");
		}
	}
	
	private Node pad(Node node, int beforeUnique) {
		int afterUnique = node.countUnique();
		
		int added = afterUnique-beforeUnique;
		
		final int GOAL = 9;
		
		// add overall -  GOAL
		if(added >  GOAL)
			throw new RuntimeException("Added too many Operations: "+added);
		
		Node cur = node;
		for(int i=added;i<GOAL;i++)
			cur =  new NodeMath1(cur, NOP);
		
		return cur;
	}
	
	


	@Override
	public void processBlock(BasicBlock block) {
		
		
		/////////////////////////////////////////////////////////////////////////////////
		// these operations remove 2 nodes and add 2 nodes
		/*
		
		List<Node> incOps = block.findNodes(new NodeMath2(null, new NodeConst(1), ADD));
		
		// x + 1 => ~(-x)
		for(Node node:incOps) {
			Node[] children = node.children();
			NodeMath1 n1 = new NodeMath1(children[0],  NOT);
			NodeMath1 n2 = new NodeMath1(n1,  NEG);
			block.replace(node, n2);
		}
		
		incOps = block.findNodes(new NodeMath2(new NodeConst(1), null, ADD));
		
		// 1 + x => ~(-x)
		for(Node node:incOps) {
			Node[] children = node.children();
			NodeMath1 n1 = new NodeMath1(children[1],  NOT);
			NodeMath1 n2 = new NodeMath1(n1,  NEG);
			block.replace(node, n2);
		}
		
		List<Node> decOps = block.findNodes(new NodeMath2(null, new NodeConst(1), SUB));
		
		// x-1 => -(~x)
		for(Node node:decOps) {
			Node[] children = node.children();
			NodeMath1 n1 = new NodeMath1(children[0],  NEG);
			NodeMath1 n2 = new NodeMath1(n1,  NOT);
			block.replace(node, n2);
		}
		
		*/
		/////////////////////////////////////////////////////////////////////////////////


		
		List<Node> addOps = block.findNodes(new NodeMath2(null, null, ADD));
		List<Node> subOps = block.findNodes(new NodeMath2(null, null, SUB));
		List<Node> mulOps = block.findNodes(new NodeMath2(null, null, MUL));

		List<Node> orOps = block.findNodes(new NodeMath2(null, null, OR));
		List<Node> andOps = block.findNodes(new NodeMath2(null, null, AND));
		List<Node> xorOps = block.findNodes(new NodeMath2(null, null, XOR));
		
		List<Node> modOps = block.findNodes(new NodeMath2(null, null, MOD));
		List<Node> divOps = block.findNodes(new NodeMath2(null, null, DIV));
		List<Node> shrOps = block.findNodes(new NodeMath2(null, null, SHR));
		List<Node> ushrOps = block.findNodes(new NodeMath2(null, null, USHR));
		List<Node> shlOps = block.findNodes(new NodeMath2(null, null, SHL));
		//List<Node> notOps = block.findNodes(new NodeMath1(null, NOT));
		//List<Node> negOps = block.findNodes(new NodeMath1(null, NEG));
		//List<Node> nopOps = block.findNodes(new NodeMath1(null, NOP));
		
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
		
		
		// basically nops
		
		for(Node node:divOps) {
			Node[] children = node.children();
			block.replace(node, pad(div(children[0], children[1]), node.countUnique()));
		}
	
		for(Node node:modOps) {
			Node[] children = node.children();
			block.replace(node, pad(mod(children[0], children[1]), node.countUnique()));
		}
		
		for(Node node:shrOps) {
			Node[] children = node.children();
			block.replace(node, pad(shr(children[0], children[1]), node.countUnique()));
		}
		
		for(Node node:ushrOps) {
			Node[] children = node.children();
			block.replace(node, pad(ushr(children[0], children[1]), node.countUnique()));
		}
		
		for(Node node:shlOps) {
			Node[] children = node.children();
			block.replace(node, pad(shl(children[0], children[1]), node.countUnique()));
		}
		
	}
	
	

}
