package re.bytecode.obfuscat.pass;

import static re.bytecode.obfuscat.cfg.MathOperation.*;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;

/** 
 * Bogus Control Flow is an obfuscation pass
 * that converts unconditional basic blocks to conditional basic blocks,
 * with random conditional connections that are never taken
 */
public class BogusControlFlowPass extends Pass {

	public BogusControlFlowPass(Context context) {
		super(context);
	}

	// https://gitlab.com/eshard/d810/-/blob/master/d810/optimizers/instructions/pattern_matching/rewrite_predicates.py
	
	// solve(x | c == -(x^c), c > 0)
	// no solution
	private Node[] opagePred0(Node x) {
		int c = getContext().rand();
		while(c <= 0) c = getContext().rand();
		Node nc = cst(c);
		return new Node[] { or(x, nc) , neg(xor(x, nc)) };
	}
	// 1 cst, 3 math
	
	// solve(~x & c == -x, c != 0)
	// no solution
	private Node[] opagePred1(Node x) {
		int c = 0;
		while(c == 0) c = getContext().rand();
		return new Node[] { and(not(x), cst(c)) , neg(x) };
	}
	// 1 cst, 3 math
	
	// solve(~((c - x)) == ~x, c%2 == 1)
	// no solution
	private Node[] opagePred2(Node x) {
		int c = 0;
		while(c <= 0 || c%2 != 1) c = getContext().rand();
		return new Node[] { not(sub(cst(c), x)), not(x) };
	}
	// 1cst 3 math
	
	@Override
	protected void processBlock(Function function, BasicBlock block, Map<String, Object> args) {
		
		if(block.isConditionalBlock()) return;
		if(block.isSwitchCase()) return;
		if(block.isExitBlock()) return;
		
		
		BasicBlock unconditional = block.getUnconditionalBranch();
		BasicBlock neverTaken    = function.getBlocks().get(Math.abs(getContext().rand())%function.getBlocks().size());
		
		int var = Math.abs(getContext().rand())%function.getVariables();
		
		Node[] res;
		Node varNode = new NodeLoad(MemorySize.INT, var);
		
		switch((getContext().rand()&0xFFFF)%3) {
		case 0:
			res = opagePred0(varNode);
			break;
		case 1:
			res = opagePred1(varNode);
			break;
		case 2:
			res = opagePred2(varNode);
			break;
		default: throw new RuntimeException("Unexpected Error");
		}
		
		// Shuffle for order in code
		{
			List<Node> shuffle = Arrays.asList(res);
			Collections.shuffle(shuffle, getContext().random());
			res = shuffle.toArray(new Node[shuffle.size()]);
		}
		
		block.getNodes().add(res[0]);
		block.getNodes().add(res[1]);
		
		// Shuffle for order in comparison
		{
			List<Node> shuffle = Arrays.asList(res);
			Collections.shuffle(shuffle, getContext().random());
			res = shuffle.toArray(new Node[shuffle.size()]);
		}
		
		block.setConditionalBranch(neverTaken, new BranchCondition(block, res[0], res[1], CompareOperation.EQUAL));
		block.setUnconditionalBranch(unconditional);
		
	}
	
	public Map<String, Node> statistics(Map<String, Object> args) {
		Map<String, Node> map = new HashMap<String, Node>();
		map.put("math",  add(cst("math"),  mul(cst("jumpBlocks"), cst(3))));
		map.put("const",  add(cst("const"),  mul(cst("jumpBlocks"), cst(1))));
		map.put("load",  add(cst("load"),  mul(cst("jumpBlocks"), cst(1))));
		map.put("conditionalBlocks",  add(cst("conditionalBlocks"), cst("jumpBlocks")));
		
		map.put("jumpBlocks",  cst(0));
		return map;
	}
	
	@Override
	public Map<String, Node> statisticsRuntime(Map<String, Object> args) {
		Map<String, Node> map = statistics(args);
		map.put("conditionalBlocksFalse", add(cst("conditionalBlocksFalse"), cst("jumpBlocks")));
		return map;
	}
	
	public String description() {
		return "Add an opaque predicate after each unconditional basic block";
	}
}

