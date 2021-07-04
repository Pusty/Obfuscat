package re.bytecode.obfuscat.builder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

// Builder exists to test specific code generation features
public class TestBuilder extends Builder {

	public TestBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();

		BasicBlock initialBlock = new BasicBlock();
		initialBlock.getNodes().add(new NodeStore(MemorySize.INT, 0, new NodeConst(25)));
		Node cmpValue = new NodeConst(0);
		initialBlock.getNodes().add(cmpValue);
		NodeLoad inp2 = new NodeLoad(MemorySize.INT, 0);
		initialBlock.getNodes().add(inp2);
		blocks.add(initialBlock);
		
		
		BasicBlock fakeBlock = new BasicBlock();
		fakeBlock.setExitBlock(null);
		blocks.add(fakeBlock);
		
		BasicBlock curBlock = new BasicBlock();
		NodeLoad inp = new NodeLoad(MemorySize.INT, 0);
		NodeMath add = new NodeMath(MathOperation.ADD, inp, inp);
		NodeMath add2 = new NodeMath(MathOperation.ADD, add, add);
		curBlock.getNodes().add(inp);
		curBlock.getNodes().add(add);
		curBlock.getNodes().add(add2);
		curBlock.setExitBlock(add2);
		blocks.add(curBlock);
		
		
		initialBlock.setConditionalBranch(fakeBlock, new BranchCondition(initialBlock, cmpValue, inp2, CompareOperation.EQUAL));
		initialBlock.setUnconditionalBranch(curBlock);
		
		
		/*
		BasicBlock initialBlock = new BasicBlock();
		Node x = cst(5);
		Node y = cst(7);
		Node res = add(mul(nop(and(ushr(sub(x, y), cst(31)), cst(1))), cst(9)), cst(14));
		initialBlock.getNodes().add(res);
		initialBlock.setExitBlock(res);
		blocks.add(initialBlock);
		*/
		
		Function f = new Function("generate", blocks, new Class<?>[] {}, 1, true);
		return f;
	}

	@Override
	public Map<String, Class<?>> supportedArguments() {
		HashMap<String, Class<?>> supported = new HashMap<String, Class<?>>();
		return supported;
	}
	
	@Override
	public Map<String, String> supportedArgumentsHelp() {
		HashMap<String, String> helpInfo = new HashMap<String, String>();
		return helpInfo;
	}
	
	public String description() {
		return "Test builder class";
	}

}
