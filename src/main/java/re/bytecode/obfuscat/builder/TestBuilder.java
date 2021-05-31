package re.bytecode.obfuscat.builder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath2;

// Builder exists to test specific code generation features
public class TestBuilder extends Builder {

	public TestBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();

		BasicBlock curBlock = new BasicBlock();
	
		NodeLoad inp = new NodeLoad(4, 0);
		
		NodeMath2 add = new NodeMath2(inp, inp, MathOperation.ADD);
		
		NodeMath2 add2 = new NodeMath2(add, add, MathOperation.ADD);
		
		curBlock.getNodes().add(inp);
		curBlock.getNodes().add(add);
		curBlock.getNodes().add(add2);
		
		curBlock.setExitBlock(add2);
		blocks.add(curBlock);
		
		Function f = new Function("generate", blocks, new Class<?>[] { int.class }, 1, false);
		return f;
	}

	@Override
	public Map<String, Class<?>> supportedArguments() {
		HashMap<String, Class<?>> supported = new HashMap<String, Class<?>>();
		return supported;
	}


}
