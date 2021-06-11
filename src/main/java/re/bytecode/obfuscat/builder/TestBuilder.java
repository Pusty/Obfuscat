package re.bytecode.obfuscat.builder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;

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
		
		NodeMath add = new NodeMath(MathOperation.ADD, inp, inp);
		
		NodeMath add2 = new NodeMath(MathOperation.ADD, add, add);
		
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
	
	@Override
	public Map<String, String> supportedArgumentsHelp() {
		HashMap<String, String> helpInfo = new HashMap<String, String>();
		return helpInfo;
	}
	
	public String description() {
		return "Test builder class";
	}

}
