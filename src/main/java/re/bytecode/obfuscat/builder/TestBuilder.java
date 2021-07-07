package re.bytecode.obfuscat.builder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;

// Builder exists to test specific code generation features
public class TestBuilder extends Builder {

	public TestBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();

		byte[] dataArray = new byte[] {1, 27, 99, 88, 5};
		

		BasicBlock initialBlock = new BasicBlock();
		Node res = new NodeALoad(new NodeConst(dataArray), new NodeConst(2), MemorySize.BYTE);
		initialBlock.getNodes().add(res);
		initialBlock.setExitBlock(res);
		blocks.add(initialBlock);
		
		Function f = new Function("generate", blocks, new Class<?>[] {byte[].class}, 2, true);
		f.registerData(dataArray);
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
