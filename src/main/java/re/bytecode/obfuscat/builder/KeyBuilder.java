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
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.exception.BuilderArgumentException;

/**
 * This Builder creates a function that fills a provided array with a hardcoded key
 * <br>
 * Supported Arguments: <br>
 * data -> byte[]: The key to produce <br>
 */
public class KeyBuilder extends Builder {

	public KeyBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();

		byte[] data = (byte[])args.get("data");
		if(data == null) throw new BuilderArgumentException("'data' argument must be provided");


		List<Integer> intList = IntStream.rangeClosed(0, data.length-1).boxed().collect(Collectors.toList());
		Collections.shuffle(intList, getContext().random()); // shuffle when which array entry is written
		
		BasicBlock curBlock;
		BasicBlock nextBlock = new BasicBlock();
		
		for(int i=0;i<data.length;i++) {
			curBlock = nextBlock;
			
			int index = intList.get(i);

			// create the next block
			nextBlock = new BasicBlock();
			
			// add the store array entry nodes
			curBlock.getNodes().add(new NodeAStore(new NodeLoad(MemorySize.POINTER, 0), new NodeConst(index), new NodeConst(data[index]), MemorySize.BYTE));
			
			// link this block to the next block
			curBlock.setUnconditionalBranch(nextBlock);
			
			// add this block to the block list
			blocks.add(curBlock);
		}
		
		// the last block only returns
		nextBlock.setExitBlock(null);
		blocks.add(nextBlock);
		
		// function takes a byte array as argument and doesn't use any other variables, doesn't return anything
		Function f = new Function("generate", blocks, new Class<?>[] { byte[].class }, 1, false);
		return f;
	}

	@Override
	public Map<String, Class<?>> supportedArguments() {
		HashMap<String, Class<?>> supported = new HashMap<String, Class<?>>();
		supported.put("data", byte[].class);
		return supported;
	}

	@Override
	public Map<String, String> supportedArgumentsHelp() {
		HashMap<String, String> helpInfo = new HashMap<String, String>();
		helpInfo.put("data", "[Required] The key this function will generate");
		return helpInfo;
	}

	public String description() {
		return "A builder for functions that write a hardcoded key into an array\n" +
			   "Call using 'function(array)', note that the array length is not dynamically verified";
	}
}
