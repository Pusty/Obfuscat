package re.bytecode.obfuscat.builder;

import java.util.ArrayList;
//import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.exception.BuilderArgumentException;

/**
 * This Builder creates a function that checks for a specific password and returns 1 if the first argument matches it and 0 otherwise
 * <br>
 * Supported Arguments: <br>
 * data -> byte[]: The key to produce <br>
 */
public class VerifyBuilder extends Builder {

	public VerifyBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();

		byte[] data = (byte[])args.get("data");
		if(data == null) throw new BuilderArgumentException("'data' argument must be provided");


		List<Integer> intList = IntStream.rangeClosed(0, data.length-1).boxed().collect(Collectors.toList());
		
		//Collections.shuffle(intList, getContext().random()); // shuffle when which array entry is written
		
		
		BasicBlock entryCheck = new BasicBlock();
		blocks.add(entryCheck);
		
		// build the failed block
		BasicBlock failed = new BasicBlock();
		{
			NodeConst retVal = new NodeConst(false);
			failed.getNodes().add(retVal);
			failed.setExitBlock(retVal);
			blocks.add(failed);
		}
		
		NodeLoad varLen = new NodeLoad(MemorySize.INT, 1);
		NodeConst constLen = new NodeConst(data.length);
		entryCheck.getNodes().add(varLen);
		entryCheck.getNodes().add(constLen);
		entryCheck.setConditionalBranch(failed, new BranchCondition(entryCheck, varLen, constLen, CompareOperation.NOTEQUAL));
		// check the length in the second argument
		
		BasicBlock curBlock;
		BasicBlock nextBlock = new BasicBlock();
		entryCheck.setUnconditionalBranch(nextBlock);
		
		// sequentially check each letter of the pass phrase
		for(int i=0;i<data.length;i++) {
			curBlock = nextBlock;
			
			int index = intList.get(i);

			nextBlock = new BasicBlock();
			
			NodeALoad b = new NodeALoad(new NodeLoad(MemorySize.POINTER, 0), new NodeConst(index), MemorySize.BYTE);
			NodeConst c = new NodeConst((int)data[index]);
			
			curBlock.getNodes().add(b);
			curBlock.getNodes().add(c);
			
			curBlock.setConditionalBranch(failed, new BranchCondition(curBlock, b, c, CompareOperation.NOTEQUAL));
			curBlock.setUnconditionalBranch(nextBlock);
			
			blocks.add(curBlock);
		}
		
		NodeConst retVal = new NodeConst(true);
		nextBlock.getNodes().add(retVal);
		nextBlock.setExitBlock(retVal);
		blocks.add(nextBlock);
		
		Function f = new Function("generate", blocks, new Class<?>[] { byte[].class, int.class }, 2, true);
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
		helpInfo.put("data", "[Required] The key for which this function will return 1");
		return helpInfo;
	}

	public String description() {
		return "A builder for functions that verify whether the input is the created key\n" +
			   "Call using 'function(array, array_length)'";
	}
}