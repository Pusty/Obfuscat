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
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;

/**
 * This Builder creates a function that fills a provided array with randomized data and uses hardware specific registers to change them up
 * <br>
 * Supported Arguments: <br>
 * length -> Integer: The fixed length of the array to fill, default 4 <br>
 */
public class HWKeyBuilder extends Builder {

	public HWKeyBuilder(Context context) {
		super(context);
	}

	@Override
	protected Function generateFunction(Map<String, Object> args) {

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();

		
		int randomInt;
		int hardwareRegister = 0x123; // random seed depends on actual hardware, 8bit random source isn't really good and more of a placeholder
		

		int length = ((Integer)args.getOrDefault("length", 4)).intValue();
		if(length < 1) throw new IllegalArgumentException("Length must at least be 1");
		
		List<Integer> intList = IntStream.rangeClosed(0, length-1).boxed().collect(Collectors.toList());
		Collections.shuffle(intList, getContext().random()); // shuffle when which array entry is written
		
		BasicBlock curBlock;
		BasicBlock nextBlock = new BasicBlock();
		
		for(int i=0;i<length;i++) {
			curBlock = nextBlock;
			
			int index = intList.get(i);
			int operation = getContext().rand()%4; // mul, add, sub, xor
			
			Node operationNode;
			
			// generate random constant, make sure it's not 0 (may want to prevent more bad constants)
			randomInt = getContext().rand();
			while(randomInt == 0) randomInt = getContext().rand();
			
			Node num = new NodeCustom("readInt", new NodeConst(hardwareRegister)); // read hardware register
			
			// choose actual operation
			switch(operation) {
			case 0:
				operationNode = new NodeMath(MathOperation.MUL, num, new NodeConst(randomInt));
				break;
			case 1:
				operationNode = new NodeMath(MathOperation.ADD, num, new NodeConst(randomInt));
				break;
			case 2:
				operationNode = new NodeMath(MathOperation.SUB, num, new NodeConst(randomInt));
				break;
			case 3:
			default:
				operationNode = new NodeMath(MathOperation.XOR, num, new NodeConst(randomInt));
				break;
			}
			
			// create the next block
			nextBlock = new BasicBlock();
			// add the store array entry nodes
			curBlock.getNodes().add(new NodeAStore(new NodeLoad(MemorySize.POINTER, 0), new NodeConst(index), new NodeMath(MathOperation.AND, operationNode, new NodeConst(0xFF)), MemorySize.BYTE));
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
		supported.put("length", Integer.class);
		return supported;
	}

	@Override
	public Map<String, String> supportedArgumentsHelp() {
		HashMap<String, String> helpInfo = new HashMap<String, String>();
		helpInfo.put("length", "The length of the randomised key being written (Default: 4)");
		return helpInfo;
	}
	
	public String description() {
		return "A builder for functions that write a randomised key with fixed size into an array\n" +
			   "Call using 'function(array)', note that the array length is not dynamically verified\n" +
			   "The function dynamically reads from hardware register 0x123 [PLACEHOLDER] to randomise per device\n";
	}

}
