package re.bytecode.obfuscat.pass;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.CompareOperation;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

import static re.bytecode.obfuscat.cfg.MathOperation.*;


public class FlatteningPass extends Pass {
	
	public FlatteningPass(Context context) {
		super(context);
	}
	

	@Override
	protected Function processFunction(Function function, Map<String, Object> args) {
		
		int cfv = function.getVariables(); // Variable to store the id of the next basic block in

		Function nf = null;
		
		if(function instanceof MergedFunction)
			nf = new MergedFunction(function.getName(), new ArrayList<BasicBlock>(), function.getArguments(), function.getVariables()+1, function.hasReturnValue());
		else
			nf = new Function(function.getName(), new ArrayList<BasicBlock>(), function.getArguments(), function.getVariables()+1, function.hasReturnValue());
		
		nf.setDataMap(function.getDataMap());
		
		BasicBlock dispatcher = new BasicBlock();
		NodeLoad dispatchValue = new NodeLoad(MemorySize.INT, cfv);
		dispatcher.getNodes().add(dispatchValue);
		
		
	
		ArrayList<BasicBlock> switchList = new ArrayList<BasicBlock>();
		HashMap<BasicBlock, Integer> blockMap = new HashMap<BasicBlock, Integer>();
		int bbIDs = 0;
		
		BasicBlock entryBlock = function.getBlocks().get(0);
		
		Collections.shuffle(function.getBlocks(), this.getContext().random()); // this way control flow can't be inferred from basic block placement
		
		for(BasicBlock bb:function.getBlocks()) {
			blockMap.put(bb, bbIDs++);
			switchList.add(bb);
		}
		
		dispatcher.setSwitchBlock(switchList, dispatchValue);
		
		int initialBasicBlockID = bb2int(blockMap, entryBlock); // set the dispatcher value initially to the first basic block
		BasicBlock initialBlock = new BasicBlock();
		initialBlock.getNodes().add(new NodeStore(MemorySize.INT, cfv, new NodeConst(initialBasicBlockID)));
		initialBlock.setUnconditionalBranch(dispatcher); // connect the initial block to the dispatcher
		
		
		// Dependency Analysis
		HashMap<BasicBlock, List<BasicBlock>> sources = new HashMap<BasicBlock, List<BasicBlock>>();
		HashMap<BasicBlock, List<BasicBlock>> poison = new HashMap<BasicBlock, List<BasicBlock>>();
		for(BasicBlock bb:function.getBlocks()) {
			sources.put(bb, new ArrayList<BasicBlock>());
			poison.put(bb, new ArrayList<BasicBlock>()); // if a poison exists then the source can't be determined
		}
		
		sources.get(entryBlock).add(initialBlock); // intial block sets id
		
		for(BasicBlock bb:function.getBlocks()) {
			if(bb.isConditionalBlock()) {
				sources.get(bb.getConditionalBranch()).add(bb);
				sources.get(bb.getUnconditionalBranch()).add(bb);
			}else if(bb.isSwitchCase()) {
				for(BasicBlock sc:bb.getSwitchBlocks())
					poison.get(sc).add(bb);
			}else if(bb.isExitBlock()) {

			}else {
				sources.get(bb.getUnconditionalBranch()).add(bb);
			}
		}
		

		// iterate all basic blocks and change their branches to the dispatcher
		for(BasicBlock bb:function.getBlocks()) {

			int curPos = bb2int(blockMap, bb); // cfv = curPos only if previous basic block did use dispatcher
			boolean isPoisoned = poison.get(bb).size() > 0;
			
			// Unpoisened means cfv = curPos
			// If this is true we can do relative "jumps"
			// through this the source of a block can only be determined if all paths backward are explored
			// this makes backwards analysis hard (forward analysis is obviously still possible)
			// in many analysis tools this breaks automatic control flow analyisis of the switch case
			// what more, tools that fail to analyze all branches of the switch through forward analysis will
			// have problems determining the bounds of the switch, which will hinder proper analysis even more
			// (this is not a problem for manual analysis though as the bounds of the switch are pretty obvious)
			
			if(bb.isConditionalBlock()) {

				int targetYes = bb2int(blockMap, bb.getConditionalBranch());
				int targetNo = bb2int(blockMap, bb.getUnconditionalBranch());
				
				Node tmp;
				Node x = bb.getCondition().getOperant1();
				Node y = bb.getCondition().getOperant2();
				CompareOperation operation = bb.getCondition().getOperation();

				// Hackers delight, Comparison Predicates
				Node compare;
				Node formula;
				switch (operation) {
				case EQUAL:
					compare = nop(nop(nop(and(ushr(not(or(sub(x, y), sub(y, x))), cst(31)), cst(1))))); // 6+3 math 2 cst
					break;
				case NOTEQUAL:	
					compare = nop(nop(nop(nop(and(ushr(or(sub(x, y), sub(y, x)), cst(31)), cst(1))))));  // 5+4 math 2cst
					break;
				case GREATERTHAN:
					tmp = x;
					x = y;
					y = tmp;
				case LESSTHAN:
					compare = nop(and(ushr(xor(sub(x, y),and(xor(x, y),xor(sub(x, y), x))), cst(31)), cst(1))); // 8+1 math 2cst
					break;
				case GREATEREQUAL:
					tmp = x;
					x = y;
					y = tmp;
				case LESSEQUAL:
					compare = and(ushr(and(or(x, not(y)),or(xor(x, y),not(sub(y, x)))), cst(31)), cst(1)); // 9 math 2cst
					break;
				default:
					throw new RuntimeException("Not implemented");
				}
				
				Node load   = new NodeLoad(MemorySize.INT, cfv);
				if(isPoisoned) {
					bb.getNodes().add(nop(load)); // 1load, 1math - this is not connected and just to pad
					formula = add(mul(compare, cst(targetYes-targetNo)), cst(targetNo));
					bb.getNodes().add(new NodeStore(MemorySize.INT, cfv, formula));  // 1store 2math 2cst
				}else {
					formula = add(mul(compare, cst(targetYes-targetNo)), cst(targetNo-curPos)); 
					bb.getNodes().add(new NodeStore(MemorySize.INT, cfv, add(load, formula))); // 1store 3math 2cst 1load
				}
				

				bb.unsetConditionalBranch();
				bb.setUnconditionalBranch(dispatcher);
				
			}else if(bb.isSwitchCase()) {
				// Switches are not considered, so do nothing
			}else if(bb.isExitBlock()) {
				// Do nothing if it is just exiting
			}else {
				// Normal branch
				
				int target = bb2int(blockMap, bb.getUnconditionalBranch());
				
				Node load = new NodeLoad(MemorySize.INT, cfv);
				if(isPoisoned) {
					bb.getNodes().add(nop(load)); // 1load, 1math - this is not connected and just to pad
					bb.getNodes().add(new NodeStore(MemorySize.INT, cfv,  new NodeConst(target))); //1store 1cst
				}else {
					bb.getNodes().add(new NodeStore(MemorySize.INT, cfv, add(load, cst(target-curPos)))); //1store 1load 1math 1cst
				}

				bb.setUnconditionalBranch(dispatcher);
			}
		}
		
		nf.getBlocks().add(initialBlock); // initial block first
		nf.getBlocks().add(dispatcher); // dispatcher after
		nf.getBlocks().addAll(function.getBlocks()); // all modified blocks now
		
		
		return nf;
	}
	
	private int bb2int(HashMap<BasicBlock, Integer> map, BasicBlock bb) {
		return map.get(bb);
	}
	
	@Override
	public Map<String, Node> statistics() {
		Map<String, Node> map = new HashMap<String, Node>();
		
		// store + const | jump - initial block
		
		// load | switch - switch table itself
		
		// conditional jump -> 9 math, 2cst + 1store, 3math, 2cst, 1load | now normal jump
		// normal jump -> 1store, 1load, 1math, 1cst
		map.put("math", add(cst("math"), add(mul(cst("conditionalBlocks"), cst(12)), mul(cst("jumpBlocks"), cst(1)))));
		map.put("const", add(cst("const"), add(add(mul(cst("conditionalBlocks"), cst(4)), mul(cst("jumpBlocks"), cst(1))),cst(1))));
		map.put("store", add(cst("store"), add(add(mul(cst("conditionalBlocks"), cst(1)), mul(cst("jumpBlocks"), cst(1))), cst(1))));
		map.put("load", add(cst("load"), add(add(mul(cst("conditionalBlocks"), cst(1)), mul(cst("jumpBlocks"), cst(1))),cst(1))));
		map.put("jumpBlocks", add(cst("jumpBlocks"), add(mul(cst("conditionalBlocks"), cst(1)), cst(1))));
		map.put("conditionalBlocks", cst(0)); // all replaced!
		map.put("switchBlocks", add(cst("switchBlocks"), cst(1)));
		map.put("blocks", add(cst("blocks"), cst(2)));
		map.put("variables", add(cst("variables"), cst(1)));
		
		return map;
	}
	
	@Override
	public Map<String, Node> statisticsRuntime() {
		Map<String, Node> map = statistics();
		// note for runtime behavior:
		// each block jumps to the dispatcher, so the dispatcher is executed for each taken jump additionally ( + load + switch)
		map.put("load", add(map.get("load"), add(cst("jumpBlocks"), cst("conditionalBlocks"))));
		map.put("blocks", add(map.get("blocks"), sub(cst("blocks"), cst(1))));
		map.put("switchBlocks", add(map.get("switchBlocks"), add(cst("jumpBlocks"), cst("conditionalBlocks"))));
		map.put("conditionalBlocksFalse", cst(0)); // all replaced!
		
		return map;
	}
	
	public String description() {
		return "Flattens the control flow";
	}

}
