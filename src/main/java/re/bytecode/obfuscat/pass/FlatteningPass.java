package re.bytecode.obfuscat.pass;

import java.util.ArrayList;
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
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

import static re.bytecode.obfuscat.cfg.MathOperation.*;


public class FlatteningPass extends Pass {
	
	public FlatteningPass(Context context) {
		super(context);
	}
	

	@Override
	protected Function processFunction(Function function, Map<String, Object> args) {
		
		
		int cfv = function.getVariables(); // Variable to store the id of the next basic block in
		int retVal = cfv+1; // Variable to temp store return values in
		
		Function nf = new Function(function.getName(), new ArrayList<BasicBlock>(), function.getArguments(), function.getVariables()+2, function.hasReturnValue());
		
		
		
		int initialBasicBlockID = bb2int(function.getBlocks().get(0)); // set the dispatcher value intially to the first basic block
		BasicBlock initialBlock = new BasicBlock();
		initialBlock.getNodes().add(new NodeStore(MemorySize.INT, cfv, new NodeConst(initialBasicBlockID)));
		
		BasicBlock dispatcher = new BasicBlock();
		NodeLoad dispatchValue = new NodeLoad(MemorySize.INT, cfv);
		dispatcher.getNodes().add(dispatchValue);
		
		
		initialBlock.setUnconditionalBranch(dispatcher); // connect the initial block to the dispatcher
		
		List<Integer> safetyList = new ArrayList<Integer>(); // make sure no dispatch constant exists twice
		
		for(BasicBlock bb:function.getBlocks()) {
			int dispatchConstValue = bb2int(bb);
			if(safetyList.contains(dispatchConstValue)) {
				throw new RuntimeException("Tried to generate same dispatch constant twice ("+bb+")");
			}
			safetyList.add(dispatchConstValue);
			NodeConst dispatchConst = new NodeConst(dispatchConstValue);
			dispatcher.getNodes().add(dispatchConst);
			dispatcher.getSwitchBlocks().put(new BranchCondition(dispatcher, dispatchValue, dispatchConst, CompareOperation.EQUAL), bb);
		}
		
		
		// this block is the convergence of all returns
		BasicBlock exitBlock = new BasicBlock();
		NodeLoad retValNode = new NodeLoad(MemorySize.POINTER, retVal);
		exitBlock.getNodes().add(retValNode);
		exitBlock.setExitBlock(retValNode);
		
		dispatcher.setUnconditionalBranch(exitBlock); // in case of illegal id jump to the exit block
		
	
		// iterate all basic blocks and change their branches to the dispatcher
		for(BasicBlock bb:function.getBlocks()) {
			
			int amountOfJumps = 1 + bb.getSwitchBlocks().size();
			if(amountOfJumps == 1) {
			
				if(bb.isExitBlock()) {
					if(bb.getReturnValue() != null)
						bb.getNodes().add(new NodeStore(MemorySize.POINTER, retVal, bb.getReturnValue()));
					bb.setUnconditionalBranch(exitBlock);
				}else {
					NodeConst jmpPos = new NodeConst(bb2int(bb.getUnconditionalBranch()));
					bb.getNodes().add(new NodeStore(MemorySize.INT, cfv,jmpPos));
					bb.setUnconditionalBranch(dispatcher);
				}
			}else if(amountOfJumps == 2) {
				// for 2 a boolean / math expression needs to be inserted that varies between the possible ids
				// TODO
			}else {
				// for now skip if more than 2 branches / skip switches
				// TODO
			}
		}
		
		nf.getBlocks().add(initialBlock); // initial block first
		nf.getBlocks().add(dispatcher); // dispatcher after
		nf.getBlocks().addAll(function.getBlocks()); // all modified blocks now
		
		
		return nf;
	}
	
	private int bb2int(BasicBlock bb) {
		return bb.hashCode();
	}
	
	
	public Map<String, Node> statistics() {
		Map<String, Node> map = new HashMap<String, Node>();
		return map;
	}
	
	public String description() {
		return "Flattens the control flow";
	}

}
