package re.bytecode.obfuscat.cfg;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

public class MergedFunction extends Function {
	
	private static final long serialVersionUID = 4854507091712950166L;

	public MergedFunction(String name, List<BasicBlock> blocks, Class<?>[] argumentTypes, int variableSlots,
			boolean returnsSomething) {
		super(name, blocks, argumentTypes, variableSlots, returnsSomething);
	}

	/*
	Class<?>[] args = convertFunctionDescriptor(method.getDescriptor());
	boolean returnValue = convertDescriptor(method.getDescriptor().split("\\x29")[1].charAt(0)) != null;
	// System.out.println("Processing: " + method.getName());
	List<BasicBlock> bbs = processMethod(classReader, method);
	// System.out.println(bbs);
	return new Function(method.getName()+method.getDescriptor(), bbs, args,
			method.getCode().getLocalVariableTable().getTable().length, returnValue);
	*/
	
	public static MergedFunction mergeFunctions(Map<String, Function> functions, String entryPoint) {
		
		
		BasicBlock handler = new BasicBlock();

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();
		blocks.add(handler);
		
		Node op1 = new NodeLoad(4, 0);
		
		int variableSlots = 0;
		int arguments     = 0;
		boolean returnSomething = false;
		
		// Iterate all functions
		for(Entry<String, Function> e: functions.entrySet()) {
			
			Function currentFunction = e.getValue();
			variableSlots = Math.max(variableSlots, currentFunction.getVariables());
			arguments     = Math.max(arguments, currentFunction.getArguments().length);
			returnSomething = returnSomething | currentFunction.hasReturnValue();

			List<BasicBlock> functionBlocks = currentFunction.getBlocks();
			
			// Iterate all blocks
			for(int b=0;b<functionBlocks.size();b++) {
				
				List<Node> nodes;
				
				BasicBlock currentBlock = functionBlocks.get(b);
				
				// Increase Loads
				nodes = currentBlock.findNodes(new NodeLoad(-1, -1));
				for(int j=0;j<nodes.size();j++) {
					NodeLoad oL = (NodeLoad)nodes.get(j);
					NodeLoad nL = new NodeLoad(oL.getLoadSize(), oL.getSlot()+1);
					currentBlock.replace(oL, nL);
				}
				
				// Increase Stores
				nodes = currentBlock.findNodes(new NodeStore(-1, -1, null));
				for(int j=0;j<nodes.size();j++) {
					NodeStore oS = (NodeStore)nodes.get(j);
					NodeStore nS = new NodeStore(oS.getStoreSize(), oS.getSlot()+1, oS.children()[0]);
					currentBlock.replace(oS, nS);
				}
				
				blocks.add(currentBlock);
			}
			
			if(!handler.getNodes().contains(op1))
				handler.getNodes().add(op1);
			Node op2 = new NodeConst(currentFunction.getName().hashCode());
			if(!handler.getNodes().contains(op2))
				handler.getNodes().add(op2);
			handler.getSwitchBlocks().put(new BranchCondition(handler, op1, op2, CompareOperation.EQUAL), currentFunction.getBlocks().get(0));
		}
		
		// Increase one for added parameter
		variableSlots += 1;
		arguments += 1;
		
		Function entryFunction = functions.get(entryPoint);
		handler.setUnconditionalBranch(entryFunction.getBlocks().get(0));
		
		Class<?>[] prevArgs = entryFunction.getArguments();
		Class<?>[] afterArgs = new Class<?>[prevArgs.length+1];
		
		for(int i=0;i<prevArgs.length;i++)
			afterArgs[i+1] = prevArgs[0];
		afterArgs[0] = int.class;
		
		return new MergedFunction(entryPoint+"_merged", blocks, afterArgs, variableSlots, returnSomething);
	}
	
}
