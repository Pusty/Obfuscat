package re.bytecode.obfuscat.cfg;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
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
	
	
	// Ironcily this merger is more efficient and was used to test the switch table
	// But in practice it weakens Flattening as code paths are not predictable
	// allowing both methods of merging would make sense
	// TODO
	// see commit eec106263e520048c66094d864eda6ce5381b424 for "old" version
	
	public static MergedFunction mergeFunctions(Map<String, Function> functions, String entryPoint) {
		

		List<BasicBlock> blocks = new ArrayList<BasicBlock>();
		
		BasicBlock handler = new BasicBlock();
		NodeLoad loadSwitchVar = new NodeLoad(MemorySize.INT, 0);
		handler.getNodes().add(loadSwitchVar);
		blocks.add(handler);
		
		int variableSlots = 0;
		int arguments     = 0;
		boolean returnSomething = false;
		
		Function entryFunction = functions.get(entryPoint);
		HashMap<Integer, Integer> resolvedCalls = new HashMap<Integer, Integer>();
		resolvedCalls.put(entryFunction.getName().hashCode(), 0);
		
		int resolveCounter = 1;
		for(Entry<String, Function> e: functions.entrySet()) {
			if(!resolvedCalls.containsKey(e.getValue().getName().hashCode())) {
				resolvedCalls.put(e.getValue().getName().hashCode(), resolveCounter++);
			}
		}
		
		

		// Iterate all functions
		for(Entry<String, Function> e: functions.entrySet()) {
			
			Function currentFunction = e.getValue();
			
			if(currentFunction instanceof MergedFunction) {
				throw new RuntimeException("Merging of already merged functions is not supported"); // this needs special cases and would only works pre-obfuscation
			}
			
			variableSlots = Math.max(variableSlots, currentFunction.getVariables());
			arguments     = Math.max(arguments, currentFunction.getArguments().length);
			returnSomething = returnSomething | currentFunction.hasReturnValue();

			List<BasicBlock> functionBlocks = currentFunction.getBlocks();
			
			// Iterate all blocks
			for(int b=0;b<functionBlocks.size();b++) {
				
				List<Node> nodes;
				
				BasicBlock currentBlock = functionBlocks.get(b);
				
				// Increase Loads
				nodes = currentBlock.findNodes(new NodeLoad(MemorySize.ANY, -1));
				for(int j=0;j<nodes.size();j++) {
					NodeLoad oL = (NodeLoad)nodes.get(j);
					NodeLoad nL = new NodeLoad(oL.getLoadSize(), oL.getSlot()+1);
					currentBlock.replace(oL, nL);
				}
				
				// Increase Stores
				nodes = currentBlock.findNodes(new NodeStore(MemorySize.ANY, -1, null));
				for(int j=0;j<nodes.size();j++) {
					NodeStore oS = (NodeStore)nodes.get(j);
					NodeStore nS = new NodeStore(oS.getStoreSize(), oS.getSlot()+1, oS.children()[0]);
					currentBlock.replace(oS, nS);
				}
				
				// Resolve calls
				nodes = currentBlock.findNodes(new NodeCustom("call_unresolved", new NodeConst(null)));
				for(int j=0;j<nodes.size();j++) {
					NodeCustom unresolvedCall = (NodeCustom)nodes.get(j);
					int callHash = ((Integer)((NodeConst)unresolvedCall.children()[0]).getObj()).intValue();
					if(!resolvedCalls.containsKey(callHash))
						throw new RuntimeException("Call to function with hash "+Integer.toHexString(callHash)+" can't be resolved");
					
					Node[] args = unresolvedCall.children();
					args[0] =  new NodeConst(resolvedCalls.get(callHash)); // replace with resolved constant
					
					NodeCustom resolvedCall = new NodeCustom("call", args);
					currentBlock.replace(unresolvedCall, resolvedCall);
				}
				blocks.add(currentBlock);
			}
		}
		
		List<BasicBlock> switchBlocks = new ArrayList<BasicBlock>();
		for(int i=0;i<resolveCounter;i++) {
			for(Entry<String, Function> e: functions.entrySet()) {
				if(i == resolvedCalls.get(e.getValue().getName().hashCode())) {
					switchBlocks.add(e.getValue().getBlocks().get(0));
					break;
				}
			}
		}

		handler.setSwitchBlock(switchBlocks, loadSwitchVar);

		// Increase one for added parameter
		variableSlots += 1;
		arguments += 1;
		
		Class<?>[] prevArgs = entryFunction.getArguments();
		Class<?>[] afterArgs = new Class<?>[prevArgs.length+1];
		
		for(int i=0;i<prevArgs.length;i++)
			afterArgs[i+1] = prevArgs[0];
		afterArgs[0] = int.class;
		
		return new MergedFunction(entryPoint+"_merged", blocks, afterArgs, variableSlots, returnSomething);
	}
	

	
}
