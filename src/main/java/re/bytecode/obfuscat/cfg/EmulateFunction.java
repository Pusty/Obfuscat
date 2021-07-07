package re.bytecode.obfuscat.cfg;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeAlloc;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

/**
 * This Emulates the execution of a function Used for DSL Verification
 */
public class EmulateFunction {

	// The emulated function
	private Function function;

	// The currently executed basic block
	private BasicBlock currentBlock;

	// Slot -> Variable Value
	private Map<Integer, Object> variables;
	
	// Array Reference -> Array
	private Map<Integer, Object> arrayTable;

	// A map of node -> result (reset every basic block entry)
	private Map<Node, Object> nodeMap;
	
	// Const map for evaluations, may be null
	private Map<String, Integer> constMap;
	
	// Runtime statistics, will reset on run
	private Map<String, Integer> runtimeStatistics;
	
	
	// temporary variable for argument preparations  (NodeCustom("prepare_call") and NodeCustom("call"))
	private Object[] nextcallArgs;
	
	// map for caching constant arrays
	private Map<Object, Object[]> constarray2objarray;
	

	/**
	 * Create a function emulator based on a function
	 * 
	 * @param f
	 *            the function to emulate
	 */
	public EmulateFunction(Function f) {
		this.function = f;

		currentBlock = f.getBlocks().get(0);
		variables = new HashMap<Integer, Object>();
		arrayTable = new HashMap<Integer, Object>();
		
		constarray2objarray = new HashMap<Object, Object[]>();
	}
	
	



	// Execute a node
	private void executeNode(Node node) {

		// if this node was already executed this basic block
		if (nodeMap.containsKey(node))
			return;
		
		executedNodes++;

		// Evaluate the children of this node first if existent
		Node[] children = node.children();
		if (children != null) {
			for (int i = 0; i < children.length; i++)
				executeNode(children[i]);
		}

		// Read out the required input from the evaluated nodes
		Object input[] = null;
		if (children != null) {
			input = new Object[children.length];
			for (int i = 0; i < children.length; i++)
				input[i] = nodeMap.get(children[i]);
		}

		Object output = null;
		
		runtimeStatistics.put(node.getNodeIdentifier(), runtimeStatistics.getOrDefault(node.getNodeIdentifier(), 0)+1);
		if (node instanceof NodeConst) {
			// If the node is a constant node then convert it to an Integer
			Object obj = ((NodeConst) node).getObj();
			Integer value = null;
			if (obj instanceof Byte) {
				value = ((Byte) obj).intValue();
			} else if (obj instanceof Boolean) {
				value = ((Boolean) obj).booleanValue()?1:0;
			} else if (obj instanceof Character) {
				value = (int) ((Character) obj).charValue();
			} else if (obj instanceof Short) {
				value = (int) ((Short) obj).intValue();
			} else if (obj instanceof Integer) {
				value = (Integer) obj;
			} else if (obj instanceof String) {
				String str = (String)obj;
				if(constMap == null) {
					output = str;
					// throw new RuntimeException("String Constants not supported");
				}else {
					if(constMap.containsKey(str))
						value = (Integer)constMap.get(str);
					else
						throw new RuntimeException("Keyword "+str+" not supported as a constant "+constMap);
					
				}
			} else if(obj.getClass().isArray()) {
				Object data = function.getData(obj);
				
				if(data == null)
					throw new RuntimeException("Constant array not registered "+obj);
				
				Object[] oarray;
				if(constarray2objarray.containsKey(data))
					oarray = constarray2objarray.get(data);
				else {
					oarray = convertToObjectArray(data); 
					constarray2objarray.put(data, oarray);
				}
				
				output = (Integer)registerArray(oarray);
				
			}else {
				throw new RuntimeException("Constant Type not supported "+obj.getClass());
			}
			if(value != null)
				output = value;
		} else if (node instanceof NodeLoad) {
			// If the node is a variable load node then read the variable and convert it to
			// an Integer (or keep it as what it was if already an Integer / Array)
			NodeLoad nl = (NodeLoad) node;
			Object value = variables.get(nl.getSlot());
			switch (nl.getLoadSize()) {
			case BYTE:
				output = Integer.valueOf((int) ((Integer) value).byteValue());
				break;
			case SHORT:
				output = Integer.valueOf((int) ((Integer) value).shortValue());
				break;
			case INT:
			case POINTER:
				output = value;
				break;
			default:
				throw new RuntimeException("Not implemented");
			}

		} else if (node instanceof NodeStore) {
			// If the node is a variable store node then convert it to an Integer and write
			// the variable (or keep it as what it was if already an Integer / Array)
			NodeStore ns = (NodeStore) node;
			Object value = input[0];
			switch (ns.getStoreSize()) {
			case BYTE:
				variables.put(ns.getSlot(), Integer.valueOf((int) ((Integer) value).byteValue()));
				break;
			case SHORT:
				variables.put(ns.getSlot(), Integer.valueOf((int) ((Integer) value).shortValue()));
				break;
			case INT:
			case POINTER:
				variables.put(ns.getSlot(), value);
				break;
			default:
				throw new RuntimeException("Not implemented");
			}
		} else if (node instanceof NodeALoad) {
			// If the node is an array load node then read from the array and convert the
			// result to an integer
			NodeALoad nl = (NodeALoad) node;

			Object[] array = (Object[]) arrayTable.get(input[0]);
			Integer index = (Integer) input[1];
			
			switch (nl.getLoadSize()) {
			case BYTE:
				output = Integer.valueOf((int) (((Integer) array[index]).byteValue()));
				break;
			case SHORT:
				output = Integer.valueOf((int) (((Integer) array[index]).shortValue()));
				break;
			case INT:
			case POINTER:
				output = ((Integer) array[index]);
				break;
			default:
				throw new RuntimeException("Not implemented");
			}

		} else if (node instanceof NodeAStore) {
			// If the node is an array store node then convert the value to write to an
			// integer and write it
			NodeAStore ns = (NodeAStore) node;

			Object[] array = (Object[]) arrayTable.get(input[0]);
			Integer index = (Integer) input[1];
			
			switch (ns.getStoreSize()) {
			case BYTE:
				array[index] = Integer.valueOf((int) (((Integer) input[2]).byteValue()));
				break;
			case SHORT:
				array[index] = Integer.valueOf((int) (((Integer) input[2]).shortValue()));
				break;
			case INT:
			case POINTER:
				array[index] = ((Integer) input[2]);
				break;
			default:
				throw new RuntimeException("Not implemented");
			}
		}else if (node instanceof NodeMath) {
			// If the node is a math operation then apply the operation
			switch (((NodeMath) node).getOperation()) {
			case ADD:
				output = ((Integer) input[0]) + ((Integer) input[1]);
				break;
			case SUB:
				output = ((Integer) input[0]) - ((Integer) input[1]);
				break;
			case MUL:
				output = ((Integer) input[0]) * ((Integer) input[1]);
				break;
			case DIV:
				output = ((Integer) input[0]) / ((Integer) input[1]);
				break;
			case MOD:
				output = ((Integer) input[0]) % ((Integer) input[1]);
				break;
			case AND:
				output = ((Integer) input[0]) & ((Integer) input[1]);
				break;
			case OR:
				output = ((Integer) input[0]) | ((Integer) input[1]);
				break;
			case XOR:
				output = ((Integer) input[0]) ^ ((Integer) input[1]);
				break;
			case SHR:
				output = ((Integer) input[0]) >> ((Integer) input[1]);
				break;
			case USHR:
				output = ((Integer) input[0]) >>> ((Integer) input[1]);
				break;
			case SHL:
				output = ((Integer) input[0]) << ((Integer) input[1]);
				break;
			case NOT:
				output = ~((Integer) input[0]);
				break;
			case NEG:
				output = -((Integer) input[0]);
				break;
			case NOP:
				output = ((Integer) input[0]);
				break;
			default:
				throw new RuntimeException("Not implemented");
			}
		} else if (node instanceof NodeAlloc) {
			
			NodeAlloc alloc = (NodeAlloc) node;
			Integer count = (Integer) input[0];
			
			
			Object[] array;
			
			switch (alloc.getAllocationSize()) {
			case BYTE:
			case SHORT:
			case INT:
			case POINTER:
				array = new Integer[count];
				break;
			default:
				throw new RuntimeException("Not implemented");
			}
			
			output = registerArray(array);

		} else if (node instanceof NodeCustom) {
			NodeCustom custom = (NodeCustom) node;

			if (custom.getIdentifier().equals("call")) {
				if (!(function instanceof MergedFunction))
					throw new RuntimeException("Can't call in unmerged function");
	
				EmulateFunction tef = new EmulateFunction(function);
				tef.arrayTable = arrayTable;
				tef.constMap = constMap;
				output = tef.run0(-1, false, nextcallArgs);
				
				// add call statistics to this one
				for(Entry<String, Integer> e:tef.runtimeStatistics.entrySet())
					runtimeStatistics.put(e.getKey(), runtimeStatistics.getOrDefault(e.getKey(), 0)+e.getValue());
				
			}else if (custom.getIdentifier().equals("prepare_call")) {
				if (!(function instanceof MergedFunction))
					throw new RuntimeException("Can't call in unmerged function");
	
				nextcallArgs = input;
			}else if(custom.getIdentifier().equals("debugPrint")) {
				// Debug Print in emulation
				StringBuilder sb = new StringBuilder("[debugPrint]: ");
				
				for(Object obj:input) {
					sb.append(obj == null? "null": obj.toString());
					sb.append(' ');
				}
				System.out.println(sb.substring(0, sb.length()-1));
				
			} else
				throw new RuntimeException("Not implemented Node " + node);

		} else {
			// Missing nodes (including custom nodes) throw exceptions
			throw new RuntimeException("Not implemented Node " + node);
		}

		// store the evaluated result
		nodeMap.put(node, output);
	}
	
	public Function getFunction() {
		return function;
	}
	
	public int getExecutedNodes() {
		return executedNodes;
	}
	
	private Random arrayRandom = new Random();
	private int arrayAddressSeed = arrayRandom.nextInt();
	
	private int registerArray(Object[] arr) {
		if(arrayTable.containsValue(arr)) {
			for(Entry<Integer, Object> e:arrayTable.entrySet()) {
				if(e.getValue() == arr)
					return e.getKey();
			}
			throw new RuntimeException("Object "+arr+" should have been in the array table");
		}else {
			int ar = arrayAddressSeed&0x7FFFFFFF;
			arrayTable.put(ar, arr);
			//System.out.println(Integer.toHexString(ar)+" # "+Arrays.toString(arr));
			arrayAddressSeed = arrayRandom.nextInt();
			return ar;
		}
	}
	
	
	private int executedNodes;
	
	public static int eval(Node node, Map<String, Integer> constMap) {
		BasicBlock bb = new BasicBlock();
		bb.getNodes().add(node);
		bb.setExitBlock(node);
		
		Function f = new Function("tmp", Arrays.asList(bb) , new Class[] {}, 0, true);
		
		EmulateFunction ef = new EmulateFunction(f);
		ef.constMap = constMap;
		return (Integer) ef.run(-1);
	}
	

	/**
	 * Run the emulation with a maximum amount of blocks to execute and the
	 * arguments to the emulations
	 * 
	 * @param blockLimit
	 *            the amount of blocks to execute (-1 for unlimited)
	 * @param args
	 *            the arguments for the emulation
	 * @return the return value
	 */
	public Object run(int blockLimit, Object... args) {
		executedNodes = 0;
		
		if(this.getFunction() instanceof MergedFunction) { // this is here to make usage of merged functions more in line with normal usage
			Object[] argsAfter = new Object[args.length + 1];
			for (int i = 0; i < args.length; i++)
				argsAfter[i + 1] = args[i];
			argsAfter[0] = 0;
			args = argsAfter;
		}
		
		return run0(blockLimit, true, args);
	}
	
	
	private Object[] convertToObjectArray(Object argV) {
		Class<?> arg = argV.getClass();
		
		if (!arg.isArray()) 
			throw new IllegalArgumentException("Can only convert arrays");
		
		if (arg == byte[].class) {
			byte[] ba = ((byte[]) argV);
			Object[] oa = new Object[ba.length];
			for (int j = 0; j < ba.length; j++)
				oa[j] = Integer.valueOf(ba[j]);
			return oa;
		}else if (arg == boolean[].class) {
			boolean[] ba = ((boolean[]) argV);
			Object[] oa = new Object[ba.length];
			for (int j = 0; j < ba.length; j++)
				oa[j] = Integer.valueOf(ba[j]?1:0);
			return oa;
		}  else if (arg == short[].class) {
			short[] sa = ((short[]) argV);
			Object[] oa = new Object[sa.length];
			for (int j = 0; j < sa.length; j++)
				oa[j] = Integer.valueOf(sa[j]);
			return oa;
		} else if (arg == char[].class) {
			char[] ca = ((char[]) argV);
			Object[] oa = new Object[ca.length];
			for (int j = 0; j < ca.length; j++)
				oa[j] = Integer.valueOf(ca[j]);
			return oa;
		} else if (arg == int[].class) {
			int[] ia = ((int[]) argV);
			Object[] oa = new Object[ia.length];
			for (int j = 0; j < ia.length; j++)
				oa[j] = Integer.valueOf(ia[j]);
			return oa;
		} else
			throw new RuntimeException("Unsupported Array Type "+argV);
		
	}
	
	
	private Object registerArrayRecursive(Object argV, boolean check, int i) {
		
		Class<?> arg = argV.getClass();
		
		// Convert arrays to boxed integer versions
		if (arg.isArray()) {
			if (arg == byte[].class) {
				argV = registerArray(convertToObjectArray(argV));
			}else if (arg == boolean[].class) {
				argV = registerArray(convertToObjectArray(argV));
			}  else if (arg == short[].class) {
				argV = registerArray(convertToObjectArray(argV));
			} else if (arg == char[].class) {
				argV = registerArray(convertToObjectArray(argV));
			} else if (arg == int[].class) {
				argV = registerArray(convertToObjectArray(argV));
			} else if (arg == Object[].class) {
				Object[] oa = ((Object[]) argV);
				Object[] replacedRef = new Object[oa.length];
				for(int j=0;j<oa.length;j++) {
					if(oa[j] == null) continue;
					replacedRef[j] = registerArrayRecursive(oa[j], false, i);
				}
				argV = registerArray(replacedRef);
			} else
				throw new RuntimeException("Unsupported Array Type "+argV);
		}
		
		// Check Type
		if (arg == Integer.class)
			arg = int.class;
		else if (arg == Short.class)
			arg = short.class;
		else if (arg == Character.class)
			arg = char.class;
		else if (arg == Byte.class)
			arg = byte.class;
		else if (arg == Boolean.class)
			arg = boolean.class;
		else if (arg.isArray())
			arg = Array.class;
		
		if (check && (function.getArguments()[i] != arg) && (!function.getArguments()[i].isArray() || arg != Array.class))
			throw new RuntimeException("Type of Argument " + i + " doesn't match signature ("+arg+" != "+function.getArguments()[i]+")");

		return argV;
	}
	
	
	private void writebackRecursive(Object argV, Integer addr ) {
		
		Class<?> arg = argV.getClass();
		
		if (arg.isArray()) {

			if (arg == byte[].class) {
				byte[] ba = ((byte[]) argV);
				Object[] oa = (Object[]) arrayTable.get(addr);
				for (int j = 0; j < ba.length; j++)
					ba[j] = ((Integer)oa[j]).byteValue();
			}else if (arg == boolean[].class) {
				boolean[] ba = ((boolean[]) argV);
				Object[] oa = (Object[]) arrayTable.get(addr);
				for (int j = 0; j < ba.length; j++)
					ba[j] = ((Integer)oa[j]).byteValue() != 0;
			} else if (arg == short[].class) {
				short[] sa = ((short[]) argV);
				Object[] oa = (Object[]) arrayTable.get(addr);
				for (int j = 0; j < sa.length; j++)
					sa[j] = ((Integer)oa[j]).shortValue();
			} else if (arg == char[].class) {
				char[] ca = ((char[]) argV);
				Object[] oa = (Object[]) arrayTable.get(addr);
				for (int j = 0; j < ca.length; j++)
					ca[j] = (char) ((Integer)oa[j]).shortValue();
			} else if (arg == int[].class) {
				int[] ia = ((int[]) argV);
				Object[] oa = (Object[]) arrayTable.get(addr);
				for (int j = 0; j < ia.length; j++)
					ia[j] = ((Integer)oa[j]).intValue();
			} else if (arg == Object[].class) {
				Object[] oa = ((Object[]) argV);
				Object[] tmpArray = (Object[]) arrayTable.get(addr);
				for (int j = 0; j < tmpArray.length; j++) {
					writebackRecursive(oa[j],(Integer)tmpArray[j]); // oa for the array, tmpArray for the internal address
				}
			}else
				throw new RuntimeException("Not supported");
		}
	}

	public Object run0(int blockLimit, boolean check, Object... args) {
		
		
		// start runtime statistics
		runtimeStatistics = new HashMap<String, Integer>();
		
		runtimeStatistics.put("calls", 1); // useful for call custom nodes
		runtimeStatistics.put("conditionalBlocks", 0);
		runtimeStatistics.put("switchBlocks", 0);
		runtimeStatistics.put("exitBlocks", 0);
		runtimeStatistics.put("jumpBlocks", 0);
		
		// Default values
		runtimeStatistics.put("const", runtimeStatistics.getOrDefault("const", 0));
		runtimeStatistics.put("math", runtimeStatistics.getOrDefault("math", 0));
		runtimeStatistics.put("store", runtimeStatistics.getOrDefault("store", 0));
		runtimeStatistics.put("load", runtimeStatistics.getOrDefault("load", 0));
		runtimeStatistics.put("astore", runtimeStatistics.getOrDefault("astore", 0));
		runtimeStatistics.put("aload", runtimeStatistics.getOrDefault("aload", 0));
		runtimeStatistics.put("custom", runtimeStatistics.getOrDefault("custom", 0));
		runtimeStatistics.put("allocate", runtimeStatistics.getOrDefault("allocate", 0));
		
		// Check if the argument length matches
		if (check && function.getArguments().length != args.length)
			throw new RuntimeException("Amount of arguments don't match");
		
		// Argument Checking
		for (int i = 0; i < args.length; i++) {
			// Store converted array as variables in the fitting slots
			variables.put(i, registerArrayRecursive(args[i], check, i));
		}
		
		// init variables with random input data
		for(int i=args.length;i<getFunction().getVariables();i++)
			variables.put(i, arrayRandom.nextInt());
		
		boolean returnedSomething = false;
		Object returnedValue = null;

		// Execute blocks until the limit is hit or no further block was found
		for (int i = 0; i < blockLimit || blockLimit == -1; i++) {
			Object v = executeBlock();
			if (currentBlock == null) {
				returnedSomething = true;
				returnedValue = v;
				break;
			}
		}

		// Write back arrays
		for (int i = 0; i < args.length; i++) {
			writebackRecursive(args[i], (Integer)variables.get(i));
		}

		if (returnedSomething) {
			return returnedValue;
		}

		// If no result was found throw an exception
		throw new RuntimeException("Execution didn't finish in the set amount of blocks");
	}

	// Execute the currently selected basic block
	private Object executeBlock() {

		// if no block is found abort
		if (currentBlock == null)
			return null;
		
		runtimeStatistics.put("blocks", runtimeStatistics.getOrDefault("blocks", 0)+1);

		List<Node> nodes = currentBlock.getNodes();

		// reset the node evaluations
		nodeMap = new HashMap<Node, Object>();

		//System.out.println(nodes);
		
		// evaluate all nodes of this basic block
		for (int i = 0; i < nodes.size(); i++)
			executeNode(nodes.get(i));

		// System.out.println(nodeMap);
		// System.out.println(currentBlock.getSwitchBlocks());

		// Evalute the conditional branches and check if one should be taken
		if(currentBlock.isConditionalBlock())  {
			runtimeStatistics.put("conditionalBlocks", runtimeStatistics.getOrDefault("conditionalBlocks", 0)+1);
			BranchCondition condition = currentBlock.getCondition();
			int op1 = (Integer) nodeMap.get(condition.getOperant1());
			int op2 = (Integer) nodeMap.get(condition.getOperant2());
			switch (condition.getOperation()) {
			case EQUAL:
				if (op1 == op2) {
					currentBlock = currentBlock.getConditionalBranch();
					return null;
				}
				break;
			case NOTEQUAL:
				if (op1 != op2) {
					currentBlock = currentBlock.getConditionalBranch();
					return null;
				}
				break;
			case LESSTHAN:
				if (op1 < op2) {
					currentBlock = currentBlock.getConditionalBranch();
					return null;
				}
				break;
			case LESSEQUAL:
				if (op1 <= op2) {
					currentBlock = currentBlock.getConditionalBranch();
					return null;
				}
				break;
			case GREATERTHAN:
				if (op1 > op2) {
					currentBlock = currentBlock.getConditionalBranch();
					return null;
				}
				break;
			case GREATEREQUAL:
				if (op1 >= op2) {
					currentBlock = currentBlock.getConditionalBranch();
					return null;
				}
				break;
			default:
				throw new RuntimeException("Not implemented");
			}
			
			// if no jump was taken use default jump
			currentBlock = currentBlock.getUnconditionalBranch();
			return null;
		}else if(currentBlock.isSwitchCase()){
			runtimeStatistics.put("switchBlocks", runtimeStatistics.getOrDefault("switchBlocks", 0)+1);
			int caseIndex = (Integer) nodeMap.get(currentBlock.getSwitchNode());
			if(caseIndex < 0 || caseIndex >= currentBlock.getSwitchBlocks().size())
				throw new RuntimeException("Switch Jump out of bounds "+caseIndex+" @ "+currentBlock);
			currentBlock = currentBlock.getSwitchBlocks().get(caseIndex);
			return null;
		}else if(currentBlock.isExitBlock()) {
			runtimeStatistics.put("exitBlocks", runtimeStatistics.getOrDefault("exitBlocks", 0)+1);
			// if the block is an exit block and no jump was taken then return
			Node ret = currentBlock.getReturnValue();
			currentBlock = null;
			if (function.hasReturnValue())
				return nodeMap.get(ret); // but if there should be a return value then provide it
			return null;
		}else {
			runtimeStatistics.put("jumpBlocks", runtimeStatistics.getOrDefault("jumpBlocks", 0)+1);
			currentBlock = currentBlock.getUnconditionalBranch();
			return null;
		}

	}
	
	public Map<String, Integer> statistics() {
		return runtimeStatistics;
	}
}
