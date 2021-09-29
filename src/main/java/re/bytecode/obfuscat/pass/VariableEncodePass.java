package re.bytecode.obfuscat.pass;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;

import static re.bytecode.obfuscat.cfg.MathOperation.*;

// Based on
// Information Hiding in Software with Mixed Boolean-Arithmetic Transforms - https://doi.org/10.1007/978-3-540-77535-5_5

/** Encode Variables before being stored and decode them right after being loaded **/
public class VariableEncodePass extends Pass {

	public VariableEncodePass(Context context) {
		super(context);
	}
	
	
	// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
	// this can be used for division assuming a%2 = 1
    private static int inverse(int a, int bits) {
    	
    	long mod = Math.round(Math.pow(2, bits));
    	
    	long t = 0;
    	long r = mod;
    	long newt = 1;
    	long newr = a&(mod-1);
    	
    	while(newr != 0) {
    		long quotient = r / newr;
    		long tt = newt;
    		long tr = newr;
    		newt = t - quotient * newt;
    		newr = r - quotient * newr;
    		t = tt;
    		r = tr;
    	}	
    	
    	if(r > 1)
    		throw new RuntimeException("Not invertable");
    	if(t < 0)
    		t = t + mod;
    	
    	int returnValue = (int)t;
    	
    	if(a*returnValue != 1)
    		throw new RuntimeException("Wrong inverse");
    	
    	return returnValue;
    }
    
    
    //  From
    //  Diversity Via Code Transformations: A Solution For NGNA Renewable Security (2006)
    //  By Yongxin Zhou, Alec Main, Cloakware Inc.
    // references Permutation Polynomials modulo 2w - Ronald L.Rivest

    
	private static int[] reverseLinear(int a, int b, int bits) {
    	if(a%2 == 0) throw new RuntimeException("a must be odd");
    	int a_i = inverse(a, bits);
    	
    	return new int[] {a_i, -a_i*b};
    }

	
	// encode variables in initial basic block or exclude inputs
	
	
	@Override
	protected void processBlock(Function function, BasicBlock block, Map<String, Object> args) {
		
		// 4 -> 32bit, 2 -> 16bit, 1 -> 8bit - consider when encoding and decoding
		// skip input variables / or apply non changing operations on them
		
		// encode at store
		List<Node> storeOps = block.findNodes(new NodeStore(MemorySize.ANY, -1, null));
	
		// decode at load
		List<Node> loadOps = block.findNodes(new NodeLoad(MemorySize.ANY, -1));
		
		for(Node nodeRaw:storeOps) {
			NodeStore node = (NodeStore)nodeRaw;
			
			long seed = ((long)function.getName().hashCode())*(node.getSlot()+0x8899AABBCCDDEEFFL);
			
			int a = getContext().seededRand(seed);
			int b = getContext().seededRand(seed+1);
			if(a % 2 == 0) a++; // make uneven
			
			Node child = node.children()[0];
			

			if(node.getSlot() < function.getArguments().length) {
				a = 1; // either do this, do something similar, or encode at the beginning
				b = 0;
				block.replace(node, new NodeStore(node.getStoreSize(), node.getSlot(), add(mul(cst(a), child), cst(b))));
			}else {
				block.replace(node, new NodeStore(node.getStoreSize(), node.getSlot(), add(mul(cst(a), child), cst(b))));
			}
		}
		
		for(Node nodeRaw:loadOps) {
			NodeLoad node = (NodeLoad)nodeRaw;
			
			long seed = ((long)function.getName().hashCode())*(node.getSlot()+0x8899AABBCCDDEEFFL);
			
			int a = getContext().seededRand(seed);
			int b = getContext().seededRand(seed+1);
			if(a % 2 == 0) a++; // make uneven
			
			
			int bits = 0;
			
			switch(node.getLoadSize()) {
			case BYTE:
				bits = 8;
				break;
			case SHORT:
				bits = 16;
				break;
			case INT:
				bits = 32;
				break;
			case POINTER: // this as a default only makes sense on some platforms
				// as of writing only Thumb2 with 32bit pointer size is supported where this makes sense
				// for architectures where this isn't true, an option should be added to specify that / disable pointer encoding
				// for now just don't use it on platforms where this assumption does not hold
				bits = 32;
				break;
			default:
				throw new RuntimeException("Unexpected size of node "+node);
			}
			
			int[] rev = reverseLinear(a, b, bits);
	
			if(node.getSlot() < function.getArguments().length) {
				rev[0] = 1; // either do this, do something similar, or encode at the beginning
				rev[1] = 0;
				block.replace(node, add(mul(cst(rev[0]), new NodeLoad(node.getLoadSize(), node.getSlot())), cst(rev[1])));
			}else {
				block.replace(node, add(mul(cst(rev[0]), new NodeLoad(node.getLoadSize(), node.getSlot())), cst(rev[1])));
			}
		}
		
	}
	
	public Map<String, Node> statistics() {
		
		Map<String, Node> map = new HashMap<String, Node>();
		
		map.put("const",  add(add(cst("const"),  mul(cst("load"), cst(2))), mul(cst("store"), cst(2))));
		map.put("math", add(add(cst("math"), mul(cst("load"), cst(2))), mul(cst("store"), cst(2))));
		
		return map;
	}
	
	public String description() {
		return "Encode all variables when storing them and decode them when loading from them";
	}
}
