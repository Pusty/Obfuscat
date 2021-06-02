package re.bytecode.obfuscat.pass;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import static re.bytecode.obfuscat.cfg.MathOperation.*;

// Based on
// Information Hiding in Software with Mixed Boolean-Arithmetic Transforms - https://doi.org/10.1007/978-3-540-77535-5_5

public class LiteralEncodePass extends Pass {

	public LiteralEncodePass(Context context) {
		super(context);
	}
	
	
	// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
	// this can be used for division assuming a%2 = 1
    private static int inverse(int a) {
    	
    	long t = 0;
    	long r = 0x100000000L;
    	long newt = 1;
    	long newr = a&0xFFFFFFFFL;
    	
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
    		t = t + 0x100000000L;
    	
    	int returnValue = (int)t;
    	
    	if(a*returnValue != 1)
    		throw new RuntimeException("Wrong inverse");
    	
    	return returnValue;
    }
    
    
    //  From
    //  Diversity Via Code Transformations: A Solution For NGNA Renewable Security (2006)
    //  By Yongxin Zhou, Alec Main, Cloakware Inc.
    // references Permutation Polynomials modulo 2w - Ronald L.Rivest

    
    @SuppressWarnings("unused")
	private static int[] reverseLinear(int a, int b) {
    	if(a%2 == 0) throw new RuntimeException("a must be odd");
    	int a_i = inverse(a);
    	
    	return new int[] {a_i, -a_i*b};
    }
    
    
    private static int[] reverseQuadratic(int a, int b, int c) {
    	if(a%2 == 1) throw new RuntimeException("a must be even");
    	if(b%2 == 0) throw new RuntimeException("b must be odd");
    	
    	int b_i = inverse((int)b);
    	return new int[] {-a*b_i*b_i*b_i, 2*a*b_i*b_i*b_i*c+b_i, -b_i*c-a*b_i*b_i*b_i*c*c};
    }

 

	@Override
	public void processBlock(BasicBlock block) {
		List<Node> constOps = block.findNodes(new NodeConst(null));
		
		for(Node nodeRaw:constOps) {
			NodeConst node = (NodeConst)nodeRaw;
			
			Object constObj = node.getObj();
			int value = 0;
			if (constObj instanceof Integer) {
				value = ((Integer) constObj).intValue();
			} else if (constObj instanceof Short) {
				value = ((Short) constObj).intValue();
			} else if (constObj instanceof Byte) {
				value = ((Byte) constObj).intValue();
			} else if (constObj instanceof Character) {
				value = (int) ((Character) constObj).charValue();
			} else {
				throw new RuntimeException("Const type " + constObj.getClass() + " not implemented");
			}
			
			int a = getContext().rand();
			int b = getContext().rand();
			int c = getContext().rand();
					
			if(b % 2 == 0) b++; // make uneven
			
			// 2 * a^2 = 0 (mod 2**32)  - e.g. 1502216192
			while(true) {
				if((2*a*a) == 0 && a % 2 == 0) break;
				a++;
			}
			
			//System.out.println("def f(x): return ("+a+"* x * x + "+b+"*x +"+c+") & 0xFFFFFFFF");
			
			int[] revQuad = reverseQuadratic(a, b, c);
			//System.out.println("def g(x): return ("+revQuad[0]+"* x * x + "+revQuad[1]+"*x +"+revQuad[2]+") & 0xFFFFFFFF");
			
			int x = (a*value*value + b*value + c);
			
			
			Node cn = cst(x);
			Node gen = add(add(mul(mul(cst(revQuad[0]), cn), cn), mul(cst(revQuad[1]), cn)), cst(revQuad[2])); // 5m 4c
			
			block.replace(node, gen);
		}
	
		
	}
	
	public Map<String, Node> statistics() {
		
		Map<String, Node> map = new HashMap<String, Node>();
		
		map.put("math",  add(cst("math"),  mul(cst("const"), cst(5))));
		map.put("const", add(cst("const"), mul(cst("const"), cst(3))));
		
		return map;
	}
}
