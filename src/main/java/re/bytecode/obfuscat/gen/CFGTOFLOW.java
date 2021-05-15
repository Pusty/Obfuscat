package re.bytecode.obfuscat.gen;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.BranchCondition;

// IGNORE - OLD ARTIFICAT - MAY BE LATER REPORPOUSED FOR VISUALIZATION
public class CFGTOFLOW {

	private List<BasicBlock> processedBlocks;
	private Map<BasicBlock, List<BasicBlock>> links;
	

	public CFGTOFLOW() {
		processedBlocks = new ArrayList<BasicBlock>();
		links = new HashMap<BasicBlock, List<BasicBlock>>();
		
	}

	public static void generate(BasicBlock start) {
		CFGTOFLOW generator = new CFGTOFLOW();
		generator.generateBlock(start);
		
		
		generator.stringifyNodes();
	}
	
	private void stringifyNodes() {
		
		boolean firstNode = true;
		for(BasicBlock bb:processedBlocks) {
			generateLine("var "+bb.getName()+" = graph.insertVertex(parent, null, '"+bb.getName()+"');");
			if(firstNode) {
				generateLine("var v1 = "+bb.getName()+";");
				firstNode = false;
			}
		}
		
		for(BasicBlock source:processedBlocks) {
			for(BasicBlock target:links.get(source)) {
				generateLine("graph.insertEdge(parent, null, '', "+source.getName()+", "+target.getName()+");");
			}
		}
		
	}

	public void generateBlock(BasicBlock block) {
		if (processedBlocks.contains(block))
			return;
		processedBlocks.add(block);
		
		
		ArrayList<BasicBlock> ll = new ArrayList<BasicBlock>();
		links.put(block, ll);
		for(Entry<BranchCondition, BasicBlock> e:block.getSwitchBlocks().entrySet()) {
			ll.add(e.getValue());
			generateBlock(e.getValue());
		}
		
		if(!block.isExitBlock()) {
			ll.add(block.getUnconditionalBranch());
			generateBlock(block.getUnconditionalBranch());
		}

	}
	
	
	private void generateLine(String str) {
		System.out.println(str);
	}
	
}
