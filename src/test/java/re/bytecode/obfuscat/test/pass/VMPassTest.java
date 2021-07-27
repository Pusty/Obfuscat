package re.bytecode.obfuscat.test.pass;

import org.junit.Test;

import re.bytecode.obfuscat.Obfuscat;
import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.test.gen.DSLCodeParsingTest;
import re.bytecode.obfuscat.test.gen.ThumbCodeGenerationTest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class VMPassTest {
	

	private static final int REPEAT_COUNT = 2;
	private static final String[] passNames = new String[] {"Virtualize"};
	
	
	@Test
	public void testDSL() throws Exception {
		
		List<List<EmulateFunction>> listOfList = new ArrayList<List<EmulateFunction>>();
		
		for(int i=0;i<REPEAT_COUNT;i++)
			listOfList.add(DSLCodeParsingTest.normalTestCases(passNames));
		
		DSLCodeParsingTest.evaluteSizeAndSpeed(listOfList);
	}


	@Test
	public void testConstrains() throws Exception {
		
		List<EmulateFunction> listNormal = DSLCodeParsingTest.normalTestCases(null);
		List<EmulateFunction> listPass = DSLCodeParsingTest.normalTestCases(passNames);
		
		List<Map<String, Node>> stats = new ArrayList<Map<String, Node>>();
		for(int i=0;i<passNames.length;i++)
			stats.add(Obfuscat.getPassStatistics(passNames[i]));
		
		List<Map<String, Node>> statsRuntime = new ArrayList<Map<String, Node>>();
		for(int i=0;i<passNames.length;i++)
			statsRuntime.add(Obfuscat.getPassRuntimeStatistics(passNames[i]));
		
		DSLCodeParsingTest.compareSizeAndSpeed(listNormal, listPass, stats, statsRuntime);
		
	}
	
	@Test
	public void testMergedDSL() throws Exception {
		
		List<List<EmulateFunction>> listOfList = new ArrayList<List<EmulateFunction>>();
		
		for(int i=0;i<REPEAT_COUNT;i++)
			listOfList.add(DSLCodeParsingTest.mergedTestCases(passNames, Arrays.asList(9)));
		
		DSLCodeParsingTest.evaluteSizeAndSpeed(listOfList);
	}
	
	
	@Test
	public void testARMThumb() throws Exception {
		
		List<List<int[]>> listOfList = new ArrayList<List<int[]>>();
		
		// 2 - is just super slow in the vm
		// 6 - contains readInt which is native - need to somehow implement this? or ignore
		for(int i=0;i<REPEAT_COUNT;i++)
			listOfList.add(ThumbCodeGenerationTest.normalTestCases(passNames, Arrays.asList(2, 6)));
		
		ThumbCodeGenerationTest.evaluteSizeAndSpeed(listOfList);
		
		
		//System.out.println(Arrays.toString(ThumbCodeGenerationTest.normalTestCases(null).stream().map(arr -> arr[1]).toArray()));
		//System.out.println(Arrays.toString(listOfList.get(0).stream().map(arr -> arr[1]).toArray()));
		
	}
	
	
}
