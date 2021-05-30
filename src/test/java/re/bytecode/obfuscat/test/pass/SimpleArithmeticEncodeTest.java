package re.bytecode.obfuscat.test.pass;

import org.junit.Test;

import re.bytecode.obfuscat.cfg.EmulateFunction;
import re.bytecode.obfuscat.test.gen.DSLCodeParsingTest;
import re.bytecode.obfuscat.test.gen.ThumbCodeGenerationTest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SimpleArithmeticEncodeTest {
	

	private static final int REPEAT_COUNT = 2;
	private static final String passName = "SimpleArithmeticEncode";
	
	
	@Test
	public void testDSL() throws Exception {
		
		List<List<EmulateFunction>> listOfList = new ArrayList<List<EmulateFunction>>();
		
		for(int i=0;i<REPEAT_COUNT;i++)
			listOfList.add(DSLCodeParsingTest.normalTestCases(new String[] {passName}));
		
		DSLCodeParsingTest.evaluteSizeAndSpeed(listOfList);
		
		//System.out.println(Arrays.toString(listOfList.get(0).stream().map(ef -> ef.getExecutedNodes()).toArray()));
		//System.out.println(Arrays.toString(normalTestCases(null).stream().map(ef -> ef.getExecutedNodes()).toArray()));
	}
	
	@Test
	public void testMergedDSL() throws Exception {
		
		List<List<EmulateFunction>> listOfList = new ArrayList<List<EmulateFunction>>();
		
		for(int i=0;i<REPEAT_COUNT;i++)
			listOfList.add(DSLCodeParsingTest.mergedTestCases(new String[] {passName}));
		
		DSLCodeParsingTest.evaluteSizeAndSpeed(listOfList);
	}
	
	@Test
	public void testARMThumb() throws Exception {
		
		List<List<int[]>> listOfList = new ArrayList<List<int[]>>();
		
		for(int i=0;i<REPEAT_COUNT;i++)
			listOfList.add(ThumbCodeGenerationTest.normalTestCases(new String[] { passName }));
		
		ThumbCodeGenerationTest.evaluteSizeAndSpeed(listOfList);
		
		
		System.out.println(Arrays.toString(ThumbCodeGenerationTest.normalTestCases(null).stream().map(arr -> arr[1]).toArray()));
		System.out.println(Arrays.toString(listOfList.get(0).stream().map(arr -> arr[1]).toArray()));
		
	}
	
}
