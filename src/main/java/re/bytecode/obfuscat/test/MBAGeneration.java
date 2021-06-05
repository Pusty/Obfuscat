package re.bytecode.obfuscat.test;

import java.util.Arrays;
import java.util.Random;

import re.bytecode.obfuscat.cfg.MathOperation;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;


// Information Hiding in Software with Mixed Boolean-Arithmetic Transforms - https://doi.org/10.1007/978-3-540-77535-5_5
// Obfuscation with Mixed Boolean-Arithmetic Expressions: reconstruction, analysis and simplification tools by Ninon Eyrolles 

public class MBAGeneration {

	// Perform matrix vector multiplication to check if the result is the null
	// vector
	private static boolean mulEqZero(int[][] matrix, int[] vector) {
		for (int r = 0; r < matrix.length; r++) {
			int sum = 0;
			for (int column = 0; column < matrix[0].length; column++) {
				sum += matrix[r][column] * vector[column];
			}
			if (sum != 0)
				return false;
		}
		return true;
	}

	// Bruteforce a kernel with no 0 values, unefficient but way easier to implement
	// then proper nullspace calculation
	private static int[] bruteforceKernel(int[][] matrix, int known) {
		final int[] vec = new int[matrix[0].length];
		
		for(int i=0;i<known;i++) // set these to 1
			vec[i] = 1;
		
		// 0 - -2, 1 - -1, 2 - 1, 3 - 2
		final int[] TABLE = new int[] { -2, -1, 1, 2 };
		int max = (int) Math.round(Math.pow(4, matrix[0].length));
		for (int i = 0; i < max; i++) {
			for (int j = known; j < matrix[0].length; j++)
				vec[j] = TABLE[(i >> (2 * j)) & 3];
			boolean fits = mulEqZero(matrix, vec);
			if (fits)
				return vec;
		}
		return null;
	}

	
	// generate identites for x + y + (3 random formulas)
	private static Object[] mbaIdentityXY() {

		Random r = new Random();

		// first column = identity x, second column = identiy y
		int[][] mat = new int[][] { new int[] { 0, 0, 0, 0, 0 }, new int[] { 0, 1, 0, 0, 0 }, new int[] { 1, 0, 0, 0, 0 },
				new int[] { 1, 1, 0, 0, 0 } };
				
		int known = 2;

		while (true) {
			
			// randomise matrix
			for (int a = 0; a < mat.length; a++)
				for (int b = known; b < mat[0].length; b++)
					mat[a][b] = r.nextInt() & 1;

			// Bruteforce a   mat * vec = 0 solution
			int[] vec = bruteforceKernel(mat, 2);

			// if no solution found generate new matrix
			if (vec == null)
				continue;

			// return matrix
			return new Object[] { mat, vec };

		}
	}

	public static int log2(int n) {
		return (int) Math.round(Math.log(n) / Math.log(2));
	}

	private static Node convertLine(int[][] mat, int col, Node[] consts) {
		Node start = null;
		int varLen = log2(mat.length);
		for(int i=0;i<mat.length;i++) {
			if (mat[i][col] == 1) {
				
				Node row = null;
				
				for(int j=0;j<varLen;j++) { // for each var
					int x = (i >> (varLen-j-1))&1; // get the supposted truth value for the variables
					
					// place holder node
					Node cur = consts[j];
					
					// not 
					if(x == 0)
						cur = new NodeMath(MathOperation.NOT, cur);
					//else
					//	cur = new NodeMath(MathOperation.NOP, cur);
					
					// and together to SOP format
					if(row == null) row = cur;
					else row = new NodeMath(MathOperation.AND, row, cur);
				}
				
				if(start == null) start = row;
				else start = new NodeMath(MathOperation.OR, start, row);
			}
		}
		if(start == null) start = new NodeConst(0);
		return start;
	}
	
	// Calculate MBA Formular
	private static Node calcFormula(int[][] mat, int[] vec, int known, boolean invert, Node[] consts) {
		Node start = null;
		
		for(int col=known;col < mat[0].length;col++) {
			
			Node res;
			
			Node form = convertLine(mat, col, consts);
			int  scalar = vec[col];
			
			
			if(start == null) {
				res = new NodeMath(MathOperation.MUL, form, new NodeConst(scalar * (invert?-1:1)));
			} else {
				res = new NodeMath(MathOperation.MUL, form, new NodeConst(Math.abs(scalar)));
			}
			
			if(start == null) {
				start = res;
			}else {
				if((scalar* (invert?-1:1)) > 0)
					start = new NodeMath(MathOperation.ADD, start, res);
				else
					start = new NodeMath(MathOperation.SUB, start, res);
			}
		}
		
		return start;
		
	}
	
	private static String formatFormular(Node node) {
		return node.toString().replaceAll("(\\ |Const|\\(|\\))", "").replaceAll("\\{", "(").replaceAll("\\}", ")");
	}
	

	public static void main(String[] args) {
		Object[] mbaIdent = mbaIdentityXY();
		int[][] mat = (int[][]) mbaIdent[0];
		int[] vec = (int[]) mbaIdent[1];

		System.out.println(Arrays.toString(Arrays.asList(mat).stream().map(row -> Arrays.toString(row)).toArray()));
		System.out.println(Arrays.toString(vec));

		// this spits formulars that are equal to var[0]+var[1]
		Node formular = calcFormula(mat, vec, 2, true, new Node[] {new NodeConst("var[0]"), new NodeConst("var[1]")});
		
		// e. g.
		// (((((((~var[0])&var[1])|(var[0]&(~var[1])))|(var[0]&var[1]))*1)+((((~var[0])&(~var[1]))|(var[0]&var[1]))*1))-(((~var[0])&(~var[1]))*1))
		
		System.out.println(formatFormular(formular));
		System.out.println(formular.countUnique());
	};
}
