package re.bytecode.obfuscat.gen.llvm;

import java.util.ArrayList;
import java.util.List;
import re.bytecode.obfuscat.Context;
import re.bytecode.obfuscat.cfg.BasicBlock;
import re.bytecode.obfuscat.cfg.Function;
import re.bytecode.obfuscat.cfg.MemorySize;
import re.bytecode.obfuscat.cfg.MergedFunction;
import re.bytecode.obfuscat.cfg.nodes.Node;
import re.bytecode.obfuscat.cfg.nodes.NodeALoad;
import re.bytecode.obfuscat.cfg.nodes.NodeAStore;
import re.bytecode.obfuscat.cfg.nodes.NodeAlloc;
import re.bytecode.obfuscat.cfg.nodes.NodeConst;
import re.bytecode.obfuscat.cfg.nodes.NodeCustom;
import re.bytecode.obfuscat.cfg.nodes.NodeLoad;
import re.bytecode.obfuscat.cfg.nodes.NodeMath;
import re.bytecode.obfuscat.cfg.nodes.NodeStore;
import re.bytecode.obfuscat.gen.CodeGenerator;
import re.bytecode.obfuscat.gen.CompiledBasicBlock;
import re.bytecode.obfuscat.gen.CustomNodeImpl;
import re.bytecode.obfuscat.gen.NodeCodeGenerator;

public class LLVMCodeGenerator extends CodeGenerator {

	private static String NATIVE_INT = "i32";
	static {
		registerCodegen(LLVMCodeGenerator.class);
		registerCustomNode(LLVMCodeGenerator.class, "prepare_call", new LLVMNodePrepareCall());
		registerCustomNode(LLVMCodeGenerator.class, "call", new LLVMNodeCall());
		registerCustomNode(LLVMCodeGenerator.class, "debugPrint", new LLVMNodeDebugPrint());
	}

	/**
	 * 
	 * 
	 * @param context  the context of this generator, may be null
	 * @param function the function to generate code for
	 */
	public LLVMCodeGenerator(Context context, Function function) {
		super(context, function);
	}

	public String description() {
		return "";
	}

	private String getNodeRef(Node n) {
		return "%n" + getNodeID(n);
	}

	public static String convertObjectToName(Object arg) {
		return String.format("%s%08X", arg.getClass().getSimpleName().replace('[', '_').replace(']', '_'),
				arg.hashCode());
	}

	public static String convertObjectToType(Object arg) {
		Class<?> argT = arg.getClass();
		if (argT == Integer.class) {
			return "i32";
		} else if (argT == Short.class) {
			return "i16";
		} else if (argT == Character.class) {
			return "i16";
		} else if (argT == Byte.class) {
			return "i8";
		} else if (argT == Boolean.class) {
			return "i8";
		} else if (argT.isArray()) {
			if (argT == byte[].class) {
				byte[] ba = ((byte[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('[');
				sb.append(ba.length);
				sb.append(" x i8]");
				return sb.toString();
			} else if (argT == boolean[].class) {

				boolean[] ba = ((boolean[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('[');
				sb.append(ba.length);
				sb.append(" x i8]");
				return sb.toString();
			} else if (argT == short[].class) {
				short[] sa = ((short[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('[');
				sb.append(sa.length);
				sb.append(" x i16]");
				return sb.toString();
			} else if (argT == char[].class) {
				char[] ca = ((char[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('[');
				sb.append(ca.length);
				sb.append(" x i16]");
				return sb.toString();
			} else if (argT == int[].class) {
				int[] ia = ((int[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('[');
				sb.append(ia.length);
				sb.append(" x i32]");
				return sb.toString();
			} else if (argT == Object[].class) {
				Object[] ooa = ((Object[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('[');
				sb.append(ooa.length);
				sb.append(" x i8*]");
				return sb.toString();
			} else
				throw new RuntimeException("Array type not supported " + arg.getClass());

		} else {
			throw new RuntimeException("Can't convert argument of type " + arg.getClass());
		}
	}

	public static String convertObjectToGlobal(String name, Object arg) {

		Class<?> argT = arg.getClass();
		if (argT == Integer.class) {
			return "@" + name + " = dso_local global i32 " + ((Integer) arg).intValue() + ", align 4\n";
		} else if (argT == Short.class) {
			return "@" + name + " = dso_local global i16 " + (((Short) arg).intValue() & 0xFFFF) + ", align 2\n";
		} else if (argT == Character.class) {
			return "@" + name + " = dso_local global i16 " + (((Character) arg).charValue() & 0xFFFF) + ", align 2\n";
		} else if (argT == Byte.class) {
			return "@" + name + " = dso_local global i8 " + (((Byte) arg).intValue() & 0xFF) + ", align 1\n";
		} else if (argT == Boolean.class) {
			return "@" + name + " = dso_local global i8 " + ((((Boolean) arg).booleanValue() ? 1 : 0)) + ", align 1\n";
		} else if (argT.isArray()) {
			if (argT == byte[].class) {
				byte[] ba = ((byte[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('@');
				sb.append(name);
				sb.append(" = dso_local global [");
				sb.append(ba.length);
				sb.append(" x i8] [");
				for (int i = 0; i < ba.length; i++) {
					sb.append("i8 ");
					sb.append(ba[i] & 0xff);
					if (i != ba.length - 1)
						sb.append(", ");
				}
				sb.append("], align 1\n");
				return sb.toString();
			} else if (argT == boolean[].class) {

				boolean[] ba = ((boolean[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('@');
				sb.append(name);
				sb.append(" = dso_local global ");
				sb.append(convertObjectToType(arg));
				sb.append(" [");
				for (int i = 0; i < ba.length; i++) {
					sb.append("i8 ");
					sb.append(ba[i] ? 1 : 0);
					if (i != ba.length - 1)
						sb.append(", ");
				}
				sb.append("], align 1\n");
				return sb.toString();
			} else if (argT == short[].class) {
				short[] sa = ((short[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('@');
				sb.append(name);
				sb.append(" = dso_local global ");
				sb.append(convertObjectToType(arg));
				sb.append(" [");
				for (int i = 0; i < sa.length; i++) {
					sb.append("i16 ");
					sb.append(sa[i] & 0xffff);
					if (i != sa.length - 1)
						sb.append(", ");
				}
				sb.append("], align 2\n");
				return sb.toString();
			} else if (argT == char[].class) {
				char[] ca = ((char[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('@');
				sb.append(name);
				sb.append(" = dso_local global ");
				sb.append(convertObjectToType(arg));
				sb.append(" [");
				for (int i = 0; i < ca.length; i++) {
					sb.append("i16 ");
					sb.append(ca[i] & 0xffff);
					if (i != ca.length - 1)
						sb.append(", ");
				}
				sb.append("], align 2\n");
				return sb.toString();
			} else if (argT == int[].class) {
				int[] ia = ((int[]) arg);
				StringBuilder sb = new StringBuilder();
				sb.append('@');
				sb.append(name);
				sb.append(" = dso_local global ");
				sb.append(convertObjectToType(arg));
				sb.append(" [");
				for (int i = 0; i < ia.length; i++) {
					sb.append("i32 ");
					sb.append(ia[i]);
					if (i != ia.length - 1)
						sb.append(", ");
				}
				sb.append("], align 4\n");
				return sb.toString();
			} else if (argT == Object[].class) {
				Object[] ooa = ((Object[]) arg);
				StringBuilder sb = new StringBuilder();
				for (int i = 0; i < ooa.length; i++) {
					sb.append(convertObjectToGlobal(name + "." + i, ooa[i]));
				}
				sb.append('@');
				sb.append(name);
				sb.append(" = dso_local global ");
				sb.append(convertObjectToType(arg));
				sb.append(" [");
				for (int i = 0; i < ooa.length; i++) {
					sb.append(convertObjectToCast(name + "." + i, ooa[i], "i8*"));
					if (i != ooa.length - 1)
						sb.append(", ");
				}
				sb.append("]\n");

				return sb.toString();
			} else
				throw new RuntimeException("Array type not supported " + arg.getClass());

		} else {
			throw new RuntimeException("Can't convert argument of type " + arg.getClass());
		}
	}

	public static String convertObjectToCast(String name, Object arg, String outType) {
		StringBuilder sb = new StringBuilder();
		sb.append(outType);
		sb.append(' ');
		String type = convertObjectToType(arg);
		if (type.endsWith("*") || type.endsWith("]")) {
			sb.append("bitcast (");
			sb.append(type);
			sb.append("* @");
			sb.append(name);

		} else {
			sb.append("inttoptr (");
			sb.append(type);
			sb.append(" ");
			Class<?> argT = arg.getClass();
			if (argT == Integer.class) {
				sb.append(((Integer) arg).intValue());
			} else if (argT == Short.class) {
				sb.append(((Short) arg).intValue() & 0xffff);
			} else if (argT == Character.class) {
				sb.append(((Character) arg).charValue() & 0xFFFF);
			} else if (argT == Byte.class) {
				sb.append(((Byte) arg).intValue() & 0xFF);
			} else if (argT == Boolean.class) {
				sb.append((((Boolean) arg).booleanValue() ? 1 : 0));
			}
		}
		sb.append(" to ");
		sb.append(outType);
		sb.append(')');
		return sb.toString();
	}

	public static String generateCall(String functionName, String[] references, boolean returnValue) {
		StringBuilder sb = new StringBuilder();

		if (returnValue) {
			sb.append("call i8* ");
		} else {
			sb.append("call void ");
		}

		if (references.length > 0) {
			sb.append("(");
			for (int i = 0; i < references.length; i++) {
				sb.append("i8*");
				if (i != references.length - 1)
					sb.append(", ");
			}
			sb.append(")");
		}

		sb.append(" @");
		sb.append(functionName);
		sb.append("(");
		for (int i = 0; i < references.length; i++) {
			sb.append("i8* ");
			sb.append(references[i]);
			if (i != references.length - 1)
				sb.append(", ");
		}
		sb.append(")");
		return sb.toString();
	}

	public static String getSizeName(MemorySize ms) {
		switch (ms) {
		case BYTE:
			return "i8";
		case SHORT:
			return "i16";
		case INT:
			return "i32";
		case POINTER:
			return "i8*";
		case ANY:
			return "i8*";
		default:
			throw new RuntimeException("Unsupported MemorySize " + ms);
		}
	}

	public static String getAlignment(MemorySize ms) {
		switch (ms) {
		case BYTE:
			return "1";
		case SHORT:
			return "2";
		case INT:
			return "4";
		default:
			throw new RuntimeException("Unsupported MemorySize " + ms);
		}
	}

	public static int getSizeByName(String name) {
		if (name.equals("i8"))
			return 1;
		if (name.equals("i16"))
			return 2;
		if (name.equals("i32"))
			return 4;
		if (name.equals("i64"))
			return 8;
		return -1;
	}

	public static String cast(String out, String in, String from, String to) {
		boolean fromP = (from.contains("*") || from.contains("["));
		boolean toP = (to.contains("*") || to.contains("["));
		if (!fromP && toP) {
			// out+" = inttoptr "+from+" "+in+" to "+to;
			if (getSizeByName(from) < getSizeByName(NATIVE_INT)) {
				return cast(out + ".2", in, from, NATIVE_INT) + "\n" + out + " = inttoptr " + NATIVE_INT + " " + out
						+ ".2 to " + to;
			} else {
				return out + " = inttoptr " + from + " " + in + " to " + to;
			}

			// out+" = inttoptr "+from+" "+in+" to "+to;
		} else if (fromP && !toP) {
			// out+" = ptrtoint "+from+" "+in+" to "+to+"\n";
			if (getSizeByName(to) < getSizeByName(NATIVE_INT)) {
				return out + ".2 = ptrtoint " + from + " " + in + " to " + NATIVE_INT + "\n"
						+ cast(out, out + ".2", NATIVE_INT, to);
			}else {
				return out + " = ptrtoint " + from + " " + in + " to " + to;
			}
		} else if (from.equals(to) || (fromP && toP)) {
			return out + " = bitcast " + from + " " + in + " to " + to;
		} else {
			int fromSize = getSizeByName(from);
			int toSize = getSizeByName(to);
			if (fromSize == -1 || toSize == -1 || fromSize == toSize) {
				throw new RuntimeException("Unsupported cast " + out + " " + in + " " + from + " " + to);
			}
			if (toSize < fromSize)
				return out + " = trunc " + from + " " + in + " to " + to;
			else if (toSize <= 4)
				return out + " = sext " + from + " " + in + " to " + to;
			else
				return out + " = zext " + from + " " + in + " to " + to;
		}
	}

	public static String getDebugPrepend(Node n) {
		return "; " + n.getNodeIdentifier() + " - " + n.toString() + "\n";
	}

	@Override
	protected void initMapping() {

		// Default case
		codeMapping.put(null, new LLVMNodeCodeGenerator() {

			@Override
			public void process(CompiledBasicBlock cbb, Node node) {
				throw new RuntimeException("Not implemented " + node);
			}

			@Override
			public String writeData(BasicBlock bb, Node n) {
				return null;
			}

		});

		// Encode Constants
		codeMapping.put(NodeConst.class, new LLVMNodeCodeGenerator() {

			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeConst);
				NodeConst node = (NodeConst) n;
				Object constObj = node.getObj();
				int value = 0;
				if (constObj instanceof Integer) {
					value = ((Integer) constObj).intValue();
				} else if (constObj instanceof Short) {
					value = ((Short) constObj).intValue();
				} else if (constObj instanceof Byte) {
					value = ((Byte) constObj).intValue();
				} else if (constObj instanceof Boolean) {
					value = ((Boolean) constObj).booleanValue() ? 1 : 0;
				} else if (constObj instanceof Character) {
					value = (int) ((Character) constObj).charValue();
				} else if (constObj.getClass().isArray()) {
					Object dataEntry = getFunction().getData(constObj);

					if (dataEntry == null)
						throw new RuntimeException("Constant array not registered " + constObj);
					return getDebugPrepend(n) + cast(getNodeRef(n), "@" + convertObjectToName(dataEntry),
							convertObjectToType(dataEntry) + "*", "i8*");

				} else {
					throw new RuntimeException("Const type " + constObj.getClass() + " not implemented");
				}

				return getDebugPrepend(n) + cast(getNodeRef(n), Integer.toString(value), NATIVE_INT, "i8*");
			}

		});

		// Encode Variable Load Operations
		codeMapping.put(NodeLoad.class, new LLVMNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeLoad);
				NodeLoad node = (NodeLoad) n;

				return getDebugPrepend(n)
						+ cast(getNodeRef(n) + "t", "%stack" + node.getSlot(), "i8**",
								getSizeName(node.getLoadSize()) + "*")
						+ "\n" + getNodeRef(n) + "b = load volatile " + getSizeName(node.getLoadSize()) + ", "
						+ getSizeName(node.getLoadSize()) + "* " + getNodeRef(n) + "t" + "\n"
						+ cast(getNodeRef(n), getNodeRef(n) + "b", getSizeName(node.getLoadSize()), "i8*");

			}
		});

		// Encode Variable Store Operations
		codeMapping.put(NodeStore.class, new LLVMNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeStore);
				NodeStore node = (NodeStore) n;

				Node[] children = node.children();

				return getDebugPrepend(n)
						+ cast(getNodeRef(n) + "b", getNodeRef(children[0]), "i8*", getSizeName(node.getStoreSize()))
						+ "\n"
						+ cast(getNodeRef(n) + "t", "%stack" + node.getSlot(), "i8**",
								getSizeName(node.getStoreSize()) + "*")
						+ "\n" + "store volatile " + getSizeName(node.getStoreSize()) + " " + getNodeRef(n) + "b, "
						+ getSizeName(node.getStoreSize()) + "* " + getNodeRef(n) + "t";
			}
		});

		// Encode Array Load Operations
		codeMapping.put(NodeALoad.class, new LLVMNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeALoad);
				NodeALoad node = (NodeALoad) n;

				Node[] children = node.children();

				return getDebugPrepend(n)
						+ cast(getNodeRef(n) + "a", getNodeRef(children[0]), "i8*",
								getSizeName(node.getLoadSize()) + "*")
						+ "\n" + cast(getNodeRef(n) + "i", getNodeRef(children[1]), "i8*", NATIVE_INT) + "\n"
						+ getNodeRef(n) + "t = getelementptr inbounds " + getSizeName(node.getLoadSize()) + ", "
						+ getSizeName(node.getLoadSize()) + "* " + getNodeRef(n) + "a, " + NATIVE_INT + " "
						+ getNodeRef(n) + "i" + "\n" + getNodeRef(n) + "b = load volatile "
						+ getSizeName(node.getLoadSize()) + ", " + getSizeName(node.getLoadSize()) + "* "
						+ getNodeRef(n) + "t" + "\n"
						+ cast(getNodeRef(n), getNodeRef(n) + "b", getSizeName(node.getLoadSize()), "i8*");
			}
		});

		// Encode Array Store Operations
		codeMapping.put(NodeAStore.class, new LLVMNodeCodeGenerator() {
			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeAStore);
				NodeAStore node = (NodeAStore) n;

				Node[] children = node.children();

				return getDebugPrepend(n)
						+ cast(getNodeRef(n) + "b", getNodeRef(children[2]), "i8*", getSizeName(node.getStoreSize()))
						+ "\n"
						+ cast(getNodeRef(n) + "a", getNodeRef(children[0]), "i8*",
								getSizeName(node.getStoreSize()) + "*")
						+ "\n" + cast(getNodeRef(n) + "i", getNodeRef(children[1]), "i8*", NATIVE_INT) + "\n"
						+ getNodeRef(n) + "t = getelementptr inbounds " + getSizeName(node.getStoreSize()) + ", "
						+ getSizeName(node.getStoreSize()) + "* " + getNodeRef(n) + "a, " + NATIVE_INT + " "
						+ getNodeRef(n) + "i" + "\n" + "store volatile " + getSizeName(node.getStoreSize()) + " "
						+ getNodeRef(n) + "b, " + getSizeName(node.getStoreSize()) + "* " + getNodeRef(n) + "t";

			}
		});

		// Encode Math Operations
		codeMapping.put(NodeMath.class, new LLVMNodeCodeGenerator() {

			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeMath);
				NodeMath node = (NodeMath) n;

				Node[] children = node.children();

				String operation = node.getOperation().toString().toLowerCase();

				String MATH_INT = "i64";
				if (operation.equals("shr")) {
					operation = "ashr";
					MATH_INT = "i32";
				} else if (operation.equals("ushr")) {
					operation = "lshr";
					MATH_INT = "i32";
				} else if (operation.equals("mod")) {
					operation = "urem";
					MATH_INT = "i32";
				} else if (operation.equals("div")) {
					operation = "udiv";
					MATH_INT = "i32";
				}

				

				if (node.getOperation().getOperandCount() == 1) {

					String prepend = getDebugPrepend(n)
							+ cast(getNodeRef(n) + "a", getNodeRef(children[0]), "i8*", MATH_INT) + "\n";

					if (operation.equals("neg")) {
						return prepend + getNodeRef(n) + "c = sub " + MATH_INT + " 0, " + getNodeRef(n) + "a\n"
								+ cast(getNodeRef(n), getNodeRef(n) + "c", MATH_INT, "i8*") + "\n";
					} else if (operation.equals("not")) {
						return prepend + getNodeRef(n) + "c = xor " + MATH_INT + " " + getNodeRef(n) + "a, -1\n"
								+ cast(getNodeRef(n), getNodeRef(n) + "c", MATH_INT, "i8*") + "\n";
					} else if (operation.equals("nop")) {
						return prepend + getNodeRef(n) + "c = add " + MATH_INT + " 0, " + getNodeRef(n) + "a\n"
								+ cast(getNodeRef(n), getNodeRef(n) + "c", MATH_INT, "i8*") + "\n";
					} else {
						throw new RuntimeException("Not implemented");
					}

				} else if (node.getOperation().getOperandCount() == 2) {
					String prepend = getDebugPrepend(n)
							+ cast(getNodeRef(n) + "a", getNodeRef(children[0]), "i8*", MATH_INT) + "\n"
							+ cast(getNodeRef(n) + "b", getNodeRef(children[1]), "i8*", MATH_INT) + "\n";

					return prepend + getNodeRef(n) + "c = " + operation + " " + MATH_INT + " " + getNodeRef(n) + "a, "
							+ getNodeRef(n) + "b" + "\n" + cast(getNodeRef(n), getNodeRef(n) + "c", MATH_INT, "i8*")
							+ "\n";
				} else {
					throw new RuntimeException("Not implemented");
				}

			}

		});

		// Encode Allocation Operation
		codeMapping.put(NodeAlloc.class, new LLVMNodeCodeGenerator() {

			@Override
			public String writeData(BasicBlock bb, Node n) {
				assert (n instanceof NodeAlloc);
				NodeAlloc node = (NodeAlloc) n;

				Node[] children = node.children();
				return getDebugPrepend(n) + cast(getNodeRef(n) + "i", getNodeRef(children[0]), "i8*", NATIVE_INT) + "\n"
						+ getNodeRef(n) + "o = alloca " + getSizeName(node.getAllocationSize()) + ", " + NATIVE_INT
						+ " " + getNodeRef(n) + "i, align " + getSizeByName(NATIVE_INT) + "\n"
						+ cast(getNodeRef(n), getNodeRef(n) + "o", getSizeName(node.getAllocationSize()) + "*", "i8*")
						+ "\n";
			}

		});

	}

	@Override
	public CompiledBasicBlock generateBlock(BasicBlock block) {

		// Instead of normal CompiledBasicBlocks this provides the ThumbCodeGenerator
		// specific variant
		CompiledBasicBlock cbb = new LLVMCompiledBasicBlock(block);

		for (Node node : block.getNodes()) {
			processNode(cbb, node);
		}

		return cbb;
	}

	@Override
	public int getNodeSize() {
		return 0;
	}

	@Override
	public int getNodeInstCount() {
		return 0;
	}

	@Override
	protected int countProgramSize() {
		return 0;
	}

	@Override
	public void link(List<CompiledBasicBlock> blocks) {
	}

	protected int[] processAppendedData() {
		return null;
	}

	@Override
	public int[] finish(List<CompiledBasicBlock> compiledBlocks) {

		StringBuilder mapTogether = new StringBuilder();

		mapTogether.append("; ModuleID = '<string>'\n");
		mapTogether.append("source_filename = \"<string>\"\n");
		mapTogether.append("target triple = \"unknown-unknown-unknown\"\n\n");

		{
			if (this.getFunction().hasReturnValue())
				mapTogether.append("define i8* @");
			else
				mapTogether.append("define void @");

			mapTogether.append(this.getFunction().getName().split("\\(")[0]);

			mapTogether.append("(");

			Class<?>[] arguments = getFunction().getArguments();

			String[] nodeNames = new String[getFunction().getArguments().length];

			int offset = 0;
			if (getFunction() instanceof MergedFunction) {
				arguments = ((MergedFunction) getFunction()).getOriginalArguments();
				offset = 1;
				nodeNames[0] = "%z";
			}
			int i = 0;
			for (; i < arguments.length; i++) {
				nodeNames[offset + i] = "%arg" + i;
				mapTogether.append("i8* %arg" + i);
				if (i != arguments.length - 1)
					mapTogether.append(", ");
			}
			i += offset;
			for (; i < getFunction().getArguments().length; i++) {
				nodeNames[i] = "%z";
			}

			mapTogether.append(") {\n");

			if (getFunction() instanceof MergedFunction) {
				mapTogether.append("%z = bitcast i8* null to i8*");
			}

			if (getFunction().hasReturnValue()) {
				mapTogether.append("%v = "
						+ generateCall(this.getFunction().getName().split("\\(")[0] + "_entry", nodeNames, true));
				mapTogether.append("\nret i8* %v\n");
			} else {
				mapTogether.append(
						generateCall(this.getFunction().getName().split("\\(")[0] + "_entry", nodeNames, false));
				mapTogether.append("\nret void\n");
			}

			mapTogether.append("}\n");
		}

		if (this.getFunction().hasReturnValue())
			mapTogether.append("define i8* @");
		else
			mapTogether.append("define void @");

		mapTogether.append(this.getFunction().getName().split("\\(")[0]);
		mapTogether.append("_entry");

		mapTogether.append("(");

		for (int i = 0; i < getFunction().getArguments().length; i++) {
			String argString = "i8* %arg" + i;
			mapTogether.append(argString);
			if (i != getFunction().getArguments().length - 1)
				mapTogether.append(", ");
		}

		mapTogether.append(") {\n");

		for (int i = 0; i < this.getFunction().getVariables(); i++) {
			mapTogether.append("%stack");
			mapTogether.append(Integer.toString(i));
			mapTogether.append(" = alloca i8*\n");
		}

		for (int i = 0; i < getFunction().getArguments().length; i++) {
			mapTogether.append("store volatile i8* %arg" + i + ", i8** %stack" + i + "\n");
		}

		mapTogether.append("br label %bb");
		mapTogether.append(Integer.toString(getBlockID(getFunction().getBlocks().get(0))));
		mapTogether.append('\n');

		// default branch <- something went wrong
		mapTogether.append("default:");
		mapTogether.append('\n');
		if (this.getFunction().hasReturnValue()) {
			mapTogether.append("ret i8* null");
		} else
			mapTogether.append("ret void");
		mapTogether.append('\n');

		for (CompiledBasicBlock cbb : compiledBlocks) {
			assert (cbb instanceof LLVMCompiledBasicBlock);
			mapTogether.append("bb" + getBlockID(cbb.getBlock()) + ":");
			mapTogether.append('\n');
			for (String line : ((LLVMCompiledBasicBlock) cbb).dataArray) {
				mapTogether.append(line);
				mapTogether.append('\n');
			}
			String blockName = "%c" + getBlockID(cbb.getBlock());
			if (cbb.getBlock().isConditionalBlock()) {

				String condition = "?";
				switch (cbb.getBlock().getCondition().getOperation()) {
				case EQUAL:
					condition = "eq";
					break;
				case NOTEQUAL:
					condition = "ne";
					break;
				case LESSTHAN:
					condition = "slt";
					break;
				case LESSEQUAL:
					condition = "sle";
					break;
				case GREATERTHAN:
					condition = "sgt";
					break;
				case GREATEREQUAL:
					condition = "sge";
					break;
				}

				mapTogether.append(";" + cbb.getBlock().getCondition());
				mapTogether.append('\n');
				mapTogether.append(cast(blockName + ".op1", getNodeRef(cbb.getBlock().getCondition().getOperant1()),
						"i8*", NATIVE_INT));
				mapTogether.append('\n');
				mapTogether.append(cast(blockName + ".op2", getNodeRef(cbb.getBlock().getCondition().getOperant2()),
						"i8*", NATIVE_INT));
				mapTogether.append('\n');
				mapTogether.append(blockName + " = icmp " + condition + " " + NATIVE_INT + " " + blockName + ".op1, "
						+ blockName + ".op2");
				mapTogether.append('\n');
				mapTogether
						.append("br i1 " + blockName + ", label %bb" + getBlockID(cbb.getBlock().getConditionalBranch())
								+ ", label %bb" + getBlockID(cbb.getBlock().getUnconditionalBranch()));
				mapTogether.append('\n');
			} else if (cbb.getBlock().isSwitchCase()) {
				mapTogether.append(
						cast(blockName + ".switch", getNodeRef(cbb.getBlock().getSwitchNode()), "i8*", NATIVE_INT));
				mapTogether.append('\n');
				mapTogether.append("switch " + NATIVE_INT + " " + blockName + ".switch, label %default [" + "\n");
				for (int i = 0; i < cbb.getBlock().getSwitchBlocks().size(); i++) {
					mapTogether.append("    " + NATIVE_INT + " " + i + ", label %bb"
							+ getBlockID(cbb.getBlock().getSwitchBlocks().get(i)) + "\n");
				}
				mapTogether.append("]\n");

			} else if (cbb.getBlock().isExitBlock()) {
				if (cbb.getBlock().getReturnValue() == null) {
					if (getFunction().hasReturnValue()) {
						mapTogether.append("ret i8* null");
					} else {
						mapTogether.append("ret void");
					}
				} else {
					mapTogether.append("ret i8* " + getNodeRef(cbb.getBlock().getReturnValue()));
				}
				mapTogether.append('\n');
			} else {
				mapTogether.append("br label %" + "bb" + getBlockID(cbb.getBlock().getUnconditionalBranch()));
				mapTogether.append('\n');
			}
		}

		mapTogether.append('}');
		mapTogether.append('\n');

		Object[] data = getFunction().getData();
		for (int i = 0; i < data.length; i++) {
			mapTogether.append(convertObjectToGlobal(convertObjectToName(data[i]), data[i]));
			mapTogether.append('\n');
		}

		String res = mapTogether.toString();

		int[] intArray = new int[res.length()];
		for (int i = 0; i < intArray.length; i++)
			intArray[i] = res.charAt(i);

		return intArray;
	}

	private int numberedNodeIndex = 0;

	@Override
	protected void numberNodes(Node node) {

		if (numberedNodes.containsKey(node))
			return;

		Node[] children = node.children();
		if (children != null) {

			// provide slots for children
			for (int i = 0; i < children.length; i++) {
				numberNodes(children[i]);
			}
		}

		numberedNodes.put(node, numberedNodeIndex);
		numberedNodeIndex++;
	}

	// Internal CompiledBasicBlock Class
	private class LLVMCompiledBasicBlock extends CompiledBasicBlock {

		List<String> dataArray;

		public LLVMCompiledBasicBlock(BasicBlock block) {
			super(block);
			dataArray = new ArrayList<String>();
		}

		public void appendLine(String data) {
			dataArray.add(data);
		}

		public String toString() {
			StringBuilder sb = new StringBuilder();
			for (String arr : dataArray) {
				sb.append(arr);
				sb.append('\n');
			}
			return sb.toString();
		}

	}

	private abstract class LLVMNodeCodeGenerator extends NodeCodeGenerator {

		private LLVMNodeCodeGenerator() {
		}

		public void process(CompiledBasicBlock cbb, Node node) {
			assert (cbb instanceof LLVMCompiledBasicBlock);
			((LLVMCompiledBasicBlock) cbb).appendLine(writeData(cbb.getBlock(), node));
		}

		public abstract String writeData(BasicBlock bb, Node node);

	}

	/**
	 * CustomNodeImpl for "prepare_call"
	 */
	public static class LLVMNodePrepareCall extends CustomNodeImpl {

		@Override
		public void process(CodeGenerator generator, CompiledBasicBlock cbb, NodeCustom node) {
			assert (generator instanceof LLVMCodeGenerator);
			assert (cbb instanceof LLVMCompiledBasicBlock);

			String thisNode = ((LLVMCodeGenerator) generator).getNodeRef(node);
			Node[] children = node.children();

			String[] nodeNames = new String[generator.getFunction().getArguments().length];
			int i = 0;
			for (; i < Math.min(children.length, nodeNames.length); i++)
				nodeNames[i] = ((LLVMCodeGenerator) generator).getNodeRef(children[i]);

			for (; i < nodeNames.length; i++) {
				nodeNames[i] = "null";
			}

			((LLVMCompiledBasicBlock) cbb).appendLine(getDebugPrepend(node));
			if (generator.getFunction().hasReturnValue()) {
				((LLVMCompiledBasicBlock) cbb).appendLine(thisNode + " = "
						+ generateCall(generator.getFunction().getName().split("\\(")[0] + "_entry", nodeNames, true));
			} else {
				((LLVMCompiledBasicBlock) cbb).appendLine(thisNode + " = bitcast i8* null to i8*\n");
				((LLVMCompiledBasicBlock) cbb).appendLine(
						generateCall(generator.getFunction().getName().split("\\(")[0] + "_entry", nodeNames, false));
			}

			// generator.getFunction().getArguments()

			// ((LLVMCompiledBasicBlock) cbb).appendLine(thisNode+"a = "+);

		}

	}

	/**
	 * CustomNodeImpl for "call"
	 */
	public static class LLVMNodeCall extends CustomNodeImpl {

		@Override
		public void process(CodeGenerator generator, CompiledBasicBlock cbb, NodeCustom node) {
			assert (generator instanceof LLVMCodeGenerator);
			assert (cbb instanceof LLVMCompiledBasicBlock);

			// String thisNode = ((LLVMCodeGenerator) generator).getNodeRef(node);
			Node[] children = node.children();

			((LLVMCompiledBasicBlock) cbb)
					.appendLine(getDebugPrepend(node) + ((LLVMCodeGenerator) generator).getNodeRef(node)
							+ " = bitcast i8* " + ((LLVMCodeGenerator) generator).getNodeRef(children[0]) + " to i8*");
		}

	}

	/**
	 * CustomNodeImpl for "debugPrint"
	 */
	public static class LLVMNodeDebugPrint extends CustomNodeImpl {

		@Override
		public void process(CodeGenerator generator, CompiledBasicBlock cbb, NodeCustom node) {
			assert (generator instanceof LLVMCodeGenerator);
			assert (cbb instanceof LLVMCompiledBasicBlock);

			// String thisNode = ((LLVMCodeGenerator) generator).getNodeRef(node);
			Node[] children = node.children();
			String nodeName = ((LLVMCodeGenerator) generator).getNodeRef(node);
			String formatName = ((LLVMCodeGenerator) generator).getNodeRef(children[0]);

			((LLVMCompiledBasicBlock) cbb).appendLine(getDebugPrepend(node));
			if (children.length == 1 || (children.length == 2
					&& (children[1] instanceof NodeStore || children[1] instanceof NodeAStore))) {
				((LLVMCompiledBasicBlock) cbb).appendLine(nodeName
						+ " = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([8 x i8], [8 x i8]* @.debug.format.0, i32 0, i32 0), i8* "
						+ formatName + ")\n");
			} else if (children.length == 2) {
				((LLVMCompiledBasicBlock) cbb).appendLine(nodeName
						+ " = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.debug.format.1, i32 0, i32 0), i8* "
						+ formatName + ", i8* " + ((LLVMCodeGenerator) generator).getNodeRef(children[1]) + ")\n");
			} else if (children.length == 3) {
				((LLVMCompiledBasicBlock) cbb).appendLine(nodeName
						+ " = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([13 x i8], [13 x i8]* @.debug.format.2, i32 0, i32 0), i8* "
						+ formatName + ", i8* " + ((LLVMCodeGenerator) generator).getNodeRef(children[1]) + ", i8* "
						+ ((LLVMCodeGenerator) generator).getNodeRef(children[2]) + ")\n");
			} else if (children.length == 4) {
				((LLVMCompiledBasicBlock) cbb).appendLine(nodeName
						+ " = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([16 x i8], [16 x i8]* @.debug.format.3, i32 0, i32 0), i8* "
						+ formatName + ", i8* " + ((LLVMCodeGenerator) generator).getNodeRef(children[1]) + ", i8* "
						+ ((LLVMCodeGenerator) generator).getNodeRef(children[2]) + ", i8* "
						+ ((LLVMCodeGenerator) generator).getNodeRef(children[3]) + ")\n");
			} else if (children.length == 5) {
				((LLVMCompiledBasicBlock) cbb).appendLine(nodeName
						+ " = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([19 x i8], [19 x i8]* @.debug.format.4, i32 0, i32 0), i8* "
						+ formatName + ", i8* " + ((LLVMCodeGenerator) generator).getNodeRef(children[1]) + ", i8* "
						+ ((LLVMCodeGenerator) generator).getNodeRef(children[2]) + ", i8* "
						+ ((LLVMCodeGenerator) generator).getNodeRef(children[3]) + ", i8* "
						+ ((LLVMCodeGenerator) generator).getNodeRef(children[4]) + ")\n");
			}
		}

	}

}
