Obfuscat
=============================================

Obfuscat is a tool to apply obfuscation techniques with predictable overhead.
This means that for a given input program the obfuscated programs will be internally different,
but the output size and the amount of instructions that need to be executed will always be the same.
This can be useful when having hard-resource limits and many versions of a program are wanted.
For more information on the design and reasoning behind it, see [my thesis](docs/thesis.pdf).

# Input Programs

The input programs for the Obfuscat tool have to be supplied as Java Class Files.
The tool only supports limited programs, so assuming they are programmed in Java:

- No Objects (primitive type arrays can be used) are usable
- No Floating Points
- No Longs
- No Exceptions
- Only Static Functions
- So synchronous features


Under these restrictions, programs look like normal Java programs:

```java
/**
 * Fibonacci Number calculation Sample
 */
public class Sample1 {

	
	public static int entry() {
		
		int n = 28; // 28th fib number
		
		int n1 = 0;
		int n2 = 1;
		int n3 = 0;
		
		if(n == 0) return n1;
		
		for(int i=2;i<=n;i++) {
			n3 = n1 + n2;
			n1 = n2;
			n2 = n3;
		}
		
		return n2;
		
	}
	
}
```

See the [`util\example_programs`](util\example_programs) folder for compiled examples
See the [`src\test\java\re\bytecode\obfuscat\samples`](src\test\java\re\bytecode\obfuscat\samples) folder for other examples and test cases
- Sample1 : Fibonacci Number Calculation
- Sample2 : Prime Number Calculation
- Sample3 : Math Operation Test
- Sample4 : CRC32 without a lookuptable
- Sample5 : Switch Table Test
- Sample6 : Testing `native` operations
- Sample7 : RC4
- Sample8 : Testing Object and primitive arrays
- Sample9 : AES-128
- Sample10 : SHA-1

# Output Format

The Intermediate Format for most Obfuscat Operations are `.fbin` files which are serilized Java Objects.
The supported Native Output Formats are `Thumb` (ARMv8 Thumb2), `Flowgraph`, `VM`.

When compiling for `Thumb` the output is native code + static data - binary file.
To see how to call the obfuscated call from C and link it together, see [`util\wrapper.c`](util\wrapper.c)

The `Flowgraph` target is used for rendering control flow graphs using [MxGraph](https://github.com/jgraph/mxgraph)
For the code that uses it see the [`util\gwt_src`](util\gwt_src) folder, or [here for a Demo](https://pusty.github.io/Obfuscat/demo.html)
Note that[`Base64Utils`](util\gwt_src\re\bytecode\obfuscat\gwt\client\Base64Utils.java), [`DataInput`](util\gwt_src\re\bytecode\obfuscat\gwt\emul\java\io\DataInput.java),
[`DataInputStream`](util\gwt_src\re\bytecode\obfuscat\gwt\emul\java\io\DataInputStream.java), [`EOFException`](util\gwt_src\re\bytecode\obfuscat\gwt\emul\java\io\EOFException.java)
and [`UTFDataFormatException`](util\gwt_src\re\bytecode\obfuscat\gwt\emul\java\io\UTFDataFormatException.java) are licensed by Google Inc. under the `Apache License, Version 2.0` license.
The license for MxGraph can be found [here](https://github.com/jgraph/mxgraph/blob/master/LICENSE).


The `VM` target generates a binary file of virtual machine code for the Virtual Machine used for the Virtualize obfuscation.
See [`src\main\java\re\bytecode\obfuscat\pass\vm\VMRefImpl.java`](src\main\java\re\bytecode\obfuscat\pass\vm\VMRefImpl.java) for a reference implementation in Java.
A C implementation can be found in [`util\vm.c`](util\vm.c). Note that the C implementation is missing some functionality (merged functions and static data).

# Usage

```
> java -jar Obfuscat.jar help
Supported commands:
    builder <builder> [args] [-output filename] [-seed someseed] - Run a builder with the provided arguments
    obfuscate <pass> [args]  [-input filename] [-output filename] [-seed someseed] - Run an obfuscation pass with the provided arguments
    compile <compile> [args]  [-input filename] [-output filename] [-seed someseed] - Compile for a platform with the provided arguments
    emulate [args]  [-input filename] - Emulate the input function and print statistics
    info [args] [-input filename] - Print statistics about the input function
    help - Provide an overview over supported commands
    help builder - List all registered builders
    help obfuscate - List all registered obfuscation passes
    help compile - List all registered generators
    help info <builder/pass/generator> - List information for the provided builder/pass or generator
```

```
> java -jar Obfuscat.jar help builder
Test : Test builder class
Class : A builder to lift java class files into functions
Verify : A builder for functions that verify whether the input is the created key
Call using 'function(array, array_length)'
Key : A builder for functions that write a hardcoded key into an array
Call using 'function(array)', note that the array length is not dynamically verified
HWKey : A builder for functions that write a randomised key with fixed size into an array
Call using 'function(array)', note that the array length is not dynamically verified
The function dynamically reads from hardware register 0x123 [PLACEHOLDER] to randomise per device
```

```
> java -jar Obfuscat.jar help obfuscate
LiteralEncode : Replace all constants with an encoded version and the decoder
FakeDependency : Inject fake dependencies to function parameters into constants
VariableEncode : Encode all variables when storing them and decode them when loading from them
Flatten : Flattens the control flow
OperationEncode : Encode all math operation nodes
Bogus : Add an opaque predicate after each unconditional basic block
Virtualize : Virtualizes the input function
```

```
> java -jar Obfuscat.jar help compile
Thumb : A code generator for ARMv8 Thumb2 code
VM : A code generator for VM code
Flowgraph : A graph generator for Control Flow Graph diagrams
```

Examples:

Parse the `CRC32.class` file to the internal format. Use the `entry` method as the entry point:
`> java -jar Obfuscat.jar builder Class -path CRC32.class -entry entry -output CRC32.fbin`

Emulate the generated file:
```
> java -jar Obfuscat.jar emulate "'CHECKSUM THIS'" 4  -input CRC32.fbin
Execution ended: -1263050787
Function Statistics: {variables=6, const=15, exitBlocks=1, blocks=10, custom=0, appendedData=0, store=10, aload=1, conditionalBlocks=3, astore=0, load=14, allocate=0, arguments=2, switchBlocks=0, math=11, jumpBlocks=6}
Execution Statistics: {variables=6, const=197, exitBlocks=1, blocks=147, custom=0, appendedData=0, conditionalBlocksFalse=49, store=83, aload=4, conditionalBlocks=73, astore=0, load=167, allocate=0, calls=1, switchBlocks=0, arguments=2, jumpBlocks=73, math=130}
=> [67, 72, 69, 67, 75, 83, 85, 77, 32, 84, 72, 73, 83] 4
```

Apply Virtualization Obfuscation on the generated file:
`> java -jar Obfuscat.jar obfuscate Virtualize -input CRC32.fbin -output CRC32.VM.fbin`

Emulate the obfuscated file:
```
> java -jar Obfuscat.jar emulate "'CHECKSUM THIS'" 4  -input CRC32.VM.fbin
Execution ended: -1263050787
Function Statistics: {variables=13, const=157, exitBlocks=2, blocks=58, custom=2, appendedData=1, store=65, aload=111, conditionalBlocks=0, astore=48, allocate=7, load=270, arguments=2, switchBlocks=1, math=236, jumpBlocks=55}
Execution Statistics: {variables=13, const=22526, exitBlocks=1, blocks=1555, custom=0, appendedData=1, conditionalBlocksFalse=0, store=5443, aload=10387, conditionalBlocks=0, astore=583, load=5072, allocate=3, calls=1, switchBlocks=777, arguments=2, jumpBlocks=777, math=27480}
=> [67, 72, 69, 67, 75, 83, 85, 77, 32, 84, 72, 73, 83] 4
```

Compile the obfuscated file to native ARMv8 Thumb2 code:
`> java -jar Obfuscat.jar compile Thumb -input CRC32.VM.fbin -output CRC32.VM.bin`



# Building

To build Obfuscat this project can be imported into eclipse as a gradle project.
Alternatively it is possible to use gradle directy to build and test this project.
For building it the [F0Cr](https://github.com/Pusty/F0Cr) Java Class File Parser is required (it is provided as a compiled jar file in the libs folder).

To run the tests an installation of the [Unicorn Framework](https://github.com/unicorn-engine/unicorn) is required, as well as the [Java Bindings](https://github.com/unicorn-engine/unicorn/tree/master/bindings/java).
For license reasons no compiled files are provided, so it is required to install and build these dependencies yourself.
