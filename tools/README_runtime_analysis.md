# Runtime Source Code Analysis Tool

This tool analyzes the Ikemen Plus Ultra source code to extract runtime execution information including function signatures, data structures, network operations, and buffer usage.

## Purpose

The tool produces a comprehensive text file (`runtime_analysis.txt`) containing:

1. **Runtime function arguments and return types** - All C++ and Lua functions with their signatures
2. **Read/write fields in objects** - All structure/class field definitions
3. **Network socket calls and patch buffers** - Functions and data structures used before network transmission
4. **Type definitions and aliases** - Typedef declarations for better understanding of data types
5. **Global variables** - Static and global variables relevant to networking

## Usage

Run the analysis tool from the repository root:

```bash
python3 tools/runtime_analysis.py
```

This will generate `runtime_analysis.txt` in the repository root directory.

## Output Format

The generated report is organized into sections:

- **Section 1**: C++ Function Signatures - All functions from C++ source files with return types, parameters, and signatures
- **Section 2**: Object Structures and Fields - Class/struct definitions with all their member fields
- **Section 3**: Network Socket Calls - All socket operations including send/receive calls with buffer information
- **Section 4**: Lua Function Signatures - All Lua script functions from the game engine
- **Section 5**: Type Definitions - Typedef declarations and type aliases
- **Section 6**: Global Variables - Network-related global and static variables
- **Summary Statistics**: Counts of each analyzed element

## What is Analyzed

### C++ Source Files
- All `.cpp` and `.h` files in the `src/` directory
- Function definitions and SSZ plugin macros (TUserFunc)
- Structure and class definitions with fields
- Socket helper functions (socconnect, socsend, socrecv, etc.)
- Type definitions and aliases
- Global and static variable declarations

### Lua Script Files
- All `.lua` files in the `script/` directory
- Function definitions
- Network/socket operation calls

### Network Operations
The tool specifically identifies:
- Socket creation, connection, listening operations
- Send/receive buffer operations with data structure information
- Buffer sizes and directions (send/receive)
- Context lines showing actual usage

## Example Output

```
Function: SocketSend
  Return Type: bool
  Parameters: intptr_t size, char *p, SOCKET *psoc
  Signature: TUserFunc(bool, SocketSend, intptr_t size, char *p, SOCKET *psoc)
  Type: SSZ_PLUGIN

Buffer: p
  File: src/lib/dll/socket/socket/socket.cpp, Line: 105
  Size: size
  Context: return socsend(*psoc, p, size) == size;
```

## Dependencies

- Python 3.6 or higher
- No external Python packages required (uses only standard library)

## Report Statistics

The typical report includes:
- 20,000+ C++ functions
- 700+ Lua functions
- 250+ structures/objects
- 1,000+ type definitions
- 500+ network calls
- Detailed socket buffer information

## Use Cases

This analysis is useful for:
- Understanding the runtime execution flow
- Identifying network protocol implementations
- Analyzing data structures passed over network connections
- Security auditing of network operations
- Code documentation and reverse engineering
- Understanding the engine's architecture

## Limitations

- Pattern-based static analysis (not runtime tracing)
- May miss dynamically generated code
- Header file macros may create false positives
- Multi-line complex declarations may not be fully captured

## Notes

This tool performs static source code analysis. For actual runtime behavior analysis, you would need to use debugging tools or instrumentation.
