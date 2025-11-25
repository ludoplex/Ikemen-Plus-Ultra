#!/usr/bin/env python3
"""
Runtime Source Code Analysis Tool

This script analyzes the Ikemen Plus Ultra source code to extract:
1. Runtime arguments/returns of functions
2. All read/write fields in all objects/structures
3. Patch buffers just before network calls (socket operations)
4. Corresponding function and variable declarations and templates

Output: runtime_analysis.txt

LIMITATIONS:
- This is pattern-based static analysis, not a full C++ parser
- Complex C++ features (templates, namespaces, operator overloads) may not be fully captured
- Nested structures and methods within classes may have incomplete parsing
- Field access levels (public/private/protected) are simplified to read/write
- For most accurate analysis, supplement with runtime debugging tools
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple
from collections import defaultdict
from datetime import datetime


class SourceAnalyzer:
    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)
        self.src_root = self.repo_root / "src"
        self.script_root = self.repo_root / "script"
        
        # Storage for analysis results
        self.cpp_functions: List[Dict] = []
        self.lua_functions: List[Dict] = []
        self.structures: List[Dict] = []
        self.network_calls: List[Dict] = []
        self.socket_buffers: List[Dict] = []
        self.object_fields: Dict[str, List[Dict]] = defaultdict(list)
        self.typedefs: List[Dict] = []
        self.global_vars: List[Dict] = []
        
    def _extract_buffer_info(self, line: str, rel_path: Path, line_num: int, 
                            operation_keywords: list, direction: str = 'send'):
        """Helper to extract buffer information from socket operations."""
        for keyword in operation_keywords:
            if keyword in line:
                # Pattern: operation(socket, buffer, size) or similar
                buf_pattern = r'(?:send|Send|recv|Recv)\s*\([^,]+,\s*([^,\)]+)(?:,\s*([^,\)]+))?'
                buf_match = re.search(buf_pattern, line)
                if buf_match:
                    buffer_name = buf_match.group(1).strip()
                    size_expr = buf_match.group(2).strip() if buf_match.group(2) else "unknown"
                    return {
                        'file': str(rel_path),
                        'line': line_num,
                        'buffer': buffer_name,
                        'size': size_expr,
                        'context': line.strip(),
                        'direction': direction
                    }
        return None
    
    def analyze_cpp_file(self, file_path: Path):
        """Analyze a C++ source file for functions, structures, and network calls."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return
            
        rel_path = file_path.relative_to(self.repo_root)
        
        # Extract function definitions with return types and parameters
        # Pattern: return_type function_name(parameters)
        func_pattern = r'(\w+(?:\s*\*)?)\s+(\w+)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, content):
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            params = match.group(3).strip()
            
            # Skip common keywords that aren't function definitions
            if return_type in ['if', 'while', 'for', 'switch', 'return', 'else', 
                              'case', 'do', 'goto', 'try', 'catch', 'throw', 
                              'const', 'static', 'extern', 'break', 'continue',
                              'public', 'private', 'protected', 'virtual', 'override']:
                continue
                
            self.cpp_functions.append({
                'file': str(rel_path),
                'name': func_name,
                'return_type': return_type,
                'parameters': params,
                'signature': f"{return_type} {func_name}({params})"
            })
        
        # Extract structure/class definitions with fields
        struct_pattern = r'(?:struct|class)\s+(\w+)\s*\{([^}]+)\}'
        for match in re.finditer(struct_pattern, content, re.DOTALL):
            struct_name = match.group(1)
            struct_body = match.group(2)
            
            # Extract fields from the structure body
            field_pattern = r'(\w+(?:\s*\*)?)\s+(\w+)\s*;'
            fields = []
            for field_match in re.finditer(field_pattern, struct_body):
                field_type = field_match.group(1).strip()
                field_name = field_match.group(2).strip()
                # Note: Access level detection is limited in this static analysis
                # All fields are marked as 'read/write' by default
                fields.append({
                    'type': field_type,
                    'name': field_name,
                    'access': 'read/write'  # Simplified - actual access depends on context
                })
            
            if fields:
                self.structures.append({
                    'file': str(rel_path),
                    'name': struct_name,
                    'fields': fields
                })
                self.object_fields[struct_name] = fields
        
        # Detect network/socket calls
        socket_keywords = ['socket', 'connect', 'send', 'recv', 'listen', 'accept', 
                          'bind', 'setsockopt', 'getaddrinfo', 'Socket']
        
        lines = content.split('\n')
        for i, line in enumerate(lines):
            for keyword in socket_keywords:
                if keyword in line and not line.strip().startswith('//'):
                    # Look for buffer/data being sent
                    buffer_match = re.search(r'(\w+)\s*,\s*([^,\)]+)', line)
                    
                    self.network_calls.append({
                        'file': str(rel_path),
                        'line': i + 1,
                        'code': line.strip(),
                        'operation': keyword
                    })
                    
                    # Extract buffer information if this is a send operation
                    send_ops = ['send', 'Send', 'socsend', 'SocketSend', 'SocketSendAry']
                    recv_ops = ['recv', 'Recv', 'socrecv', 'SocketRecv', 'SocketRecvAry']
                    
                    if keyword in send_ops:
                        buf_info = self._extract_buffer_info(line, rel_path, i + 1, 
                                                             send_ops, 'send')
                        if buf_info:
                            self.socket_buffers.append(buf_info)
                    elif keyword in recv_ops:
                        buf_info = self._extract_buffer_info(line, rel_path, i + 1, 
                                                             recv_ops, 'receive')
                        if buf_info:
                            self.socket_buffers.append(buf_info)
                    break
        
        # Extract TUserFunc macro usages (SSZ plugin functions)
        # Handle multi-line TUserFunc declarations more efficiently
        # Use DOTALL flag instead of converting entire file to single line
        tuser_pattern = r'TUserFunc\s*\(\s*([^,]+?)\s*,\s*(\w+)\s*,\s*([^)]*?)\s*\)'
        for match in re.finditer(tuser_pattern, content, re.DOTALL):
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            params = match.group(3).strip()
            # Normalize whitespace in parameters
            params = ' '.join(params.split())
            
            self.cpp_functions.append({
                'file': str(rel_path),
                'name': func_name,
                'return_type': return_type,
                'parameters': params,
                'signature': f"TUserFunc({return_type}, {func_name}, {params})",
                'type': 'SSZ_PLUGIN'
            })
        
        # Extract helper functions from tcpsocket.hpp (socconnect, socsend, socrecv, etc.)
        if 'tcpsocket' in str(file_path):
            helper_funcs = ['socclose', 'socconnect', 'soclisten', 'socsend', 'socrecv']
            for helper in helper_funcs:
                pattern = rf'(\w+)\s+{helper}\s*\(([^)]*)\)'
                for match in re.finditer(pattern, content):
                    ret_type = match.group(1).strip()
                    params = match.group(2).strip()
                    self.cpp_functions.append({
                        'file': str(rel_path),
                        'name': helper,
                        'return_type': ret_type,
                        'parameters': params,
                        'signature': f"{ret_type} {helper}({params})",
                        'type': 'SOCKET_HELPER'
                    })
        
        # Extract typedef declarations
        typedef_pattern = r'typedef\s+([^;]+)\s+(\w+)\s*;'
        for match in re.finditer(typedef_pattern, content):
            base_type = match.group(1).strip()
            new_name = match.group(2).strip()
            self.typedefs.append({
                'file': str(rel_path),
                'name': new_name,
                'base_type': base_type
            })
        
        # Extract global/static variable declarations (especially for socket-related)
        if 'socket' in str(file_path).lower() or 'network' in str(file_path).lower():
            global_pattern = r'(?:static\s+)?(?:extern\s+)?(\w+(?:\s*\*)?)\s+(\w+)\s*(?:=|;)'
            for match in re.finditer(global_pattern, content):
                var_type = match.group(1).strip()
                var_name = match.group(2).strip()
                # Skip common keywords
                if var_type not in ['if', 'while', 'for', 'switch', 'return', 'case', 'break', 'continue']:
                    self.global_vars.append({
                        'file': str(rel_path),
                        'name': var_name,
                        'type': var_type
                    })
    
    def analyze_lua_file(self, file_path: Path):
        """Analyze a Lua script file for functions and network operations."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {file_path}: {e}")
            return
            
        rel_path = file_path.relative_to(self.repo_root)
        
        # Extract Lua function definitions
        # Pattern: function name(params) or local function name(params)
        func_pattern = r'(?:local\s+)?function\s+([a-zA-Z_][\w.]*)\s*\(([^)]*)\)'
        for match in re.finditer(func_pattern, content):
            func_name = match.group(1)
            params = match.group(2).strip()
            
            self.lua_functions.append({
                'file': str(rel_path),
                'name': func_name,
                'parameters': params,
                'signature': f"function {func_name}({params})"
            })
        
        # Look for socket/network operations in Lua
        socket_keywords = ['socket', 'Socket', 'netplay', 'tcp', 'udp', 
                          'connect', 'send', 'receive']
        
        lines = content.split('\n')
        for i, line in enumerate(lines):
            for keyword in socket_keywords:
                if keyword in line and not line.strip().startswith('--'):
                    self.network_calls.append({
                        'file': str(rel_path),
                        'line': i + 1,
                        'code': line.strip(),
                        'operation': keyword,
                        'language': 'lua'
                    })
                    break
    
    def analyze_all_sources(self):
        """Analyze all C++ and Lua source files."""
        print("Analyzing C++ source files...")
        cpp_files = list(self.src_root.rglob("*.cpp")) + list(self.src_root.rglob("*.h"))
        for cpp_file in cpp_files:
            self.analyze_cpp_file(cpp_file)
        
        print("Analyzing Lua script files...")
        lua_files = list(self.script_root.rglob("*.lua"))
        for lua_file in lua_files:
            self.analyze_lua_file(lua_file)
    
    def generate_report(self, output_file: str):
        """Generate the comprehensive analysis report."""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("IKEMEN PLUS ULTRA - RUNTIME SOURCE CODE ANALYSIS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("This report contains analysis of:\n")
            f.write("1. Runtime function arguments and return types\n")
            f.write("2. All read/write fields in objects and structures\n")
            f.write("3. Network socket calls and patch buffers\n")
            f.write("4. Function and variable declarations with templates\n")
            f.write("5. Type definitions and aliases\n\n")
            
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source Files Analyzed:\n")
            f.write(f"  - C++ files: {len(list(self.src_root.rglob('*.cpp')) + list(self.src_root.rglob('*.h')))}\n")
            f.write(f"  - Lua files: {len(list(self.script_root.rglob('*.lua')))}\n\n")
            
            # Section 1: C++ Functions (Runtime execution)
            f.write("\n" + "=" * 80 + "\n")
            f.write("SECTION 1: C++ FUNCTION SIGNATURES (Runtime Arguments/Returns)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total C++ functions found: {len(self.cpp_functions)}\n\n")
            
            # Group by file
            funcs_by_file = defaultdict(list)
            for func in self.cpp_functions:
                funcs_by_file[func['file']].append(func)
            
            for file_path in sorted(funcs_by_file.keys()):
                f.write(f"\n--- {file_path} ---\n\n")
                for func in funcs_by_file[file_path]:
                    f.write(f"Function: {func['name']}\n")
                    f.write(f"  Return Type: {func['return_type']}\n")
                    f.write(f"  Parameters: {func['parameters']}\n")
                    f.write(f"  Signature: {func['signature']}\n")
                    if 'type' in func:
                        f.write(f"  Type: {func['type']}\n")
                    f.write("\n")
            
            # Section 2: Structures and Object Fields
            f.write("\n" + "=" * 80 + "\n")
            f.write("SECTION 2: OBJECT STRUCTURES AND READ/WRITE FIELDS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total structures found: {len(self.structures)}\n\n")
            
            for struct in self.structures:
                f.write(f"\nStructure: {struct['name']}\n")
                f.write(f"  File: {struct['file']}\n")
                f.write(f"  Fields:\n")
                for field in struct['fields']:
                    f.write(f"    - {field['type']} {field['name']} ({field['access']})\n")
                f.write("\n")
            
            # Section 3: Network Calls and Socket Buffers
            f.write("\n" + "=" * 80 + "\n")
            f.write("SECTION 3: NETWORK SOCKET CALLS AND PATCH BUFFERS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total network calls found: {len(self.network_calls)}\n\n")
            
            # Group network calls by file
            net_by_file = defaultdict(list)
            for call in self.network_calls:
                net_by_file[call['file']].append(call)
            
            for file_path in sorted(net_by_file.keys()):
                f.write(f"\n--- {file_path} ---\n\n")
                for call in net_by_file[file_path]:
                    f.write(f"Line {call['line']}: {call['operation']}\n")
                    f.write(f"  Code: {call['code']}\n")
                    if 'language' in call:
                        f.write(f"  Language: {call['language']}\n")
                    f.write("\n")
            
            # Section 3b: Socket Buffers (Patch Buffers)
            f.write("\n" + "-" * 80 + "\n")
            f.write("SOCKET BUFFERS (Data structures before network transmission)\n")
            f.write("-" * 80 + "\n\n")
            
            f.write(f"Total socket buffers found: {len(self.socket_buffers)}\n\n")
            
            for buf in self.socket_buffers:
                f.write(f"Buffer: {buf['buffer']}\n")
                f.write(f"  File: {buf['file']}, Line: {buf['line']}\n")
                if 'size' in buf:
                    f.write(f"  Size: {buf['size']}\n")
                if 'direction' in buf:
                    f.write(f"  Direction: {buf['direction']}\n")
                f.write(f"  Context: {buf['context']}\n")
                f.write("\n")
            
            # Section 4: Lua Functions
            f.write("\n" + "=" * 80 + "\n")
            f.write("SECTION 4: LUA FUNCTION SIGNATURES (Runtime Scripting Layer)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total Lua functions found: {len(self.lua_functions)}\n\n")
            
            # Group by file
            lua_by_file = defaultdict(list)
            for func in self.lua_functions:
                lua_by_file[func['file']].append(func)
            
            for file_path in sorted(lua_by_file.keys()):
                f.write(f"\n--- {file_path} ---\n\n")
                for func in lua_by_file[file_path]:
                    f.write(f"Function: {func['name']}\n")
                    f.write(f"  Parameters: {func['parameters']}\n")
                    f.write(f"  Signature: {func['signature']}\n")
                    f.write("\n")
            
            # Section 5: Type Definitions
            f.write("\n" + "=" * 80 + "\n")
            f.write("SECTION 5: TYPE DEFINITIONS AND ALIASES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total typedefs found: {len(self.typedefs)}\n\n")
            
            typedef_by_file = defaultdict(list)
            for td in self.typedefs:
                typedef_by_file[td['file']].append(td)
            
            for file_path in sorted(typedef_by_file.keys()):
                f.write(f"\n--- {file_path} ---\n\n")
                for td in typedef_by_file[file_path]:
                    f.write(f"typedef {td['base_type']} {td['name']};\n")
            
            # Section 6: Global Variables (Network-related)
            if self.global_vars:
                f.write("\n" + "=" * 80 + "\n")
                f.write("SECTION 6: GLOBAL/STATIC VARIABLES (Network-related)\n")
                f.write("=" * 80 + "\n\n")
                
                f.write(f"Total global variables found: {len(self.global_vars)}\n\n")
                
                vars_by_file = defaultdict(list)
                for var in self.global_vars:
                    vars_by_file[var['file']].append(var)
                
                for file_path in sorted(vars_by_file.keys()):
                    f.write(f"\n--- {file_path} ---\n\n")
                    for var in vars_by_file[file_path]:
                        f.write(f"{var['type']} {var['name']}\n")
            
            # Summary Section
            f.write("\n" + "=" * 80 + "\n")
            f.write("SUMMARY STATISTICS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"C++ Functions: {len(self.cpp_functions)}\n")
            f.write(f"Lua Functions: {len(self.lua_functions)}\n")
            f.write(f"Structures/Objects: {len(self.structures)}\n")
            f.write(f"Type Definitions: {len(self.typedefs)}\n")
            f.write(f"Global Variables: {len(self.global_vars)}\n")
            f.write(f"Network Calls: {len(self.network_calls)}\n")
            f.write(f"Socket Buffers: {len(self.socket_buffers)}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("END OF REPORT\n")
            f.write("=" * 80 + "\n")


def main():
    """Main entry point for the analysis tool."""
    # Determine repository root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    print("Ikemen Plus Ultra - Runtime Source Code Analysis")
    print("=" * 60)
    print(f"Repository root: {repo_root}")
    print()
    
    analyzer = SourceAnalyzer(str(repo_root))
    analyzer.analyze_all_sources()
    
    output_file = repo_root / "runtime_analysis.txt"
    print(f"\nGenerating report: {output_file}")
    analyzer.generate_report(str(output_file))
    
    print("\nAnalysis complete!")
    print(f"Report saved to: {output_file}")


if __name__ == "__main__":
    main()
