#!/usr/bin/env python3
import re
import random
import string
import sys
import os

def generate_random_name(length=8):
    """Generate a random variable name with lowercase and uppercase letters."""
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def is_sensitive_name(name):
    """Check if a variable name is sensitive (should not be renamed)."""
    # List of sensitive names that should not be renamed
    sensitive_names = [
        # Windows API and standard types
        "HANDLE", "DWORD", "PVOID", "BOOL", "WORD", "BYTE", "SIZE_T", "NTSTATUS", "ULONG",
        "HINTERNET", "INTERNET_PORT", "PBYTE", "PCHAR", "PTEB", "PPEB", "VOID",
        # System call names
        "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtQueueApcThread",
        # Function names from Windows headers
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
        "WinHttpReceiveResponse", "WinHttpQueryDataAvailable", "WinHttpReadData",
        "CreateProcess", "CreateThread", "CloseHandle", "GetLastError", "SimpleDecryption",
        "HellsGate", "HellDescent", "GetThreadId", "MsgWaitForMultipleObjectsEx", "CreateEvent",
        # Special names and structure fields that should be preserved
        "AesCipherText", "AesKey", "AesIv", "SYS_TABLE", "SYS_TABLE_ENTRY",
        "pAddress", "dwHash", "wSystemCall", "dataSize", "name", "data",
        # Core Windows constants
        "NULL", "TRUE", "FALSE", "INFINITE", "PAGE_READWRITE", "PAGE_EXECUTE_READWRITE",
        "MEM_RESERVE", "MEM_COMMIT", "WINHTTP_FLAG_SECURE", "QS_HOTKEY", "MWMO_ALERTABLE",
        "INTERNET_DEFAULT_HTTPS_PORT", "INTERNET_DEFAULT_HTTP_PORT",
        # Other important names
        "main", "argc", "argv", "ByteArrayVar"
    ]
    
    # Add all Windows API prefixes to avoid renaming functions
    prefixes = ["Nt", "Rtl", "Win", "Is", "Get", "Set", "Create", "Close", "Open", 
                "Query", "Read", "Write", "Alloc", "Free", "Enum", "Wait", "Msg"]
    
    # Check if the name is in the sensitive list
    if name in sensitive_names:
        return True
    
    # Check if the name starts with a sensitive prefix
    for prefix in prefixes:
        if name.startswith(prefix) and len(name) > len(prefix) and name[len(prefix)].isupper():
            return True
    
    # Handle specific patterns
    if (name.startswith("p") or name.startswith("h") or name.startswith("sz") or 
        name.startswith("dw") or name.startswith("lp") or name.startswith("cb") or
        name.startswith("ul")):
        # Common Win32 API naming conventions - consider these potentially sensitive
        return True
        
    # Consider global/special names (starting with g_) as sensitive
    if name.startswith("g_"):
        return True
        
    # Consider all-caps names as constants (sensitive)
    if name.isupper() and len(name) > 2:
        return True
        
    return False

def obfuscate_file(file_path, output_path=None):
    """Rename non-sensitive variables in the C file."""
    if not output_path:
        base, ext = os.path.splitext(file_path)
        output_path = f"{base}_obfuscated{ext}"
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # First, identify all function and variable names
    # Find function declarations
    function_pattern = r'\b(\w+)\s*\([^)]*\)\s*{'
    function_matches = re.finditer(function_pattern, content)
    function_names = [match.group(1) for match in function_matches if not is_sensitive_name(match.group(1))]
    
    # Find variable declarations
    variable_pattern = r'\b((?:const|static|extern)?\s*(?:int|char|float|double|long|unsigned|size_t|DWORD|WORD|BYTE|BOOL|HANDLE|PVOID|void|PBYTE|ULONG|SIZE_T)\s*\*?\s*)(\w+)(?:\s*[\[,;=)])'
    variable_matches = re.finditer(variable_pattern, content)
    variable_names = [match.group(2) for match in variable_matches if not is_sensitive_name(match.group(2))]
    
    # Add function parameters
    param_pattern = r'\([^)]*?(\w+)\s*(?:,|\))'
    param_matches = re.finditer(param_pattern, content)
    param_names = [match.group(1) for match in param_matches if not is_sensitive_name(match.group(1)) and match.group(1) not in ['void']]
    
    # Combine all names to rename
    all_names = set(function_names + variable_names + param_names)
    
    # Create a mapping of original names to random names
    name_mapping = {}
    for name in all_names:
        # Skip names that are likely to be important
        if is_sensitive_name(name) or len(name) < 3:
            continue
        name_mapping[name] = generate_random_name(random.randint(6, 12))
    
    # Replace all occurrences of these names
    for original_name, new_name in name_mapping.items():
        # Use word boundaries to avoid partial replacements
        pattern = r'\b' + re.escape(original_name) + r'\b'
        content = re.sub(pattern, new_name, content)
    
    # Write to output file
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # Print the mapping for reference
    print(f"Obfuscation complete. Saved to {output_path}")
    print(f"Variable name mapping:")
    for original, new_name in name_mapping.items():
        print(f"  {original} -> {new_name}")
    
    return output_path, name_mapping

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python obfuscate.py <input_file> [output_file]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    obfuscate_file(input_file, output_file)
