# C/C++ AST Subtree Analyzer

This project provides a tool for analyzing C/C++ code by extracting, serializing, and counting subtrees from its abstract syntax tree (AST). The tool uses the Clang library to parse the C/C++ code and generate the AST.

## Requirements

- Python 3.7+
- Clang 12+
- LLVM library

## Setup

1. **Install Clang and LLVM**:

   On macOS, you can install it using Homebrew:
   ```sh
   brew install llvm

2. **Set up the Python environment**:

    ```sh
    python3 -m venv .venv
    ```sh
    source .venv/bin/activate
    ```sh
    pip install clang

3. **Set up Clang library path**:

    Here is an example for macOS:
    ```sh
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'

## Usage

1. **Assign your target:**

    Assign `target_file` to the path of the desired C/C++ file to parse.
    If parsing C++, remember to modify parse_to_ast as guided by the comments.

2. **Run the script:**    

    ```sh
    python parse.py

3. **Output:**

    The script will generate a subtrees.csv file containing the following columns:

    - Hash: SHA-256 hash of the serialized subtree.
    - Count: Number of occurrences of this subtree.
    - Human Readable Expression: A human-readable representation of the subtree.
    - Serialized Subtree: The serialized subtree.
    - Deserialized Tree: The deserialized tree structure in pretty-printed format.

## Script Details

    `parse.py`
    This script contains the following main functions:

    - serialize_node(node, anon_map=None): Serializes an AST node, anonymizing variable names.
    - extract_subtrees(node, subtrees=None): Extracts all subtrees starting from a given node.
    - hash_subtree(subtree): Returns the SHA-256 hash of a serialized subtree.
    - count_subtrees(subtrees): Counts the occurrences of each subtree.
    - deserialize_subtree(serialized_subtree): Deserializes a serialized subtree back into its tree structure.
    - print_tree(node, depth=0): Pretty prints a deserialized tree.
    - parse_to_ast(file_path): Parses a C/C++ file into an AST using Clang.
    - tree_to_expression(node): Converts a deserialized subtree into a human-readable expression.

    `add.c`
    This is an example C file for parsing. `subtrees.csv` contains the output of `parse.py` with `add.c` as the target file.
    
## Acknowledgments
    [LLVM Project](llvm.org)
    [Clang Python Bindings](https://pypi.org/project/clang/)

## Author
- [Anuraag Pandhi](https://github.com/Anumon6395)