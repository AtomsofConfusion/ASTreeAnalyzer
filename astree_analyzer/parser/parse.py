import platform
import csv
import clang.cindex
import hashlib
from collections import Counter
from pathlib import Path
from . import PROJECT_ROOT

# Change path as necessary. This is for Mac.

if platform.system() ==  "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'


clang.cindex.Config.set_library_file(library_file)

def serialize_node(node, anon_map=None):
    if anon_map is None:
        anon_map = {}
    identifier_kinds = {
        clang.cindex.CursorKind.VAR_DECL,
        clang.cindex.CursorKind.PARM_DECL,
        clang.cindex.CursorKind.FIELD_DECL,
        clang.cindex.CursorKind.FUNCTION_DECL,
        clang.cindex.CursorKind.DECL_REF_EXPR
    }

    # Extended beyond just primitives
    primitive_replacements = {
        clang.cindex.CursorKind.INTEGER_LITERAL: '0',
        clang.cindex.CursorKind.FLOATING_LITERAL: '0.0',
        clang.cindex.CursorKind.CHARACTER_LITERAL: "'*'",
        clang.cindex.CursorKind.CXX_BOOL_LITERAL_EXPR: 'false',
        clang.cindex.CursorKind.STRING_LITERAL: '"str"' # not primitive, add more as needed
    }

    if node.kind in identifier_kinds:
        if node.spelling not in anon_map:
            anon_map[node.spelling] = f"var_{len(anon_map)}"
        node_rep = f"{anon_map[node.spelling]}_{node.type.spelling}"
        if '[' in node.type.spelling and ']' in node.type.spelling:
            base_type, subscript = node.type.spelling.split('[', 1)
            subscript = 0  # interpret as an integer literal for anonymization
            node_rep = f"{anon_map[node.spelling]}_{base_type}[{subscript}]"
    elif node.kind in primitive_replacements:
        node_rep = primitive_replacements[node.kind]
    else:
        node_rep = str(node.kind)

    if node.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
        tokens = list(node.get_tokens())
        operator = None
        for token in tokens:
            if token.spelling in {'+', '-', '*', '/', '%', '<', '>', '<=', '>=', '==', '!=', '&', '|', '^', '&&', '||', '=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^='}:
                operator = token.spelling
                break
        if operator:
            node_rep = f"{node_rep}_{operator}"
    elif node.kind == clang.cindex.CursorKind.UNARY_OPERATOR:
        tokens = list(node.get_tokens())
        if tokens:
            if tokens[0].spelling in {'++', '--', '+', '-', '!', '~'}:
                operator = tokens[0].spelling + '_pre'
            elif tokens[-1].spelling in {'++', '--', '+', '-', '!', '~'}:
                operator = tokens[-1].spelling + '_post'
            else:
                operator = tokens[0].spelling
            node_rep = f"{node_rep}_{operator}"
    elif node.kind == clang.cindex.CursorKind.CALL_EXPR:
        node_rep = f"{node_rep}_{node.displayname}"
    elif node.kind == clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        array_base = serialize_node(list(node.get_children())[0], anon_map)
        subscript = serialize_node(list(node.get_children())[1], anon_map)
        node_rep = f"{array_base}[{subscript}]"

    children_rep = [serialize_node(child, anon_map) for child in node.get_children() if node.kind != clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR]
    return f"{node_rep}({','.join(children_rep)})" if children_rep else node_rep

# Gets all subtrees with node parameter as root
def extract_subtrees(node, subtrees=None):
    if subtrees is None:
        subtrees = []
    subtree = serialize_node(node)
    subtrees.append(subtree)
    for child in node.get_children():
        extract_subtrees(child, subtrees)
    return subtrees

def hash_subtree(subtree):
    return hashlib.sha256(subtree.encode('utf-8')).hexdigest()

def count_subtrees(subtrees):
    subtree_counter = Counter(subtrees)
    return subtree_counter

def deserialize_subtree(serialized_subtree):
    def parse_subtree(s):
        if '(' not in s:
            return s, []
        node_rep, rest = s.split('(', 1)
        children_rep = []
        child = ''
        depth = 0
        for char in rest:
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            if char == ',' and depth == 0:
                children_rep.append(child)
                child = ''
            else:
                child += char
        if child:
            children_rep.append(child[:-1])  # remove the last ')'
        children = [parse_subtree(c) for c in children_rep]
        return node_rep, children

    return parse_subtree(serialized_subtree)

# Pretty prints tree
def print_tree(node, depth=0):
    node_rep, children = node
    result = '  ' * depth + str(node_rep) + '\n'
    for child in children:
        result += print_tree(child, depth + 1)
    return result

def parse_to_ast(file_path):
    index = clang.cindex.Index.create()
    # If parsing C++, replace the following line with: tu = index.parse(file_path, args=['-std=c++14'])
    tu = index.parse(file_path)
    return tu.cursor

# Human readable column
def tree_to_expression(node):
    node_rep, children = node

    if not children:
        return str(node_rep)

    if node_rep.startswith("CursorKind.BINARY_OPERATOR"):
        lhs = tree_to_expression(children[0])
        rhs = tree_to_expression(children[1])
        return f"{lhs} {node_rep.split('_')[-1]} {rhs}"
    elif node_rep.startswith("CursorKind.UNARY_OPERATOR"):
        parts = node_rep.split('_')
        operator = parts[-2] + parts[-1]
        operand = tree_to_expression(children[0])
        return f"{operator}{operand}" if '_pre' in operator else f"{operand}{operator}"
    elif node_rep.startswith("CursorKind.VAR_DECL"):
        var_name = tree_to_expression(children[0])
        if len(children) > 1:
            initializer = tree_to_expression(children[1])
            return f"{var_name} = {initializer}"
        else:
            return var_name
    elif node_rep.startswith("CursorKind.DECL_STMT"):
        return " ".join(tree_to_expression(child) for child in children)
    elif node_rep.startswith("CursorKind.DECL_REF_EXPR"):
        return str(children[0][0])
    elif node_rep.startswith("CursorKind.INTEGER_LITERAL"):
        return '0'
    elif node_rep.startswith("CursorKind.FLOATING_LITERAL") or node_rep.startswith("CursorKind.DOUBLE_LITERAL"):
        return '0.0'
    elif node_rep.startswith("CursorKind.CHARACTER_LITERAL"):
        return "'*'"
    elif node_rep.startswith("CursorKind.STRING_LITERAL"):
        return '"str"'
    elif node_rep.startswith("CursorKind.ASSIGNMENT_OPERATOR"):
        lhs = tree_to_expression(children[0])
        rhs = tree_to_expression(children[1])
        return f"{lhs} = {rhs}"
    elif node_rep.startswith("CursorKind.FUNCTION_DECL"):
        return_type = tree_to_expression(children[0])
        function_name = tree_to_expression(children[1])
        params = ", ".join(tree_to_expression(child) for child in children[2:])
        return f"{return_type} {function_name}({params})"
    elif node_rep.startswith("CursorKind.CALL_EXPR"):
        function_name = tree_to_expression(children[0])
        args = ", ".join(tree_to_expression(child) for child in children[1:])
        return f"{function_name}({args})"
    elif node_rep.startswith("CursorKind.IF_STMT"):
        condition = tree_to_expression(children[0])
        then_branch = tree_to_expression(children[1])
        else_branch = tree_to_expression(children[2]) if len(children) > 2 else ''
        return f"if ({condition}) {{ {then_branch} }} else {{ {else_branch} }}"
    elif node_rep.startswith("CursorKind.FOR_STMT"):
        init = tree_to_expression(children[0])
        condition = tree_to_expression(children[1])
        increment = tree_to_expression(children[2])
        body = tree_to_expression(children[3])
        return f"for ({init}; {condition}; {increment}) {{ {body} }}"
    elif node_rep.startswith("CursorKind.WHILE_STMT"):
        condition = tree_to_expression(children[0])
        body = tree_to_expression(children[1])
        return f"while ({condition}) {{ {body} }}"
    elif node_rep.startswith("CursorKind.RETURN_STMT"):
        return f"return {tree_to_expression(children[0])};"
    elif node_rep.startswith("CursorKind.UNEXPOSED_EXPR"):
        return tree_to_expression(children[0])
    elif node_rep.startswith("CursorKind.COMPOUND_STMT"):
        return " ".join(tree_to_expression(child) for child in children)
    else:
        return f"{node_rep}(" + ", ".join(tree_to_expression(child) for child in children) + ")"



def parse(input_path: str, output_dir: str):
    """
    TODO write docstring
    """

    ast = parse_to_ast(input_path)
    subtrees = extract_subtrees(ast)

    # Create a mapping between serialized and deserialized subtrees
    subtree_map = {subtree: print_tree(deserialize_subtree(subtree)) for subtree in subtrees}
    subtree_counter = count_subtrees(subtrees)

    output_path = str(Path(output_dir, "subtrees.csv"))
    # Write to CSV
    with open(output_path, 'w', newline='') as csvfile:
        fieldnames = ['Hash', 'Count', 'Human Readable Expression', 'Serialized Subtree', 'Deserialized Tree']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for subtree, count in subtree_counter.items():
            hash_val = hash_subtree(subtree)
            deserialized_tree = subtree_map[subtree]
            human_readable_expression = tree_to_expression(deserialize_subtree(subtree))
            writer.writerow({
                'Hash': hash_val,
                'Count': count,
                'Human Readable Expression': human_readable_expression,
                'Serialized Subtree': subtree,
                'Deserialized Tree': deserialized_tree
            })
    print(f"Output written to {output_path}")
