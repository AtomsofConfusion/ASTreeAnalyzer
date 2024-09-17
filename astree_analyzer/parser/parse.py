import json
import platform
import csv
import clang.cindex
import hashlib
from collections import Counter
from pathlib import Path

# Change path as necessary. This is for Mac.
PROJECT_ROOT = Path(__file__).parent.parent.parent
if platform.system() ==  "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'

CONFIG = json.loads((PROJECT_ROOT / "config.json").read_text())

IDENTIFIER_KINDS = {
    clang.cindex.CursorKind.VAR_DECL,
    clang.cindex.CursorKind.PARM_DECL,
    clang.cindex.CursorKind.FIELD_DECL,
    clang.cindex.CursorKind.FUNCTION_DECL,
    clang.cindex.CursorKind.DECL_REF_EXPR,
    clang.cindex.CursorKind.STRUCT_DECL,
    clang.cindex.CursorKind.TYPE_REF,
}

# Extended beyond just primitives
PRIMITIVE_REPLACEMENTS = {
    clang.cindex.CursorKind.INTEGER_LITERAL: '0',
    clang.cindex.CursorKind.FLOATING_LITERAL: '0.0',
    clang.cindex.CursorKind.CHARACTER_LITERAL: "'*'",
    clang.cindex.CursorKind.CXX_BOOL_LITERAL_EXPR: 'false',
    clang.cindex.CursorKind.STRING_LITERAL: '"str"' # not primitive, add more as needed
}

BINARY_OPERATORS = {'+', '-', '*', '/', '%', '<', '>', '<=', '>=', '==', '!=', '&', '|', '^', '&&', '||', '=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^='}
ASSIGNMENTS_OPERATORS = {'=', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^='}
COMPARISON_OPERATORS = {'<', '>', '<=', '>=', '==', '!='}
BITWISE_OPERATORS =  { '&', '|', '^', '<<', '>>'}
ARITHMETIC_OPERATORS = {'+', '-', '*', '/', '%'}
LOGICAL_OPERATORS = {'&&', '||'}
UNARY_OPERATORS = {'++', '--', '+', '-', '!', '~', '&', '*'}

clang.cindex.Config.set_library_file(library_file)

class ExtendedCursorKind(clang.cindex.CursorKind):
    UNKNOWN_TEMPLATE_ARGUMENT_KIND = clang.cindex.CursorKind(10000)

def extend_cursor_kind():
    # Add mappings for known unknown kinds
    known_unknown_kinds = [436, 437]
    for kind_id in known_unknown_kinds:
        if kind_id not in clang.cindex.CursorKind._kinds:
            clang.cindex.CursorKind._kinds[kind_id] = ExtendedCursorKind.UNKNOWN_TEMPLATE_ARGUMENT_KIND

extend_cursor_kind()


def get_node_text(node):
    return  " "

class ASTSerializer:
    def __init__(self, primitive_replacements=PRIMITIVE_REPLACEMENTS, project_root=None):
        self.primitive_replacements = primitive_replacements
        self.node_cache = {}
        self.anon_map = {}
        self.project_root = project_root

    def extract_subrees_for_file(self, filepath):
        self.node_cache.clear()
        self.anon_map.clear()
        ast = parse_to_ast(filepath)
        return self._extract_subtrees(ast)

    def exctract_subtrees_for_node(self, node):
        self.node_cache.clear()
        self.anon_map.clear()
        subtrees, root_subtrees = self._extract_subtrees(node)
        return subtrees, root_subtrees

    def _get_node_cache(self, node):
        node_id = node.hash
        node_data = self.node_cache.get(node_id)
        if node_data is None:
            node_data = {}
            self.node_cache[node_id] = node_data
        return node_data

    def _get_node_children(self, node):
        node_data = self._get_node_cache(node)
        children = node_data.get("children")
        if children is None:
            children = list(node.get_children())
            node_data["children"] = children
        return children

    def _serialize_node(self, node):
        node_data = self._get_node_cache(node)
        node_kind = node_data.get("kind")
        if node_kind is None:
            try:
                node_kind = node.kind
            except ValueError as e:
                kind_id = int(str(e).split()[-1])
                if kind_id not in clang.cindex.CursorKind._kinds:
                    clang.cindex.CursorKind._kinds[kind_id] = ExtendedCursorKind.UNKNOWN_TEMPLATE_ARGUMENT_KIND
                node_kind = clang.cindex.CursorKind.from_id(kind_id)
            node_data["kind"] = node_kind

        # If the node is an UNEXPOSED_EXPR, serialize only its children
        if node_kind == clang.cindex.CursorKind.UNEXPOSED_EXPR:
            children = self._get_node_children(node)
            if len(children) == 1:
                return self._serialize_node(children[0])
            else:
                # exclude unexposed expr
                return f",".join(self._serialize_node(child) for child in children)

        if node_kind == ExtendedCursorKind.UNKNOWN_TEMPLATE_ARGUMENT_KIND:
            node_rep = "UnknownTemplateArgument"
        elif node_kind in IDENTIFIER_KINDS:
            node_spelling = node_data.get("spelling")
            if node_spelling is None:
                node_spelling = node.spelling
                node_data["spelling"] = node_spelling

            anon_name = self.anon_map.get(node_spelling)
            node_type_spelling = node.type.spelling

            if anon_name is None:
                anon_name = f"var_{len(self.anon_map)}"
                self.anon_map[node_spelling] = anon_name

            # ignore types
            # node_rep = f"{anon_name}_{node_type_spelling}"
            node_rep = anon_name

            index = node_type_spelling.find('[')
            if index != -1:
                subscript = node_type_spelling[index + 1:]
                subscript = 0
                # ignore types
                # base_type = node_type_spelling[:index]
                # node_rep = f"{anon_name}_{base_type}[{subscript}]"
                node_rep = f"{anon_name}[{subscript}]"
        else:
            cached_node_rep = node_data.get("node_rep")

            if cached_node_rep is None:
                node_rep = self.primitive_replacements.get(node_kind)
                if node_rep is None:
                    node_rep = str(node_kind)

                if node_kind == clang.cindex.CursorKind.BINARY_OPERATOR:
                    operator = None
                    for token in node.get_tokens():
                        token_spelling = token.spelling
                        if token_spelling in BINARY_OPERATORS:
                            if token_spelling in ASSIGNMENTS_OPERATORS:
                                operator = '='
                            elif token_spelling in BINARY_OPERATORS:
                                operator = '&'
                            elif token_spelling in COMPARISON_OPERATORS:
                                operator = '>'
                            elif token_spelling in ARITHMETIC_OPERATORS:
                                operator = '+'
                            elif token_spelling in LOGICAL_OPERATORS:
                                operator = '&&'
                            else:
                                operator = token_spelling
                            break
                    if operator:
                        node_rep = f"{node_rep}_{operator}"
                elif node_kind == clang.cindex.CursorKind.UNARY_OPERATOR:
                    first_token, last_token = _get_first_and_last_tokens(node)
                    if first_token:
                        first_token_spelling = first_token.spelling
                        last_token_spelling = last_token.spelling
                        if first_token_spelling in UNARY_OPERATORS:
                            operator = first_token_spelling + '_pre'
                        elif last_token_spelling in UNARY_OPERATORS:
                            operator = last_token_spelling + '_post'
                        else:
                            operator = first_token_spelling
                        node_rep = f"{node_rep}_{operator}"

                elif node_kind == clang.cindex.CursorKind.CALL_EXPR:
                    node_rep = f"{node_rep}_func"

                node_data["node_rep"] = node_rep
            else:
                node_rep = cached_node_rep

        if node_kind == clang.cindex.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            children_iterator = node.get_children()
            first_child = next(children_iterator, None)
            second_child = next(children_iterator, None)

            array_base = self._serialize_node(first_child)
            subscript = self._serialize_node(second_child)
            node_rep = f"{array_base}[{subscript}]"
            children_rep = []
        else:
            children = self._get_node_children(node)
            children_rep = [self._serialize_node(child) for child in children]

        return f"{node_rep}({','.join(children_rep)})" if children_rep else node_rep

    def _is_standalone_statement(self, node):
        """
        Check if the node itself is a full statement.
        This assumes we are starting the check from a suspected full statement node.
        """

        # Define node kinds that generally represent standalone statements
        standalone_kinds = {
            clang.cindex.CursorKind.COMPOUND_STMT, clang.cindex.CursorKind.IF_STMT,
            clang.cindex.CursorKind.FOR_STMT, clang.cindex.CursorKind.WHILE_STMT,
            clang.cindex.CursorKind.DO_STMT, clang.cindex.CursorKind.RETURN_STMT,
            clang.cindex.CursorKind.DECL_STMT
        }
        return node.kind in standalone_kinds

    def _is_standalone_parent(self, node):
        """
        Check if the node itself is a full statement.
        This assumes we are starting the check from a suspected full statement node.
        """
        if node.kind == clang.cindex.CursorKind.TRANSLATION_UNIT:
            return False
        # Define node kinds that generally represent standalone statements
        standalone_kinds = {
            clang.cindex.CursorKind.COMPOUND_STMT, clang.cindex.CursorKind.IF_STMT,
            clang.cindex.CursorKind.FOR_STMT, clang.cindex.CursorKind.WHILE_STMT,
            clang.cindex.CursorKind.DO_STMT
        }
        return node.kind in standalone_kinds


    # Gets all subtrees with node parameter as root
    def _extract_subtrees(self, root):

        subtrees = []
        stack = [(root, True)]
        root_subtrees = []

        while stack:
            node, is_top_level = stack.pop()
            if node.location.file is not None:
                file_path = Path(node.location.file.name)
                if file_path.suffix == ".h": # headers are parsed many times at the moment, skip them until we are able to properly handle them
                    continue
                if not is_in_project_directory(file_path, self.project_root):
                    print("not in dir")
                    continue

            self.anon_map.clear()
            subtree = self._serialize_node(node)
            subtrees.append(subtree)

            children = self._get_node_children(node)

            if is_top_level:
                root_subtrees.append(hash_subtree(subtree))

            is_stanalone_parent = self._is_standalone_parent(node)
            for child in children:
                stack.append((child, is_stanalone_parent))
        return subtrees, root_subtrees


def _get_first_and_last_tokens(node):
    tokens_iterator = node.get_tokens()
    first_token = next(tokens_iterator, None)
    last_token = first_token  # Initialize last_token in case there's only one
    if not first_token:
        return first_token, last_token

    for last_token in tokens_iterator:  # This will end with the last token
        pass
    return first_token, last_token

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
    include_paths = CONFIG.get("include_paths", [])

    # -includetypes.h - types.h should be in /usr/include/sys/types on Linux.
    # On Windows, download and add path to config.json
    args = [
        "-std=c99",
        "-fms-extensions",
        "-fms-compatibility",
        "-fdelayed-template-parsing",
        "-DUSE_CURL_MULTI",
        "-includetypes.h",
        "-DDEFINES"
    ] + [f"-I{path}" for path in include_paths]

    tu = index.parse(str(file_path), args=args)
    return tu.cursor

# Human readable column
def tree_to_expression(node):
    node_rep, children = node

    if not children:
        return str(node_rep)

    if node_rep.startswith("CursorKind.BINARY_OPERATOR"):
        if len(children) >= 2:
            lhs = tree_to_expression(children[0])
            rhs = tree_to_expression(children[1])
            return f"{lhs} {node_rep.split('_')[-1]} {rhs}"
    elif node_rep.startswith("CursorKind.UNARY_OPERATOR"):
        if len(children) >= 1:
            parts = node_rep.split('_')
            operator = parts[-2] + parts[-1]
            operand = tree_to_expression(children[0])
            return f"{operator}{operand}" if '_pre' in operator else f"{operand}{operator}"
    elif node_rep.startswith("CursorKind.VAR_DECL"):
        if len(children) >= 1:
            var_name = tree_to_expression(children[0])
            if len(children) > 1:
                initializer = tree_to_expression(children[1])
                return f"{var_name} = {initializer}"
            else:
                return var_name
    elif node_rep.startswith("CursorKind.DECL_STMT"):
        return " ".join(tree_to_expression(child) for child in children)
    elif node_rep.startswith("CursorKind.DECL_REF_EXPR"):
        if len(children) >= 1:
            return str(children[0][0])
    elif node_rep.startswith("CursorKind.INTEGER_LITERAL"):
        return '0'
    elif node_rep.startswith("CursorKind.FLOATING_LITERAL") or node_rep.startswith("CursorKind.DOUBLE_LITERAL"):
        return '0.0'
    elif node_rep.startswith("CursorKind.CHARACTER_LITERAL"):
        return "'*'"
    elif node_rep.startswith("CursorKind.ASSIGNMENT_OPERATOR"):
        if len(children) >= 2:
            lhs = tree_to_expression(children[0])
            rhs = tree_to_expression(children[1])
            return f"{lhs} = {rhs}"
    elif node_rep.startswith("CursorKind.FUNCTION_DECL"):
        if len(children) >= 2:
            return_type = tree_to_expression(children[0])
            function_name = tree_to_expression(children[1])
            params = ", ".join(tree_to_expression(child) for child in children[2:])
            return f"{return_type} {function_name}({params})"
    elif node_rep.startswith("CursorKind.CALL_EXPR"):
        if len(children) >= 1:
            function_name = tree_to_expression(children[0])
            args = ", ".join(tree_to_expression(child) for child in children[1:])
            return f"{function_name}({args})"
    elif node_rep.startswith("CursorKind.IF_STMT"):
        if len(children) >= 2:
            condition = tree_to_expression(children[0])
            then_branch = tree_to_expression(children[1])
            else_branch = tree_to_expression(children[2]) if len(children) > 2 else ''
            return f"if ({condition}) {{ {then_branch} }} else {{ {else_branch} }}"
    elif node_rep.startswith("CursorKind.FOR_STMT"):
        if len(children) >= 4:
            init = tree_to_expression(children[0])
            condition = tree_to_expression(children[1])
            increment = tree_to_expression(children[2])
            body = tree_to_expression(children[3])
            return f"for ({init}; {condition}; {increment}) {{ {body} }}"
    elif node_rep.startswith("CursorKind.WHILE_STMT"):
        if len(children) >= 2:
            condition = tree_to_expression(children[0])
            body = tree_to_expression(children[1])
            return f"while ({condition}) {{ {body} }}"
    elif node_rep.startswith("CursorKind.RETURN_STMT"):
        if len(children) >= 1:
            return f"return {tree_to_expression(children[0])};"
    elif node_rep.startswith("CursorKind.UNEXPOSED_EXPR"):
        if len(children) >= 1:
            return tree_to_expression(children[0])
    else:
        return f"{node_rep}(" + ", ".join(tree_to_expression(child) for child in children) + ")"

    return str(node_rep)


def parse(input_path: str, output_dir: str):
    """
    TODO write docstring
    """
    serializer = ASTSerializer()
    subtrees = serializer.extract_subrees_for_file(input_path)

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



def is_in_project_directory(file_path, project_root):
    """
    Check if the file path is within the project root directory using pathlib.
    """
    abs_file_path = Path(file_path).resolve()
    abs_project_root = Path(project_root).resolve()
    return abs_project_root in abs_file_path.parents or abs_file_path == abs_project_root

# def print_node_details(node, depth=0):
#     # Fetch the source location of the node
#     location = node.location
#     source_location = f"{location.file}:{location.line}:{location.column}" if location.file else "Unknown location"

#     # Prepare the node details
#     node_details = (
#         f"{' ' * depth}Node Kind: {node.kind}, "
#         f"Location: {source_location}\n"
#     )
#     node_details +=  print_node_spellings(node)
#     node_details += "\n"

#     with open("../output/test", 'a') as file:
#         # Print the node details
#         file.write(node_details)


# def print_node_spellings(node, depth=0):
#     # Print the spelling of the node
#     text = ' ' * depth + node.spelling

#     # Recurse for each child of the current node
#     for child in node.get_children():
#         text = text + print_node_spellings(child, depth + 2)
#     return text