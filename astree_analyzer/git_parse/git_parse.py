import json
import platform
import tempfile
from git_parse.exceptions import TextInCommentError
import clang.cindex
import pygit2
import re
from pydriller import Repository
from pathlib import Path
from clang.cindex import CursorKind

# Path to your local Git repository


PROJECT_ROOT = Path(__file__).parent.parent.parent
if platform.system() ==  "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'

clang.cindex.Config.set_library_file(library_file)

def is_fix_commit(commit):
    # TODO - this is far to simple, we need to analyze the issues and PRs
    return commit.msg.lower().startswith('fix')

def get_file_content_at_commit(repo, commit_hash, file_path):
    commit = repo.get(commit_hash)
    tree = commit.tree
    blob = tree[file_path].data
    return blob.decode('utf-8')

def get_previous_commit(repo, commit):
    walker = repo.walk(commit, pygit2.GIT_SORT_TOPOLOGICAL | pygit2.GIT_SORT_TIME)
    next(walker)
    parent_commit = next(walker)
    return parent_commit.id

def get_code_from_extent(code, extent):
    lines = code.splitlines()
    start = extent.start
    end = extent.end

    if start.line == end.line:
        return lines[start.line - 1][start.column - 1:end.column - 1]

    code_lines = []
    code_lines.append(lines[start.line - 1][start.column - 1:])
    for line in range(start.line, end.line - 1):
        code_lines.append(lines[line])
    try:
        code_lines.append(lines[end.line - 1][:end.column - 1])
    except:
        pass
    return code_lines

def normalize_code(text):
    """
    Normalize code by removing extra spaces around punctuation and making it lowercase.
    This function also standardizes common variations in array declarations.
    """
    # text = text.replace('\t', ' ').replace('\n', ' ')
    # text = re.sub(r'\s+', ' ', text)  # Replace multiple spaces with one
    # text = re.sub(r'\s*\[\s*', '[', text)  # Remove spaces around [
    # text = re.sub(r'\s*\]\s*', ']', text)  # Remove spaces around ]
    # text = re.sub(r'\s*\(\s*', '(', text)  # remove spaces around parentheses
    # text = re.sub(r'\s*\)\s*', ')', text)  # remove spaces around parentheses
    # text = re.sub(r'\s*\)\s*', '*', text)  # remove spaces around *
    return text.replace(" ", "")

def is_text_in_comment(node, search_text, line_number=0):
    search_text = normalize_code(search_text)
    for token in node.get_tokens():
        if token.kind == clang.cindex.TokenKind.COMMENT:
            # Normalize spaces and check if the search text is in the comment
            normalized_comment = normalize_code(token.spelling)
            if search_text in normalized_comment:
                print(f"{search_text} is a comment")
                return True
    return False

def contains_expression(node, expression, line_number):
    """
    Check if the normalized node text contains the normalized expression.
    """
    if line_number < node.extent.start.line or line_number > node.extent.end.line:
        return False
    node_text = ' '.join([token.spelling for token in node.get_tokens()])
    if expression.endswith(";"):
        expression = expression[:-1]
    normalized_node_text = normalize_code(node_text)
    normalized_expression = normalize_code(expression)
    return normalized_expression in normalized_node_text

def find_smallest_containing_node(node, expression, line_number, ancestors, best_match=None):
    """
    Recursively find the smallest node that contains the given expression.
    """
    if contains_expression(node, expression, line_number):
        ancestors.append(node)
        best_match = node
        for child in node.get_children():
            best_match = find_smallest_containing_node(child, expression, line_number, ancestors, best_match)
    return best_match


def extract_headers(code):
    header_pattern = re.compile(r'#include\s+"([^"]+)"')
    headers = header_pattern.findall(code)
    return headers


def get_function_or_statement_context(file_path, code, source_code, line_number):
    index = clang.cindex.Index.create()
    include_paths = [
        'C:/Program Files (x86)/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.40.33807/include',
        'C:/Program Files (x86)/Windows Kits/10/Include/10.0.22000.0/ucrt',
        'C:/Program Files (x86)/Windows Kits/10/Include/10.0.22000.0/shared'
    ]


    args = ['-std=c99'] + [f'-I{path}' for path in include_paths]

    tu = index.parse(str(file_path), args=args)


    root_node = tu.cursor
    ancestors = []
    try:
        if is_text_in_comment(root_node, source_code):
            raise TextInCommentError("modified text is a comment")
        node = find_smallest_containing_node(root_node, source_code, line_number, ancestors)
    except UnicodeDecodeError:
        print(f"Could not parse {file_path}. Skipping")
        return None

    # if node is not None:
    #     ancestors.reverse()
    #     # Ensure we capture broader context by moving up the AST if needed
    #     for parent_node in ancestors:
    #         if parent_node.kind in (clang.cindex.CursorKind.FUNCTION_DECL,
    #                                    clang.cindex.CursorKind.CXX_METHOD,
    #                                    clang.cindex.CursorKind.STRUCT_DECL,
    #                                    clang.cindex.CursorKind.CLASS_DECL):
    #             node = parent_node
    #             break
    if node is not None:
        return get_code_from_extent(code, node.extent)
    return None

def extract_removed_code(repo, commit):
    removed_code = []
    previous_commit = get_previous_commit(repo, commit.hash)
    with tempfile.TemporaryDirectory() as temp_dir:
        for modified_file in commit.modified_files:
            if modified_file.new_path is None:
                continue
            file_path = Path(modified_file.new_path)
            if file_path.suffix not in (".h", ".c"):
                continue
            if modified_file.diff_parsed:
                try:
                    full_code = get_file_content_at_commit(repo, previous_commit, modified_file.new_path)
                    file_path = Path(temp_dir, file_path)
                    file_path.write_text(full_code)
                except Exception:
                    print(f"Could not load {modified_file.new_path} at {previous_commit}. Skipping")
                    continue
                headers = extract_headers(full_code)
                try:
                    for header in headers:
                        if not Path(temp_dir, header).is_file():
                            header_content = get_file_content_at_commit(repo, previous_commit, header)
                            Path(temp_dir, header).write_text(header_content)
                except Exception:
                    print(f"Could not load {header} at {previous_commit}. Skipping")
                    continue


                removed = modified_file.diff_parsed['deleted']
                removed_line_data = {}
                for line_number, code in removed:
                    code = code.strip()
                    if code == "":
                        continue
                    try:
                        context = get_function_or_statement_context(file_path, full_code, code, line_number)
                    except TextInCommentError:
                        continue
                    removed_line_data[line_number] = {
                        "context": context,
                        "code": code
                    }

                removed_code.append({
                    "file": modified_file.new_path,
                    "removed": removed_line_data,
                    })
    return removed_code


def dump_bugfix_data(project_dir, output_file, num_of_commits=None):

    repo = pygit2.Repository(project_dir)
    fix_commits_data = {}

    # Mining the local repository
    count = 0
    for commit in Repository(project_dir).traverse_commits():
        if num_of_commits is not None and count == num_of_commits:
            break
        if is_fix_commit(commit):
            count += 1
            removed_code = extract_removed_code(repo, commit)
            if removed_code:
                fix_commits_data[commit.hash] = removed_code
    Path(output_file).write_text(json.dumps(fix_commits_data, indent=4))