import json
import platform
import clang.cindex
import pygit2
import re
from pydriller import Repository
from pathlib import Path

# Path to your local Git repository
repo_path = 'D:/atoms/projects/git'
repo = pygit2.Repository(repo_path)

PROJECT_ROOT = Path(__file__).parent.parent.parent
if platform.system() == "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'

clang.cindex.Config.set_library_file(library_file)

def is_fix_commit(commit):
    return commit.msg.lower().startswith('fix')

def get_file_content_at_commit(commit_hash, file_path):
    commit = repo.get(commit_hash)
    tree = commit.tree
    blob = tree[file_path].data
    return blob.decode('utf-8')

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
    text = re.sub(r'\s+', ' ', text)  # Replace multiple spaces with one
    text = re.sub(r'\s*\[\s*', '[', text)  # Remove spaces around [
    text = re.sub(r'\s*\]\s*', ']', text)  # Remove spaces around ]
    text = re.sub(r'\s*\(\s*', '(', text)  # remove spaces around parentheses
    text = re.sub(r'\s*\)\s*', ')', text)  # remove spaces around parentheses
    return text.strip().lower()

def contains_expression(node_text, expression):
    normalized_node_text = normalize_code(node_text)
    normalized_expression = normalize_code(expression)
    return normalized_expression in normalized_node_text

def find_smallest_containing_node(node, expression, line_number, best_match=None):
    node_text = ' '.join([token.spelling for token in node.get_tokens()])
    if contains_expression(node_text, expression):
        if node.extent.start.line is not None and node.extent.end.line is not None and node.extent.start.line <= line_number <= node.extent.end.line:
            if best_match is None or (len(normalize_code(node_text)) < len(normalize_code(' '.join([token.spelling for token in best_match.get_tokens()])))):
                best_match = node
        for child in node.get_children():
            best_match = find_smallest_containing_node(child, expression, line_number, best_match)
    return best_match

def get_function_or_statement_context(code, source_code, line_number):
    index = clang.cindex.Index.create()
    tu = index.parse('temp.c', args=['-std=c99'], unsaved_files=[('temp.c', code)])

    root_node = tu.cursor
    node = find_smallest_containing_node(root_node, source_code, line_number)
    
    if node is not None:
        parent_node = node
        while parent_node.kind not in {clang.cindex.CursorKind.FUNCTION_DECL,
                                       clang.cindex.CursorKind.CXX_METHOD,
                                       clang.cindex.CursorKind.STRUCT_DECL,
                                       clang.cindex.CursorKind.CLASS_DECL}:
            if parent_node.semantic_parent:
                parent_node = parent_node.semantic_parent
            else:
                break
        
        return get_code_from_extent(code, parent_node.extent)
    return None

def find_inline_comments(source_code):
    index = clang.cindex.Index.create()
    tu = index.parse('temp.c', args=['-std=c99'], unsaved_files=[('temp.c', source_code)])
    inline_comments = []

    for token in tu.get_tokens(extent=tu.cursor.extent):
        if token.kind == clang.cindex.TokenKind.COMMENT:
            line_extent = clang.cindex.SourceRange.from_locations(
                clang.cindex.SourceLocation.from_position(tu, tu.cursor.extent.start.file, token.location.line, 1),
                clang.cindex.SourceLocation.from_position(tu, tu.cursor.extent.start.file, token.location.line, 10000)
            )
            line_tokens = list(tu.get_tokens(extent=line_extent))
            if any(t.kind != clang.cindex.TokenKind.COMMENT for t in line_tokens):
                inline_comments.append((token.location.line, token.spelling))

    return inline_comments

def extract_comments(commit):
    comments_data = []
    for modified_file in commit.modified_files:
        if modified_file.new_path.endswith('.c'):
            full_code = get_file_content_at_commit(commit.hash, modified_file.new_path)
            comments = find_inline_comments(full_code)
            comments_line_data = {}
            for line_number, comment in comments:
                context = get_function_or_statement_context(full_code, comment, line_number)
                comments_line_data[line_number] = {
                    "context": context,
                    "comment": comment
                }

            comments_data.append({
                "file": modified_file.new_path,
                "comments": comments_line_data
            })
    return comments_data

comments_commits_data = {}

# Mining the local repository
count = 0
for commit in Repository(repo_path).traverse_commits():
    if count == 20:
        break
    if is_fix_commit(commit):
        count += 1
        comments_data = extract_comments(commit)
        if comments_data:
            comments_commits_data[commit.hash] = comments_data

Path("../../output/comments.json").write_text(json.dumps(comments_commits_data, indent=4))