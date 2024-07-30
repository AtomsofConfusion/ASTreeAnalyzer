import json
import platform
import tempfile
from git_parse.exceptions import TextInCommentError
import clang.cindex
import pygit2
import re
from pydriller import Repository
from pathlib import Path

# Path to your local Git repository


PROJECT_ROOT = Path(__file__).parent.parent.parent
CONFIG = json.loads((PROJECT_ROOT / "config.json").read_text())

if platform.system() == "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = "/opt/homebrew/opt/llvm/lib/libclang.dylib"

clang.cindex.Config.set_library_file(library_file)

INCLUDE_PATTERN = r'^\s*#include\s+(<[^>]+>|"[^"]+")\s*$'


def is_fix_commit(commit):
    # TODO - this is far to simple, we need to analyze the issues and PRs
    return commit.msg.lower().startswith("fix")


def get_file_content_at_commit(repo, commit_hash, file_path):
    commit = repo.get(commit_hash)
    tree = commit.tree
    blob = tree[file_path].data
    content = blob.decode("utf-8")
    content = remove_conditional_definitions(content)
    return content


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
        return lines[start.line - 1][start.column - 1 : end.column - 1]

    code_lines = []
    code_lines.append(lines[start.line - 1][start.column - 1 :])
    for line in range(start.line, end.line - 1):
        code_lines.append(lines[line])
    try:
        code_lines.append(lines[end.line - 1][: end.column - 1])
    except:
        pass
    return code_lines


def _init_translation_unit(file_path):
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
    ] + [f"-I{path}" for path in include_paths]

    tu = index.parse(str(file_path), args=args)
    return tu


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
                return True
    return False


def contains_expression(node, expression, line_number):
    """
    Check if the normalized node text contains the normalized expression.
    """
    if line_number < node.extent.start.line or line_number > node.extent.end.line:
        return False
    node_text = " ".join([token.spelling for token in node.get_tokens()])
    if expression.endswith(";"):
        expression = expression[:-1]
    normalized_node_text = normalize_code(node_text)
    normalized_expression = normalize_code(expression)
    return normalized_expression in normalized_node_text


def find_smallest_containing_node(
    node, expression, line_number, ancestors, best_match=None
):
    """
    Recursively find the smallest node that contains the given expression.
    """
    if contains_expression(node, expression, line_number):
        ancestors.append(node)
        best_match = node
        # print("--------------------")
        # node_text = " ".join([token.spelling for token in node.get_tokens()])
        # print(node_text)
        # print("**************************88")
        for child in node.get_children():
            # node_text = " ".join([token.spelling for token in child.get_tokens()])
            # print(node_text)
            # print("***************8")
            best_match = find_smallest_containing_node(
                child, expression, line_number, ancestors, best_match
            )
    return best_match


def _extract_headers(code, repo, commit, processed=None):
    """
    Recursively extract all unique header file names from the C code.

    :param code: C code from which to extract header files.
    :param base_path: The base directory where header files are searched (as a Path object).
    :param processed: A set to keep track of processed header files to avoid cyclic includes.
    :return: A set of all header files included in the code, directly or indirectly.
    """
    if processed is None:
        processed = set()

    header_pattern = re.compile(r'#include\s+"([^"]+)"')
    headers = set(header_pattern.findall(code))
    all_headers = set(headers)

    for header in headers:
        if header not in processed:
            processed.add(header)
            try:
                file_content = get_file_content_at_commit(repo, commit, header)
            except Exception:
                print(f"Cannot load {header} at {commit}")
                continue
            included_headers = _extract_headers(file_content, repo, commit, processed)
            all_headers.update(included_headers)
    return all_headers


def _save_file_to_temp(repo, output_dir, commit, file_path):
    full_code = get_file_content_at_commit(repo, commit, file_path)
    file_path = Path(output_dir, file_path)
    file_path.parent.mkdir(exist_ok=True, parents=True)
    file_path.write_text(full_code)
    return full_code


def _save_headers_to_temp(full_code, output_dir, repo, commit, loaded_headers):
    headers = _extract_headers(full_code, repo, commit, loaded_headers)
    try:
        for header in headers:
            path = Path(output_dir, header)
            if not path.is_file():
                path.parent.mkdir(exist_ok=True, parents=True)
                header_content = get_file_content_at_commit(repo, commit, header)
                Path(output_dir, header).write_text(header_content)
    except Exception as e:
        print(f"Could not load {header} at {commit} due to {e}. Skipping")


def _run_diagnostics(tu, file_name):
    if len(tu.diagnostics):
        print(f"Error(s) occurred while parsing {file_name}")
        for diag in tu.diagnostics:
            print(diag)
        # if "undeclared identifier" in diag.spelling:
        #     print(f"Undefined Identifier in {file_name}: {diag.spelling}")


def remove_conditional_definitions(content):
    return re.sub(
        r"^#ifdef.*?$\n|^#ifndef.*?$\n|^#endif.*?$\n", "\n", content, flags=re.M
    )


def get_function_or_statement_context(file_path, code, source_code, line_number):
    tu = _init_translation_unit(file_path)
    # _run_diagnostics(tu, file_path)

    root_node = tu.cursor
    ancestors = []
    try:
        if is_text_in_comment(root_node, source_code):
            raise TextInCommentError("modified text is a comment")
        node = find_smallest_containing_node(
            root_node, source_code, line_number, ancestors
        )
    except UnicodeDecodeError as e:
        print(f"Could not parse {file_path} due to {e}. Skipping")
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
    if node is not None and node != root_node:
        return get_code_from_extent(code, node.extent)
    return None


def extract_removed_code(repo, commit):
    removed_code = []
    previous_commit = get_previous_commit(repo, commit.hash)
    loaded_headers = set()
    with tempfile.TemporaryDirectory() as temp_dir:
        for modified_file in commit.modified_files:
            if modified_file.new_path is None:
                continue

            file_path = Path(modified_file.new_path)
            if file_path.suffix not in (".h", ".c"):
                continue
            if modified_file.diff_parsed:
                try:
                    full_code = _save_file_to_temp(
                        repo,
                        temp_dir,
                        previous_commit,
                        Path(modified_file.new_path).as_posix(),
                    )
                    file_path = Path(temp_dir, file_path)
                except Exception as e:
                    print(
                        f"Could not load {modified_file.new_path} at {previous_commit} due to {e}. Skipping"
                    )
                    continue

                _save_headers_to_temp(
                    commit=previous_commit,
                    output_dir=temp_dir,
                    repo=repo,
                    full_code=full_code,
                    loaded_headers=loaded_headers,
                )
                removed_line_data = {}
                removed = modified_file.diff_parsed["deleted"]
                for line_number, code in removed:
                    code = code.strip()
                    if code == "":
                        continue
                    match = re.match(INCLUDE_PATTERN, code)
                    if match:
                        continue
                    try:
                        context = get_function_or_statement_context(
                            file_path, full_code, code, line_number
                        )
                    except TextInCommentError:
                        continue
                    removed_line_data[line_number] = {"context": context, "code": code}

                removed_code.append(
                    {
                        "file": modified_file.new_path,
                        "removed": removed_line_data,
                    }
                )
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


def find_code_next_to_comments(file_path):
    tu = _init_translation_unit(file_path)
    relevant_code_snippets = []
    root = tu.cursor

    def recursive_node_search(node, file_path):
        # Check each child node
        parent_tokens = list(node.get_tokens())
        comment_lines = []
        # Identify lines that contain comments
        for token in parent_tokens:
            if token.kind == clang.cindex.TokenKind.COMMENT:
                comment_lines.append(token.location.line)

        # Check each child node
        for child in node.get_children():
            if child.location and child.location.file:
                if (
                    Path(child.location.file.name).as_posix()
                    != Path(file_path).as_posix()
                ):
                    continue

            if child.kind not in [
                clang.cindex.CursorKind.TYPEDEF_DECL,
                clang.cindex.CursorKind.FUNCTION_DECL,
                clang.cindex.CursorKind.CXX_METHOD,
                clang.cindex.CursorKind.FUNCTION_TEMPLATE,
            ]:
                child_start_line = child.extent.start.line

                # Check if the line before the child's start contains a comment
                if (
                    child_start_line - 1 in comment_lines
                    or child_start_line in comment_lines
                ):
                    # If found, capture the entire content of the child node
                    node_text = " ".join(
                        [token.spelling for token in child.get_tokens()]
                    )
                    relevant_code_snippets.append((child_start_line, node_text))

            # Recursively search within the child
            recursive_node_search(child, file_path)

    recursive_node_search(root, file_path)
    return relevant_code_snippets


def dump_comments_data(project_dir, output_file, commit):
    comments_data = []
    repo = pygit2.Repository(project_dir)
    if commit is None:
        head_commit = repo.head.peel(pygit2.GIT_OBJECT_COMMIT)
        commit = head_commit.id

    project_dir = Path(project_dir)
    loaded_headers = set()
    comments_line_data = {}
    with tempfile.TemporaryDirectory() as temp_dir:
        for file_path in project_dir.rglob("*.[ch]"):
            relative_path = file_path.relative_to(project_dir).as_posix()
            try:
                full_code = _save_file_to_temp(
                    repo, temp_dir, commit, str(relative_path)
                )
                file_path = Path(temp_dir, relative_path)
            except Exception as e:
                print(
                    f"Could not load {relative_path} at {commit} due to {e}. Skipping"
                )
            _save_headers_to_temp(
                commit=commit,
                output_dir=temp_dir,
                repo=repo,
                full_code=full_code,
                loaded_headers=loaded_headers,
            )
            comments = find_code_next_to_comments(file_path)
            for comment_data in comments:
                comments_line_data.setdefault(relative_path, {})[
                    comment_data[0]
                ] = comment_data[1]

            comments_data.append({"file": file_path, "comments": comments_line_data})
        Path(output_file).write_text(json.dumps(comments_line_data, indent=4))


def parse_test_file(test_file, code, line_number):
    full_code = Path(test_file).read_text()
    context = get_function_or_statement_context(
        Path(test_file), full_code, code, line_number
    )
    print(context)
