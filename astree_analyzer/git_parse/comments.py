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
if platform.system() ==  "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'

clang.cindex.Config.set_library_file(library_file)

def find_inline_comments(source_file):
    index = clang.cindex.Index.create()
    tu = index.parse(source_file)
    inline_comments = []

    for token in tu.get_tokens(extent=tu.cursor.extent):
        if token.kind == clang.cindex.TokenKind.COMMENT:
            # Check if there's a non-comment code token on the same line
            line_extent = clang.cindex.SourceRange.from_locations(
                clang.cindex.SourceLocation.from_position(tu, tu.cursor.extent.start.file, token.location.line, 1),
                clang.cindex.SourceLocation.from_position(tu, tu.cursor.extent.start.file, token.location.line, 10000)
            )
            line_tokens = list(tu.get_tokens(extent=line_extent))
            if any(t.kind != clang.cindex.TokenKind.COMMENT for t in line_tokens):
                inline_comments.append((token.location.line, token.spelling))

    return inline_comments

def main():
    source_file = '../../input/add.c'
    source_lines = Path(source_file).read_text().splitlines()
    comments = find_inline_comments(source_file)
    lines = [source_lines[line-1].strip() for line, _ in comments]
    print(lines)

    Path("../../output/comments.json").write_text("\n".join(lines))

if __name__ == "__main__":
    main()