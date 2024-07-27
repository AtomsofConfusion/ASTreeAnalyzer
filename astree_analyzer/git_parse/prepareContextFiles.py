import json
from pathlib import Path
import shutil

# Function to write the context to a file
def write_context_to_file(
    directory, commit_hash, file_name, line_number, context, code, suffix
):
    context_str = "\n".join(context)
    file_content = f"/* Commit: {commit_hash}\n * File: {file_name}\n * Line: {line_number}\n * Code: {code}\n */\n\n{context_str}"

    output_file_path = (
        Path(directory) / f"{commit_hash}_{file_name}_{line_number}_{suffix}.c"
    )
    with open(output_file_path, "w") as output_file:
        output_file.write(file_content)


# Create a fresh context_files directory
context_files_dir = Path("context_files")
if context_files_dir.exists():
    shutil.rmtree(context_files_dir)
context_files_dir.mkdir(parents=True, exist_ok=True)

# Create output directories for comments and commits
output_comments_dir = context_files_dir / "comments"
output_comments_dir.mkdir(parents=True, exist_ok=True)

output_commits_dir = context_files_dir / "commits"
output_commits_dir.mkdir(parents=True, exist_ok=True)

# Load the JSON data
with open("../../output/comments.json", "r") as file:
    comments_data = json.load(file)

with open("../../output/commits.json", "r") as file:
    commits_data = json.load(file)

# Process comments data
for commit_hash, files in comments_data.items():
    for file_info in files:
        file_name = file_info["file"]
        comments = file_info["comments"]
        for line_number, comment_info in comments.items():
            context = comment_info["context"]
            code = comment_info["comment"]
            if context:
                write_context_to_file(
                    output_comments_dir,
                    commit_hash,
                    file_name,
                    line_number,
                    context,
                    code,
                    "comment",
                )

# Process commits data
for commit_hash, files in commits_data.items():
    for file_info in files:
        file_name = file_info["file"]
        removed_lines = file_info["removed"]
        for line_number, line_info in removed_lines.items():
            context = line_info["context"]
            code = line_info["code"]
            if context:
                write_context_to_file(
                    output_commits_dir,
                    commit_hash,
                    file_name,
                    line_number,
                    context,
                    code,
                    "commit",
                )
