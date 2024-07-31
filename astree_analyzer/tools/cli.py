from pathlib import Path
import click
import multiprocessing

# import sys
# import os
# Add the parent directory to the sys.path
# sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analysis.statistics import calculate_frequencies
from extraction.extract import dump_bugfix_data, dump_comments_data, parse_test_file
from parser.projectAnalyzer import process_file, process_directory


@click.group()
def ast():
    """Commands related to AST analysis."""
    pass


@ast.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option(
    "--human-readable",
    is_flag=True,
    default=False,
    help="Include human-readable columns in the output.",
)
@click.option("--profile", is_flag=True, default=False, help="Profile using cProfile")
def parse_file(input_file, output_file, human_readable, profile):
    """Analyze the given INPUT_FILE."""
    process_file(
        Path(input_file),
        Path(output_file),
        include_human_readable=human_readable,
        profile=profile,
    )


@ast.command()
@click.argument("input_dir", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option(
    "--human-readable",
    is_flag=True,
    default=False,
    help="Include human-readable columns in the output.",
)
def parse_dir(input_dir, output_file, human_readable):
    """Analyze the given INPUT_DIR."""
    process_directory(
        Path(input_dir),
        Path(output_file),
        include_human_readable=human_readable,
    )


@ast.command()
@click.argument("test_file", type=click.Path(exists=True))
@click.argument("test_sample", type=click.Path(exists=True))
@click.argument("line_number", type=int)
def test_parse(test_file, test_sample, line_number):
    """Analyze the given INPUT_DIR."""
    code = Path(test_sample).read_text()
    parse_test_file(
        test_file,
        code,
        line_number,
    )


@ast.command()
@click.argument("project_dir", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option("--num-of-commits", type=int, default=None)
def dump_bugfix_commits(project_dir, output_file, num_of_commits):
    """Analyze the given INPUT_DIR."""
    dump_bugfix_data(
        project_dir,
        output_file,
        num_of_commits,
    )


@ast.command()
@click.argument("project_dir", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option("--commit", type=str, default=None)
@click.option("--num-of-files", type=int, default=None)
def dump_comments(project_dir, output_file, commit, num_of_files):
    """Analyze the given INPUT_DIR."""
    dump_comments_data(
        project_dir,
        output_file,
        commit,
        num_of_files,
    )


@ast.command()
@click.argument("all_subtrees_input_path", type=click.Path(exists=True))
@click.argument("bugfixes_input_path", type=click.Path(exists=True))
@click.argument("comments_input_path", type=click.Path(exists=True))
def analyze(all_subtrees_input_path, bugfixes_input_path, comments_input_path):
    calculate_frequencies(
        Path(all_subtrees_input_path),
        Path(bugfixes_input_path),
        Path(comments_input_path),
    )


if __name__ == "__main__":
    # Set the multiprocessing start method to 'fork'
    multiprocessing.set_start_method("fork")
    ast()
