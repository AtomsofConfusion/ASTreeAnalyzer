import sys
import os
from pathlib import Path
import click
import multiprocessing

# Add the parent directory to the sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from parser.projectAnalyzer import process_file, process_directory


@click.group()
def ast():
    """Commands related to AST analysis."""
    pass

@ast.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option("--human-readable", is_flag=True, default=False, help="Include human-readable columns in the output.")
@click.option("--profile", is_flag=True, default=False, help="Profile using cProfile")
def parse_file(input_file, output_file, human_readable, profile):
    """Analyze the given INPUT_FILE."""
    process_file(
        Path(input_file),
        Path(output_file),
        include_human_readable=human_readable,
        profile=profile
    )

@ast.command()
@click.argument("input_dir", type=click.Path(exists=True))
@click.argument("output_file", type=click.Path())
@click.option("--human-readable", is_flag=True, default=False, help="Include human-readable columns in the output.")
def parse_dir(input_dir, output_file, human_readable):
    """Analyze the given INPUT_DIR."""
    process_directory(
        Path(input_dir),
        Path(output_file),
        include_human_readable=human_readable,
    )

if __name__ == '__main__':
    # Set the multiprocessing start method to 'fork'
    multiprocessing.set_start_method('fork')
    ast()
