import click
from parser.parse import parse  # Replace with your actual function


@click.group()
def ast():
    """Commands related to AST analysis."""
    pass

@ast.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.argument('output_dir', type=click.Path(exists=True))
def analyze(input_file, output_dir):
    """Analyze the given INPUT_FILE."""
    result = parse(input_file, output_dir)
    click.echo(result)

ast()
