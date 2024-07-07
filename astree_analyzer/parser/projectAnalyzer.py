import pstats
import datetime
from typing import Optional
from parser.parse import *
import os
import time
import pickle
import cProfile
from pathlib import Path



profiler = cProfile.Profile()

def _convert_time(timestamp):
    date_time = datetime.datetime.fromtimestamp(timestamp)  # Convert to a datetime object
    return  date_time.strftime('%Y-%m-%d %H:%M:%S')


def process_directory(intput_dir, output, include_human_readable=False):
    # Start timing
    start_time = time.time()
    print("Start:", _convert_time(start_time))

    all_subtrees = []

    for filepath in Path(intput_dir).rglob('*.c'):
        subtrees = process_file(filepath)
        all_subtrees.extend(subtrees)

    _write_subtrees(output, subtrees, include_human_readable=include_human_readable)

    end_time = time.time()
    print("End:", _convert_time(end_time))

    # Print the elapsed time
    elapsed_time = end_time - start_time
    print(f"Time elapsed: {elapsed_time:.2f} seconds")


def process_file(filepath: Path, output: Optional[Path]=None, include_human_readable: Optional[bool]=False, profile: Optional[bool]=False):
    serializer = ASTSerializer()
    filename = filepath.name

    try:
        if profile:
            profiler.enable()
        print(f"Parsing {filename}")
        file_start_time = time.time()
        subtrees = serializer.extract_subrees_for_file(filepath)
        if profile:
            profiler.disable()
            # Optionally, save the stats for later analysis:
            stats = pstats.Stats(profiler).sort_stats("cumtime")
            if output:
                output_dir = output.parent
                stats.dump_stats(output_dir / "profile_results.prof")
            else:
                stats.print_stats()

        file_end_time = time.time()
        print(file_end_time - file_start_time)
        if output:
            _write_subtrees(output, subtrees, include_human_readable=include_human_readable)

        print("Completed:", filename)
        return subtrees

    except Exception as e:
        print(f"Error processing {filename}: {e}")
        raise


def _write_subtrees(output: Path, subtrees: list, include_human_readable: Optional[bool]=False):
    try:

        print("Writing to CSV")
        if not output.parent.is_dir():
            output.mkdir(parents=True)

        # Create a mapping between serialized and deserialized subtrees
        subtree_map = {}
        if include_human_readable:
            subtree_map = {subtree: print_tree(deserialize_subtree(subtree)) for subtree in subtrees}

        subtree_counter = count_subtrees(subtrees)

        # Write to CSV
        output.write_text("")  # Clears the file

        if include_human_readable:
            fieldnames = ['Hash', 'Count', 'Human Readable Expression', 'Serialized Subtree', 'Deserialized Tree']
        else:
            fieldnames = ['Hash', 'Count', 'Serialized Subtree']


        with open(output, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for subtree, count in subtree_counter.items():
                hash_val = hash_subtree(subtree)

                if include_human_readable:
                    deserialized_tree = subtree_map[subtree]
                    human_readable_expression = tree_to_expression(deserialize_subtree(subtree))
                    writer.writerow({
                        'Hash': hash_val,
                        'Count': count,
                        'Human Readable Expression': human_readable_expression,
                        'Serialized Subtree': subtree,
                        'Deserialized Tree': deserialized_tree
                    })
                else:
                    writer.writerow({
                        'Hash': hash_val,
                        'Count': count,
                        'Serialized Subtree': subtree,
                    })

        print(f"Reuslts saved to {output.absolute().resolve()}")
    except Exception as e:
        print(f"An error occurred: {e}")
        temp_file = 'subtrees_temp.pkl'
        with open(temp_file, 'wb') as f:
            pickle.dump(subtrees, f)



def __main__():
    directory = "./git"
    output = "../../output/subtreesGit.csv"
    # Load any existing subtrees if available

    temp_file = 'subtrees_temp.pkl'
    all_subtrees = []
    if os.path.exists(temp_file):
        with open(temp_file, 'rb') as f:
                all_subtrees = pickle.load(f)

    if all_subtrees:
        _write_subtrees(output, all_subtrees, True)
    else:
        process_directory(Path(directory), output,)
