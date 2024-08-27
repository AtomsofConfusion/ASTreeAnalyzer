import csv
import json
from parser.parse import ASTSerializer, count_subtrees, deserialize_subtree, get_node_text, hash_subtree, print_tree, tree_to_expression
from pathlib import Path
import pandas as pd
from multiprocessing import Process, Queue
import pstats
import datetime
import tempfile
from typing import Optional
import os
import time
import pickle
import cProfile
from tqdm import tqdm

profiler = cProfile.Profile()


def _convert_time(timestamp):
    date_time = datetime.datetime.fromtimestamp(
        timestamp
    )  # Convert to a datetime object
    return date_time.strftime("%Y-%m-%d %H:%M:%S")


def process_directory(
    input_dir, output, include_human_readable=False, output_format="json"
):
    # Start timing
    start_time = time.time()
    print("Start:", _convert_time(start_time))

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file = Path(temp_dir) / "temp_results.csv"
        print(f"Writing temp to {temp_file}")

        queue = Queue()
        # Start the subtree generator process
        filepaths = list(input_dir.rglob("*.c"))
        producer = Process(target=_generate_subtrees, args=(filepaths, input_dir,  queue))
        # Start the writer process
        consumer = Process(target=_write_to_temp, args=(temp_file, queue))

        producer.start()
        consumer.start()

        producer.join()
        queue.put(None)  # Signal the consumer to stop after the producer is done
        consumer.join()

        _write_to_final_output(temp_file, output, output_format)

    end_time = time.time()
    print("End:", _convert_time(end_time))

    # Print the elapsed time
    elapsed_time = end_time - start_time
    print(f"Time elapsed: {elapsed_time:.2f} seconds")


def process_file(
    filepath: Path,
    output: Optional[Path] = None,
    include_human_readable: Optional[bool] = False,
    profile: Optional[bool] = False,
    output_format="csv",
):
    serializer = ASTSerializer(project_root=filepath.parent)
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
            _write_subtrees(
                output, subtrees, include_human_readable=include_human_readable
            )

        print("Completed:", filename)
        return subtrees

    except Exception as e:
        print(f"Error processing {filename}: {e}")
        raise


def _generate_subtrees(filepaths, input_dir, queue):
    for filepath in tqdm(filepaths, desc="Processing files"):
        filepath = Path(filepath)
        serializer = ASTSerializer(project_root=input_dir)
        filename = filepath.name
        try:
            subtrees, root_subtrees = serializer.extract_subrees_for_file(filepath)
            queue.put((subtrees, root_subtrees))
        except Exception as e:
            print(f"Error processing {filename}: {e}")
            raise
    queue.put(None)


def _write_to_temp(temp_file: Path, queue):
    while True:
        subtrees_data = queue.get()
        if subtrees_data is None:
            break
        subtrees, root_subtrees = subtrees_data
        root_subtrees_count = {}
        rows = []
        for subtree in root_subtrees:
            root_subtrees_count[subtree] = root_subtrees_count.get(subtree, 0) + 1
        subtree_counter = count_subtrees(subtrees)
        for subtree, count in subtree_counter.items():
            hash_val = hash_subtree(subtree)
            rows.append([hash_val, count, subtree, root_subtrees_count.get(hash_val, 0)])

        with temp_file.open("a", newline="") as file:
            writer = csv.writer(file)
            writer.writerows(rows)


def _write_to_final_output(temp_file, output, output_format):
    subtrees_with_count = {}
    csv.field_size_limit(2**31 - 1)
    with open(temp_file, "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            hash_val = row[0]
            count = int(row[1])
            root_count = int(row[3])
            if not hash_val in subtrees_with_count:
                subtree = row[2]
                subtrees_with_count[hash_val] = {
                    "Hash": hash_val,
                    "Count": count,
                    "Serialized Subtree": subtree,
                    "Root Count":root_count
                }
            else:
                subtrees_with_count[hash_val]["Count"] = (
                    subtrees_with_count[hash_val]["Count"] + count
                )
                subtrees_with_count[hash_val]["Root Count"] = (
                    subtrees_with_count[hash_val]["Root Count"] + root_count
                )


    if output_format == "csv":
        with open(output, "w", newline="") as csvfile:
            fieldnames = ["Hash", "Count", "Serialized Subtree", "Root Count"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for subtree_with_count in subtrees_with_count.values():
                writer.writerow(subtree_with_count)
    elif output_format == "json":
        data = list(subtrees_with_count.values())
        Path(output).write_text(json.dumps(data, indent=True))

    else:
        raise Exception("Invalid output format")



    print(f"Results saved to {output.absolute().resolve()}")

def write_subtrees_to_file(output, subtrees, root_subtrees, output_format):

    subtree_counter = count_subtrees(subtrees)

    if output_format == "csv":
        with open(output, "w", newline="") as csvfile:
            fieldnames = ["Hash", "Count", "Serialized Subtree", "Root Count"]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for subtree, count in subtree_counter.items():
                hash_val = hash_subtree(subtree)
                writer.writerow(
                    {
                        "Hash": hash_val,
                        "Count": count,
                        "Serialized Subtree": subtree,
                        "Root Count": root_subtrees.get(hash_val, 0)
                    }
                )
    elif output_format == "json":
        data = []
        for subtree, count in subtree_counter.items():
            hash_val = hash_subtree(subtree)
            data.append(
                {
                    "Hash":  hash_val,
                    "Count": count,
                    "Serialized Subtree": subtree,
                    "Root Count": root_subtrees.get(hash_val, 0)
                }
            )
        Path(output).write_text(json.dumps(data, indent=True))

    else:
        raise Exception("Invalid output format")



def _write_subtrees(
    output: Path, subtrees: list, include_human_readable: Optional[bool] = False
):
    try:
        if not output.parent.is_dir():
            output.mkdir(parents=True)

        # Create a mapping between serialized and deserialized subtrees
        subtree_map = {}
        if include_human_readable:
            subtree_map = {
                subtree: print_tree(deserialize_subtree(subtree))
                for subtree in subtrees
            }

        subtree_counter = count_subtrees(subtrees)

        # Write to CSV
        output.write_text("")  # Clears the file

        if include_human_readable:
            fieldnames = [
                "Hash",
                "Count",
                "Human Readable Expression",
                "Serialized Subtree",
                "Deserialized Tree",
            ]
        else:
            fieldnames = ["Hash", "Count", "Serialized Subtree"]

        with open(output, "w", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for subtree, count in subtree_counter.items():
                hash_val = hash_subtree(subtree)

                if include_human_readable:
                    deserialized_tree = subtree_map[subtree]
                    human_readable_expression = tree_to_expression(
                        deserialize_subtree(subtree)
                    )
                    writer.writerow(
                        {
                            "Hash": hash_val,
                            "Count": count,
                            "Human Readable Expression": human_readable_expression,
                            "Serialized Subtree": subtree,
                            "Deserialized Tree": deserialized_tree,
                        }
                    )
                else:
                    writer.writerow(
                        {
                            "Hash": hash_val,
                            "Count": count,
                            "Serialized Subtree": subtree,
                        }
                    )

        print(f"Results saved to {output.absolute().resolve()}")
    except Exception as e:
        print(f"An error occurred: {e}")
        temp_file = "subtrees_temp.pkl"
        with open(temp_file, "wb") as f:
            pickle.dump(subtrees, f)


def __main__(process_commits=True, process_comments=True):
    commits_directory = "../git_parse/context_files/commits"
    comments_directory = "../git_parse/context_files/comments"
    output_commits = "../../output/subtreesGitCommits.csv"
    output_comments = "../../output/subtreesGitComments.csv"

    # Load any existing subtrees if available
    temp_file = "subtrees_temp.pkl"
    all_subtrees = []
    if os.path.exists(temp_file):
        with open(temp_file, "rb") as f:
            all_subtrees = pickle.load(f)

    if all_subtrees:
        _write_subtrees(Path(output_commits), all_subtrees, True)
    else:
        if process_commits:
            process_directory(Path(commits_directory), Path(output_commits))
        if process_comments:
            process_directory(
                Path(comments_directory), Path(output_comments), is_comment=True
            )

    # Merge comments table with commits table on the subtree hash value and serialized subtree
    if process_commits and process_comments:
        commits_df = pd.read_csv(output_commits)
        comments_df = pd.read_csv(output_comments)

        merged_df = pd.merge(
            commits_df,
            comments_df,
            on=["Hash", "Serialized Subtree"],
            how="outer",
            suffixes=("_commit", "_comment"),
        )

        # Reorder the columns
        merged_df = merged_df[
            ["Hash", "Count_commit", "Count_comment", "Serialized Subtree"]
        ]
        merged_df.rename(
            columns={"Count_commit": "CountCommit", "Count_comment": "CountComment"},
            inplace=True,
        )

        merged_output_path = "../../output/merged_subtreesGit.csv"
        merged_df.to_csv(merged_output_path, index=False)


if __name__ == "__main__":
    __main__(process_commits=True, process_comments=True)
