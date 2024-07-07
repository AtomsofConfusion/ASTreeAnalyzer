import pstats
from parse import *
import os
import time
import pickle
import cProfile
from pathlib import Path

# Start timing
start_time = time.time()
print("Start:", start_time)

profiler = cProfile.Profile()

profile = False

def process_directory(directory):
    all_subtrees = []
    serializer = ASTSerializer()
    for file_path in Path(directory).rglob('*.c'):
        try:
            if profile:
                profiler.enable()
            filename = file_path.name
            print(f"Parsing {filename}")
            file_start_time = time.time()
            subtrees = serializer.extract_subrees_for_file(file_path)
            if profile:
                profiler.disable()
                stats = pstats.Stats(profiler).sort_stats('cumtime')
                stats.print_stats()
                # Optionally, save the stats for later analysis:
                stats.dump_stats('profile_results.prof')
            file_end_time = time.time()
            print(file_end_time - file_start_time)
            all_subtrees.extend(subtrees)
            print("Completed:", filename)
        except Exception as e:
            print(f"Error processing {filename}: {e}")
    return all_subtrees

# Load any existing subtrees if available
temp_file = 'subtrees_temp.pkl'
all_subtrees = []
if os.path.exists(temp_file):
    with open(temp_file, 'rb') as f:
        all_subtrees = pickle.load(f)

directory = './git'  # Update with your directory path

try:
    new_subtrees = process_directory(directory)
    all_subtrees.extend(new_subtrees)

    # Create a mapping between serialized and deserialized subtrees
    subtree_map = {subtree: print_tree(deserialize_subtree(subtree)) for subtree in all_subtrees}
    subtree_counter = count_subtrees(all_subtrees)

    # Write to CSV
    with open('subtreesGit.csv', 'w', newline='') as csvfile:
        fieldnames = ['Hash', 'Count', 'Human Readable Expression', 'Serialized Subtree', 'Deserialized Tree']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for subtree, count in subtree_counter.items():
            hash_val = hash_subtree(subtree)
            deserialized_tree = subtree_map[subtree]
            human_readable_expression = tree_to_expression(deserialize_subtree(subtree))
            writer.writerow({
                'Hash': hash_val,
                'Count': count,
                'Human Readable Expression': human_readable_expression,
                'Serialized Subtree': subtree,
                'Deserialized Tree': deserialized_tree
            })
except Exception as e:
    print(f"An error occurred: {e}")
    with open(temp_file, 'wb') as f:
        pickle.dump(all_subtrees, f)

# End timing
end_time = time.time()

# Print the elapsed time
elapsed_time = end_time - start_time
print(f"Time elapsed: {elapsed_time:.2f} seconds")
