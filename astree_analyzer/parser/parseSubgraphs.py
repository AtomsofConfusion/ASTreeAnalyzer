import platform
import clang.cindex
import hashlib
from collections import deque, Counter
from pathlib import Path
import csv

# Change path as necessary
PROJECT_ROOT = Path(__file__).parent.parent.parent
if platform.system() ==  "Windows":
    library_file = str(PROJECT_ROOT / "libs/windows/libclang.dll")
else:
    library_file = '/opt/homebrew/opt/llvm/lib/libclang.dylib'

clang.cindex.Config.set_library_file(library_file)

# Class to handle AST Subgraph Extraction and Serialization
class ASTSubgraphExtractor:
    def __init__(self, max_subgraph_size):
        self.max_subgraph_size = max_subgraph_size
        self.node_cache = {}

    def parse_file_to_ast(self, filepath):
        index = clang.cindex.Index.create()
        tu = index.parse(filepath)
        return tu.cursor

    def _get_node_cache(self, node):
        node_id = node.hash
        if node_id not in self.node_cache:
            self.node_cache[node_id] = {"children": list(node.get_children())}
        return self.node_cache[node_id]

    def extract_subgraphs(self, root):
        subgraphs = []
        queue = deque([root])

        while queue:
            node = queue.popleft()
            subgraph = self._extract_subgraph(node)

            if subgraph:
                subgraphs.append(subgraph)

            children = self._get_node_cache(node)["children"]
            queue.extend(children)

        return subgraphs

    def _extract_subgraph(self, root):
        subgraph = []
        queue = deque([root])
        visited = set()

        while queue and len(subgraph) < self.max_subgraph_size:
            node = queue.popleft()
            node_id = node.hash  # Use the hash attribute for uniqueness

            if node_id in visited:
                continue
            visited.add(node_id)

            node_rep = self._serialize_node(node)
            subgraph.append(node_rep)

            children = self._get_node_cache(node)["children"]
            queue.extend(children)

        return subgraph if subgraph else None

    def _serialize_node(self, node):
        node_kind = node.kind
        node_rep = str(node_kind)

        if node.spelling:
            node_rep += f"_{node.spelling}"

        return node_rep

    def hash_subgraph(self, subgraph):
        serialized_subgraph = ",".join(subgraph)
        return hashlib.sha256(serialized_subgraph.encode('utf-8')).hexdigest()

    def process_file(self, filepath, output_dir):
        root = self.parse_file_to_ast(filepath)
        subgraphs = self.extract_subgraphs(root)

        # Serialize and hash the subgraphs
        subgraph_data = [(self.hash_subgraph(subgraph), ','.join(subgraph)) for subgraph in subgraphs]

        # Use a dictionary to drop duplicates (hash as key ensures uniqueness)
        unique_subgraph_data = {}
        for subgraph_hash, serialized_subgraph in subgraph_data:
            if subgraph_hash not in unique_subgraph_data:
                unique_subgraph_data[subgraph_hash] = serialized_subgraph

        output_path = Path(output_dir, f"{Path(filepath).stem}_subgraph_hashes.csv")
        
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = ['Hash', 'Count', 'Serialized Subgraph']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for subgraph_hash, serialized_subgraph in unique_subgraph_data.items():
                writer.writerow({
                    'Hash': subgraph_hash,
                    'Count': subgraph_data.count((subgraph_hash, serialized_subgraph)),  # Count how many times each subgraph appears
                    'Serialized Subgraph': serialized_subgraph
                })

        print(f"Processed {len(unique_subgraph_data)} unique subgraphs from {filepath}. Output written to {output_path}.")


if __name__ == "__main__":
    extractor = ASTSubgraphExtractor(max_subgraph_size=100)
    source_code_file = "input/add.c"  
    output_directory = "astree_analyzer/output"  
    extractor.process_file(source_code_file, output_directory)
