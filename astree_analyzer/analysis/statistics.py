import csv
import json
import math
from pathlib import Path
import re
import plotly.express as px
import pandas as pd

post_inc_pattern = r'CursorKind\.UNARY_OPERATOR_\+\+_post'


def _show_node(code):
    return _contains_assignment_operator(code)

def calculate_frequencies(all_subtrees_input_path, bugfixes_input_path, comments_input_path, output_dir=None):
    bugfix_data = _extract_data_from_json(bugfixes_input_path)
    comment_data  = _extract_data_from_json(comments_input_path)
    project_frequencies = _extract_data_from_json(all_subtrees_input_path)
    # comments_input_path = _calculate_frequencies(bugfixes_input_path)

    # bugfix_root_frequencies = {
    #     item["Hash"]: item["Root Count"]
    #     for item in bugfix_data
    # }

    # project_root_frequencies = {
    #     item["Hash"]: item["Root Count"]
    #     for item in project_frequencies
    # }

    # comment_root_frequencies = {
    #     item["Hash"]: item["Root Count"]
    #     for item in comment_data
    # }


    bugfix_all_frequencies = {
        item["Hash"]: item["Count"]
     for item in bugfix_data
    }

    project_all_frequencies = {
        item["Hash"]: item["Count"]
        for item in project_frequencies
    }

    comment_all_frequencies = {
        item["Hash"]: item["Count"]
        for item in comment_data
    }

    bugfix_code = {
        item["Hash"]: f"{item['Serialized Subtree']}"
        for item in bugfix_data
    }

    comment_code = {
        item["Hash"]: f"{item['Serialized Subtree']}"
        for item in comment_data
    }


    # deviation_ratios_root_bugfix, deviation_ratios_root_comments = calculate_deviations(
    #     project_root_frequencies, bugfix_root_frequencies, comment_root_frequencies,
    #     bugfix_code, comment_code
    #     )

    deviation_ratios_all_bugfix, deviation_ratios_all_comments = calculate_deviations(
        project_all_frequencies, bugfix_all_frequencies, comment_all_frequencies,
        bugfix_code, comment_code
        )

    deviation_ratios_bugfix = dict(deviation_ratios_all_bugfix)
    deviation_ratios_comments = dict(deviation_ratios_all_comments)


    bugfix_frequencies = dict(bugfix_all_frequencies)
    comment_frequencies = dict(comment_all_frequencies)


    # for k, v in deviation_ratios_all_bugfix.items():
    #     if k not in deviation_ratios_root_bugfix:
    #         deviation_ratios_bugfix[k] = v
    #         bugfix_frequencies[k] = bugfix_all_frequencies[k]

    # for k, v in deviation_ratios_all_bugfix.items():
    #     if k not in deviation_ratios_root_bugfix:
    #         deviation_ratios_bugfix[k] = v
    #         bugfix_frequencies[k] = bugfix_all_frequencies[k]
    #     else:
    #         if k in bugfix_code:
    #             key = f"{k}_1"
    #             deviation_ratios_bugfix[key] = v
    #             bugfix_frequencies[key] = bugfix_all_frequencies[k]
    #             bugfix_code[key] = bugfix_code[k]


    # for k, v in deviation_ratios_all_comments.items():
    #     if k not in deviation_ratios_root_comments:
    #         deviation_ratios_comments[k] = v
    #         comment_frequencies[k] = comment_all_frequencies[k]
    #     else:
    #         if k in comment_code:
    #             key = f"{k}_1"
    #             deviation_ratios_comments[key] = v
    #             comment_frequencies[key] = comment_all_frequencies[k]
    #             comment_code[key] = comment_code[k]

    
    bugfix_values = []
    comment_values = []
    for k in deviation_ratios_bugfix:
        bugfix_values.append(deviation_ratios_bugfix[k])
        comment_values.append(deviation_ratios_comments[k])



    size = [bugfix_frequencies[tree_hash] + comment_frequencies[tree_hash] for tree_hash in bugfix_frequencies ]


    code = []
    color = []
    for tree_hash in bugfix_frequencies:
        if tree_hash in bugfix_code:
            subtree_str = bugfix_code[tree_hash]
        else:
            subtree_str = comment_code[tree_hash]
        code.append(subtree_str)
        # if tree_hash in deviation_ratios_root_bugfix:
        #     color.append("green")
        # else:
        #     color.append("red")


    if output_dir:
        output_dir = Path(output_dir)
        if not output_dir.is_dir():
            output_dir.mkdir(parents=True)

        output_data = [{
            "deviation": deviation_ratios_bugfix[tree_hash],
            "subtree": bugfix_code[tree_hash],
            "count": bugfix_frequencies[tree_hash],
            }
            for tree_hash in deviation_ratios_bugfix if deviation_ratios_bugfix[tree_hash] > 0 and tree_hash in bugfix_frequencies
        ]

        Path(output_dir, "bugfix_deviation.json").write_text(json.dumps(output_data, indent=4))
        output_data = [{
            "deviation": deviation_ratios_comments[tree_hash],
            "subtree": comment_code[tree_hash],
            "count": comment_frequencies[tree_hash],
            }
            for tree_hash in deviation_ratios_comments if deviation_ratios_comments[tree_hash] > 0 and tree_hash in comment_frequencies
        ]
        Path(output_dir, "comments_deviation.json").write_text(json.dumps(output_data, indent=4))


    df = pd.DataFrame({
        'Bugfix Deviation': bugfix_values,
        'Comment Deviation': comment_values,
        'Size': size,
        'Code': code,
        # "Color": color,
    })

    fig = px.scatter(
        df,
        x='Comment Deviation',
        y='Bugfix Deviation',
        hover_name="Code",
        title='Comparison of Subtree Deviations in Bug Fixes and Comments',
        size='Size',
        # color="Color",
        size_max=50,
    )

    fig.show()


def calculate_deviations(project_frequencies, bugfix_frequencies, comment_frequencies, bugfix_code, comment_code):

    total_project = sum(project_frequencies.values())
    total_bugfix = sum(bugfix_frequencies.values())
    total_comment = sum(comment_frequencies.values())

    # Ensure both bugfix_frequencies and comment_frequencies have entries for all subtrees
    for subtree in comment_frequencies:
        if subtree not in bugfix_frequencies:
            bugfix_frequencies[subtree] = 0
    for subtree in bugfix_frequencies:
        if subtree not in comment_frequencies:
            comment_frequencies[subtree] = 0


    expected_bugfix = {k: (v / total_project) * total_bugfix for k, v in project_frequencies.items()}
    expected_comment = {k: (v / total_project) * total_comment for k, v in project_frequencies.items()}


    # Calculating deviation ratios for bug fixes and comments
    deviation_ratios_bugfix = {
        k: math.log((bugfix_frequencies[k] / expected_bugfix[k]) + 1)
        if k in expected_bugfix and expected_bugfix[k] != 0 and expected_bugfix[k] < bugfix_frequencies[k] else 0
        for k in bugfix_frequencies
    }
    deviation_ratios_comments = {
        k: math.log((comment_frequencies[k] / expected_comment[k]) + 1)
        if k in expected_comment and expected_comment[k] != 0  and  expected_comment[k] < comment_frequencies[k] else 0
        for k in comment_frequencies
    }

    for k in dict(deviation_ratios_bugfix):
        if k in bugfix_code and not _show_node(bugfix_code[k]) or k in comment_code and not _show_node(comment_code[k]) or \
            bugfix_frequencies.get(k, 0) + comment_frequencies.get(k, 0) < 10 or  bugfix_frequencies.get(k, 0) + comment_frequencies.get(k, 0) > 1000 or \
            deviation_ratios_bugfix.get(k, 0) == 0 or deviation_ratios_comments.get(k, 0) == 0:
            deviation_ratios_bugfix.pop(k)
            deviation_ratios_comments.pop(k)
            bugfix_frequencies.pop(k)
            comment_frequencies.pop(k)

    return deviation_ratios_bugfix, deviation_ratios_comments


def _contains_assignment_operator(s):
    # Regular expressions for post-increment and post-decrement
    pattern1 = r'CursorKind\.BINARY_OPERATOR_=\('
    pattern2 = r'CursorKind\.BINARY_OPERATOR_\+=\('

    # Check if either pattern is found in the string
    if re.search(pattern1, s) or re.search(pattern2, s):
        return True
    return False

def _contains_post_inc_dec_operator(s):
    # Regular expressions for post-increment and post-decrement
    post_inc_pattern = r'CursorKind\.UNARY_OPERATOR_\+\+_post'
    post_dec_pattern = r'CursorKind\.UNARY_OPERATOR_--_post'

    # Check if either pattern is found in the string
    if re.search(post_inc_pattern, s) or re.search(post_dec_pattern, s):
        return True
    return False

def _contains_standalone_post_inc_dec(s):
    standalone_post_inc_pattern = r'^CursorKind\.UNARY_OPERATOR_\+\+_post\(var_\d+_[\w\s\*]+\)$'
    standalone_post_dec_pattern = r'^CursorKind\.UNARY_OPERATOR_--_post\(var_\d+_[\w\s\*]+\)$'
    return re.search(standalone_post_inc_pattern, s) or re.search(standalone_post_dec_pattern, s)

# Function to check for post-increment or post-decrement in a for loop
def _contains_post_inc_dec_in_for_loop(s):
    for_loop_post_inc_pattern = r'CursorKind\.FOR_STMT\(.*CursorKind\.UNARY_OPERATOR_\+\+_post'
    for_loop_post_dec_pattern = r'CursorKind\.FOR_STMT\(.*CursorKind\.UNARY_OPERATOR_--_post'
    return re.search(for_loop_post_inc_pattern, s) or re.search(for_loop_post_dec_pattern, s)


def has_children(node_string):
    # Check if the string contains '(' and ')'
    return '(' in node_string and ')' in node_string


def _extract_csv_counts(file_path):
    hash_count = {}
    csv.field_size_limit(2**31 - 1)
    with open(file_path, "r", newline="") as file:
        reader = csv.reader(file)
        for row in reader:
            try:
                hash_val = row[0]
                count = int(row[1])
                if count < 5:
                    continue
                hash_count[hash_val] = count
            except ValueError:
                pass # skip the first row

    return hash_count

def _extract_data_from_json(file_path):
    subtrees_data = json.loads(Path(file_path).read_text())
    return [
        item for item in subtrees_data
    ]
