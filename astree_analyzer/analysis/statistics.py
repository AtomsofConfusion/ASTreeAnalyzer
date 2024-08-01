import csv
import json
import math
from pathlib import Path
# import matplotlib.pyplot as plt
import plotly.express as px
from scipy.stats import chisquare
import pandas as pd


def calculate_frequencies(all_subtrees_input_path, bugfixes_input_path, comments_input_path):
    bugfix_data = _extract_data_from_json(bugfixes_input_path)
    comment_data  = _extract_data_from_json(comments_input_path)
    project_frequencies = _extract_proejct_counts(all_subtrees_input_path)
    # comments_input_path = _calculate_frequencies(bugfixes_input_path)

    bugfix_frequencies = {
        item["Hash"]: item["Count"]
        for item in bugfix_data
    }

    comment_frequencies = {
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


    # chi2_stat, p_value = calculate_chi_square(bugfix_count, project_count)
    # print(chi2_stat)
    # print(p_value)

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
        if k in expected_bugfix and expected_bugfix[k] != 0 and bugfix_frequencies[k] > expected_comment[k] else 0
        for k in bugfix_frequencies
    }
    deviation_ratios_comments = {
        k: math.log((comment_frequencies[k] / expected_comment[k]) + 1)
        if k in expected_comment and expected_comment[k] != 0 and comment_frequencies[k] > expected_comment[k] else 0
        for k in comment_frequencies
    }

    # Prepare for plotting
    bugfix_values = list(deviation_ratios_bugfix.values())
    comment_values = list(deviation_ratios_comments.values())

    size = [bugfix_frequencies[tree_hash] + comment_frequencies[tree_hash] for tree_hash in bugfix_frequencies]

    code = []
    for tree_hash in bugfix_frequencies:
        if tree_hash in bugfix_code:
            code.append(bugfix_code[tree_hash])
        else:
            code.append(comment_code[tree_hash])

    output_data = [{
        "deviation": deviation_ratios_bugfix[tree_hash],
        "subtree": bugfix_code[tree_hash]
        }
        for tree_hash in deviation_ratios_bugfix if deviation_ratios_bugfix[tree_hash] > 0
    ]
    Path("D:/atoms/output/bugfix_deviation.json").write_text(json.dumps(output_data, indent=4))
    output_data = [{
        "deviation": deviation_ratios_comments[tree_hash],
        "subtree": comment_code[tree_hash]
        }
        for tree_hash in deviation_ratios_comments if deviation_ratios_comments[tree_hash] > 0
    ]
    Path("D:/atoms/output/comments_deviation.json").write_text(json.dumps(output_data, indent=4))


    df = pd.DataFrame({
        'Bugfix Deviation': bugfix_values,
        'Comment Deviation': comment_values,
        'Size': size,
        'Code': code,
    })

    # Create the scatter plot with plotly express
    fig = px.scatter(
        df,
        x='Comment Deviation',
        y='Bugfix Deviation',
        hover_name="Code",
        title='Comparison of Subtree Deviations in Bug Fixes and Comments',
        size='Size',  # Optional: Size of the points proportional to bugfix deviation
        size_max=50  # Maximum size of the points
    )

    # Show the plot
    fig.show()


def calculate_chi_square(bugfix_count, project_count, scale_factor=1):
    bugfix_count = {
        subtree: count for subtree, count in bugfix_count.items() if subtree in project_count
    }
    total_bugfix_subtrees = sum(bugfix_count.values())
    total_project_subtrees = sum(project_count.values())

    observed_count = []
    expected_count = []

    # Compute expected and observed count
    for subtree, bugfix_freq in bugfix_count.items():
        expected_freq = (project_count.get(subtree, 0) / total_project_subtrees) * total_bugfix_subtrees
        expected_freq_scaled = expected_freq * scale_factor
        observed_freq_scaled = bugfix_freq * scale_factor
        expected_count.append(expected_freq_scaled)
        observed_count.append(observed_freq_scaled)

    # Adjust expected count if their sum does not match the observed sum
    sum_observed = sum(observed_count)
    sum_expected = sum(expected_count)
    if sum_expected != sum_observed:
        expected_count = [freq * (sum_observed / sum_expected) for freq in expected_count]

    # Perform the chi-square test
    chi2_stat, p_value = chisquare(f_obs=observed_count, f_exp=expected_count)
    return chi2_stat, p_value


def _extract_proejct_counts(file_path):
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
        item for item in subtrees_data if "struct" not in item["Serialized Subtree"]
    ]
