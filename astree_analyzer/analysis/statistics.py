import csv
import json
from pathlib import Path
import matplotlib.pyplot as plt
from scipy.stats import chisquare


def calculate_frequencies(all_subtrees_input_path, bugfixes_input_path, comments_input_path):
    bugfix_frequencies   = _extract_counts(bugfixes_input_path)
    comment_frequencies  = _extract_counts(comments_input_path)
    project_frequencies = _extract_counts(all_subtrees_input_path)
    # comments_input_path = _calculate_frequencies(bugfixes_input_path)

    # chi2_stat, p_value = calculate_chi_square(bugfix_count, project_count)
    # print(chi2_stat)
    # print(p_value)

    # Calculate total occurrences in the entire project
    total_project = sum(project_frequencies.values())

    # Ensure both bugfix_frequencies and comment_frequencies have entries for all subtrees
    for subtree in comment_frequencies:
        if subtree not in bugfix_frequencies:
            bugfix_frequencies[subtree] = 0  # Add missing subtree with count 0
    for subtree in bugfix_frequencies:
        if subtree not in comment_frequencies:
            comment_frequencies[subtree] = 0  # Add missing subtree with count 0
    # Calculate expected frequencies based on total project proportions
    expected_bugfix = {k: (v / total_project) * sum(bugfix_frequencies.values()) for k, v in project_frequencies.items()}
    expected_comment = {k: (v / total_project) * sum(comment_frequencies.values()) for k, v in project_frequencies.items()}

    # Calculating deviation ratios for bug fixes and comments
    deviation_ratios_bugfix = {k: (bugfix_frequencies[k] - expected_bugfix[k]) / expected_bugfix[k] if k in expected_bugfix and expected_bugfix[k] != 0 else 0 for k in bugfix_frequencies}
    deviation_ratios_comments = {k: (comment_frequencies[k] - expected_comment[k]) / expected_comment[k] if k in expected_comment and  expected_comment[k] != 0 else 0 for k in comment_frequencies}

    # Prepare for plotting
    bugfix_values = list(deviation_ratios_bugfix.values())
    comment_values = list(deviation_ratios_comments.values())


    Path("D:/atoms/output/bugfix_deviation.json").write_text(json.dumps(deviation_ratios_bugfix, indent=4))
    Path("D:/atoms/output/comments_deviation.json").write_text(json.dumps(deviation_ratios_comments, indent=4))
    plt.scatter(bugfix_values, comment_values, alpha=0.5)
    plt.title('Comparison of Subtree Deviations in Bug Fixes and Comments')
    plt.xlabel('Deviation Ratio - Bug Fixes')
    plt.ylabel('Deviation Ratio - Comments')
    plt.xticks([])
    plt.yticks([])
    plt.grid(True)
    plt.show()


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


def _extract_counts(file_path):
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


