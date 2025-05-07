import pandas as pd
import os
import subprocess
import git
from datetime import datetime
import requests
from bs4 import BeautifulSoup

# List of known Kubernetes kinds
kubernetes_kinds = [
    'Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 
    'CronJob', 'ConfigMap', 'Secret', 'PersistentVolume',
    'PersistentVolumeClaim', 'Role', 'RoleBinding', 'ClusterRole',
    'ClusterRoleBinding', 'ServiceAccount', 'Ingress'
]

# Function to check if the file is a Helm chart
def is_helm_chart(file_path):
    path_parts = file_path.split(os.sep)
    if 'templates' in path_parts:
        templates_index = path_parts.index('templates')
        if templates_index > 0:
            parent_directory = os.sep.join(path_parts[:templates_index])
            if 'values.yaml' in os.listdir(parent_directory):
                return True
    return False

# Function to calculate the total number of lines in the repository
def find_k8s_yaml_file(repo_dir):
    result = subprocess.run(['git', '-C', repo_dir, 'ls-files'], stdout=subprocess.PIPE, text=True)
    files = result.stdout.splitlines()

    
    k8s_non_test_example_files = 0
    k8s_kind_files = 0
    k8s_helm_files = 0
    k8s_kind_non_test_example_files = 0
    k8s_helm_non_test_example_files = 0


    for file in files:
        try:
            file_path = os.path.join(repo_dir, file)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                if file.endswith('.yaml') or file.endswith('.yml'):
                    if 'apiVersion:' in content:
                        is_k8s_file = False
                        for kind in kubernetes_kinds:
                            if f'kind: {kind}' in content:
                                is_k8s_file = True

                        if is_k8s_file:
                            
                            if is_helm_chart(file_path):
                                k8s_helm_files += 1
                                if 'test' not in file.lower() and 'example' not in file.lower():
                                    k8s_helm_non_test_example_files += 1
                            else:
                                k8s_kind_files += 1
                                if 'test' not in file.lower() and 'example' not in file.lower():
                                    k8s_kind_non_test_example_files += 1
                            if 'test' not in file.lower() and 'example' not in file.lower():
                                k8s_non_test_example_files += 1
                

        except:
            pass  # Ignore files that cannot be read
    return  k8s_non_test_example_files, k8s_kind_files, k8s_helm_files, k8s_kind_non_test_example_files, k8s_helm_non_test_example_files



# Store the current working directory
original_dir = os.getcwd()

# Path to save the output Excel file
output_excel_path = os.path.join(original_dir, 'summary_results.xlsx')

# Load existing results if the output file already exists
if os.path.exists(output_excel_path):
    existing_results_df = pd.read_excel(output_excel_path)
    processed_repos = set(existing_results_df['Repository URL'])
else:
    existing_results_df = pd.DataFrame()
    processed_repos = set()

# Parent directory containing the subfolders with repositories
parent_dir = 'D:/PhD/Research/K8s-config-bugs_FSE25/final_repo_list/repos'  # Replace with the actual path to your parent folder

# Iterate through each subfolder in the parent directory
for subfolder in os.listdir(parent_dir):
    subfolder_path = os.path.join(parent_dir, subfolder)

    # Check if the subfolder is a directory
    if os.path.isdir(subfolder_path):
        for repo_name in os.listdir(subfolder_path):
            repo_dir = os.path.join(subfolder_path, repo_name)

            

            # Skip if the repo has already been processed
            if repo_dir in processed_repos:
                continue

            print(f"Processing repository: {repo_name}")
            print("fuck")
            print(repo_dir)
            # Calculate total lines, number of commits, times of first and last commits, and number of contributors, issues, stars
            total_lines, yaml_lines, non_test_example_lines, yaml_non_test_example_lines, k8s_files, k8s_non_test_example_files, k8s_kind_files, k8s_helm_files, k8s_kind_non_test_example_files, k8s_helm_non_test_example_files, k8s_objects, k8s_objects_non_test_example = find_k8s_yaml_file(repo_dir)
            
       

    
            # Add the results to the existing DataFrame
            new_result = pd.DataFrame([{
                'Repository URL': repo_dir,
                'Repository Name': repo_name,
                'Total Lines': total_lines,
                'Total Lines (excluding test/examples)': non_test_example_lines,
                'Total YAML Lines': yaml_lines,
                'Total YAML Lines (excluding test/examples)': yaml_non_test_example_lines,
                'Number of K8s Files': k8s_files,
                'Number of K8s Kind Files': k8s_kind_files,
                'Number of K8s Helm Files': k8s_helm_files,
                'Number of K8s Files (excluding test/examples)': k8s_non_test_example_files,
                'Number of K8s Kind Files (excluding test/examples)': k8s_kind_non_test_example_files,
                'Number of K8s Helm Files (excluding test/examples)': k8s_helm_non_test_example_files,
                'Number of K8s Objects': k8s_objects,
                'Number of K8s Objects (excluding test/examples)': k8s_objects_non_test_example
            }])
            existing_results_df = pd.concat([existing_results_df, new_result], ignore_index=True)

            # Save the updated results to the Excel file
            existing_results_df.to_excel(output_excel_path, index=False)

            # Add the repo to the processed set
            processed_repos.add(repo_dir)

print("Script execution completed.")
