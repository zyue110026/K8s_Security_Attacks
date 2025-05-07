import os
import pandas as pd
import random

# List of known Kubernetes kinds
kubernetes_kinds = {
    'Pod', 'Deployment', 'StatefulSet', 'DaemonSet', 'Job', 
    'CronJob', 'ConfigMap', 'Secret', 'PersistentVolume',
    'PersistentVolumeClaim', 'Role', 'RoleBinding', 'ClusterRole',
    'ClusterRoleBinding', 'ServiceAccount', 'Ingress'
}

# Function to check if a file is a Helm chart
def is_helm_chart(file_path):
    path_parts = file_path.split(os.sep)
    if 'templates' in path_parts:
        templates_index = path_parts.index('templates')
        if templates_index > 0:
            parent_directory = os.sep.join(path_parts[:templates_index])
            if 'values.yaml' in os.listdir(parent_directory):
                return True
    return False

# Function to find Kubernetes YAML files in a given repository
def find_k8s_yaml_files(repo_dir, repo_name):
    k8s_files = []
    
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'apiVersion:' in content:
                            for kind in kubernetes_kinds:
                                if f'kind: {kind}' in content:
                                    file_type = "Helm" if is_helm_chart(file_path) else ""
                                    if any(keyword in file_path.lower() for keyword in ["test", "example", "e2e"]):
                                        file_type = "Test"
                                    
                                    k8s_files.append((repo_name, file_path, file_type))
                                    break  # Stop checking other kinds once a match is found
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    
    return k8s_files

# Main function
def main():
    parent_dir = r"D:/PhD/Research/K8s-config-bugs_FSE25/final_repo_list/repos"
    output_path = os.path.join(parent_dir, "k8s_yaml_files.xlsx")

    all_k8s_files = []

    # Open Excel writer to save results one repo at a time
    with pd.ExcelWriter(output_path, mode="w") as writer:
        for repo_name in os.listdir(parent_dir):
            repo_path = os.path.join(parent_dir, repo_name)
            if os.path.isdir(repo_path):
                print(f"Processing repository: {repo_name}")
                repo_k8s_files = find_k8s_yaml_files(repo_path, repo_name)
                all_k8s_files.extend(repo_k8s_files)

        # Convert to DataFrame and write to a single sheet
        if all_k8s_files:
            df_all_files = pd.DataFrame(all_k8s_files, columns=['Repo Name', 'File Path', 'File Type'])
            df_all_files.to_excel(writer, sheet_name="All K8s YAML Files", index=False)

            # Sample 381 files only from "Helm" and empty file types
            df_sampled_files = df_all_files[df_all_files["File Type"].isin(["", "Helm"])]
            df_sampled_files = df_sampled_files.sample(n=min(381, len(df_sampled_files)), random_state=42)
            df_sampled_files.to_excel(writer, sheet_name="Sampled 381 Files", index=False)

    print(f"Results saved to {output_path}")

if __name__ == "__main__":
    main()
