import pandas as pd
import subprocess
import os
import re
import logging

# Load the Excel file
input_file = "D:/PhD/Research/k8s-config-testing/k8s_yaml_files.xlsx"
output_file = "D:/PhD/Research/k8s-pod-securityattack/ToolEva/result/slikube1.csv"
sheet_name = "Sheet1"
root_path = "D:/PhD/Research/K8s-config-bugs_FSE25/final_repo_list/repos"
slikube_output_file_name = "slikube_results.csv"

# Function to remove ANSI escape codes
def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def run_sli_kube(path):
    command = [
        "powershell.exe",
        "-command",
        f"python C:/Users/zyue1_nh8hzsr/Downloads/KubeSec/main.py '{path}'"
    ]
    logging.debug("Running command: %s", " ".join(command))
    try:
        subprocess.run(command, check=True, capture_output= True)

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e.stderr}")
        return f"Error: {e.stderr.strip()}"
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return f"Unexpected Error: {e}"
    

    
def main():
    try:
        df = pd.read_excel(input_file, sheet_name=sheet_name)
    except Exception as e:
        logging.error(f"Error reading Excel file: {e}")
        exit(1)

    if 'File Path' not in df.columns:
        logging.error("Error: 'File Path' column not found in Excel sheet.")
        exit(1)
    current_working_path = None
    current_repo_name = None
    for index, row in df.iterrows():
        file_path = row['File Path']
        repo_name = row['Repo Name']
        repo_path = os.path.join(root_path, repo_name)
        repo_path = os.path.normpath(repo_path)

        file_path = os.path.normpath(file_path)
        if not os.path.exists(repo_path):
            continue
        parts = file_path.split(os.sep)
        repo_index = len(repo_path.split(os.sep))
        working_path = os.sep.join(parts[:repo_index + 1])
        print(working_path)

        if working_path != current_working_path:
            current_working_path = working_path
            current_repo_name = repo_name
            run_sli_kube(working_path)
        else:
            logging.info(f"Skipping file (already scanned: {current_working_path})")

        slikube_results_path = os.path.join(current_working_path, slikube_output_file_name)

        if not os.path.exists(slikube_results_path):
            print(f"result file: {slikube_results_path} not found")
            df.loc[index, 'Output'] = "Error: command execute failed"
            continue
        if os.path.getsize(slikube_results_path) > 0:
            try:
                slikube_result_df = pd.read_csv(slikube_results_path)
            except Exception as e:
                logging.error(f"Error reading Excel file: {e}")
                exit(1)
        else:
            print(f"File {slikube_results_path} is empty.")

        if working_path == current_working_path:
            # Find the rows in the temp_csv_df that match the file_path from the Excel file
            matching_rows = slikube_result_df[slikube_result_df['YAML_FULL_PATH'].str.contains(file_path, regex=False, na=False)]
            if not matching_rows.empty:
                # Check columns C to T for the value 1
                columns_to_check = matching_rows.columns[2:20]  # Assuming columns C to T are the 3rd to 20th columns
                found_columns = []
                for col in columns_to_check:
                    if 1 in matching_rows[col].values:
                        found_columns.append(col)
                df.loc[index, 'Output'] = ", ".join(found_columns)  

        df.iloc[:index+1].to_csv(output_file, index=False) 

    print(f"Processing complete. Output saved to {output_file}")

if __name__ == "__main__":
    main()
