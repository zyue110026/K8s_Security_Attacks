import pandas as pd
import subprocess
import os
import re
import logging
import json
import time

# Load the Excel file
input_file = "D:/PhD/Research/k8s-pod-securityattack/k8s_yaml_files.xlsx"
output_file = "D:/PhD/Research/k8s-pod-securityattack/ToolEva/result/tool.csv"
sheet_name = "Sheet1"
root_path = "D:/PhD/Research/K8s-config-bugs_FSE25/final_repo_list/repos"
slikube_output_file_name = "tool.csv"

# Function to remove ANSI escape codes
def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def run_sli_kube(file_path, repo_path):
    command = [
        "powershell.exe",
        "-command",
        f"python3 D:/PhD/Research/k8s-pod-securityattack/src/main.py --security-attack-scan --file-path '{file_path}' --repo-path '{repo_path}'"
    ]
    print("Running command: %s", " ".join(command))
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
        output_text = remove_ansi_codes(result.stdout.strip())

        # Try to extract JSON-like line
        for line in reversed(output_text.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                return line  # This is the JSON string

        return "" 

        # # If no valid JSON found
        # return {"error": "No valid JSON found in output."}
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")
        return {"error": e.stderr}
    except Exception as e:
        print(f"Unexpected Error: {e}")
        return {"error": str(e)}

def is_json_string(s):
    try:
        json_string = json.dumps(s, ensure_ascii=False, indent=2)
        result = json.loads(json_string)
        return True
    except (ValueError, TypeError):
        return False   

    
def main():
    start_time = time.time()
    try:
        df = pd.read_excel(input_file, sheet_name=sheet_name)
    except Exception as e:
        logging.error(f"Error reading Excel file: {e}")
        exit(1)

    if 'File Path' not in df.columns:
        logging.error("Error: 'File Path' column not found in Excel sheet.")
        exit(1)
    
    for index, row in df.iterrows():
        file_path = row['File Path']
        repo_name = row['Repo Name']
        repo_path = os.path.join(root_path, repo_name)
        repo_path = os.path.normpath(repo_path)
        file_path = os.path.normpath(file_path)
        if not os.path.exists(repo_path):
            continue
        # print(file_path, repo_path)
        output_text = run_sli_kube(file_path, repo_path)
        # data = json.loads(output_text)
        # try:
        #     result_json = json.loads(output_text)
        #     result = result_json.get('detected_dangerous_patterns_summary', [])
        #     if not result:
        #         result = "NO security attacks found"
        # except (ValueError, TypeError, json.JSONDecodeError) as e:
        #     # print(f"Failed to parse JSON: {e}")
        #     result = f"Failed to parse JSON: {e}"


        # Save result line by line
        df.loc[index, 'Output'] = output_text
        # df.iloc[:index+1].to_excel(output_file, sheet_name=sheet_name, index=False)
        df.iloc[:index+1].to_csv(output_file, index=False)
    end_time = time.time()
    run_time = end_time - start_time
    print(f"Complete scanning in {run_time}s")
    print(f"Processing complete. Output saved to {output_file}")

if __name__ == "__main__":
    main()
