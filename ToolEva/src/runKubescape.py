import pandas as pd
import subprocess
import os
import re
import logging

# Load the Excel file
input_file = "D:/PhD/Research/k8s-config-testing/k8s_yaml_files.xlsx"
output_file = "D:/PhD/Research/k8s-pod-securityattack/ToolEva/result/kubescape1.csv"
sheet_name = "Sheet1"

# Function to remove ANSI escape codes
def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def run_kubescape_scan(target_path):
    """
    Run the kubescape scan command and return the filtered output.
    """
    command = [
        "powershell.exe",  # Use PowerShell
        "-Command",  # Indicate that the following is a PowerShell command
        f"kubescape scan '{target_path}'"  # Scan the target path
    ]
    logging.debug("Running command: %s", " ".join(command))
    
    try:
        # Execute the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace')
        output_text = result.stdout.strip()
        
        # Find the line containing "Security posture overview for repo:"
        start_index = output_text.find("Security posture overview for repo:")
        
        # If the line is found, extract everything after it
        if start_index != -1:
            return output_text[start_index:]
        else:
            return "No security posture overview found in the output."
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e.stderr}")
        return f"Error: {e.stderr.strip()}"
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return f"Unexpected Error: {e}"

def is_helm_chart_path(file_path):
    """
    Check if the file path is part of a Helm chart by checking if it contains a 'templates' directory.
    """
    return "templates" in file_path.split(os.sep)

def extract_helm_chart_path(file_path):
    """
    Extract the Helm chart directory (path before 'templates').
    """
    return file_path.split("templates")[0]

# Read Excel file
try:
    df = pd.read_excel(input_file, sheet_name=sheet_name)
except Exception as e:
    print(f"Error reading Excel file: {e}")
    exit(1)

# Ensure 'File Path' column exists
if 'File Path' not in df.columns:
    print("Error: 'File Path' column not found in Excel sheet.")
    exit(1)

current_helm_chart_path = None

# Iterate over rows and write results line by line
for index, row in df.iterrows():
    file_path = row['File Path']
    
    # Normalize path (convert \ to /)
    file_path = os.path.normpath(file_path)
    
    if not os.path.exists(file_path):
            continue
    print(file_path)
    # check if file is a helm chart
    if is_helm_chart_path(file_path):
        helm_chart_path = extract_helm_chart_path(file_path)

        if helm_chart_path != current_helm_chart_path:
            current_helm_chart_path = helm_chart_path
            logging.info(f"Detected Helm chart: {helm_chart_path}")
            # Run kubescape scan for the Helm chart directory
            output_text = run_kubescape_scan(helm_chart_path)
            # Save the output for all files in this Helm chart
            df.loc[index, 'Output'] = output_text
        else:
            # Skip scanning if this file belongs to the current Helm chart
            logging.info(f"Skipping file (already scanned as part of Helm chart: {current_helm_chart_path})")
    # Run the checkov command under D: disk
    
    else:
        # If the file is not part of a Helm chart, run the scan directly
        output_text = run_kubescape_scan(file_path)
        df.loc[index, 'Output'] = output_text
    # Save result line by line
    # df.loc[index, 'Output'] = filtered_output
    # df.iloc[:index+1].to_excel(output_file, sheet_name=sheet_name, index=False)
    df.iloc[:index+1].to_csv(output_file, index=False)
    
print(f"Processing complete. Output saved to {output_file}")
