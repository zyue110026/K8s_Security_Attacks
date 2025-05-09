import pandas as pd
import subprocess
import os
import re
import json

# Load the Excel file
input_file = "D:/PhD/Research/k8s-config-testing/k8s_yaml_files.xlsx"
output_file = "D:/PhD/Research/k8s-pod-securityattack/ToolEva/result/trivy1.csv"
sheet_name = "Sheet1"

# Function to remove ANSI escape codes
def remove_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


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

# Iterate over rows and write results line by line
for index, row in df.iterrows():
    file_path = row['File Path']
    
    # Normalize path (convert \ to /)
    file_path = os.path.normpath(file_path)
    
    if not os.path.exists(file_path):
            continue
    print(file_path)
    # Run the checkov command under D: disk
    try:
        # command = ["cmd.exe", "/c", "D:", "&&", "checkov", "--framework", "kubernetes", "--file", file_path]
        command = [
            "powershell.exe",  # Use PowerShell
            "-Command",  # Indicate that the following is a PowerShell command
            f"trivy fs --scanners vuln,secret,misconfig '{file_path}' -q"
        ]
        print("Running command:", " ".join(command))
        # print("Environment variables:", os.environ)
        result = subprocess.run(command,
                                capture_output=True, text=True, encoding='utf-8')
        output_text = result.stdout.encode('utf-8', 'ignore').decode('utf-8').strip()
        # Clean the output by removing ANSI escape codes
        output_text = remove_ansi_codes(output_text)
        # json_data = json.loads(output_text)
        # print(output_text)
    except subprocess.CalledProcessError as e:
        print("Command failed with error:", e.stderr)
        output_text = f"Error: {e.stderr.strip()}"
    except Exception as e:
        output_text = f"Unexpected Error: {e}"
    
    # Extract only failed results
    pattern = re.compile(r"AVD-KSV-\d+\s*\([A-Z]+\):.*")
    # Filter the output using regex
    filtered_output = []
    for line in output_text.splitlines():
        if pattern.search(line):
            filtered_output.append(line.strip())
    
    # Join filtered lines into a single string
    filtered_output_text = "\n".join(filtered_output) if filtered_output else "No relevant issues found"
    # failed_results = []
    # for match in re.finditer(r'AVD-KSV-\d+\s*\([A-Z]+\):.*', output_text):
    #     check_id, description, resource = match.groups()
    #     failed_results.append(f"{check_id}: {description} (Resource: {resource})")
    
    # output_filtered = "\n".join(failed_results) if failed_results else "No failed checks"
    
    # Save result line by line
    df.loc[index, 'Output'] = filtered_output_text
    # df.iloc[:index+1].to_excel(output_file, sheet_name=sheet_name, index=False)
    df.iloc[:index+1].to_csv(output_file, index=False)
    
print(f"Processing complete. Output saved to {output_file}")
