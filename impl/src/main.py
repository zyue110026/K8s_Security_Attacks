import os
import yaml
import renderTemplate
from glob import glob
import handleJSON
import constantsVal
import csv
import time
import pairwise_test
import check_secuirty_attacks
import argparse
import security_attack_constants

def loadSingleYamlFile(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(f"loadSingleYamlFile: Error parsing YAML file {file_path}: {exc}")
        return None
    
def loadMultiYamlFile(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as stream:
            return list(yaml.safe_load_all(stream))
    except yaml.YAMLError as exc:
        pass
        print(f"loadMultiYamlFile: Error parsing YAML file {file_path}: {exc}")
        return None



def checkIfWeirdYAML(yaml_path):
    '''
    to filter invalid YAMLs such as ./github/workflows/ 
    '''
    val = False
    # print(yaml_path)
    for weird_path in constantsVal.WEIRD_PATHS:
        if weird_path in yaml_path:
            val = True 
    return val

def getRequiredK8sManifest(yaml_path, requiredK8sKind = None):
    manifestContents = []
    # check if a yaml is a valid k8s manifest
    # check if key: kind and apiVersion exist
    # skip template in templates folder as some templates can be load as yaml file
    try:
        # Skip the file if it is under a templates folder
        if 'templates' in yaml_path.split(os.sep):
            # print(f"Skipping {yaml_path} as it is under a templates folder.")
            return None
        with open(yaml_path, 'r', encoding='utf-8') as file:
            docs = yaml.safe_load_all(file)
            print("Loading yaml files...")
            for doc in docs:
                # print(doc)
                kind = handleJSON.find_values(constantsVal.KEY_KIND, doc, level=0)
                kind_value = handleJSON.get_find_value_results(kind, constantsVal.KEY_KIND)
                # print(kind)
                # print(kind_value)
                apiVersion = handleJSON.find_values(constantsVal.KEY_APIVERSION, doc, level=0)
                if not kind_value:
                    continue
                if any(k_value in kind_value for k_value in constantsVal.K8S_FORBIDDEN_KW_LIST):
                    # print(kind_value)
                    continue
                if kind_value == constantsVal.SKIP_CRD:
                    continue
                if requiredK8sKind:
                    # print(kind_value)
                    if kind and apiVersion and any(k_value == kind_value for k_value in requiredK8sKind):
                        manifestContents.append(doc)
                elif kind and apiVersion:
                    manifestContents.append(doc)
        return manifestContents
    except yaml.YAMLError:
        print(f"Invalid yaml file: {yaml_path}")
        pass
    except FileNotFoundError as e:
        print(f"File not found: {yaml_path}")
        pass
    return False

def check_if_templates_contain_yaml(templates_dir_list_include_subchart):
    for template_dir in templates_dir_list_include_subchart:
        for root, dirs, files in os.walk(template_dir):
            for file in files:
                if file.endswith('.yaml') or file.endswith('.yml'):
                    return True
    return False


def check_if_helm_chart_template_file(file_path):
    return "templates" in file_path.split(os.sep)


# get helm chart directory
def findHelmChartDirectory(repo_path):
    helm_script_count = 0
    charts = glob(os.path.join(repo_path, '**/Chart.yaml'), recursive=True)
    
    # print(charts)
        

    # print(charts)

    # json file to collect rendered templates
    helm_charts_list = []
    value_file_path_list = []
    templates_dir_list = []
    if charts:
        # hanle subcharts in charts
        chart_dir_list = []
        for chart in charts:
            relative_path = os.path.relpath(chart, repo_path)
            if any(folder in relative_path for folder in constantsVal.SKIP_FOLDERS):
                print(f'skip helm: {relative_path}')
                continue
            chart_dir = os.path.dirname(chart)
            chart_dir_list.append(chart_dir)
        # print(chart_dir_list)
        # Normalize paths to avoid issues with mixed slashes
        chart_dir_list = [os.path.normpath(path) for path in chart_dir_list]
    
        # Create the new list of dictionaries
        new_charts_list = []

        # Process each chart path
        for chart in chart_dir_list:
            subcharts = [subchart for subchart in chart_dir_list if subchart.startswith(chart) and subchart != chart]
            
            new_charts_list.append({"chartPath": chart, "parentChartPath": None, "subChartPath": subcharts})
        for chart in new_charts_list:
            for chart_compare in new_charts_list:
                if chart != chart_compare:
                    chartPath = chart['chartPath']
                    if chartPath in chart_compare['subChartPath']:
                        chart['parentChartPath'] = chart_compare['chartPath']
                        break
        # print(new_charts_list)

        for chart in new_charts_list:
            chart_dir = chart["chartPath"]
            values_file_path = os.path.join(chart_dir, 'values.yaml')
            templates_dir = os.path.join(chart_dir, 'templates')

            if not os.path.exists(values_file_path) or not os.path.exists(templates_dir):
                # print(templates_dir)
                continue
    

            values = loadSingleYamlFile(values_file_path)
            if values is None:
                continue
            values_file_path_dic = {
                'valuesFilePath': values_file_path,
                'parentValuesFilePath': None
            }

            if chart['parentChartPath']:
                parent_values_file_path = os.path.join(chart['parentChartPath'], 'values.yaml')

                values_file_path_dic['parentValuesFilePath'] = parent_values_file_path


            helm_charts = renderTemplate.process_template(chart_dir, templates_dir, values_file_path_dic)
            helm_charts_list.extend(helm_charts)
            
            value_file_path_list.append(values_file_path)
            templates_dir_list.append(templates_dir)

            
        
        
        
        return helm_charts_list
    else:
        return []
    

    

    
def check_if_valid_yaml(file_path):
    if file_path.endswith('.yaml') or file_path.endswith('.yml'):
        if checkIfWeirdYAML(file_path):
            # print(f'wired yaml: {os.path.join(root, file)}')
            return False
        return True
    return False
        


def analyze_repo(repo_path):
    
    analysis_scripts_count = 0
    helm_charts_json_path = os.path.join(repo_path, 'helm_charts.json')
    kind_manifests_json_path = os.path.join(repo_path, 'kind_manifests.json')

    kind_manifests = []
    for root, dirs, files in os.walk(repo_path):
        keyList= []
        # Calculate the relative path from the repo_path
        relative_path = os.path.relpath(root, repo_path)
        
        if any(folder in relative_path for folder in constantsVal.SKIP_FOLDERS):
            continue
        # for dir in dirs:
            # print(dir)
            # getValuesYamlFileAndTemplatesFromDirectory(os.path.join(root, dir))
            # json_path = os.path.join(repo_path, 'helm_charts.json')
            # renderTemplate.save_to_json(helm_charts, json_path)
        for file in files:
            filePath = os.path.join(root, file)
            if file.endswith('.yaml') or file.endswith('.yml'):
                if checkIfWeirdYAML(filePath):
                    # print(f'wired yaml: {os.path.join(root, file)}')
                    continue
                
                manifestContents = getRequiredK8sManifest(filePath, constantsVal.KIND_RB)
                if manifestContents:
                # if getRequiredK8sManifest(filePath):
                    # print(f'file: {file}, dir: {filePath}')
                    
                    # manifestContents = loadMultiYamlFile(filePath)
                    # if manifestContents:
                        # print('manifestContents')
                    analysis_scripts_count += 1
                    kind_manifests.append({
                                'filePath': filePath,
                                'manifestContents': manifestContents
                            })
   
                # if contains_keys_in_helm_template(filePath):
                #     # print(f'yamlcontent: {yaml_contents}')
                #     print(f'containkey: file: {file}, dir: {dir}')

        # print(kind_manifests)

    # collect kind manifest into a json file
    # structure is {filePath:.., manifestContents:[{...}, {...}]}
    # print(kind_manifests)
    handleJSON.save_to_json(kind_manifests, kind_manifests_json_path)
    # collect rendered helm chart template
    # structure is {valuesYamlPath:..., templates: [{templatePath:..., templateContents: ...}, {...}]}
    helm_charts = findHelmChartDirectory(repo_path)
    handleJSON.save_to_json(helm_charts, helm_charts_json_path)
    # analysis_scripts_count += helm_script_count
    
    
    
    # print(orphan_count)
    # print(f'script_count: {analysis_scripts_count}, complete analysis in {run_time:.4f} seconds')  
    return analysis_scripts_count
                

def generate_json_result_output(scan_results, file_path):
    if scan_results:
        if all(result == 0 for result in scan_results):
            report = "✅ No dangerous configuration parameter combinations found."
            # print("")
            return report
        detected_attacks = []
        details = {}
        for i, count in enumerate(scan_results):
            if count > 0:
                attack_name = constantsVal.SECURITY_ATTACK_NAMES[i]
                detected_attacks.append(attack_name)
                details[attack_name] = {
                "reason": constantsVal.WHY_CONFIG_COMB_DANGEROUS[i],
                "dangerous_configuration_key_combinations": security_attack_constants.SECURITY_ATTACKS[attack_name]
            }
        report = {
        "file_name": file_path,
        "detected_dangerous_patterns_summary": detected_attacks,
        "details": details
        }
        return report


def main(file_path, repo_path):
    start_time = time.time()
    detected_security_attacks, unmatched_test_cases = pairwise_test.main()
    normalized_file_path = os.path.normpath(file_path)
    scan_results = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    helm_charts_json_path = os.path.join(repo_path, 'helm_charts.json')
    kind_manifests_json_path = os.path.join(repo_path, 'kind_manifests.json')
    if not os.path.exists(helm_charts_json_path) or not os.path.exists(kind_manifests_json_path):
        analysis_scripts_count = analyze_repo(repo_path)

    helm_charts_json = handleJSON.load_from_json(helm_charts_json_path)
    kind_manifests_json = handleJSON.load_from_json(kind_manifests_json_path)
    manifestContents = []
    roles_and_rolebindings = []

    output_csv = os.path.join(repo_path, 'results.csv')
    # Open the CSV file in write mode initially to write the header
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["file_path", 'repoPath', 'run_time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
    # Open the CSV file in append mode to write each result one by one
    with open(output_csv, 'a', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        if check_if_valid_yaml(normalized_file_path):
            
            if check_if_helm_chart_template_file(normalized_file_path):
                manifestContents, valuesYamlPath = handleJSON.extract_content_from_helm_chart_based_on_file_path(helm_charts_json, normalized_file_path)
                related_helm_charts = []
                if valuesYamlPath:
                    for item in helm_charts_json:
                        chartPath = item.get('valuesYamlPath', "")
                        # templates = item.get('templates', [])
                        if chartPath == valuesYamlPath:

                            related_helm_charts.append(item)
                if related_helm_charts:
                    roles_and_rolebindings = handleJSON.extract_content_from_helm_chart_based_on_kind(related_helm_charts, constantsVal.KIND_RB)
            else:
                # print("finding yamls...")
                manifestContents = getRequiredK8sManifest(normalized_file_path, constantsVal.K8S_CONTAINER_KIND)
                roles_and_rolebindings = handleJSON.extract_content_from_kind_manifest_based_on_kind(kind_manifests_json, constantsVal.KIND_RB)
            
            print(constantsVal.SEPARATOR)
            
            if manifestContents:
                print("Start scan security attacks for Kubernetes pod YAML configuration scripts...")
                #TODO: change constantsVal.SECURITY_ATTACK_NAMES to detected_security_attacks
                for content in manifestContents:
                    scan_result = check_secuirty_attacks.scan_security_attacks(content, roles_and_rolebindings, constantsVal.SECURITY_ATTACK_NAMES)
                    # print(scan_results)
                    scan_results = [a + b for a, b in zip(scan_results, scan_result)]
            else:
                print("Can not found valid Kubernetes pod YAML configuration scripts.")
                # print("End Scanning.")
        end_time = time.time()
        # Calculate the run time
        run_time = end_time - start_time
        result_json = generate_json_result_output(scan_results, normalized_file_path)
        print(constantsVal.SEPARATOR)
        print(f"Complete scanning in {run_time}s")
        print(constantsVal.SEPARATOR)
        if result_json:
            print(result_json)
            
        
            
            
            # print(manifestContents)
        # if os.path.isdir(repo_path):
        #     print(f'start repo: {repo_path}')
        #     analysis_scripts_count, run_time = analyze_repo(repo_path)
        #     writer.writerow([file_path, repo_path, run_time])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run security attack scan on a Kubernetes YAML file."
    )

    parser.add_argument(
        "--security-attack-scan",
        action="store_true",
        help="Enable security attack scan mode."
    )
    parser.add_argument(
        "--file-path",
        type=str,
        help="Path to the Kubernetes YAML manifest file."
    )
    parser.add_argument(
        "--repo-path",
        type=str,
        help="Path to the root directory of the repository."
    )

    args = parser.parse_args()

    if args.security_attack_scan:
        if not args.file_path or not args.repo_path:
            parser.error("Both --file-path and --repo-path must be provided with --security-attack-scan.")
        main(args.file_path, args.repo_path)
    else:
        parser.print_help()

# Example usage
# change the repo path for single repo
# analyze_repo('single-repo-path')
# change the path for repos folder
# main('repos-folder-path')
# file_path = "/Users/yuezhang/research/k8s-security-acctack/longhorn/deploy/prerequisite/longhorn-cifs-installation.yaml"    
# file_path = "D:/PhD/Research/K8s-config-bugs_FSE25/final_repo_list/repos/version-checker\deploy\charts/version-checker/templates\deployment.yaml"    

# repo_path = "D:/PhD/Research/K8s-config-bugs_FSE25/final_repo_list/repos/version-checker"
# main(file_path, repo_path)




