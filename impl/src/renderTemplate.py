import os
import yaml
import subprocess
from glob import glob
import constantsVal


def load_yaml(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(f"Error parsing YAML file {file_path}: {exc}")
        return None


# render template via helm cli
def render_helm_template(chart_dir, values_file_path_dic, template_path):
    try:
        relative_template_path = os.path.relpath(template_path, chart_dir)
        if any(folder in relative_template_path for folder in constantsVal.SKIP_FOLDERS):
            print(f'skip template: {relative_template_path}')
            return None
        if values_file_path_dic['valuesFilePath']:
            values_path = values_file_path_dic['valuesFilePath']
            if values_file_path_dic['parentValuesFilePath']:
                parent_chart_path = values_file_path_dic['parentValuesFilePath']
                cmd = ['helm', 'template', chart_dir, '-f', values_path, '-f', parent_chart_path, '--show-only', relative_template_path, '--namespace', 'tool']
            else:
                cmd = ['helm', 'template', chart_dir, '-f', values_path, '--show-only', relative_template_path, '--namespace', 'tool']
        # print(cmd)
        # , '--namespace', 'your-namespace'
        rendered_template = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
       
        # print(f"Running command: {' '.join(cmd)}")
        # Parse the rendered output
        rendered_docs = list(yaml.safe_load_all(rendered_template))
        # Check if rendered template is empty or not
        # if not rendered_template.strip():
        #     print(f"Template {template_path} did not render any content.")
        #     return None

        return rendered_docs
    
    except subprocess.CalledProcessError as exc:
        error_message = exc.output
        error_lines = [line for line in error_message.split('\n') if line.strip() and line.startswith('Error')]
        if any("could not find template" in line for line in error_lines):
            print(f"Template {template_path} did not render any content due to some condition directives or template can not found under 'charts-dir/templates' folder.")
        else:
            for line in error_lines:
                
                if relative_template_path.replace("\\", "/") in line:
                    print(f"{constantsVal.SEPARATOR}")
                    print(f"{constantsVal.FILEPATH_INDICATOR} {template_path}")
                    # print(f"Syntac error: Error rendering Helm template with values {values_path}: {error_message}")
                    
                    print(f"{constantsVal.DEFECT_INFO_SEPARATOR}")
                    print(f"{line}")
        return None
    except Exception as exc:
        print(f"General error rendering template {template_path}: {exc}")
        return None


# json structure for collected rendered template files
def process_template(chart_dir, templates_dir, values_file_path_dic):
# def process_repository(repo_path):
    helm_charts = []
    # charts = glob(os.path.join(repo_path, '**/Chart.yaml'), recursive=True)

    # for chart in charts:
    #     chart_dir = os.path.dirname(chart)
    #     values_path = os.path.join(chart_dir, 'values.yaml')
    #     templates_dir = os.path.join(chart_dir, 'templates')

    #     if not os.path.exists(values_path) or not os.path.isdir(templates_dir):
    #         continue

    #     values = load_yaml(values_path)
    #     if values is None:
    #         continue

    templates = []
    for root, _, files in os.walk(templates_dir):
        for file in files:
            if file.endswith('.yaml') or file.endswith('.yml'):
                template_path = os.path.join(root, file)
                
                rendered_templates = render_helm_template(chart_dir, values_file_path_dic, template_path)
                if render_helm_template:
                    # print('have redered template')
                    with open(template_path, 'r', encoding='utf-8') as file:
                        template_content = file.read()
                        templates.append({
                            'templatePath': template_path,
                            'templateContents': rendered_templates
                        })

    # rendered_templates = render_helm_template(chart_dir, values_path, template_path)
    if templates:
        helm_charts.append({
            'valuesYamlPath': values_file_path_dic['valuesFilePath'],
            'templates': templates
            # 'renderedTemplates': rendered_templates
        })
    # print(helm_charts)
    return helm_charts


# def main(folder_path):
#     for repo in os.listdir(folder_path):
#         repo_path = os.path.join(folder_path, repo)
#         if os.path.isdir(repo_path):
#             helm_charts = process_template(repo_path)
#             json_path = os.path.join(repo_path, 'helm_charts.json')
#             save_to_json(helm_charts, json_path)

# if __name__ == "__main__":
#     folder_path = '...'  # Replace with your folder path
#     main(folder_path)