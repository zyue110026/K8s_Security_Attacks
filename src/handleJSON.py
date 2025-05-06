import json
import constantsVal
from datetime import datetime
import handleJSON

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

def save_to_json(data, file_path):
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, indent=4, cls=DateTimeEncoder)


def load_from_json(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
            return data
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None
    except json.JSONDecodeError as exc:
        print(f"Error decoding JSON from file {file_path}: {exc}")
        return None
    
# # Function to recursively find all values for a given key
# def find_values(key, dictionary):
#     if isinstance(dictionary, list):
#         for item in dictionary:
#             yield from find_values(key, item)
#     elif isinstance(dictionary, dict):
#         if key in dictionary:
#             yield dictionary[key]
#         for value in dictionary.values():
#             yield from find_values(key, value)


# if property path contain one list, then level should add 1 in addtion
def find_values(key, dictionary, level=None, current_level=0):
    results = []
    # results = {}
    # Check if current level matches the specified level (if provided)
    if level is not None and current_level == level:
        if isinstance(dictionary, dict):
            if key in dictionary:
                results.append({key: dictionary[key]})
        return results

    if isinstance(dictionary, list):
        if dictionary:  # Check if the list is empty
            current_level_list = current_level + 1
            # results.append({'filePath': current_path, key: None})
            for item in dictionary:
                results.extend(find_values(key, item, level, current_level_list))
                # print(current_level)
    elif isinstance(dictionary, dict):
        if level is None:  # Search key at any level if level is not specified
            if key in dictionary:
                results.append({key: dictionary[key]})
            # else:
            #     results.append({'filePath': current_path, key: None})
        for subkey, value in dictionary.items():
            results.extend(find_values(key, value, level, current_level + 1))
    return results

def get_find_value_results(results, key):
    if len(results) == 1:
        return results[0][key]
    else:
        return [r.get(key) for r in results]

def extract_values_from_kind_manifests(json_data, key, level=None, objects=None):
    results = []
    for item in json_data:
        file_path = item.get('filePath', '')
        manifest_contents = item.get('manifestContents', [])
        if manifest_contents:
            for manifest in manifest_contents:
                # Ensure null entry for each manifest if key is not found at top level
                key_value_pair = find_values(key, manifest, level)
                kind = find_values(constantsVal.KEY_KIND, manifest, level=0)
                metadata = find_values(constantsVal.KEY_METADATA, manifest, level=0)
                if not metadata:
                    continue
                # print(metadata)
                # print(kind)
                # if key not in manifest:
                #     results.append({'filePath': file_path, key: None})
                metadata_result = get_find_value_results(metadata, constantsVal.KEY_METADATA)
                if not metadata_result or constantsVal.KEY_NAME not in metadata_result:
                    continue
                kind_result = get_find_value_results(kind, constantsVal.KEY_KIND)
                if not kind_result:
                    continue
                
                # If objects is provided and kind does not match, skip this manifest
                if objects is not None and kind_result not in objects:
                    continue

                if len(key_value_pair) == 0:
                    results.append({
                        'filePath': file_path,
                        'kind': kind_result,
                        'name': metadata_result[constantsVal.KEY_NAME],
                        key: None
                    })
                else:
                    results.append({
                        'filePath': file_path,
                        'kind': get_find_value_results(kind, constantsVal.KEY_KIND),
                        'name': metadata_result[constantsVal.KEY_NAME],
                        key: get_find_value_results(key_value_pair, key)
                    })
    return results

def extract_content_from_helm_chart_based_on_file_path(json_data, file_path):
    contents = []
    valuesYamlPath = ""
    for item in json_data:
        chartPath = item.get('valuesYamlPath', "")
        templates = item.get('templates', [])
        for template in templates:
            template_path = template.get('templatePath', '')
            if template_path == file_path:
                valuesYamlPath = chartPath
                template_contents = template.get('templateContents', [])
                if template_contents:
                    for template_content in template_contents:
                        kind = handleJSON.find_values(constantsVal.KEY_KIND, template_content, level=0)
                        kind_value = handleJSON.get_find_value_results(kind, constantsVal.KEY_KIND)
                        if kind and any(k_value in kind_value for k_value in constantsVal.K8S_CONTAINER_KIND):
                            contents.append(template_content)
    return contents, valuesYamlPath

def extract_content_from_helm_chart_based_on_kind(json_data, required_kind):
    contents = []
    
    for item in json_data:
        templates = item.get('templates', [])
        for template in templates:
            template_path = template.get('templatePath', '')
           
            template_contents = template.get('templateContents', [])
            if template_contents:
                for template_content in template_contents:
                    kind = handleJSON.find_values(constantsVal.KEY_KIND, template_content, level=0)
                    kind_value = handleJSON.get_find_value_results(kind, constantsVal.KEY_KIND)
                    if kind and any(k_value in kind_value for k_value in required_kind):
                        contents.append(template_content)
    return contents

def extract_content_from_kind_manifest_based_on_kind(json_data, required_kind):
    contents = []
    for item in json_data:
        manifestContents = item.get('manifestContents', [])
        for content in manifestContents:
            
            if content:
                
                kind = handleJSON.find_values(constantsVal.KEY_KIND, content, level=0)
                kind_value = handleJSON.get_find_value_results(kind, constantsVal.KEY_KIND)
                if kind and any(k_value in kind_value for k_value in required_kind):
                    contents.append(content)
    return contents

def extract_values_from_helm_charts(json_data, key, level=None, objects=None):
    results = []

    for item in json_data:
        templates = item.get('templates', [])
        for template in templates:
            template_path = template.get('templatePath', '')
            template_contents = template.get('templateContents', {})
            if template_contents:
                for template_content in template_contents:
                    key_value_pair = find_values(key, template_content, level)
                    kind = find_values(constantsVal.KEY_KIND, template_content, level=0)
                    metadata = find_values(constantsVal.KEY_METADATA, template_content, level=0)
                    if not metadata:
                        continue
                    # Ensure null entry for each template if key is not found at top level
                    # if key not in template_contents:
                    #     results.append({'filePath': template_path, key: None})
                    metadata_result = get_find_value_results(metadata, constantsVal.KEY_METADATA)
                    if not metadata_result or constantsVal.KEY_NAME not in metadata_result:
                        continue
                    kind_result = get_find_value_results(kind, constantsVal.KEY_KIND)
                    if not kind_result:
                        continue

                    # If objects is provided and kind does not match, skip this manifest
                    if objects is not None and kind_result not in objects:
                        continue

                    if len(key_value_pair) == 0:
                        results.append({
                            'filePath': template_path,
                            'kind': kind_result,
                            'name': metadata_result[constantsVal.KEY_NAME],
                            key: None
                        })
                    else:
                        results.append({
                            'filePath': template_path,
                            'kind': get_find_value_results(kind, constantsVal.KEY_KIND),
                            'name': metadata_result[constantsVal.KEY_NAME],
                            key: get_find_value_results(key_value_pair, key)
                        })
    return results

def extract_values_based_on_manifest_type(json_data, key, type, level=None, objects=None):
    results = []
    if type == constantsVal.K8S_MANIFESTS_KIND_CATG:
        for item in json_data:
            file_path = item.get('filePath', '')
            manifest_contents = item.get('manifestContents', [])
            if manifest_contents:
                for manifest in manifest_contents:
                    # Ensure null entry for each manifest if key is not found at top level
                    key_value_pair = find_values(key, manifest, level)
                    kind = find_values(constantsVal.KEY_KIND, manifest, level=0)
                    metadata = find_values(constantsVal.KEY_METADATA, manifest, level=0)
                    if not metadata:
                        continue
                    # print(kind)
                    # if key not in manifest:
                    #     results.append({'filePath': file_path, key: None})
                    # print(metadata)
                    metadata_result = get_find_value_results(metadata, constantsVal.KEY_METADATA)
                    if not metadata_result or constantsVal.KEY_NAME not in metadata_result:
                        # print(metadata)
                        continue
                    # print(metadata_result)
                    kind_result = get_find_value_results(kind, constantsVal.KEY_KIND)
                    if not kind_result:
                        continue
                    # print(kind_result)
                    # print(objects)
                    # If objects is provided and kind does not match, skip this manifest
                    # print(not objects)
                    if objects is not None and kind_result not in objects:
                        # print(kind_result)
                        continue

                    if len(key_value_pair) == 0:
                        results.append({
                            'filePath': file_path,
                            'kind': kind_result,
                            'name': metadata_result[constantsVal.KEY_NAME],
                            key: None
                        })
                    else:
                        results.append({
                            'filePath': file_path,
                            'kind': get_find_value_results(kind, constantsVal.KEY_KIND),
                            'name': metadata_result[constantsVal.KEY_NAME],
                            key: get_find_value_results(key_value_pair, key)
                        })
    if type == constantsVal.K8S_MANIFESTS_HELM_CATG:
        for item in json_data:
            templates = item.get('templates', [])
            for template in templates:
                template_path = template.get('templatePath', '')
                template_contents = template.get('templateContents', {})
                if template_contents:
                    for template_content in template_contents:
                        key_value_pair = find_values(key, template_content, level)
                        kind = find_values(constantsVal.KEY_KIND, template_content, level=0)
                        metadata = find_values(constantsVal.KEY_METADATA, template_content, level=0)
                        if not metadata:
                            continue
                        # Ensure null entry for each template if key is not found at top level
                        # if key not in template_contents:
                        #     results.append({'filePath': template_path, key: None})
                        metadata_result = get_find_value_results(metadata, constantsVal.KEY_METADATA)
                        # print(metadata)
                        # print(metadata_result)
                        if not metadata_result or constantsVal.KEY_NAME not in metadata_result:
                            continue
                        kind_result = get_find_value_results(kind, constantsVal.KEY_KIND)
                        if not kind_result:
                            continue

                        # If objects is provided and kind does not match, skip this manifest
                        if objects is not None and kind_result not in objects:
                            continue

                        if len(key_value_pair) == 0:
                            results.append({
                                'filePath': template_path,
                                'kind': kind_result,
                                'name': metadata_result[constantsVal.KEY_NAME],
                                key: None
                            })
                        else:
                            results.append({
                                'filePath': template_path,
                                'kind': get_find_value_results(kind, constantsVal.KEY_KIND),
                                'name': metadata_result[constantsVal.KEY_NAME],
                                key: get_find_value_results(key_value_pair, key)
                            })
    if type != constantsVal.K8S_MANIFESTS_KIND_CATG and type != constantsVal.K8S_MANIFESTS_HELM_CATG:
        print(f'Failed to extract value for key: {key}, due to invalid manifest type: {type}')
        return
    # # print(type)
    # for item in json_data:
    #     if  type == constantsVal.K8S_MANIFESTS_KIND_CATG:
    #         # print('aa')
    #         file_path = item.get('filePath', '')
    #         manifest_contents = item.get('manifestContents', [])
    #     if type == constantsVal.K8S_MANIFESTS_HELM_CATG:
    #         # print('kk')
    #         templates = item.get('templates', [])
    #         for template in templates:
    #             file_path = template.get('templatePath', '')
    #             manifest_contents = template.get('templateContents', {})
    #             # print(file_path)
    #     else:
    #         print(f'Failed to extract value for key: {key}, due to invalid manifest type: {type}')
    #         break
    #     if manifest_contents:
    #         for manifest in manifest_contents:
    #             # Ensure null entry for each manifest if key is not found at top level
    #             key_value_pair = find_values(key, manifest, level)
    #             kind = find_values(constantsVal.KEY_KIND, manifest, level=0)
    #             metadata = find_values(constantsVal.KEY_METADATA, manifest, level=0)
    #             # print(kind)
    #             # if key not in manifest:
    #             #     results.append({'filePath': file_path, key: None})
    #             metadata_result = get_find_value_results(metadata, constantsVal.KEY_METADATA)
    #             kind_result = get_find_value_results(kind, constantsVal.KEY_KIND)
                
    #             # If objects is provided and kind does not match, skip this manifest
    #             if objects is not None and kind_result not in objects:
    #                 continue
    #             if not metadata_result or constantsVal.KEY_NAME not in metadata_result:
    #                 continue
    #             # print(metadata_result)
    #             if len(key_value_pair) == 0:
    #                 results.append({
    #                     'filePath': file_path,
    #                     'kind': kind_result,
    #                     'name': metadata_result[constantsVal.KEY_NAME],
    #                     key: None
    #                 })
    #             else:
    #                 results.append({
    #                     'filePath': file_path,
    #                     'kind': kind_result,
    #                     'name': metadata_result[constantsVal.KEY_NAME],
    #                     key: get_find_value_results(key_value_pair, key)
    #                 })
    return results




# data = {
#     "volumes": [
#         {
#             "configMap": {
#                 "name": "argocd-ssh-known-hosts-cm"
#             },
#             "name": "ssh-known-hosts"
#         },
#         {
#             "configMap": {
#                 "name": "argocd-tls-certs-cm"
#             },
#             "name": "tls-certs"
#         }
#     ]
# }

# result = find_values("name", data, level=2)
# print(result)

# Example usage
# with open('...', 'r') as kind_file:
#     kind_manifests = json.load(kind_file)

# with open('...', 'r') as helm_file:
#     helm_charts = json.load(helm_file)

# key_to_find = 'namespace'

# kind_results = extract_values_from_kind_manifests(kind_manifests, key_to_find, level=1)
# helm_results = extract_values_from_helm_charts(helm_charts, key_to_find, level=1)

# # Combine results
# all_results = kind_results + helm_results

# Print or save the results
# print(all_results)


# combined_data = combine_and_check_namespace_consistency(all_results)
# print(combined_data)
