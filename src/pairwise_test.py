from typing import Dict, List, Set, Union, Any
from allpairspy import AllPairs
import yaml
import json
import security_attack_constants

T_WAY_PAIR_WISE_TEST = 4

def generate_security_parameters() -> Dict[str, List[Union[str, int, List[str]]]]:
    """Extract all security parameters from the attack patterns"""
    params = {
        "hostPID": ["true", "false"],
        "hostIPC": ["true", "false"],
        "hostNetwork": ["true", "false"],
        "runAsUser": [0, "non-zero"],
        "readOnlyRootFilesystem": ["true", "false"],
        "allowPrivilegeEscalation": ["true", "false"],
        "privileged": ["true", "false"],
        "runAsNonRoot": ["true", "false"],
        "privileged_apiGroup": ["present", "missing"],
        "privileged_resources": ["present", "missing"],
        "privileged_verbs": ["present", "missing"],
        "automountServiceAccountToken": ["true", "false"],
        "resources_limits": ["present", "missing"],
        "mount_host_system": ["present", "missing"],
        "docker_sock_volume": ["present", "missing"],
        "hardcoded_secrets": ["present", "missing"],
        "hardcoded_secrets_env_ref": ["present", "missing"],
        "capabilities_add_all": ["present", "missing"],
        "at_least_two_containers": ["present", "missing"]
    }

    return params






def generate_pairwise_test_cases(t_way_pairs = 4) -> List[Dict[str, Union[str, int]]]:
    """Generate pairwise test cases from security parameters"""
    params = generate_security_parameters()
    parameters = [
        params["hostPID"],
        params["hostIPC"],
        params["hostNetwork"],
        params["runAsUser"],
        params["readOnlyRootFilesystem"],
        params["allowPrivilegeEscalation"],
        params["privileged"],
        params["runAsNonRoot"],
        params["privileged_apiGroup"],
        params["privileged_resources"],
        params["privileged_verbs"],
        params["automountServiceAccountToken"],
        params["resources_limits"],
        params["mount_host_system"],
        params["docker_sock_volume"],
        params["hardcoded_secrets"],
        params["hardcoded_secrets_env_ref"],
        params["capabilities_add_all"],
        params["at_least_two_containers"]
    ]
    # print(parameters)
    test_cases = []
    def is_valid_combination(values) -> bool:
        n = len(values)
        if n > 7:
            run_as_user = values[3]  # runAsUser is at index 3
            run_as_non_root = values[7]  # runAsNonRoot is at index 7
            # Only enforce runAsNonRoot=false if runAsUser=0
            if run_as_user == 0 and run_as_non_root == "true":
                return False
            return True  # Allow all other combinations
        return True
    
    for i, case in enumerate(AllPairs(parameters=parameters, filter_func=is_valid_combination, n = t_way_pairs)):
        test_case = {
            "hostPID": case[0],
            "hostIPC": case[1],
            "hostNetwork": case[2],
            "runAsUser": case[3],
            "readOnlyRootFilesystem": case[4],
            "allowPrivilegeEscalation": case[5],
            "privileged": case[6],
            "runAsNonRoot": case[7],
            "privileged_apiGroup": case[8],
            "privileged_resources": case[9],
            "privileged_verbs": case[10],
            "automountServiceAccountToken": case[11],
            "resources_limits": case[12],
            "mount_host_system": case[13],
            "docker_sock_volume": case[14],
            "hardcoded_secrets": case[15],
            "hardcoded_secrets_env_ref": case[16],
            "capabilities_add_all": case[17],
            "at_least_two_containers": case[18]
        }
        # print("{:2d}: {}".format(i, test_case))
        test_cases.append(test_case)

    
    return test_cases

def map_test_case_to_attack_pattern(test_case: Dict) -> Dict:
    """
    Convert a pairwise test case to the structure used in SECURITY_ATTACKS patterns
    for easier comparison.
    """
    attack_pattern_format = {}
    
    # Pod-level settings
    if test_case["hostPID"] == "true":
        attack_pattern_format["hostPID"] = "true"
    if test_case["hostIPC"] == "true":
        attack_pattern_format["hostIPC"] = "true"
    if test_case["hostNetwork"] == "true":
        attack_pattern_format["hostNetwork"] = "true"
    
    # Security context
    security_context = {}
    if test_case["runAsUser"] == 0:
        security_context["runAsUser"] = 0
    if test_case["readOnlyRootFilesystem"] == "false":
        security_context["readOnlyRootFilesystem"] = "false"
    if test_case["allowPrivilegeEscalation"] == "true":
        security_context["allowPrivilegeEscalation"] = "true"
    if test_case["privileged"] == "true":
        security_context["privileged"] = "true"
    if test_case["runAsNonRoot"] == "false":
        security_context["runAsNonRoot"] = "false"
    if test_case["capabilities_add_all"] == "present":
        security_context.setdefault("capabilities", {})["add"] = ["all"]
    
    if security_context:
        attack_pattern_format["securityContext"] = security_context
    
    # Service account
    if test_case["automountServiceAccountToken"] == "true":
        attack_pattern_format["automountServiceAccountToken"] = "true"
    
    # Resources
    if test_case["resources_limits"] == "missing":
        attack_pattern_format["resources"] = {"limits": "missing"}
    
    # Volumes
    volumes = []
    if test_case["mount_host_system"] == "present":
        volumes.append({"hostPath": {"path": "/"}})
    if test_case["docker_sock_volume"] == "present":
        volumes.append({"hostPath": {"path": "/var/run/docker.sock"}})
    if volumes:
        attack_pattern_format["volumes"] = volumes
    
    # RBAC
    if (test_case["privileged_apiGroup"] == "present" and 
        test_case["privileged_resources"] == "present" and 
        test_case["privileged_verbs"] == "present"):
        attack_pattern_format["privilegedRole"] = {
            "apiGroup": "*",
            "resources": "*",
            "verbs": "*"
        }
    
    # Secrets
    if (test_case["hardcoded_secrets"] == "present" and 
        test_case["hardcoded_secrets_env_ref"] == "present"):
        attack_pattern_format["secret"] = {
            "name": "hardcode-secret",
            "data": {"key": ["user", "password", "passwd", "pwd", "pswd", "psswd"]}
        }
        attack_pattern_format["env"] = {
            "valueFrom": {
                "secretKeyRef": {
                    "name": "hardcode-secret",
                    "key": ["user", "password", "passwd", "pwd", "pswd", "psswd"]
                }
            }
        }
    
    # Multiple containers
    if test_case["at_least_two_containers"] == "present":
        attack_pattern_format["another_victim_container"] = [
            {"name": "victim-container"}
        ]
    
    return attack_pattern_format

def is_attack_match(test_case: Dict, attack_name: str, attack_pattern: Dict) -> bool:
    """
    Check if a test case matches a specific attack pattern.
    """
    # Convert test case to attack pattern format
    test_case_pattern = map_test_case_to_attack_pattern(test_case)
    
    # # Special handling for ATTACK10_POD2POD
    # if attack_name == "ATTACK10_POD2POD":
    #     if "containers" not in test_case_pattern:
    #         return False
    #     if len(test_case_pattern["containers"]) < 2:
    #         return False
        
    #     # Check if any container matches the attacker pattern
    #     attacker_ctx = attack_pattern["containers"][0]["securityContext"]
    #     for container in test_case_pattern["containers"]:
    #         if "securityContext" in container:
    #             container_ctx = container["securityContext"]
    #             match = True
    #             for key, val in attacker_ctx.items():
    #                 if key not in container_ctx:
    #                     match = False
    #                     break
    #                 if str(container_ctx[key]).lower() != str(val).lower():
    #                     match = False
    #                     break
    #             if match:
    #                 return True
    #     return False
    
    # Normal case - compare all fields in attack pattern
    for key, expected_val in attack_pattern.items():
        if key not in test_case_pattern:
            return False
        
        # Handle nested dictionaries
        if isinstance(expected_val, dict):
            if not isinstance(test_case_pattern[key], dict):
                return False
            for sub_key, sub_val in expected_val.items():
                if sub_key not in test_case_pattern[key]:
                    return False
                if str(test_case_pattern[key][sub_key]).lower() != str(sub_val).lower():
                    return False
        # Handle lists (simplified comparison)
        elif isinstance(expected_val, list):
            if not isinstance(test_case_pattern[key], list):
                return False
            # Just check if the list isn't empty
            if not test_case_pattern[key]:
                return False
        # Handle primitive values
        else:
            if str(test_case_pattern[key]).lower() != str(expected_val).lower():
                return False
    
    return True

def analyze_test_cases(test_cases: List[Dict]) -> Dict[str, Dict]:
    """
    Analyze all test cases and return results organized by security attack.
    
    Returns:
        Dictionary with attack names as keys, each containing:
        {
            "attack_details": attack pattern details,
            "test_cases": {
                "test_case_1": first matching test case,
                "test_case_2": second matching test case,
                ...
            }
        }
    """
    results = {}
    unmatched_test_cases = []
    
    for test_case in test_cases:
        # Find which attacks this test case matches
        matched_attacks = [
            (attack_name, attack_pattern)
            for attack_name, attack_pattern in security_attack_constants.SECURITY_ATTACKS.items()
            if is_attack_match(test_case, attack_name, attack_pattern)
        ]
        if matched_attacks:
            # Add to results for each matched attack
            for attack_name, attack_pattern in matched_attacks:
                if attack_name not in results:
                    results[attack_name] = {
                        "attack_details": attack_pattern,
                        "test_cases": {}
                    }
                
                # Count existing test cases for this attack to generate the sequence number
                case_num = len(results[attack_name]["test_cases"]) + 1
                case_key = f"test_case_{case_num}"
                results[attack_name]["test_cases"][case_key] = test_case
        else:
            unmatched_test_cases.append(test_case)
    
    return results, unmatched_test_cases

def save_results(results: List[Dict], filename: str = "security_analysis_results.json"):
    """Save analysis results to a JSON file."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)

def main():
    # for tnum in range(9,20):
    # Generate pairwise test cases
    test_cases = generate_pairwise_test_cases(T_WAY_PAIR_WISE_TEST)
    print(f"Generated {len(test_cases)} test cases for {T_WAY_PAIR_WISE_TEST}-way pairwise test.")

    # Analyze which test cases match security attacks
    analysis_results, unmatched_test_cases = analyze_test_cases(test_cases)
    top_keys = [key for key in analysis_results]
    # print(len(unmatched_test_cases))
    # print(f"{tnum}: {top_keys}")
    # Save results
    save_results(analysis_results)
    
    print(f"{T_WAY_PAIR_WISE_TEST}-way pairwise test analysis complete. ")
    print(f"Found {len(test_cases)-len(unmatched_test_cases)} test cases matching {len(analysis_results)} security attacks.")
    print(f"Results saved to security_analysis_results.json")
    return top_keys, unmatched_test_cases

main()