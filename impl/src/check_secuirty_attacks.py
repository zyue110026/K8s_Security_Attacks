import check_security_config
import yaml
import constantsVal
import handleJSON

def scan_security_attacks(content, roles_and_rolebindings, detectedSecurityAttacks = []):
    attack1 = 0
    attack2 = 0
    attack3 = 0
    attack4 = 0
    attack5 = 0
    attack6 = 0
    attack7 = 0
    attack8 = 0
    attack9 = 0
    attack10 = 0
    pod_level_sc = check_security_config.get_pod_level_security_context(content)
    pod_run_as_user = check_security_config.check_run_as_user(pod_level_sc) if pod_level_sc else None
    pod_run_as_non_root = check_security_config.check_run_as_non_root(pod_level_sc) if pod_level_sc else None
    pod_read_only_root_fs = check_security_config.check_read_only_root_fs(pod_level_sc) if pod_level_sc else None
    host_network = check_security_config.check_hostnetwork(content)
    host_pid = check_security_config.check_hostpid(content)
    host_ipc = check_security_config.check_hostipc(content)
    all_containers = check_security_config.get_all_containers(content)
    # print(pod_level_sc)
    service_account_name = check_security_config.get_service_account_name(content)
    pod_resources_limits_missiing = check_security_config.check_pod_level_resources_limits_missing(content)
    auto_mount_sa_token = check_security_config.check_auto_mount_sa_token(content)
    roles = []
    role_bindings = []
    # print(pod_resources_limits_missiing)
    

    #check for attack 6
    if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[5] in detectedSecurityAttacks:
        if host_pid:
            attack6 += 1
            # print("attack 6 found")
    # print(all_containers)
    for container in all_containers:
        container_level_sc = check_security_config.get_container_level_security_context(container)
        
        # print(container_level_sc)
        container_run_as_user = check_security_config.check_run_as_user(container_level_sc) if container_level_sc else None
        container_run_as_non_root = check_security_config.check_run_as_non_root(container_level_sc) if container_level_sc else None
        container_read_only_root_fs = check_security_config.check_read_only_root_fs(container_level_sc) if container_level_sc else None
        container_resources_limits_missing = check_security_config.check_container_level_resources_limits_missing(container)
        # print(container)
        # print(container_resources_limits_missing)
        # print(container_read_only_root_fs)
        #check for attack 3
        if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[2] in detectedSecurityAttacks:
            # print("check for security attack 3....")
            hardcoded_secret_env_ref = check_security_config.check_hardcoded_secret_env_ref(container)
            
            if hardcoded_secret_env_ref:
                attack3 += 1
                # print("security attack 3 found")
        # Prefer container-level setting, fall back to pod-level if not set
        if container_run_as_user is not None:
            effective_run_as_user = container_run_as_user
        elif pod_run_as_user is not None:
            effective_run_as_user = pod_run_as_user
        else:
            effective_run_as_user = 0
        # print(effective_run_as_user)
        if container_run_as_non_root is not None:
            effective_run_as_non_root = container_run_as_non_root
        elif pod_run_as_non_root is not None:
            effective_run_as_non_root = pod_run_as_non_root
        else:
            effective_run_as_non_root = False
        
        if container_read_only_root_fs is not None:
            effective_read_only_root_fs = container_read_only_root_fs
        elif pod_read_only_root_fs is not None:
            effective_read_only_root_fs = pod_read_only_root_fs
        else:
            effective_read_only_root_fs = False
        # print(effective_run_as_non_root)
        # print(effective_read_only_root_fs)
        # runAsUser: 0, runAsNonRoot: false, readOnlyRootFileSystem: false
        # are requied by attack 1, 2, 4, 5, 7, 8, 9, and 10, total 8 attacks
        if not effective_run_as_non_root and effective_run_as_user == 0 and not effective_read_only_root_fs:
            
            #check for privileged role
            if roles_and_rolebindings:
                for r_or_rb in roles_and_rolebindings:
                    kind = handleJSON.find_values(constantsVal.KEY_KIND, r_or_rb, level=0)
                    kind_value = handleJSON.get_find_value_results(kind, constantsVal.KEY_KIND)
                    #get roles and cluster roles
                    
                    if kind and any(k_value in kind_value for k_value in constantsVal.KIND_ROLE):
                        roles.append(r_or_rb)
                    #get rolebindings and cluster role bindings
                    
                    if kind and any(k_value in kind_value for k_value in constantsVal.KIND_ROLE_BINDING):
                        role_bindings.append(r_or_rb) 
            
            if service_account_name:
                bound_roles = check_security_config.find_bound_roles(service_account_name, role_bindings)

            if bound_roles:
                related_roles = check_security_config.get_related_roles_content(bound_roles, roles)
            else:
                related_roles = []

            # default value
            privileged_role = False
            if related_roles:
                for related_role in related_roles:
                    privileged_role = check_security_config.check_privileged_role(related_role)
                    if privileged_role:
                        break # Exit early if a privileged role is found
            # print(service_account_name)
            # print("continue check")
            # privileged: true is reuqired for attack 1, 8, 9, 10
            privileged = check_security_config.check_privileged(container_level_sc)
            # print(privileged)

            # allowPrivilegeEscalation: true is required by attack 1, 2, 8, 9, 10
            allow_privilege_escalation = check_security_config.check_allow_privilege_escalation(container)

            if privileged:
                # start check for attack 2
                if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[1] in detectedSecurityAttacks:
                    mount_docker_sock = check_security_config.check_docker_sock(content)
                    if mount_docker_sock:
                        attack2 += 1
                        # print("security attack 2 found")

            if privileged and allow_privilege_escalation:
                # start check for attack 1
                if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[0] in detectedSecurityAttacks:
                    mount_host_sys = check_security_config.check_mount_host_sys(content)
                    if mount_host_sys and privileged_role:
                        attack1 += 1
                        # print("security attack 1 found")

                #start check for attack 8
                if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[7] in detectedSecurityAttacks:
                    if host_network:
                        capabilities_add_all = check_security_config.check_capabilities_add_all(container)
                        if capabilities_add_all:
                            attack8 += 1
                            # print("security attack 8 found")
                        
                #start check for attack 9
                if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[8] in detectedSecurityAttacks:
                    attack9 += 1
                    # print("security attack 9 found")

            #check for attack 4, 5, 7
            #check for attack 4, 
            if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[3] in detectedSecurityAttacks:
                # print("start checking attack 4....")
                # print(container_resources_limits_missing)
                # print(pod_resources_limits_missiing)
                if container_resources_limits_missing and pod_resources_limits_missiing:
                    attack4 += 1
                    # print("security attack 4 found")

            #check for attack 5
            if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[4] in detectedSecurityAttacks:
                if auto_mount_sa_token and privileged_role:
                    attack5 += 1

                    # print("security attack 5 found")
            #check for attack 7
            if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[6] in detectedSecurityAttacks:
                if host_ipc:
                    attack7 += 1
                    # print("security attack 7 found")
                        
    #start check for attack 10
    #check if victim container exists
    if detectedSecurityAttacks and constantsVal.SECURITY_ATTACK_NAMES[9] in detectedSecurityAttacks:
        container_num = len(all_containers)
        if container_num > attack9 and attack9 > 0:
            attack10 += 1
            # print("security attack 10 found")
    
    return [attack1, attack2, attack3, attack4, attack5, attack6, attack7, attack8, attack9, attack10]
                



        
        


# file_path = "/Users/yuezhang/research/k8s-security-acctack/longhorn/deploy/prerequisite/longhorn-cifs-installation.yaml"    
# try:
#     with open(file_path, 'r', encoding='utf-8') as stream:
#         manifests = yaml.safe_load_all(stream)
        
#         for manifest in manifests:
            
#             scan_security_attacks(manifest)

# except yaml.YAMLError as exc:
#     print(f"loadMultiYamlFile: Error parsing YAML file {file_path}: {exc}")