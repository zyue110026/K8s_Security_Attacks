import yaml
import security_attack_constants



def get_pod_level_security_context(content):
    pod_level_security_contect = {}
    if content:
        pod_level_security_contect = content.get("spec", {}).get("securityContext", {}) or content.get("spec", {}).get("template", {}).get("spec", {}).get("securityContext", {}) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("securityContext", {}) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("securityContext", {})
        return pod_level_security_contect
    return pod_level_security_contect

def get_all_containers(content):
    if content:
        init_containers = content.get("spec", {}).get("initContainers", [])
        containers = content.get("spec", {}).get("containers", [])
        template_init_containers = content.get("spec", {}).get("template", {}).get("spec", {}).get("initContainers", [])
        template_containers = content.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        jobtemplate_init_containers = content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("initContainers", [])
        jobtemplate_containers = content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("containers", [])
        jobtemplate_template_init_containers = content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("initContainers", [])
        jobtemplate_template_containers = content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        all_containers = init_containers + containers + template_init_containers + template_containers + jobtemplate_containers + jobtemplate_init_containers + jobtemplate_template_containers + jobtemplate_template_init_containers
        return all_containers
    return []

def get_container_level_security_context(container):
    if container:
        container_level_security_contect = container.get("securityContext", {})
        return container_level_security_contect
    return {}

def check_run_as_user(securityContext):
    if securityContext and "runAsUser" in securityContext:
        return securityContext["runAsUser"]
    return None

def check_run_as_non_root(securityContext):
    if securityContext and "runAsNonRoot" in securityContext:
        return securityContext["runAsNonRoot"]
    return None

# container level security contect

def check_read_only_root_fs(securityContext):
    if securityContext:
        # print(securityContext)
        read_only_root_fs = securityContext.get("readOnlyRootFilesystem", False)
        # print(read_only_root_fs)
        return read_only_root_fs
    return None


def check_allow_privilege_escalation(securityContext):
    if securityContext:
        allow_privilege_escalation = securityContext.get("allowPrivilegeEscalation", True)
        return allow_privilege_escalation
    return True

def check_privileged(securityContext):
    if securityContext:
        privileged = securityContext.get("privileged", False)
        return privileged
    return False

def check_capabilities_add_all(securityContext):
    if securityContext:
        capabilities_add = securityContext.get("capabilities", {}).get("add", [])
        if capabilities_add:
            # Check for any variant of ALL (case-insensitive) or -all
            for cap in capabilities_add:
                if isinstance(cap, str):
                    normalized_cap = cap.strip().lower()
                    # Case 1: Exact 'all' (any case)
                    if normalized_cap == "all":
                        return True
                        
                    # Case 2: Starts with '-' then optional spaces then 'all'
                    if normalized_cap.startswith('-'):
                        remaining = normalized_cap[1:].strip()  # Remove '-' and trim
                        if remaining == "all":
                            return True
                        
        return False
    return False


# ######## under spec

def check_hostpid(content):
    if content:
        host_pid = content.get("spec", {}).get("hostPID", False) or content.get("spec", {}).get("template", {}).get("spec", {}).get("hostPID", False) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("hostPID", False) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("hostPID", False)
        return host_pid
    return False

def check_hostipc(content):
    if content:
        host_ipc = content.get("spec", {}).get("hostIPC", False) or content.get("spec", {}).get("template", {}).get("spec", {}).get("hostIPC", False) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("hostIPC", False) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("hostIPC", False)
        return host_ipc
    return False

def check_hostnetwork(content):
    if content:
        host_network = content.get("spec", {}).get("hostNetwork", False) or content.get("spec", {}).get("template", {}).get("spec", {}).get("hostNetwork", False) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("hostNetwork", False) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("hostNetwork", False)
        return host_network
    return False

# check automountserviceaccounttoken

def check_auto_mount_sa_token(content):
    if content:
        auto_mount_sa_token = content.get("spec", {}).get("automountServiceAccountToken", True) or content.get("spec", {}).get("template", {}).get("spec", {}).get("automountServiceAccountToken", True) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("automountServiceAccountToken", True) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("automountServiceAccountToken", True)
        return auto_mount_sa_token
    return True


# volume

def check_mount_host_sys(content):
    if content:
        volumes = content.get("spec", {}).get("volumes", []) or content.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", []) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("volumes", []) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
        if volumes:
            for volume in volumes:
                if "hostPath" in volume:
                    path = volume["hostPath"].get("path", "").strip()
                    if path == "/":
                        return True
        return False                  
    return False

def check_docker_sock(content):
    if content:
        volumes = content.get("spec", {}).get("volumes", []) or content.get("spec", {}).get("template", {}).get("spec", {}).get("volumes", []) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("volumes", []) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("volumes", [])
        if volumes:
            for volume in volumes:
                if "hostPath" in volume:
                    path = volume["hostPath"].get("path", "").strip()
                    if path == "/var/run/docker.sock" or path.endswith("docker.sock"):
                        return True
        return False                  
    return False


# check if env ref a secret contain hardcoded secret

def check_hardcoded_secret_env_ref(container):
    if not container.get("env", []):
        return False

    for env_var in container["env"]:
        # print(env_var)
        if not isinstance(env_var, dict):
            continue
            
        # Check env vars with secret references
        secret_ref = env_var.get("valueFrom", {}).get("secretKeyRef", {}) or env_var.get("valueFrom", {}).get("configMapKeyRef", {})
        if not secret_ref:
            continue
            
        # Check if referenced key matches hardcoded patterns
        env_name = env_var.get("name", "").lower()
        secret_key = secret_ref.get("key", "").lower()
        if any(hardcoded_key in secret_key for hardcoded_key in security_attack_constants.HARDCODED_SECRET_KEYS) or any(hardcoded_key in env_name for hardcoded_key in security_attack_constants.HARDCODED_SECRET_KEYS):
            return True
            
        # # Optional: Verify actual secret data if available
        # if secrets:
        #     secret_name = secret_ref.get("name")
        #     secret_data = secrets.get(secret_name, {}).get("data", {})
        #     if secret_key in secret_data:
        #         secret_value = secret_data[secret_key]
        #         if is_hardcoded_value(secret_value):  # See helper below
        #             return True
                    
    return False

# check if resources limits missing
def check_pod_level_resources_limits_missing(content):
    if content:
        pod_level_resources = content.get("spec", {}).get("resources", {}) or content.get("spec", {}).get("template", {}).get("spec", {}).get("resources", {}) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("resources", {}) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("resources", {})
        if pod_level_resources:
            pod_level_resources_limits = pod_level_resources.get("limits", {})
            if pod_level_resources_limits:
                return False
            return True
        return True
    return False


def check_container_level_resources_limits_missing(container):
    if container:
        container_level_resources = container.get("resources", {})
        if container_level_resources:
            container_level_resources_limits = container_level_resources.get("limits", {})
            if container_level_resources_limits:
                return False
            return True
        return True
    return False

# check privileged role and cluster role




def check_privileged_role(role):
    if not role or not isinstance(role.get("rules"), list):
        return False
    
    for rule in role["rules"]:
        privileged_apiGroups = False
        privileged_resources = False
        privileged_verbs = False
        # Check apiGroups
        api_groups = set(rule.get("apiGroups", []))
        resources = set(rule.get("resources", []))
        verbs = set(rule.get("verbs", []))
        if "*" in api_groups or "" in api_groups:
            privileged_apiGroups = True
            
        # Check resources
        if "*" in resources:
            privileged_resources = True
            
        # Check verbs
        # "*" in verbs or verbs >= PRIVILEGED_VERBS
        if "*" in verbs or verbs.issuperset(security_attack_constants.PRIVILEGED_VERBS):
            # print(verbs)
            privileged_verbs = True
        # print(privileged_verbs)
        # print(privileged_apiGroups)
        # print(privileged_resources)

        if privileged_resources and privileged_apiGroups and privileged_verbs:
            return True
        
    return False

def get_service_account_name(content):
    
    if content:
        sa_name = content.get("spec", {}).get("serviceAccountName", None) or content.get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName", None) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("serviceAccountName", None) or content.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}).get("serviceAccountName", None)
        if sa_name:
            return sa_name
        else:
            return "default"
    return None


def find_bound_roles(service_account_name, role_bindings):
    bound_roles = []

    # Process RoleBindings (namespace-scoped Roles)
    for rb in role_bindings:
        subjects = rb.get("subjects", [])
        for subject in subjects:
            if (
                subject.get("kind") == "ServiceAccount" and
                subject.get("name") == service_account_name #and
                # subject.get("namespace") == service_account_namespace
            ):
                role_ref = rb.get("roleRef", {})
                if role_ref:
                    bound_roles.append({
                        "roleType": role_ref.get("kind"),
                        "name": role_ref.get("name")
                    })




    # # Process ClusterRoleBindings (cluster-wide ClusterRoles)
    # for crb in cluster_role_bindings:
    #     subjects = crb.get("subjects", [])
    #     for subject in subjects:
    #         if (
    #             subject.get("kind") == "ServiceAccount" and
    #             subject.get("name") == service_account_name #and
    #             # subject.get("namespace") == service_account_namespace
    #         ):
    #             role_ref = crb.get("roleRef", {})
    #             if role_ref:
    #                 bound_roles.append({
    #                     "roleType": role_ref.get("kind", "ClusterRole"),
    #                     "name": role_ref.get("name")
    #                 })

    return bound_roles



def get_related_roles_content(bound_roles, roles):
    related_roles = []
    for bound in bound_roles:
        role_type = bound.get("roleType")
        role_name = bound.get("name")

        
        for role in roles:
            if role.get("kind") == role_type and role.get("metadata", {}).get("name") == role_name:
                related_roles.append(role)
                break  # assuming unique names within namespace

    return related_roles

                
                

# with open('privileged_role_test.yaml', 'r') as file:
#     data = yaml.safe_load(file)

# privileged_role = check_privileged_role(data)

# print(privileged_role)