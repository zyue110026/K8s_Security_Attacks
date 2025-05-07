

SEPARATOR = '|------------------------------------------'
ANALYISIS = 'Start Analyzing........'
COMPLETE_ANA = 'Completion Analysis!'
FILEPATH_INDICATOR = '>>>'
DEFECT_INFO_SEPARATOR = '------------------------------------------'
KEY_KIND = 'kind'
KEY_NAME = 'name'
KEY_METADATA = 'metadata'
KEY_APIVERSION = 'apiVersion'
KEY_NAMESPACE = 'namespace'
K8S_MANIFESTS_KIND_CATG = 'Kind Manifests'
K8S_MANIFESTS_HELM_CATG = 'Helm Charts'
SKIP_FOLDERS = ['example', 'test', 'tests', 'e2e', 'testdata', 'sample', 'docs', '.git', '.github']
COLUMNS = ['repoPath', 'orphan_count', 'incorrect_helming_count']
WEIRD_PATHS = ['github\workflows', '.github', '.travis.yml']


K8S_FORBIDDEN_KW_LIST        = ['OpenDataHub', 'List', 'ClusterServiceVersion', 'ClusterIssuer', 'Kustomization']

SKIP_CRD = 'CustomResourceDefinition'

CLUSTER_SCOPED_KINDS = [
        'Node', 'PersistentVolume', 'ClusterRole', 'ClusterRoleBinding',
        'CustomResourceDefinition', 'StorageClass', 'VolumeAttachment',
        'CSIDriver', 'CSINode', 
        'Certificates', 'PodSecurityPolicy', 'NodeMetrics', 'Namespace'
    ]
VALID_SYS_NAMESPACE = ['kube-system']


K8S_CONTAINER_KIND = ['Pod','Deployment', 'ReplicaSet', 'DaemonSet', 'StatefulSet', 'Job', 'CronJob', "ReplicationController"]

KIND_RB = ['RoleBinding', 'ClusterRoleBinding', 'Role', 'ClusterRole']
KIND_ROLE = ['Role', 'ClusterRole']
KIND_ROLE_BINDING = ['RoleBinding', 'ClusterRoleBinding']

SECURITY_ATTACK_NAMES = ["ATTACK1_CONTAINER2HOST", "ATTACK2_DOCKER_IN_DOCKER", "ATTACK3_ENV_INFO_HARDCODED_SECRET", 
                         "ATTACK4_DOS_CPU_MEMORY", "ATTACK5_RBAC_LEAST_PRIILEGE","ATTACK6_HOSTPID", 
                         "ATTACK7_HOSTIPC", "ATTACK8_HOSTNETWORK", "ATTACK9_PRIVILEGED", "ATTACK10_POD2POD"]
WHY_CONFIG_COMB_DANGEROUS = ["With these configuration parameter combinations, the attacks allow containers to access and potentially modify the host filesystem, breaking container isolation.", #attack 1
                             "With these configuration parameter combinations, the attacks enable containers to run Docker inside Docker, giving them control over sibling containers and the host Docker daemon.", # attack 2
                             "With these configuration parameter combinations, the attacks expose sensitive secrets or credentials through environment variables, which can be easily leaked or exfiltrated.", # attack 3
                             "With these configuration parameter combinations, the attacks exploit the absence of CPU or memory limits to consume excessive resources and cause Denial of Service (DoS).", # attack 4
                             "With these configuration parameter combinations, the attacks grant overly permissive RBAC roles, violating the principle of least privilege and enabling privilege escalation.", # attack 5
                             "With these configuration parameter combinations, the attacks grant access to the host’s process namespace, allowing containers to observe or interfere with host processes.", # attack 6
                             "With these configuration parameter combinations, the attacks allow containers to share IPC resources with the host, enabling unauthorized inter-process communication.", # attack 7
                             "With these configuration parameter combinations, the attacks place containers on the host network, bypassing network isolation and firewall rules.", # attack 8
                             "With these configuration parameter combinations, the attacks run containers in privileged mode, giving them full access to all devices and capabilities on the host.", # attack 9
                             "With these configuration parameter combinations, the attacks permit unrestricted intra-cluster communication between pods, increasing the risk of lateral movement." # attack 10
                            ]

