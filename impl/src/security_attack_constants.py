from typing import Final, Dict, List, Optional, Union
import constantsVal

SECURITY_ATTACK_NAMES = constantsVal.SECURITY_ATTACK_NAMES

PRIVILEGED_VERBS = {
    "get", "list", "watch", "create", "update", "patch",
    "delete", "deletecollection"   #, "exec", "portforward"
}

HARDCODED_SECRET_KEYS = {"user", "password", "passwd", "pwd", "pswd", "psswd"}

SECURITY_ATTACKS = {
    SECURITY_ATTACK_NAMES[0]: {
        "securityContext": {
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "allowPrivilegeEscalation": "true", 
            "privileged": "true",
            "runAsNonRoot": "false"
        },
        "volumes": {
            "hostPath": {"path": "/"}
        },
        # kind: role, clusterrole
        "privilegedRole": { 
            "apiGroup": "*",
            "resources": "*",
            "verbs": "*", #["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]]
        }

    },

    SECURITY_ATTACK_NAMES[1]: {
        "securityContext": {
            # "runAsGroup": 0 or deault value,
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "allowPrivilegeEscalation": "true", 
            "runAsNonRoot": "false"
        },
        # "volumeMounts": {
        #     "mountPath": "/var/run/docker.sock" //5
        # },
        "volume": {
            "hostPath": {"path": "/var/run/docker.sock"}
        },
    },

    SECURITY_ATTACK_NAMES[2]: {
        # kind = secret
        "secret": {
            "name": "hardcode-secret",
            "data": {
                # keys in secret data field which contains hardcoded secret
                "key": ["user", "password", "passwd", "pwd", "pswd", "psswd"]
            }, 
        },
        # kind contain pod
        "env": {
            # the name of secret should keep the same as the secret contain hardcoded secret
            # "name": "HARDCODEDSECRET",
            "valueFrom": {
                "secretKeyRef": {
                    # name is the secret name
                    "name": "hardcode-secret",
                    # key value can be any of these value
                    "key": ["user", "password", "passwd", "pwd", "pswd", "psswd"] 
                }
            }
        }
    },

    SECURITY_ATTACK_NAMES[3]: {
        "securityContext": {
            # "runAsGroup": 0, 
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "runAsNonRoot": "false", 
        },
        "resources": {
            # missing resource limits for container, considering pod level and container level resource limits
            "limits": "missing" 
        }
    },


    SECURITY_ATTACK_NAMES[4]:{
        "securityContext": {
            # "runAsGroup": 0 or deault value, //1
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "runAsNonRoot": "false"
        },
        "automountServiceAccountToken": "true", 
        # kind: role, clusterrole
        "privilegedRole": { 
            "apiGroup": "*",
            "resources": "*",
            "verbs": "*", #["get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"]]

        }
    },

    SECURITY_ATTACK_NAMES[5]: {
        "hostPID": "true"
    },


    SECURITY_ATTACK_NAMES[6]: {
        "hostIPC": "true",   
        "securityContext": {
            # "runAsGroup": 0 or deault value, //2
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "runAsNonRoot": "false"
        },

    },



    SECURITY_ATTACK_NAMES[7]: {
        "hostNetwork": "true",   
        "securityContext": {
            # "runAsGroup": 0 or default value, //2
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "runAsNonRoot": "false",
            "allowPrivilegeEscalation": "true", 
            "capabilities": {
                "add": ["all"]
            }, 
            "privileged": "true"
        },
    },


    SECURITY_ATTACK_NAMES[8]: {
        "securityContext": {
            # "runAsGroup": 0 or default value, //1
            "runAsUser": 0, 
            "readOnlyRootFilesystem": "false", 
            "runAsNonRoot": "false",
            "allowPrivilegeEscalation": "true", 
            "privileged": "true" 
        }
    },
    # This attack require a container within one pod satisfied attack 9 and another
    # container within the same pod as victim container
    SECURITY_ATTACK_NAMES[9]: {
       "securityContext": {
                    # "runAsGroup": 0 or default value,
                    "runAsUser": 0, 
                    "readOnlyRootFilesystem": "false", 
                    "allowPrivilegeEscalation": "true", 
                    "privileged": "true",
                    "runAsNonRoot": "false"
                },
                

            "another_victim_container":{
                "name": "victim-container"  
            } # security context in victim-container is not important
                
            
    }
}
