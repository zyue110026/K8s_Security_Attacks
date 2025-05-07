import matplotlib.pyplot as plt

# Precision and recall values for each attack (index 0 is attack1)
precision = [0, 0, 1, 1, 1, 1, 0, 0, 1, 1]
recall = [0, 0, 0.470588235, 0.844067797, 1, 0.933333333, 0, 0, 0.852941176, 0.833333333]

# Detected attacks per t value (t from 1 to 19)
t_detections = {
    1: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    2: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID', 'ATTACK4_DOS_CPU_MEMORY', 'ATTACK7_HOSTIPC'],
    3: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID', 'ATTACK4_DOS_CPU_MEMORY', 'ATTACK7_HOSTIPC', 'ATTACK5_RBAC_LEAST_PRIILEGE'],
    4: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID', 'ATTACK4_DOS_CPU_MEMORY', 'ATTACK9_PRIVILEGED', 'ATTACK7_HOSTIPC', 'ATTACK5_RBAC_LEAST_PRIILEGE'],
    5: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID', 'ATTACK7_HOSTIPC', 'ATTACK4_DOS_CPU_MEMORY'],
    6: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    7: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    8: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    9: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    10: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    11: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    12: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    13: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    14: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    15: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    16: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    17: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    18: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
    19: ['ATTACK3_ENV_INFO_HARDCODED_SECRET', 'ATTACK6_HOSTPID'],
}

# Mapping from attack names to index
attack_map = {
    "ATTACK1_CONTAINER2HOST": 0,
    "ATTACK2_DOCKER_IN_DOCKER": 1,
    "ATTACK3_ENV_INFO_HARDCODED_SECRET": 2,
    "ATTACK4_DOS_CPU_MEMORY": 3,
    "ATTACK5_RBAC_LEAST_PRIILEGE": 4,
    "ATTACK6_HOSTPID": 5,
    "ATTACK7_HOSTIPC": 6,
    "ATTACK8_HOSTNETWORK": 7,
    "ATTACK9_PRIVILEGED": 8,
    "ATTACK10_POD2POD": 9
}

# Generate precision and recall for each attack over t values
t_values = range(1, 20)
attack_count = len(precision)

fig, axs = plt.subplots(3, 3, figsize=(15, 20))
axs = axs.flatten()

# Identify attacks that have all zero precision and recall across all t values
zero_attacks = []
nonzero_attacks = []

for attack_name, idx in attack_map.items():
    detected_any = False
    for t in t_values:
        if attack_name in t_detections.get(t, []):
            detected_any = True
            break
    if detected_any:
        nonzero_attacks.append((attack_name, idx))
    else:
        zero_attacks.append((attack_name, idx))

# Create new figure layout: one row for all-zero attacks, rest individually
num_nonzero = len(nonzero_attacks)
# cols = 2
# rows = num_nonzero + 1  # +1 for merged zero plot

# fig, axs = plt.subplots(rows, cols, figsize=(15, 5 * rows))
# axs = axs.flatten()

# Plot individual non-zero attacks
for i, (attack_name, idx) in enumerate(nonzero_attacks):
    attack_prec = []
    attack_rec = []
    for t in t_values:
        if attack_name in t_detections.get(t, []):
            attack_prec.append(precision[idx])
            attack_rec.append(recall[idx])
        else:
            attack_prec.append(0)
            attack_rec.append(0)
    
    axs[i].plot(t_values, attack_prec, label='Precision', marker='o')
    axs[i].plot(t_values, attack_rec, label='Recall', marker='x')
    axs[i].set_title(attack_name)
    axs[i].set_xlabel('t value')
    axs[i].set_ylabel('Score')
    axs[i].set_ylim(0, 1.1)
    axs[i].legend()
    axs[i].grid(True)
    axs[i].set_xticks(range(1, 20, 1))

# Merge plot for zero attacks
# merge_prec = [[0] * len(t_values) for _ in zero_attacks]
# merge_rec = [[0] * len(t_values) for _ in zero_attacks]

# zero_ax = axs[num_nonzero]  # Next subplot after non-zero plots
# for i, (attack_name, _) in enumerate(zero_attacks):
#     zero_ax.plot(t_values, merge_prec[i], label=f'{attack_name} Precision', linestyle='--')
#     zero_ax.plot(t_values, merge_rec[i], label=f'{attack_name} Recall', linestyle=':')
# zero_ax.set_title('All-Zero Precision and Recall Attacks')
# zero_ax.set_xlabel('t value')
# zero_ax.set_ylabel('Score')
# zero_ax.set_ylim(0, 1.1)
# zero_ax.legend()
# zero_ax.grid(True)

# Hide any unused subplots
for j in range(len(nonzero_attacks), len(axs)):
    fig.delaxes(axs[j])

plt.tight_layout(pad=3.0)
# plt.xticks(range(1, 20, 1))
plt.subplots_adjust(top=0.95, bottom=0.05, hspace=0.4, wspace=0.3)
plt.suptitle("Precision and Recall vs. t value for Each Attack", y=1.02, fontsize=16)
plt.show()