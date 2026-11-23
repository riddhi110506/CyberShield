MITRE_TECHNIQUES = {
    "command_execution": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "description": "Execution of commands or scripts through an interpreter."
    },

    "powershell": {
        "id": "T1059.001",
        "name": "PowerShell",
        "description": "Execution of commands and scripts using PowerShell."
    },

    "scheduled_task": {
        "id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "description": "Use of scheduled tasks for execution or persistence."
    },

    "process_discovery": {
        "id": "T1057",
        "name": "Process Discovery",
        "description": "Discovery of running processes on a system."
    },

    "certutil": {
        "id": "T1140",
        "name": "Deobfuscate/Decode Files or Information",
        "description": "Use of certutil or similar utilities may indicate decoding or transformation of encoded data."
    }
}


def get_technique(behavior):
    return MITRE_TECHNIQUES.get(behavior)


def map_behaviors(behaviors):
    results = []

    for behavior in behaviors:

        technique = get_technique(behavior)

        if technique and technique not in results:
            results.append(technique)

    return results
