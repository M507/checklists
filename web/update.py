import json
import re

# File to read and update
checklist_file = "checklist.js"
new_findings_file = "Hari-prasaanth_Web-App-Pentest-Checklist/parsed_tests.json"  # The JSON file generated from README.md parsing

# Step 1: Load existing checklist.js content
def load_checklist():
    try:
        with open(checklist_file, "r", encoding="utf-8") as file:
            content = file.read()

            # Extract JSON array using regex (to remove `const checklistItems =`)
            match = re.search(r"const checklistItems = (\[.*\]);", content, re.DOTALL)
            if match:
                existing_data = json.loads(match.group(1))
                return existing_data
            else:
                print("Error: Could not parse checklist.js")
                return []
    except FileNotFoundError:
        print(f"{checklist_file} not found, creating a new one.")
        return []
    except json.JSONDecodeError:
        print("Error decoding JSON from checklist.js.")
        return []

# Step 2: Load new findings from parsed_tests.json
def load_new_findings():
    try:
        with open(new_findings_file, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"{new_findings_file} not found.")
        return []
    except json.JSONDecodeError:
        print("Error decoding JSON from parsed_tests.json.")
        return []

# Step 3: Merge new findings without duplicates
def merge_findings(existing, new_findings):
    existing_titles = {item["name"] for item in existing}  # Use set for fast lookups
    merged_list = existing[:]

    for new_item in new_findings:
        if new_item["name"] not in existing_titles:
            merged_list.append(new_item)

    return merged_list

# Step 4: Save the updated checklist.js file
def save_checklist(updated_data):
    js_content = f"const checklistItems = {json.dumps(updated_data, indent=4)};\n"
    with open(checklist_file, "w", encoding="utf-8") as file:
        file.write(js_content)
    print(f"Updated {checklist_file} with merged findings.")

# Run the update process
existing_checklist = load_checklist()
new_findings = load_new_findings()
updated_checklist = merge_findings(existing_checklist, new_findings)
save_checklist(updated_checklist)
