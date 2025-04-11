# TODO send error logs to a file
# TODO add AWS lambda function to send alert

import re

patterns = {
    "failed_login": re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*Failed password for (?:invalid user\s+)?(?P<user>\w+).* from (?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    ),
    "successful_login": re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*Accepted password for (?P<user>\w+).* from (?P<ip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    ),
    "privilege_escalation": re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*sudo:.*session opened for user (?P<target_user>\w+)"
    )
}

results = {event: [] for event in patterns}
unmatched_log_lines = []

def add_threshold(failed_login_entries):
    failed_login_username = []
    for x in failed_login_entries:
        failed_login_username.append(x['user'])
        username_count = failed_login_username.count(x['user'])
        x['occurrence'] = username_count
        if x['occurrence'] > 4:
            print(f'User: {x['user']} account lockout. send alert')
    
    return failed_login_entries

with open(r"auth.log", "r") as file:
    for line in file:
        line = line.strip()
        is_event_match_pattern = False

        for event, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                results[event].append(match.groupdict())
                is_event_match_pattern = True
                break  
        if not is_event_match_pattern:
            unmatched_log_lines.append(line)

print("Summary of events parsed:")
for event, entries in results.items():
    print(f"{event}: {len(entries)} entries")

print("\nEntries from each event:")
for event, entries in results.items():
    if event == 'failed_login':
        result = add_threshold(entries)
        print(f"\n--- {event} ---")
        print(result)
    else:
        print(f"\n--- {event} ---")
        print(entries)
        
if unmatched_log_lines:
    print("\nLines that do not match any pattern:")
    for line in unmatched_log_lines[:5]:
        print(line)