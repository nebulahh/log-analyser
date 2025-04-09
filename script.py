# TODO
# setup threshold for each user
# send error logs to a file

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
        print(f"\n--- {event} ---")
        print(entries)
    else:
        print(f"\n--- {event} ---")
        print(entries)
        
if unmatched_log_lines:
    print("\nLines that do not match any pattern:")
    for line in unmatched_log_lines[:5]:
        print(line)