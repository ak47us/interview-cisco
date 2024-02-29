import datetime
import json
import matplotlib.pyplot as plt
import pandas as pd
import sqlite3




# Get the JSON data:
json_data = list()
with open('data/log.json', 'r') as file:
    # data = json.load(file)  # The JSON file, as received from the interviewer, is missing enclosing braces and commas between each entry, so this line needed to be replaced.
    for line in file:
        json_data.append(json.loads(line))

# Keep track of how many unknown dispositions found:
unknown_dispositions = list()

# Open the database file:
conn = sqlite3.connect('data/seen_malware.sqlite3')
cursor = conn.cursor()

insert_counter    = 0
change_counter    = 0
iteration_counter = 0

print(f"Searching the sqlite file for {len(json_data)} entries from the JSON file.")


# This is super slow. Maybe it can be sped up with multiprocessing if we have more time:
for entry in json_data:
    if entry['dp'] != 1 and entry['dp'] != 2:
        unknown_dispositions.append(entry)
    cursor.execute("SELECT * FROM {} WHERE {} LIKE ?".format('seen_malware', 'sha'), ('%' + entry['sha'] + '%',))
    row = cursor.fetchall()
    if row:
        # print(f"Found {len(row)} occurrence(s) for hash: {entry['sha']}. Incrementing 'cnt' column by 1.")
        # Execute the update query:
        new_cnt_value = int(row[0][1]) + 1  # 'cnt' column
        query = """
            UPDATE {table} SET cnt = ? WHERE sha = ?
            """.format(table='seen_malware')
        cursor.execute(query,
                       (new_cnt_value, entry['sha']))
        change_counter += 1
    else:
        # print(f"No occurrences found for entry: {entry}. Adding a new entry to the database.")
        # Execute the insert query
        query = """
            INSERT INTO {table} (sha, cnt, dp)
            VALUES (?, 1, ?)
            """.format(table='seen_malware')
        cursor.execute(query,
                       (entry['sha'], entry['dp']))
        insert_counter += 1
    iteration_counter += 1
    if iteration_counter % 100 == 0:
        print(f"Search iteration number {iteration_counter}.")
try:
    print(f"Writing {insert_counter} inserts and {change_counter} changes to the sqlite file...")
    conn.commit()  # Commit the changes to the database file
except Exception as e:
    print(f"{e}")
pass


# make_graphs(json_data)

print(f"Done. Found {len(unknown_dispositions)} unknown dispositions.")
