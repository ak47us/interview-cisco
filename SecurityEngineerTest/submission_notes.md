
# Overview
- There are 100,000 entries in `./data/log.json`:
    ```sh
    $ wc -l data/log.json
    100000 data/log.json
    ```
- There are 171 rows in the original `./data/seen_malware.sqlite3` file:
    ```sh
    $ sqlite3 ./data/seen_malware.sqlite3 "SELECT COUNT(*) FROM seen_malware;"
    ```
- After running `./merge.py`, we see that the upsert resulted in exactly 100,000 rows.
- My code "upserts" the data from the JSON file into the sqlite database file.

# Analysis
1. The JSON file looks like it came from a SIEM or other system monitoring tool.
2. We can see that the json log consists of various media files, documents, key files, and websites.
3. Based on context from the log file and `README.pdf`, we can assume that this data may have come from Cisco Secure Endpoint or Cisco Secure Malware Analytics
   - https://www.cisco.com/c/en/us/support/docs/security/sourcefire-amp-appliances/118121-technote-sourcefire-00.html
   - https://docs.amp.cisco.com/en/SecureEndpoint/Secure%20Endpoint%20User%20Guide.pdf
4. `analyze.py` shows more of my analysis.
5. I was unable to find any real insights from the data presented.
6. My next troubleshooting steps would be to gain access to the affected server and attempt to reproduce the issue.
7. I would also attempt to access the same resources from different clients to see if the issue can be reproduced in that way.
8. I want further context on the environment that this service is deployed in.