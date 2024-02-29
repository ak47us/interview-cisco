import datetime
import json
import matplotlib.pyplot as plt
import pandas as pd


# Get the JSON data:
json_data = list()
with open('data/log.json', 'r') as file:
    # data = json.load(file)  # The JSON file, as received from the interviewer, is missing enclosing braces and commas between each entry, so this line needed to be replaced.
    for line in file:
        json_data.append(json.loads(line))

# Use pandas to analyze and print the data:
df = pd.DataFrame(json_data)
pd.set_option('display.max_columns', None)
pd.set_option('display.max_seq_items', 10)
pd.set_option('display.max_rows', None)


# Tables:

print(f"\nA few files have been re-requested a few times:")
print( df['nm'].value_counts().sort_values(ascending=False) )
print(  df.groupby('ph')['dp'].value_counts().unstack(fill_value=0)  )

print(f"\nTop files marked as Malicious:")
filtered_df = df[df['dp'] == 1]
print( filtered_df.groupby('ph')
                  .size()
                  .to_frame(name='count')
                  .reset_index()
                  .sort_values(by='count', ascending=False)
                  .head(10) )
                  # .merge(df[['nm', 'ph']], how='left', on='nm'))
print(f"\nTop files marked as Clean:")
filtered_df = df[df['dp'] == 2]
print( filtered_df.groupby('ph')
                  .size()
                  .to_frame(name='count')
                  .reset_index()
                  .sort_values(by='count', ascending=False)
                  .head(10) )
print(f"\nTop files marked as Unknown:")
filtered_df = df[df['dp'] == 3]
print( filtered_df.groupby('ph')
                  .size()
                  .to_frame(name='count')
                  .reset_index()
                  .sort_values(by='count', ascending=False)
                  .head(10) )


print(f"\nIt appears that all files are being flagged on an equally-weighted basis (one-thirds chance of being classified in any which-way during busy periods):")
print( df['dp'].value_counts() )


# Render a chart:
timestamps             = list()
dispositions_malicious = list()
dispositions_clean     = list()
dispositions_unknown   = list()
ts_values              = list()
pt_values              = list()
si_values              = list()
uu_values              = list()
bg_values              = list()
sha_values             = list()
nm_values              = list()
ph_values              = list()
dp_values              = list()

# Separate the data for plotting
for i in json_data:
    ts_values.append( datetime.datetime.utcfromtimestamp(i["ts"]).isoformat() + 'Z' )
    pt_values.append(i["pt"])
    si_values.append(i["si"])
    uu_values.append(i["uu"])
    bg_values.append(i["bg"])
    sha_values.append(i["sha"])
    nm_values.append(i["nm"])
    ph_values.append(i["ph"])
    dp_values.append(i["dp"])
    timestamp   = i["ts"]
    disposition = i["dp"]
    ph          = i["ph"]
    if timestamp not in timestamps:
        timestamps.append(timestamp)
        # Gather all ph values:
        if disposition == 1:                      dispositions_malicious.append(ph)
        if disposition == 2:                      dispositions_clean.append(ph)
        if disposition != 1 and disposition != 2: dispositions_unknown.append(ph)
# Create the plot
index = range(len(timestamps))         # x-axis positions for each bar
plt.plot(ts_values, dp_values )  # Create bars for each timestamp and disposition
# Set labels and title
plt.xlabel("Timestamp")
plt.ylabel("Total events")
plt.title("Timestamps and Dispositions")
plt.xticks(rotation=90)
plt.tight_layout()
plt.savefig("timestamps.png")
plt.show()
