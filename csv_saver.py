import csv
import os

csv_columns = ['ipClient', 'ipServer', 'domainSrc', 'domainDst', 
               'numberOfPackets', 'totalMbSize', 'startTime', 'endTime', 'protocol']

# Insert a row in the results csv file
def save_element(element):
    if not os.path.exists('results.csv'):
        with open('results.csv', 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            writer.writerow(element)
    else:
        with open('results.csv', 'a') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writerow(element)
