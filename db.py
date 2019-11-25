import os
import pymongo

MONGO_DB_ADDRESS = os.getenv('MONGO_DB_ADDRESS')
MONGO_DB_USER = os.getenv('MONGO_DB_USER')
MONGO_DB_PASSWORD = os.getenv('MONGO_DB_PASSWORD')


# Connection to mongoDB
cluster = pymongo.MongoClient(
    "mongodb+srv://{}:{}@{}/test?retryWrites=true&w=majority".format(MONGO_DB_USER, MONGO_DB_PASSWORD, MONGO_DB_ADDRESS))
capitrain_db = cluster['capitrain']
analysed_packets = capitrain_db["analysed_packets"]

# Insert a document in our analysed_packets collection
def save_element(element):
    analysed_packets.insert_one(element)
