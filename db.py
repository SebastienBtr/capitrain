import os
import pymongo

MONGO_CLUSTER_ADDRESS = os.getenv('MONGO_CLUSTER_ADDRESS')
MONGO_DB_NAME = os.getenv('MONGO_DB_NAME')
MONGO_DB_USER = os.getenv('MONGO_DB_USER')
MONGO_DB_PASSWORD = os.getenv('MONGO_DB_PASSWORD')
db = None

# Connect to db
def connect_to_db():
    global db
    cluster = pymongo.MongoClient(
        "mongodb+srv://{}:{}@{}/test?retryWrites=true&w=majority".format(MONGO_DB_USER, MONGO_DB_PASSWORD, MONGO_CLUSTER_ADDRESS))
    db = cluster[MONGO_DB_NAME]

# Insert a document in our analysed_packets collection
def save_element(element, collection_name):
    global db
    if db is None:
        raise Exception("Please connect to database before inserting an element")
    collection = db[collection_name]
    collection.insert_one(element)
