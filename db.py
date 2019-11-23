import os
import pymongo

MONGO_DB_USER = os.getenv('MONGO_DB_USER')
MONGO_DB_PASSWORD = os.getenv('MONGO_DB_PASSWORD')
analysed_packets = None

# Connection to mongoDB
def connectToCluster():
    cluster = pymongo.MongoClient(
        "mongodb+srv://{}:{}@cluster0-llznq.gcp.mongodb.net/test?retryWrites=true&w=majority".format(MONGO_DB_USER, MONGO_DB_PASSWORD))
    capitrain_db = cluster['capitrain']
    analysed_packets = capitrain_db["analysed_packets"]


# Insert a document in our analysed_packets collection
def saveOnePacket(packet):
    analysed_packets.insert_one(packet)
