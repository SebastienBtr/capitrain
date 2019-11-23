import os
import pymongo

MONGO_DB_USER = os.getenv('MONGO_DB_USER')
MONGO_DB_PASSWORD = os.getenv('MONGO_DB_PASSWORD')
analyzed_packets = None


def connectToCluster():
    cluster = pymongo.MongoClient(
        "mongodb+srv://{}:{}@cluster0-llznq.gcp.mongodb.net/test?retryWrites=true&w=majority".format(MONGO_DB_USER, MONGO_DB_PASSWORD))
    capitrain_db = cluster['capitrain']
    analyzed_packets = capitrain_db["analyzed_packets"]


def saveOnePacket(packet):
    analyzed_packets.insert_one(packet)
