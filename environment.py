import os
from dotenv import load_dotenv
load_dotenv()

# Check if we have all the environment variables for the sniffer
def check_sniffer_env():
    if ((os.getenv('LISTENED_IP') is None or os.getenv('LISTENED_IP') == "") 
        or (os.getenv('LISTENED_IPV6') is None or os.getenv('LISTENED_IPV6') == "")
        or (os.getenv('LOCAL_IP') is None or os.getenv('LOCAL_IP') == "")
        or (os.getenv('LOCAL_IPV6') is None or os.getenv('LOCAL_IPV6') == "")
        or os.getenv('INTERFACE') is None or os.getenv('INTERFACE') == ""):
        raise Exception(
            '\n\nPlease complete the following environment variables in the .env file:\nLISTENED_IP\nLOCAL_IP\nINTERFACE\n')


# Check if we have all the environment variables for mongoDB
def check_mongo_env():
    if (os.getenv('MONGO_CLUSTER_ADDRESS') is None or os.getenv('MONGO_CLUSTER_ADDRESS') == ""
        or os.getenv('MONGO_DB_NAME') is None or os.getenv('MONGO_DB_NAME') == ""
        or os.getenv('MONGO_DB_USER') is None or os.getenv('MONGO_DB_USER') == ""
        or os.getenv('MONGO_DB_PASSWORD') is None or os.getenv('MONGO_DB_PASSWORD') == ""):
        raise Exception(
            '\n\nPlease complete the following environment variables in the .env file:\nMONGO_CLUSTER_ADDRESS\nMONGO_DB_NAME\nMONGO_DB_USER\nMONGO_DB_PASSWORD\n')
