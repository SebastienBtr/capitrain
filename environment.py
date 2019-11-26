import os
from dotenv import load_dotenv
load_dotenv()

if (os.getenv('MONGO_DB_USER') is None or os.getenv('MONGO_DB_USER') == ""
    or os.getenv('MONGO_DB_PASSWORD') is None or os.getenv('MONGO_DB_PASSWORD') == ""
    or os.getenv('LISTENED_IP') is None or os.getenv('LISTENED_IP') == ""
    or os.getenv('LOCAL_IP') is None or os.getenv('LOCAL_IP') == ""
    or os.getenv('INTERFACE') is None or os.getenv('INTERFACE') == ""):
    raise Exception(
        'Please complete all the environment variables in the .env file')
