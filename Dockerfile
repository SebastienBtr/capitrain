FROM ubuntu:18.04

ARG mongoDbUser
ARG mongoDbPassword
ARG listenedIp

ENV MONGO_DB_USER $mongoDbUser
ENV MONGO_DB_PASSWORD $mongoDbPassword
ENV DEBIAN_FRONTEND noninteractive
ENV LISTENED_IP $listenedIp

COPY requirements.txt sniffer.py analyze_tcp_packets.py ./

RUN apt-get update && apt-get install -y \
    python3-pip \
    tshark \
    && pip3 --no-cache-dir install -r requirements.txt

CMD [ "python3" , "sniffer.py" ]