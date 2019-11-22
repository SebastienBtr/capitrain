FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

COPY requirements.txt sniffer.py analyze_tcp_packets.py ./

RUN apt-get update && apt-get install -y \
    python3-pip \
    tshark \
    && pip3 --no-cache-dir install -r requirements.txt

CMD [ "python3" , "sniffer.py" ]