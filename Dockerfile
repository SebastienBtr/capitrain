FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive

RUN mkdir /app/
COPY requirements.txt db.py main.py sniffer.py analyse_tcp_packets.py /app/

RUN apt-get update && apt-get install -y \
    python3-pip \
    tshark \
    && pip3 --no-cache-dir install -r /app/requirements.txt

CMD [ "python3" , "/app/main.py" ]