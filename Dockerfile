FROM debian:sid

RUN apt-get update
RUN apt-get install -y tshark
RUN apt-get install -y python3 python3-venv
RUN apt-get install -y tcpdump vim curl iproute2 mitmproxy
RUN apt-get install -y git tmux

WORKDIR /root
RUN python3 -m venv venv
RUN . venv/bin/activate && pip3 install -q jupyterlab bash_kernel pandas cryptography pyshark loguru tabulate
RUN . venv/bin/activate && python3 -m bash_kernel.install
