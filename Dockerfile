# Digital Forensics Lab Environment Dockerfile
# Maintainer & Packaging: Subham Biswas
# Upstream Lab Materials: Frank W. Xu (Licensed under Apache 2.0)

FROM ubuntu:22.04

LABEL maintainer="Subham Biswas"
LABEL description="Full-featured Digital Forensics Lab execution container with CLI tools, Python forensics libraries, and JupyterLab."

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# 1. Base packages and Forensics Utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    wget \
    git \
    unzip \
    p7zip-full \
    tree \
    vim \
    nano \
    sudo \
    tzdata \
    ca-certificates \
    software-properties-common \
    # Forensics & Network Analysis Tools
    sleuthkit \
    tshark \
    tcpdump \
    foremost \
    binwalk \
    hashdeep \
    sqlite3 \
    libsqlite3-dev \
    xmlstarlet \
    libhivex-bin \
    pasco \
    ewf-tools \
    pff-tools \
    libesedb-utils \
    liblnk-utils \
    steghide \
    yara \
    libcapstone-dev \
    # Python 3
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    python3-evtx \
    # Node.js for CLI tools
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# 2. Python Forensics & Data Science Libraries
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir \
    jupyterlab \
    notebook \
    pandas \
    numpy \
    scapy \
    matplotlib \
    seaborn \
    openpyxl \
    scikit-learn \
    stix2 \
    stix2-patterns \
    graphviz \
    python-dateutil \
    pytz \
    usnparser \
    usncarve \
    windowsprefetch \
    volatility3 \
    openai

# 3. Additional Forensic Tool Repositories
WORKDIR /opt/forensics-tools

# Time Decode
RUN git clone https://github.com/digitalsleuth/time_decode.git /opt/forensics-tools/time_decode && \
    ln -s /opt/forensics-tools/time_decode/time_decode/time_decode.py /usr/local/bin/time_decode.py && \
    chmod +x /usr/local/bin/time_decode.py

# Vinetto (Thumbcache parser)
RUN git clone https://github.com/AtesComp/Vinetto.git /opt/forensics-tools/Vinetto && \
    cd /opt/forensics-tools/Vinetto && pip3 install .

# Undark (SQLite Carving Tool)
RUN git clone https://github.com/inflex/undark.git /opt/forensics-tools/undark && \
    cd /opt/forensics-tools/undark && make && \
    cp undark /usr/local/bin/undark

# Workspace setup
WORKDIR /workspace

EXPOSE 8888 8080

CMD ["bash"]
