FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    docker.io \
    nmap \
    curl \
    wget \
    unzip \
    tar \
    git \
    masscan \
    ffuf \
    gobuster \
    jq \
    sqlmap \
    ruby \
    ruby-dev \
    default-jre \
    build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && wget https://github.com/anchore/grype/releases/download/v0.79.6/grype_0.79.6_linux_amd64.tar.gz \
    && tar -xzf grype_0.79.6_linux_amd64.tar.gz -C /usr/local/bin grype \
    && rm grype_0.79.6_linux_amd64.tar.gz \
    && curl -sL https://github.com/sullo/nikto/archive/master.tar.gz | tar -xz -C /opt \
    && ln -s /opt/nikto-main/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto-main/program/nikto.pl \
    && apt-get install -y cpanminus libnet-ssleay-perl libcrypt-ssleay-perl \
    && cpanm --notest JSON XML::Writer \
    && wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip \
    && unzip nuclei_3.2.0_linux_amd64.zip -d /usr/local/bin \
    && rm nuclei_3.2.0_linux_amd64.zip \
    && wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.8/httpx_1.6.8_linux_amd64.zip \
    && unzip -o httpx_1.6.8_linux_amd64.zip -d /tmp/pd-httpx \
    && mv /tmp/pd-httpx/httpx /usr/local/bin/pd-httpx \
    && rm -rf /tmp/pd-httpx httpx_1.6.8_linux_amd64.zip \
    && wget https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip \
    && unzip -o amass_Linux_amd64.zip \
    && mv amass_Linux_amd64/amass /usr/local/bin/ \
    && rm -rf amass_Linux_amd64 amass_Linux_amd64.zip \
    && git clone https://github.com/aboul3la/Sublist3r.git /opt/Sublist3r \
    && ln -s /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r \
    && gem install wpscan \
    && wget https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip \
    && unzip -q ZAP_2.17.0_Crossplatform.zip -d /opt/ \
    && ln -s /opt/ZAP_2.17.0/zap.sh /usr/local/bin/zap \
    && rm ZAP_2.17.0_Crossplatform.zip

# ── Wordlists (SecLists common subsets) ───────────────────────────────────────
RUN mkdir -p /usr/share/wordlists/dirb /usr/share/wordlists/seclists/Discovery/Web-Content \
    && wget -q -O /usr/share/wordlists/dirb/common.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    && wget -q -O /usr/share/wordlists/dirb/big.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt \
    && wget -q -O /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt \
       https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt \
    && echo 'Wordlists installed.'

# We don't have a requirements.txt yet, let's write one
# RUN pip install --no-cache-dir -r requirements.txt

# Just installing dependencies directly for now
RUN pip install --no-cache-dir -r /opt/Sublist3r/requirements.txt && \
    pip install --no-cache-dir fastapi uvicorn sqlalchemy psycopg2-binary redis celery groq pyyaml prometheus-fastapi-instrumentator passlib python-jose neo4j "crewai[litellm]" langchain-groq pgvector python-json-logger croniter alembic langgraph bcrypt boto3 fpdf2 playwright opensearch-py

RUN playwright install chromium --with-deps

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
