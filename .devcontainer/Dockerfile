FROM mcr.microsoft.com/devcontainers/python:1-3.12-bullseye

COPY requirements.txt requirements.txt
RUN pip3 install black && pip3 install -r requirements.txt

USER vscode
RUN echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc 
