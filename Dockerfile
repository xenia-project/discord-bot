FROM ubuntu:latest

ENV LC_ALL C.UTF-8
ENV LANG C.UTF-8

# Run through APT updates.
RUN apt-get update
RUN apt-get install -y python python3 python3-pip

# Install pipenv.
RUN pip3 install pipenv

RUN groupadd    -g 999    discordbot && \
    useradd -mr -u 999 -g discordbot discordbot

ADD discordbot.py    /srv/xenia-bot/
ADD Pipfile          /srv/xenia-bot/
Add Pipfile.lock     /srv/xenia-bot/
ADD disco            /srv/xenia-bot/disco

# Run based in the bot folder from now on.
WORKDIR /srv/xenia-bot

# Set up the app.
RUN pipenv install --python /usr/bin/python3 --system --deploy --ignore-pipfile

# Setup permissions.
RUN chmod -R u+rwX,go+rX,go-w      /srv/xenia-bot && \
    chown -R discordbot:discordbot /srv/xenia-bot

# Run as discordbot.
USER discordbot
ENTRYPOINT [ "python3", "-m", "disco.cli", "--run-bot", "--plugin", "discordbot" ]