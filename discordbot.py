from disco.bot import Plugin
from disco.types.message import MessageEmbed
from disco.util.sanitize import S as sanitize

import io
import magic
import re
import requests
import zipfile


SIZE_LIMIT_MB = 64 * 1024 * 1024

ALLOWED_CHANNELS = ["dev", "help", "secret"]

COLOR_RED = 0x992D22
COLOR_BLUE = 0x22992D


class XeniaBot(Plugin):
    def parse_log_file(self, file_name, file):
        """
        Parses a log file, and returns a Discord MessageEmbed describing it.
        """
        embed = MessageEmbed()
        embed.title = "**{}**\n".format(sanitize(file_name,
                                                 escape_codeblocks=True))
        embed.description = ''
        embed.color = COLOR_BLUE

        build_info = {}
        message_levels = {
            'w': [],
            '!': [],
        }
        seen = set()
        lines = 0

        for line in file:
            # Process up to 500,000 lines
            if lines > 500000:
                break

            # Decode the line if it needs it.
            try:
                line = line.decode('utf-8')
            except AttributeError:
                pass

            sanitized_line = sanitize(line, escape_codeblocks=True).replace('\r\n', '').replace('\r', '')

            if 'date' not in build_info:
                # Scan for build info
                res = re.search(
                    r'^i> ([0-9a-fA-f]{8}) Build: (.*) / ([0-9a-fA-F]{40}) on (.*)$', sanitized_line)
                if res:
                    build_info.update({
                        "branch": res.group(2),
                        "commit": res.group(3),
                        "date": res.group(4),
                    })

            # See if we can find a game ID.
            if 'title_id' not in build_info:
                res = re.search(r'^\s*Title ID: ([0-9a-fA-F]{8})$', sanitized_line)
                if res:
                    build_info.update({"title_id": res.group(1)})

            if len(sanitized_line) > 1 and (sanitized_line[0] in message_levels):
                if sanitized_line not in seen:
                    seen.add(sanitized_line)
                    message_levels[sanitized_line[0]].append(sanitized_line)
            
            lines += 1

        if 'date' not in build_info:
            embed.color = COLOR_RED
            embed.description = "\t**Invalid file**. Could not find build information - is this a Xenia logfile?"
            return embed

        # Setup the description
        if 'branch' in build_info and 'date' in build_info and 'commit' in build_info:
            embed.description = "Branch: {branch}\nDate: {date}\nCommit: {commit}\n".format(
                **build_info)
        if 'title_id' in build_info:
            embed.description += "Title ID: {title_id}".format(**build_info)

        # Errors
        if len(message_levels['!']) > 0:
            errors = "```\n"
            for line in message_levels['!']:
                if len(errors) + len(line) > 997:
                    errors += '...'
                    break

                errors += "{}\n".format(line)
            errors += "```\n"
            embed.add_field(name="Errors", value=errors)

        # Warnings
        if len(message_levels["w"]) > 0:
            warnings = "```\n"
            for line in message_levels['w']:
                if len(warnings) + len(line) > 997:
                    warnings += '...'
                    break

                warnings += "{}\n".format(line)
            warnings += "```\n"
            embed.add_field(name="Warnings", value=warnings)

        return embed

    @Plugin.command('a')
    @Plugin.command('analyze')
    def on_analyze_command(self, event):
        if event.channel.name not in ALLOWED_CHANNELS:
            event.msg.reply(
                "{}, please run this command in #help.".format(event.author.mention))
            return

        if len(event.msg.attachments) < 1:
            event.msg.reply("{}, usage: Attach Xenia's logfile with your message (preferably compressed in a .zip).".format(
                event.author.mention))
            return

        # Fire off a typing event.
        self.client.api.channels_typing(event.channel.id)
        for _, attach in event.msg.attachments.items():
            s_file_name = sanitize(attach.filename, escape_codeblocks=True)
            if attach.size > SIZE_LIMIT_MB:
                event.msg.reply(event.author.mention, embed=MessageEmbed(title=s_file_name, color=COLOR_RED,
                                                                         description="**File above size limit, not analyzed**. Did you compress it?"))
                continue

            r = requests.get(attach.url)
            if r.status_code != 200:
                event.msg.reply(event.author.mention, embed=MessageEmbed(title=s_file_name, color=COLOR_RED,
                                                                         description="**Failed to fetch file from Discord**, status code {}".format(r.status_code)))
                continue

            mime = magic.from_buffer(r.content, mime=True)
            if mime == 'text/plain':
                # Plaintext, straight to the parser!
                event.msg.reply(event.author.mention, embed=self.parse_log_file(
                    attach.filename, io.StringIO(r.text)))
            elif mime == 'application/zip':
                z = zipfile.ZipFile(io.BytesIO(r.content))
                if len(z.namelist()) != 1:
                    event.msg.reply(event.author.mention, embed=MessageEmbed(
                        title=s_file_name, color=COLOR_RED, description="**Archives must contain only a single file**."))
                    continue

                # Parse every file in the zip file.
                for name in z.namelist():
                    # Check the guessed type as well. No voodoo embedding zip files inside one another.
                    mime = magic.from_buffer(z.open(name).read(1024), mime=True)
                    if mime != 'text/plain':
                        event.msg.reply(event.author.mention, embed=MessageEmbed(
                            title=s_file_name, color=COLOR_RED, description="**Contents not plaintext, ignored**."))
                        continue

                    event.msg.reply(event.author.mention, embed=self.parse_log_file(
                        name, z.open(name)))
                    
                z.close()
            else:
                event.msg.reply(event.author.mention, embed=MessageEmbed(
                    title=s_file_name, color=COLOR_RED, description="**Unsupported file type, not analyzed**."))
                continue

    @Plugin.command('help')
    def on_help_command(self, event):
        message = '{}, commands available:\n'.format(event.author.mention)
        message += '\tanalyze (a): Analyze an attached logfile (zipped or uncompressed). Must be < 64MB, and must be ran in #help.\n'
        event.msg.reply(message)
