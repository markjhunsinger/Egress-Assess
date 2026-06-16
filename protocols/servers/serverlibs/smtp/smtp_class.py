import base64
from email.parser import BytesParser
import time
from common import helpers


class CustomSMTPHandler:

    def __init__(self, loot_directory):
        self.loot_directory = loot_directory

    async def handle_DATA(self, server, session, envelope):
        peer = session.peer
        mailfrom = envelope.mail_from
        rcpttos = envelope.rcpt_tos
        data = envelope.content  # bytes

        print('Receiving message from:', peer)
        print('Message addressed from:', mailfrom)
        print('Message addressed to  :', rcpttos)
        print('Message length        :', len(data))

        p = BytesParser()
        msgobj = p.parsebytes(data)
        for part in msgobj.walk():
            attachment = self.email_parse_attachment(part)
            if type(attachment) is dict and 'filedata' in attachment:
                decoded_file_data = base64.b64decode(attachment['filedata'])
                attach_file_name = attachment['filename']
                with open(self.loot_directory + "/" + attach_file_name, 'wb') as attached_file:
                    helpers.received_file(attach_file_name)
                    attached_file.write(decoded_file_data)
            else:
                current_date = time.strftime("%m/%d/%Y")
                current_time = time.strftime("%H:%M:%S")
                file_name = current_date.replace("/", "") + \
                    "_" + current_time.replace(":", "") + "email_data.txt"

                with open(self.loot_directory + "/" + file_name, 'ab') as email_file:
                    email_file.write(b'METADATA: File from - ' + str(peer).encode() + b'\n\n')
                    email_file.write(data)

        return '250 Message accepted for delivery'

    @staticmethod
    def email_parse_attachment(message_part):
        content_disposition = message_part.get("Content-Disposition", None)
        if content_disposition:
            dispositions = content_disposition.strip().split(";")
            if bool(content_disposition and dispositions[0].lower() == "attachment"):
                attachment = {
                        'filedata': message_part.get_payload(),
                        'content_type': message_part.get_content_type(),
                        'filename': "default"
                    }
                for param in dispositions[1:]:
                    name, value = param.split("=")
                    name = name.strip().lower()

                    if name == "filename":
                        attachment['filename'] = value.replace('"', '')

                return attachment

        return None
