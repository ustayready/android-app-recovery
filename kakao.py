'''
Script Name: kakao.py
Version: 1
Revised Date: 07/07/2015
Python Version: 3
Description: A script to parse large Android binary images and extracts deleted Kakao messages.
Copyright: 2015 Mike Felch <mike@linux.edu> 
URL: http://www.forensicpy.com/
--
- ChangeLog -
v1 - [07-07-2015]: Original code
'''

import sys, re, struct, datetime
from functools import partial

size_in_bytes = 100000000 # 100mb
file_name = "C:\\mobiledata\\images\\Samsung S2\\S2_main.bin"

# Open the file for examination (Parsing binary data)
with open(file_name, 'r+b') as f:

    # Split the file into chunks using size_in_bytes and create a list (collection) of the chunks
    f_data  = partial(f.read, size_in_bytes)

    # Iterate through each chunk in the list
    for data in iter(f_data, ''):

        # Make sure we haven't hit the end of the file and that we are looking at data still
        if len(data) > 0:

            # Create a regular expression that finds message matches
            regex = b'DirectChat\[\d{9}\]\[\d{9}\].*\d{18}\].*\d{9}'

            # Create a variable for containing a unique collection
            messages = []

            # Create a variable to hold the matches from the data using the regular expression
            message_matches = re.finditer(regex, data)

            # Loop through all the message matches
            for number, match in enumerate(message_matches):

                # Create variables for the start and stop offset
                begin_offset = match.span()[0]
                end_offset = match.span()[1]

                # Parse just the current message from the chunk of data
                raw_data = data[begin_offset:end_offset]
                
                # Slice the parts of the message from the raw data
                user_id         = raw_data[11:20]
                user_id_copy    = raw_data[22:31]
                file_time       = raw_data[-10:]
                conversation_id = raw_data[-56:-42]
                parsed_message  = raw_data[40:-61]
                
                # Decode the data to UTF-8 and ignore any decoding errors
                user_id         = user_id.decode('utf-8', 'ignore')
                user_id_copy    = user_id_copy.decode('utf-8', 'ignore')
                file_time       = file_time.decode('utf-8', 'ignore')
                conversation_id = conversation_id.decode('utf-8', 'ignore')
                parsed_message  = parsed_message.decode('utf-8', 'ignore')

                # Convert the parsed timestamp into a date and time
                dt = datetime.datetime.utcfromtimestamp(int(file_time))

                # Create variable to store decoded data
                decoded_data = [dt, user_id, user_id_copy, conversation_id, parsed_message]

                # Add message to messages collection
                if decoded_data not in messages:
                    messages.append(decoded_data)

            # Loop through messages and print to screen
            for message in messages:
                print(message[0], message[1], message[2], message[3], message[4])                
        else:
            break
