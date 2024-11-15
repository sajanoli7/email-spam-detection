from simplegmail import Gmail
from simplegmail.query import construct_query

gmail = Gmail()

query_params = {
    "newer_than": (1, "years"),
    # "older_than": (0, "months")
}

messages = gmail.get_messages(query=construct_query(query_params))

for message in messages:
    # print("To: " + message.recipient)
    print("From: " + message.sender)
    # print("Subject: " + message.subject)
    # print("Date: " + message.date)
    # print("Preview: " + message.snippet)
    if message.plain is not None:
        print("Body:" + message.plain)
    else:
        print("Body: [No plaintext body available]")
    print("*****************************************")
    print("\n\n\n\n\n")
