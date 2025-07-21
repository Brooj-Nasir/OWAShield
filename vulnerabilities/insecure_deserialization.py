import pickle
import base64
import json

class MaliciousPayload:
    def __reduce__(self):
        import os
        return (os.system, ('echo "Malicious code executed!"',))

def insecure_deserialization(payload):
    decoded = base64.b64decode(payload)
    return pickle.loads(decoded)

def secure_deserialization(payload):
    decoded = base64.b64decode(payload)
    return json.loads(decoded)