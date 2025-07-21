# Mock vulnerable XML parser (similar to legacy XML libraries)
class InsecureXMLParser:
    def parse(self, data):
        return f"Parsed: {data}"

# Secure XML parser (mock updated version)
class SecureXMLParser:
    def __init__(self):
        self.entities = {}

    def parse(self, data):
        if '!ENTITY' in data:
            raise ValueError("External entities not allowed")
        return f"Parsed: {data}"

def insecure_parse(xml_data):
    parser = InsecureXMLParser()
    return parser.parse(xml_data)

def secure_parse(xml_data):
    parser = SecureXMLParser()
    return parser.parse(xml_data)