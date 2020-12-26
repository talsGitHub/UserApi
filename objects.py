import json

# object of point with a name and address
class User:
    def __init__(name, email, password):
        self.name = name
        self.email = email
        self.password = password


# Object to convert to json
class Object:
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)