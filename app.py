import os
from flask import Flask, request, jsonify, make_response
from flask_bcrypt import Bcrypt
import pandas as pd
import urllib.request
import json
import pymongo
from pymongo import MongoClient
from bson.json_util import loads, dumps
from objects import User
from objects import Object
import re
import jwt
from dotenv import load_dotenv
import pathlib
import requests
from http import cookies
from flask_httpauth import HTTPBasicAuth
import datetime
from functools import wraps
from bson import ObjectId
from requests import get

load_dotenv()


secret = os.environ.get("secret_key")

app = Flask(__name__)
bcrypt = Bcrypt(app)


client = pymongo.MongoClient(
    "mongodb://tal2:tal2@cluster0-shard-00-00.t5lmh.mongodb.net:27017,cluster0-shard-00-01.t5lmh.mongodb.net:27017,cluster0-shard-00-02.t5lmh.mongodb.net:27017/<dbname>?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin&retryWrites=true&w=majority"
)

db = client["finance"]
userCollection = db["users"]
blacklistCollection = db["blacklist"]

regex = "^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"  # email validation


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        message = {}

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            message["key"] = "error"

            message["msg"] = "Token is missing!"
            message = json.dumps(message)
            return message

        print("Token: ", token)

        try:

            data = jwt.decode(token, secret, algorithms=["HS256"])
            checkExists = checkUserExists(data["id"])
            print(data["id"])

            cur = userCollection.find({"_id": ObjectId(data["id"])})
            current_user = dumps(cur)

            # blacklisted = checkBlacklist(token)

            # if blacklisted == True:
            #   message["key"] = "error"
            #  message["msg"] = "Token is expired!"
            # message = json.dumps(message)
            # return message

        except:

            # return jsonify({"msg": "Token is invalid!"}), 401
            message["key"] = "error"

            message["msg"] = "Token is invalid!"
            message = json.dumps(message)
            return message

        return f(current_user, *args, **kwargs)

    return decorated


def checkBlacklist(token):
    query = {"token": token}

    cur = blacklistCollection.find(query)

    checkBlacklist = list(cur)

    if len(checkBlacklist) == 0:
        return False
    else:
        return True


def checkUserExists(email):
    query = {"email": email}

    cur = userCollection.find(query)

    # checkExists = dumps(checkExists)
    checkExists = list(cur)

    if len(checkExists) == 0:
        return False
    else:
        return checkExists


@app.route("/users/checkLoggedIn", methods=["GET"])
@token_required
def test(current_user):

    result = {}
    if current_user:
        result = {
            "key": "Logged In Status",
            "msg": "User is logged in",
            "current_user": current_user,
        }
    else:
        result = {
            "key": "Logged In Status",
            "msg": "Not logged in",
            "current_user": "",
        }

    return result


@app.route("/users/logout", methods=["GET", "POST"])
@token_required
def logout(current_user):

    message = {}

    if "x-access-token" in request.headers:
        token = request.headers["x-access-token"]
    if not token:
        message["key"] = "error"
        message["msg"] = "Token is missing!"
        message = json.dumps(message)
        return message

    token_to_insert = {"token": token}

    try:
        cur = blacklistCollection.insert_one(token_to_insert)
    except:
        message["key"] = "error"
        message["msg"] = "Could not log out!"
        message = json.dumps(message)
        return message

    message["key"] = "Success"
    message["msg"] = "Successfully logged out!"
    message = json.dumps(message)
    return message


@app.route("/users/login", methods=["GET", "POST"])
def login():
    # email = request.args.get("email", None)
    # password = request.args.get("password", None)

    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
            "Could not verify",
            401,
            {"WWW-Authenticate": 'Basic realm="Login required!"'},
        )

    email = auth.username
    password = auth.password
    print("E: ", email)
    print("p: ", password)
    checkExists = checkUserExists(email)
    print(checkExists[0]["password"])
    message = {}

    if checkExists == False:
        if "key" not in message:
            message["key"] = "Error"

            message["msg"] = "No such user"
    else:

        decryptPassword = bcrypt.check_password_hash(
            checkExists[0]["password"], password
        )
        print(decryptPassword)
        if decryptPassword == False:
            if "key" not in message:
                message["key"] = "Error"

                message["msg"] = "Incorrect password"

    if message:
        print(message)
        message = json.dumps(message)
        return jsonify(message)
    else:

        userID = dumps(checkExists[0]["_id"])
        userID = json.loads(userID)
        print('userid: ', userID["$oid"])
        # encodedToken = jwt.encode({"id": userID["$oid"]}, secret, algorithm="HS256", 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)})
        encodedToken = jwt.encode(
            {
                "id": userID["$oid"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            },
            secret,
            algorithm="HS256",
        )
        s = requests.Session()
        s.auth = ("user", "pass")
        s.headers.update({"x-test": "true"})
        print(encodedToken)
        # print(userID["$oid"])
        # print(auth["id"])
        try:
            decodedToken = jwt.decode(
                encodedToken, secret, algorithms=["HS256"])
            print(decodedToken)
        except:

            message["key"] = "Error"

            message["msg"] = "Invalid Token"

            message = json.dumps(message)
            return message

        message["key"] = "token"
        token = ""
        token = encodedToken.decode("utf-8")
        # token = encodedToken
        message["msg"] = str(token)

        message = json.dumps(message)
        return message

    # return dumps(checkExists[0]["name"])
    # print(encodedToken)
    # return encodedToken


@app.route("/users/signup", methods=["POST"])
def signup():
    name = request.args.get("name", None)
    email = request.args.get("email", None)
    password = request.args.get("password", None)
    confirmPassword = request.args.get("confirmPassword", None)

    message = {}

    checkExists = checkUserExists(email)

    if not checkExists == False:
        if "key" not in message:
            message["key"] = "Error"

            message["msg"] = "User already exists"

    if not name:
        if "key" not in message:
            message["key"] = "Error"

            message["msg"] = "Name is empty"

    if not email:
        if "key" not in message:
            message["key"] = "Error"

            message["msg"] = "Email is empty"
    # else:
    #   if not re.search(regex, email):
    #      if "key" not in errorMsg:
    #         errorMsg["key"] = "Validation Errors"

    #    errorMsg["email"] = "Email is not valid"

    if not password:
        if "key" not in message:
            message["key"] = "Error"

            message["msg"] = "Password is empty"

    if password != confirmPassword:
        if "key" not in message:
            message["key"] = "Error"

            message["msg"] = "Passwords do not match"

    if message:
        message = json.dumps(message)
        return message
    else:
        try:
            hashedPassword = bcrypt.generate_password_hash(password)

            userList = {name, hashedPassword}

            # result = Object()
            # result.user = Object()
            result = {"name": name, "email": email, "password": hashedPassword}

            # jsonResult = result.toJSON()
            # resultToInsert = json.loads(jsonResult)
            returnData = dumps(result)
            _id = userCollection.insert_one(result)

            returnedID = _id.inserted_id

            message["key"] = "token"

            message["msg"] = str(returnedID)

            return message

        except Exception as e:
            print(e)
            return "Error: error with saving user: "

        # check = bcrypt.check_password_hash(hashedPassword, "hunter2")
        # print(check)
        # check = json.dumps(check)


@app.route("/")
def index():
    return "<h1>Welcome to our server !!</h1>"


if __name__ == "__main__":

    app.run(threaded=True, port=3000, debug=True)
