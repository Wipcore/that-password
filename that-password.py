from flask import Flask, g, url_for, request, redirect, render_template, flash, abort
from pymongo import MongoClient
import time
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = "qwerty"

def get_db():
    db = getattr(g, 'mongodb', None)
    if db is None:
        db = g.mongodb = MongoClient('mongodb://localhost:27017/')
    return db.thatpassword

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, 'mongodb', None)
    if db is not None:
        db.close()

def create_password_link(password, validity):
    db = get_db()
    collection = db.passwords
    link = str(uuid.uuid4())
    doc = {"link": link,
           "password": password, 
           "views": 0,
           "max_views": validity['views'],
           "max_age": validity['days'],
           "created": time.strftime("%Y/%m/%d %H:%M:%S")}
    collection.insert(doc)
    return link
       
def get_password(password_id):
    db = get_db()
    passwords = db.passwords
    doc = passwords.find_one({"link": password_id})
    if doc is None:
        abort(404)
    passwords.update({"link": password_id},
                     {"$inc": {"views": 1}})
    password = doc['password']
    if int(doc['views']) >= int(doc['max_views']) - 1:
        passwords.remove({"link": password_id})
    return password

    
@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == "POST":
        password = request.form["password"]
        valid_type = request.form.getlist("valid_type")
        validity = {}
        if 'views' in valid_type:
            validity['views'] = request.form["valid_views"]
        if 'days' in valid_type:
            validity['days'] = request.form["valid_days"]
        link = create_password_link(password, validity)
        flash(link)
        return render_template('index.html')
    
    return render_template('index.html')


@app.route("/password/<password_id>")
def view_password(password_id):
    password = get_password(password_id)
    return render_template('password.html', password=password)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404



if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
