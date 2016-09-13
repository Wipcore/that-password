# That-Password, a tool for distributing passwords
# Copyright (C) 2014  Roger Steneteg <roger@steneteg.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from werkzeug.contrib.fixers import ProxyFix
from flask import (
    Flask, g, url_for, request, redirect, render_template, flash, abort)
import redis
from datetime import datetime, timedelta
import time
import uuid
import os

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.config['SECRET_KEY'] = os.environ.get("TP_SECRET", str(uuid.uuid4()))

database_engine = None


def get_db():
    global database_engine
    if database_engine is None:
        database_engine = g.redis = redis.StrictRedis(
            host=os.environ.get("TP_REDIS_HOST", "localhost"),
            port=int(os.environ.get("TP_REDIS_PORT", 6379)),
            db=int(os.environ.get("TP_REDIS_DB", 0)),
            charset="utf-8",
            decode_responses=True)
    return database_engine


def create_password_id(password, validity):
    db = get_db()
    password_id = str(uuid.uuid4())
    entry = {
        "password": password,
        "views": 0,
        "created": int(time.time())}
    if "views" in validity:
        entry["max_views"] = validity['views']
    if "days" in validity:
        entry["max_days"] = validity['days']
    if "ip" in validity:
        entry["valid_ip"] = validity['ip']
    db.hmset("password:{}".format(password_id), entry)
    if "days" in validity:
        db.expire(
            "password:{}".format(password_id),
            int(entry["max_days"]) * 86400)
    return password_id


def get_password(id):
    db = get_db()
    # Check is password id exists
    if not db.exists("password:{}".format(id)):
        abort(404)

    # Update password views
    with db.pipeline() as pipe:
        while True:
            try:
                pipe.watch("password:{}".format(id))
                views = pipe.hget("password:{}".format(id), "views")
                pipe.multi()
                pipe.hset("password:{}".format(id), "views", int(views) + 1)
                pipe.execute()
                # Value updated, exit loop
                break
            except redis.WatchError as err:
                # Key changed between watch and execute, try again
                continue

    # Get password info
    entry = db.hgetall("password:{}".format(id))
    if "max_views" in entry:
        if int(entry["views"]) >= int(entry["max_views"]):
            db.delete("password:{}".format(id))
    if "max_days" in entry:
        now = time.time()
        due_date = int(entry["created"]) + (int(entry["max_days"]) * 86400)
        if now > due_date:
            db.delete("password:{}".format(id))
    if "valid_ip" in entry:
        client_ip = None
        if not request.headers.getlist("X-Forwarded-For"):
            client_ip = request.remote_addr
        else:
            client_ip = request.headers.getlist("X-Forwarded-For")[0]
        if client_ip != entry["valid_ip"]:
            abort(404)

    return entry["password"]


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
        if 'ip' in valid_type:
            validity['ip'] = request.form["valid_ip"]
        link = create_password_id(password, validity)
        flash(url_for('view_password', id=link, _external=True))
        return render_template('index.html')

    return render_template('index.html')


@app.route("/password/<id>", methods=["GET", "POST"])
def view_password(id):
    """View password"""
    if request.method == "POST":
        password = get_password(id)
        return render_template('password.html', password=password)
    else:
        return render_template('password.html')


@app.errorhandler(404)
def page_not_found(error):
    """Flask error handleing page"""
    return render_template('page_not_found.html'), 404


if __name__ == "__main__":
    app.run(
        host=os.environ.get("TP_HOST", "127.0.0.1"),
        port=int(os.environ.get("TP_PORT", 8080)),
        debug=bool(os.environ.get("TP_DEBUG", False)))
