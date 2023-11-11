from flask import Flask,render_template,request,jsonify
import threading
import asyncio
from lib.server_core import ServerCore
application = Flask(__name__,template_folder='templates',static_url_path='',static_folder='templates/static')
server = ServerCore()

@application.route("/",methods=["GET"])
def home():
    return render_template("home.html")

@application.route("/scan_site_quick",methods=["GET","POST"])
def scan_site_quick():
    print(f"scanning site {request.form['target']}")
    server.q_scan(request.form['target'])
    return render_template('scan.html')

if __name__=="__main__":
    application.run(debug=True)

# there would be an update route that would consistently get requested by the browser to see the updates of your task