from flask import Flask,render_template,request,jsonify
import threading
import asyncio
from lib.logging import Logger
application = Flask(__name__,template_folder='templates',static_url_path='',static_folder='templates/static')

@application.route("/",methods=["GET"])
def home():
    return render_template("home.html")

@application.route("/scan_site",methods=["GET","POST"])
def scan_site():
    print(f"scanning site {request.form['target']}")
    return render_template('scan.html')

if __name__=="__main__":
    application.run(debug=True)
