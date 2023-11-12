from flask import Flask,render_template,request,jsonify
import threading
import asyncio
from lib.server_core import ServerCore
from lib.xmap.scan_core import ScanCore
application = Flask(__name__,template_folder='templates',static_url_path='',static_folder='templates/static')
server = ServerCore()

@application.route("/",methods=["GET"])
def home():
    return render_template("home.html")

@application.route("/scan_site",methods=["GET","POST"])
def scan_site():
    print(f"scanning site {request.form['target']}")
    scan_type = request.form.get("scanType")
    id : int
    if scan_type=="qScan":
        id = server.quick_scan(request.form['target'])
    elif scan_type=="dScan":
        id = server.deep_scan(request.form['target'])
    return render_template('scan.html',id=id)

@application.route("/scan_status",methods=["GET"])
def scan_status():
    scan: ScanCore = server.get_running_scan(int(request.args["id"]))
    return jsonify(scan.to_json())

if __name__=="__main__":
    application.run(debug=True)

# there would be an update route that would consistently get requested by the browser to see the updates of your task

# test site: http://sudo.co.il/xss/level3.php?email=232#