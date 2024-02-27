from flask import Flask,render_template,request,jsonify
from lib.server_core import ServerCore
from lib.xmap.scan_core import ScanCore
application = Flask(__name__,template_folder='templates',static_url_path='',static_folder='templates/static')
server = ServerCore()

@application.route("/",methods=["GET"])
def home():
    return render_template("home.html")

@application.route("/scan_site",methods=["GET","POST"])
def scan_site(): # route where your scan gets visualized
    print(f"Scanning site {request.form['target']}")
    scan_type = request.form.get("scanType")
    id : int
    if scan_type=="qScan":
        id = server.quick_scan(request.form['target'])
    elif scan_type=="dScan":
        id = server.deep_scan(request.form['target'])
    elif scan_type=="mScan":
        cdepth = int(request.form['crawl_depth'])
        sdepth = int(request.form['scan_depth'])
        brute : bool
        if request.form.get("brute")=='on':
            brute=True
        else:
            brute=False
        id = server.manual_scan(request.form['target'],cdepth,sdepth,brute)
    return render_template('scan.html',id=id)

@application.route("/scan_status",methods=["GET"])
def scan_status(): # this returns a json scan object to the user, in which will be all the currently available data about scanned targets so far
    scan: ScanCore | None = server.get_running_scan(int(request.args["id"]))
    if scan==None:
        return jsonify({"failed":True})
    return jsonify(scan.to_json())

@application.route('/about',methods=["GET"])
def about():
    return render_template('about.html')

if __name__=="__main__":
    application.run(debug=True)

