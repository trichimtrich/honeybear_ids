from flask import render_template, redirect, request, url_for
from app import app
import time, thread, glob


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/about-us')
def aboutus():
    return render_template('about-us.html')


def getConfig():
	line = open("../code/bear.conf", "rb").read().split("\n")
	i = 0
	config = []

	while i < len(line):
		if line[i]=="[module]":
			if i+2>=len(line): break
			tmp_name = line[i+1]
			tmp_fn = line[i+2]
			if tmp_name[:5]!="name=" or tmp_fn[:5]!="file=" : break
			tmp_name = tmp_name[5:]
			tmp_fn = tmp_fn[5:]

			config.append([tmp_name, tmp_fn])

			i = i+2

		i+=1
	return config

@app.route('/config', methods=['GET', 'POST'])
def config():
	mess_cont = ""
	mess_type = ""
	
	if request.method == 'POST':
		name = request.form.getlist('name[]')
		files = request.form.getlist('file[]')
		mess_cont = "Saving failed!"
		mess_type = "danger"
		if len(name)==len(files):
			st = ""
			for i in range(len(name)):
				if name[i]!="" and files[i]!="":
					st += "[module]\n"
					st += "name=%s\n" % name[i]
					st += "file=%s\n" % files[i]
					st += "\n"

			if st!="":
				open("../code/bear.conf", "wb").write(st)
				mess_cont = "Saving successed! You may need to restart HoneyBear."
				mess_type = "success"

	config = getConfig()	
	return render_template('config.html', mess_cont=mess_cont, mess_type=mess_type, config=config)


log_files = []
logs = []

def updateLog():
	global log_files, logs

	while True:
		log_files = glob.glob("../code/log/*.log")
		logs = []
		for fn in log_files:
			sub_logs = []
			for line in open(fn):
				line = line.strip()
				if line.count("--")!=2: continue
				sub_logs.append(line.split("--"))
			logs.append(sub_logs)

		print "Parse log ok!"
		time.sleep(300)

thread.start_new_thread(updateLog, () )

@app.route('/log')
def listlog():
	global log_files
	files = []
	for i in range(len(log_files)):
		files.append([i, log_files[i].split('/')[-1]])
	return render_template('log.html', files=files)


@app.route('/log/<int:fid>')
def datelog(fid):
	global logs, log_files
	if (fid>=len(logs) or fid<0): return redirect("/")
	title = log_files[fid].split('/')[-1]
	li_log = []
	i = 0
	for pk_tmp, pk_mod, pk_b64con in logs[fid]:
		li_log.append([i, time.ctime(int(pk_tmp)), pk_mod, pk_b64con[:64]])
		i += 1

	return render_template('datelog.html', title=title, fid=fid, li_log=li_log)


def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

@app.route('/log/<int:fid>/<int:pid>')
def detaillog(fid, pid):
	global logs, log_files
	if (fid>=len(logs) or fid<0): return redirect("/")
	if (pid>=len(logs[fid]) or pid<0): return redirect("/")
	title = log_files[fid].split('/')[-1]
	pk_tmp, pk_mod, pk_b64con = logs[fid][pid]
	pk_dump = hexdump(pk_b64con.decode('base64'))
	pkdump = pk_dump.split('\n')
	return render_template('detaillog.html', title=title, pid=pid, pkdate=time.ctime(int(pk_tmp)), pkmod=pk_mod, pkb64=pk_b64con, pkdump=pkdump)
