#!/usr/bin/env python

# FIXME: some things should be lists as output!

# requires:
# python-simplejson
# http://svn.red-bean.com/bob/simplejson/tags/simplejson-1.3/docs/index.html

# can I used this?
# https://github.com/amoffat/pbs

# this script will need to require bind-utils for reverse lookups to work

elasticsearch_url = "http://localhost:9200"

import simplejson
import urllib2
import sys
import os
import re
import subprocess
from time import sleep, localtime, strftime
from datetime import datetime
from shlex import split

timeout = 5
recdate = strftime("%d%m%Y", localtime())

def sanitize(txt):
	# reference: http://www.degraeve.com/reference/specialcharacters.php
        txt = txt.replace("&", "&amp;")
        txt = txt.replace('<', '&lt;')
        txt = txt.replace('>', '&gt;')
        txt = txt.replace('"', '&quot;')
        txt = txt.replace("'", "&#039;")
        txt = txt.replace("[", "&#91;")
        txt = txt.replace("]", "&#93;")
        txt = txt.replace("{", "&#123;")
        txt = txt.replace("|", "&#124;")
        txt = txt.replace("}", "&#125;")
        #txt = txt.replace(":", "&#58;")
        #txt = txt.replace(";", "&#59;")
        #txt = txt.replace(",", "&#44;")
        return txt

def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

def runcom(command_line):
        start = datetime.now()
        process = subprocess.Popen(split(command_line), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        while process.poll() is None:
                sleep(0.1)
        now = datetime.now()
        if (now - start).seconds> timeout:
                os.kill(process.pid, signal.SIGKILL)
                os.waitpid(-1, os.WNOHANG)
                return None
        out, error = process.communicate()
        return out.strip()

def strchk(test,string):
	p = re.compile(test)
	result = re.search(p, string)
	if result:
		return 'T'
	else:
		return result

def nettest(test,string):
	if strchk(test, string) == 'T':
		return string.split(test)[1].split()[0]
	else:
		return "Empty"

def readfile(fname):
	if os.path.exists(fname):
        	f = open(fname)
		try:
       			data = f.read()
		finally:
       			f.close()
		return data.strip()
	else:
		return None

class AutoVivification(dict):
	"""Implementation of perl's autovivification feature."""
	def __getitem__(self, item):
		try:
			return dict.__getitem__(self, item)
		except KeyError:
			value = self[item] = type(self)()
			return value

sysdata = AutoVivification()

# collect network information

# get interface info
# yay, thanks ifconfig for having shifty output and nonstandard delimiters from line to line, switching to 'ip addr show'
data = runcom('ip addr show')
p = re.compile(r'\n\d+: ')
nets = p.split(data)

# we're generating the unique ID for our system based on the first mac address and caching it after that
miconfdir = '/etc/machinfo'
miconf = '%s/%s' % (miconfdir, 'id.txt')
if not os.path.exists(miconf):
	if not os.path.exists(miconfdir):
		os.mkdir(miconfdir)
	for i in range(1,len(nets)):
        	ifname = nets[i].split(':')[0]
		# FIXME: bad hack to get around various virtual network devices, constructs, etc.
		if re.search('eth', ifname):
			if re.search('veth', ifname) == None:
        			for x in nets[i].split('\n'):
					s = re.compile(' link/ether ')
					if re.search(s, x):
						sysid = x.split()[1]
						f = open(miconf, 'w')
						try:
							f.write(sysid)
						finally:
							f.close()
						break
else:
	sysid = readfile(miconf)

# for the below to work, I'm assuming lo will always be the first interface returned by ip addr show. Hopefully this is really the case.
for i in range(1,len(nets)):
	ifname = nets[i].split(':')[0]
	for x in nets[i].split('\n'):
		s = re.compile(' link/ether ')
		if re.search(s, x):
			sysdata['interfaces'][ifname]['macaddr'] = x.split()[1]
		s = re.compile(' inet ')
		if re.search(s, x):
			# FIXME: does ipv4 ever have multiple values on the same NIC?
			sysdata['interfaces'][ifname]['ipv4_ipaddr'] = x.split()[1]
			sysdata['interfaces'][ifname]['broadcast'] = x.split()[3]
		s = re.compile(' inet6 ')
		if re.search(s, x):
			# FIXME: does ipv6 ever have multiple values on the same NIC?
			sysdata['interfaces'][ifname]['ipv6_ipaddr'] = x.split()[1]

# get routes
data = runcom('ip route show')
dp = data.split('\n')
rlist = []
for i in range(0,len(dp)):
	rlist.append(dp[i])
sysdata['routes'] = rlist

# get iptables rules
data = runcom('iptables -L')
dp = data.split('Chain')
for i in dp:
	if len(i.split()) > 0:
		clist = []
		chain = i.split()[0]
		x = i.split('\n')
		x = filter(None, x)
		if len(x) > 2:
			for y in range(2,len(x)):
				clist.append(x[y])
				#sysdata['iptables'][chain][y-2] = x[y]
			sysdata['iptables'][chain] = clist

# get system info

# get timezone
sysdata['timezone'] = runcom("/bin/date '+%Z'")
sysdata['hostname'] = runcom("uname -n")

# reverse lookups of interfaces
lookups = []
if which('dig'):
	for iface in sysdata['NICs'].keys():
		if sysdata['NICs'][iface]['ipv4_ipaddr']:
			rcom = "%s +noall +answer -x %s" % (which('dig'),sysdata['NICs'][iface]['ipv4_ipaddr'][0].split("/")[0])
			r = runcom(rcom)
			if r:
				lookups.append(r.split()[4])
else:
	lookups.append("ERROR: dig not found.")

lookups = filter(None, lookups)
if len(lookups) == 0:
	lookups.append('ERROR: No reverse addresses found!')

sysdata['reverse_lookups'] = lookups

# FIXME - find other version file info for other distros
version_files = ["/etc/redhat-release",]
for i in version_files:
	x = readfile(i)
	if x:
		sysdata['os_version'] = x.strip()
		break

uname_a = runcom('uname -a')
x = re.split(' x86_64 | i386 ', uname_a)
sysdata['kernel_version'] = x[0].split(sysdata['hostname'])[1].strip()
sysdata['hardware-platform'] = runcom('uname -i')
sysdata['processor'] = runcom('uname -i')

# collect CPU information
data = readfile('/proc/cpuinfo')
dp = data.split('\n\n')
for i in dp:
	if i:
        	pl = i.split('\n')[0].split()
        	#if len(pl) > 0:
                for x in i.split('\n'):
                        xp = x.split(":")
                        sysdata['CPUs'][pl[2]][xp[0].strip()] =  xp[1].strip()

# collect memory information
data = readfile('/proc/meminfo')
for i in data.split('\n'):
	if i:
		l = i.split(':')
		sysdata['memory'][l[0]] = l[1].strip()

data = readfile('/proc/uptime')
d = data.split()
sysdata['seconds_uptime'] = d[0].strip()
sysdata['seconds_idle'] = d[1].strip()

if which('lspci'):
	sysdata['device_info'] = runcom('lspci')
else:
	sysdata['device_info'] = 'ERROR: lspci not found'

crondir = '/var/spool/cron'
for root, subFolders, files in os.walk(crondir):
	for file in files:
		c = []
		cronfile = "%s/%s" % (crondir,file)
		c = sanitize(readfile(cronfile)).split('\n')
		sysdata['cron'][file] = c

data = sanitize(runcom('w'))
sysdata['who'] = data

data = sanitize(runcom('last'))
sysdata['last'] = data

data = sanitize(runcom('df -h'))
sysdata['filesystem_info'] = data

data = runcom('rpm -qa --qf "%{NAME} %{VERSION} %{RELEASE}\n"').split('\n')
for i in sorted(data):
	n = i.split()
	sysdata['rpms'][n[0]]['version'] = n[1]
	sysdata['rpms'][n[0]]['release'] = n[2]

#print simplejson.dumps(sysdata, sort_keys=True, indent=2)
url = "%s/machinfo/%s/%s" % (elasticsearch_url, recdate, sysid)
data = simplejson.dumps(sysdata, sort_keys=True, indent=2)
req = urllib2.Request(url, data, {'Content-Type': 'application/json'})
f = urllib2.urlopen(req)
response = f.read()
f.close()
#print response
