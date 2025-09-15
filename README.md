This content is mainly taken from the Pluralsight course content https://app.pluralsight.com/library/courses/python-log-file-analysis/ , however I have mainly made changes to the file demos > LogAnalysis >  log_analyzer.py .

Examples of usage: 
>>> from log_analyzer import openLogFile
>>> log_file = openLogFile('../logs/smb.log')
>>> log_file
<generator object openLogFile at 0x0000012135F52340>
>>> next(log_file)
'06:14:56 : win10-charlie|192.168.55.133|RShare|pwrite|ok|picture-Charlie-5.bmp\n' ---> this is the first line in the file

>>> from extra.log_samples import samples
>>> samples.zeek_conn
>>> samples.zeek_conn 
'1659704789.147938\tCJTvUc1gwQ6ZlYWJn8\t192.168.253.154\t51429\t104.19.134.78\t443\ttcp\t-\t-\t-\t-\tOTH\t-\t-\t0\tR\t1\t40\t0\t0\t-'


>>> from log_analyzer import parse_smb
>>> log_entry="08:31:33 : win10-charlie|192.168.55.133|RShare|unlink|ok|autorun.inf"
>>> parse_smb(log_entry)
{'ts': '08:31:33', 'client_hostname': 'win10-charlie', 'client_IP': '192.168.55.133', 'share': 'RShare', 'operation': 'unlink', 'path': 'autorun.inf'}
>>> myvar = parse_smb(log_entry)
>>> myvar["ts"]
'08:31:33'


>>> from log_analyzer import printDnsAnomalies
>>> printDnsAnomalies("..\logs\dns.log")      
Domain                  Occurence               Similarity
--------------------------------------------------------------
globonamtics.com                           2                      88
mfadsrvr.com                               2                      50
netsolssl.com                              2                      48
office365.com                              1                      48
microsoftonline.com                        1                      46
greenhousegroup.com                        2                      40
cdn-apple.com                              2                      34
windows.net                                1                      22
azurefd.net                                1                      15
t-msedge.net                               2                      14


>>> from log_analyzer import printDnsQueries  
>>> printDnsQueries("..\logs\dns.log","globonamtics.com")
c2.globonamtics.com     192.168.253.166
c2.globonamtics.com     192.168.253.166


>>> from log_analyzer import plotEvents
>>> events={'Monday':3,'Tuesday':8,'Wednesday':5} 
>>> plotEvents(events)
<img width="292" height="248" alt="image" src="https://github.com/user-attachments/assets/a8bc511a-e940-459b-95f6-095bea7acd7c" />

