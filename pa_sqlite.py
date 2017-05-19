'''
Script Name: pa_sqlite.py
Version: 1
Revised Date: 10/30/2015
Python Version: 2
Description: A Cellebrite Physical Analyzer plugin to enumerate file systems looking for sqlite dbs.
Copyright: 2015 Mike Felch <mike@linux.edu> 
URL: http://www.forensicpy.com/
--
- ChangeLog -
v1 - [10-30-2015]: Wrote original code
'''

from physical import *
import hashlib
import math
import glob
import os
import datetime

def entropy(data):
    if not data:
        return 0
    e = 0
    for x in range(256):
        p_x = float(data.count(chr(x)))/len(data)
        if p_x > 0:
            e += -p_x*math.log(p_x, 2)
    return e

local_dir = 'c:\\dbs\\'

file = open(local_dir + 'databases.log', 'w')
file.write('FileSystem\tPath\tFile\tSize\tEntropy\tStatus\tMD5\tCreated\tModified\tAccessed\n')

for fs in ds.FileSystems:
    nodes = fs.GetAllNodes()
    for f in nodes:
        if f.AbsolutePath[-3:] == '.db':
            db_data = f.Data.read()

            with open(local_dir + f.Name, 'w') as db_file:
                db_file.write(db_data)

            if f.Size>0:
                data = f.read()
            else:
                data = ''
            e = entropy(data)

            md5 = hashlib.md5()
            md5.update(data)
            md5hash = md5.hexdigest()

            if isinstance(f.CreationTime, TimeStamp):
                ct = str(f.CreationTime)
            else:
                ct = ''
            if isinstance(f.ModifyTime, TimeStamp):
                mt = str(f.ModifyTime)
            else:
                mt = ''
            if isinstance(f.AccessTime, TimeStamp):
                at = str(f.AccessTime)
            else:
                at = ''
            file.write(fs.Name + '\t' + f.AbsolutePath + '\t' + f.Name + '\t' + str(f.Size) + '\t' + str(e) + '\t' + md5hash + '\t' + ct + '\t' + mt + '\t' + at + '\t' + '\r\n')

file.close()

