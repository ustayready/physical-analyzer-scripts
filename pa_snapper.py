'''
Script Name: pa_snapper.py
Version: 1
Revised Date: 07/07/2015
Python Version: 2
Description: A Cellebrite Physical Analyzer plugin to enumerate file systems looking for Snapchat thumbnails.
Copyright: 2015 Mike Felch <mike@linux.edu> 
URL: http://www.forensicpy.com/
--
- ChangeLog -
v1 - [07-07-2015]: Wrote original code
'''

# Import Physical Analyzer Project into Python
from physical import *

# Enumerate the file systems it parsed
for fs in ds.FileSystems:

  # Search all files for anything matching ".nomedia"
  for origfile in fs.Search('/*.nomedia'):

  	# Make sure the file has data
    if origfile.Size > 0:

      # Make sure Physical Analyzer says it's still intact and not deleted
      if origfile.Deleted == DeletedState.Intact:

      	# Create a variable using the original filename without the .nomedia
        path = 'c:\\snapchat\\' + origfile.Name.replace('.nomedia','')

        # Open a new file for writing
        with open(path, 'wb') as newfile:

          # Create a variable to store the original files content
          imgdata = origfile.Data.read()

          # Write the new file using the original file data with the new name
          newfile.write(imgdata)
