#!/usr/bin/python
# 20151028 Created by SkiTheSlicer
# 20151029 Removed redundancy in parse_hashes()
# 20151102 Broke parse_hashes() into search_HASH(), calculate_HASH()
# 20151108 Converted to html scraping (vice hardcoded download links)
# 20151117 Renamed from elk-airgap to elk-airgap-download

urls_to_scrape_elastic = [
  'https://www.elastic.co/downloads/elasticsearch',
  'https://www.elastic.co/downloads/logstash',
  'https://www.elastic.co/downloads/kibana',
  'https://www.elastic.co/downloads/beats/filebeat',
  'https://www.elastic.co/downloads/beats/topbeat'
]

urls_to_scrape_java = [
  'http://java.com/en/download/linux_manual.jsp'
]
#http://java.com/en/download/manual.jsp

urls_to_scrape_nginx = [
  'http://packages.ubuntu.com/trusty/all/nginx/download',
  'http://packages.ubuntu.com/trusty/amd64/nginx-light/download',
  'http://packages.ubuntu.com/trusty/i386/nginx-light/download',
  'http://packages.ubuntu.com/trusty/all/nginx-common/download',
  'http://packages.ubuntu.com/trusty/amd64/apache2-utils/download',
  'http://packages.ubuntu.com/trusty/i386/apache2-utils/download',
  'http://packages.ubuntu.com/trusty/amd64/libapr1/download',
  'http://packages.ubuntu.com/trusty/i386/libapr1/download',
  'http://packages.ubuntu.com/trusty/amd64/libaprutil1/download',
  'http://packages.ubuntu.com/trusty/i386/libaprutil1/download'
]

def check_lib_deps():
  import sys
  # Ref: http://www.crummy.com/software/BeautifulSoup/bs4/doc/
  # Ref: http://docs.python-requests.org/en/latest/
  try:
    import requests
    from bs4 import BeautifulSoup
  except:
    print "Script requires python-requests library:"
    print "  https://github.com/kennethreitz/requests/releases"
    print "Script requires beautifulsoup4 library:"
    print "  http://www.crummy.com/software/BeautifulSoup/bs4/download/"
    sys.exit(1)
  #else:
  #  print "pass requests"
  #  print "pass bs4"

#def urllib_download_file(url_to_download, os_file_path):
#  # Ref: http://stackoverflow.com/questions/5797344/python-downloading-a-exe-file-from-the-internet
#  import urllib
#  urllib.urlretrieve(url_to_download, os_file_path)

def count_file_lines(file_to_count):
  # Ref: http://stackoverflow.com/questions/845058/how-to-get-line-count-cheaply-in-python
  with open(file_to_count, 'r') as file:
    for index, lines in enumerate(file):
      pass
  return index + 1

def parse_hashes(file_to_parse, file_to_hash):
  from os.path import basename
  found = False
  lines = count_file_lines(file_to_parse)
  filename = basename(file_to_hash)
  print "Hashing " + filename
  with open(file_to_parse, 'r') as hashfilecontents:
    for line in hashfilecontents:            
      if filename in line or (lines==1):
        if search_md5(line, True):
          print "Actual MD5:   " + calculate_md5(file_to_hash)
          found = True
        if search_sha1(line, True):
          print "Actual SHA1:   " + calculate_sha1(file_to_hash)
          found = True
        if search_sha256(line, True):
          print "Actual SHA256:   " + calculate_sha256(file_to_hash)
          found = True
    if (found==False):
      hashfilecontents.seek(0)
      for line in hashfilecontents:
        if search_md5(line, True):
          print "Actual MD5:   " + calculate_md5(file_to_hash)
          found = True
        if search_sha1(line, True):
          print "Actual SHA1:   " + calculate_sha1(file_to_hash)
          found = True
        if search_sha256(line, True):
          print "Actual SHA256:   " + calculate_sha256(file_to_hash)
          found = True
    if (found==False):
      print "Error: Valid hash not found in hashfile."

def search_md5(string_to_search_in, should_print):
  # Note: re.match has to find the pattern at the beginning of the string.
  # Note: re.search can find the pattern anywhere in the string.
  import re
  md5pattern = re.compile("(^|[^0-9a-f])([0-9a-f]{32})([^0-9a-f]|$)")
  md5search = re.search(md5pattern, string_to_search_in)
  if md5search and should_print:
    print "Expected MD5: " + md5search.group(2)
    return md5search.group(2)
  elif md5search:
    return md5search.group(2)
  else:
    return md5search

def calculate_md5(file_to_hash):
  # Ref: http://pythoncentral.io/hashing-files-with-python/
  import hashlib
  BLOCKSIZE = 65536
  hasher = hashlib.md5()
  #hashlib.sha512(open(fn).read()[8:]).hexdigest()
  with open(file_to_hash, 'rb') as binaryfile:
    bufferedfile = binaryfile.read(BLOCKSIZE)
    while len(bufferedfile) > 0:
      hasher.update(bufferedfile)
      bufferedfile = binaryfile.read(BLOCKSIZE)
  return hasher.hexdigest()
        
def search_sha1(string_to_search_in, should_print):
  # Note: re.match has to find the pattern at the beginning of the string.
  # Note: re.search can find the pattern anywhere in the string.
  import re
  sha1pattern = re.compile("(^|[^0-9a-f])([0-9a-f]{40})([^0-9a-f]|$)")
  sha1search = re.search(sha1pattern, string_to_search_in)
  if sha1search and should_print:
    print "Expected SHA1: " + sha1search.group(2)
  return sha1search
    
def calculate_sha1(file_to_hash):
  # Ref: http://pythoncentral.io/hashing-files-with-python/
  import hashlib
  BLOCKSIZE = 65536
  hasher = hashlib.sha1()
  with open(file_to_hash, 'rb') as binaryfile:
    bufferedfile = binaryfile.read(BLOCKSIZE)
    while len(bufferedfile) > 0:
      hasher.update(bufferedfile)
      bufferedfile = binaryfile.read(BLOCKSIZE)
  return hasher.hexdigest()

def search_sha256(string_to_search_in, should_print):
  # Note: re.match has to find the pattern at the beginning of the string.
  # Note: re.search can find the pattern anywhere in the string.
  import re
  sha256pattern = re.compile("(^|[^0-9a-f])([0-9a-f]{64})([^0-9a-f]|$)")
  sha256search = re.search(sha256pattern, string_to_search_in)
  if sha256search and should_print:
    print "Expected SHA256: " + sha256search.group(2)
  return sha256search

def calculate_sha256(file_to_hash):
  # Ref: http://pythoncentral.io/hashing-files-with-python/
  import hashlib
  BLOCKSIZE = 65536
  hasher = hashlib.sha256()
  with open(file_to_hash, 'rb') as binaryfile:
    bufferedfile = binaryfile.read(BLOCKSIZE)
    while len(bufferedfile) > 0:
      hasher.update(bufferedfile)
      bufferedfile = binaryfile.read(BLOCKSIZE)
  return hasher.hexdigest()

##urllib hardcoded downloading
#def main():
#  import os
#  for index in range(len(urllist)):
#    category = categorylist[index]
#    url = urllist[index]
#    filename = urllist[index].split('/')[-1]
#    filepath = os.path.join(category, filename)
#    hashurl = hashurllist[index]
#    hashfilename = hashurllist[index].split('/')[-1]
#    hashpath = os.path.join(category, hashfilename)
#    
#    if not os.path.exists(category):
#      os.makedirs(category)
#    print "\n" + "Downloading " + filename + "..."
#    urllib_download_file(url, filepath)
#    urllib_download_file(hashurl, hashpath)
#    parse_hashes(hashpath, filepath)

def request_url_to_disk(url_to_download, local_folder_name):
  import os
  import requests
  file = requests.get(url_to_download, stream=True)
  if file.status_code == 200:
    filename = file.url.split('?')[0].split('/')[-1]
    filepath = os.path.join(local_folder_name, filename)
    if not os.path.exists(local_folder_name):
      os.makedirs(local_folder_name)
    print "\n" + "Downloading " + filename + "..."
    with open(filepath, 'wb') as binaryfile:
      for chunk in file.iter_content(1024):
        binaryfile.write(chunk)
    if 'sha1' in filename:
      if filename.rsplit(".",2)[1] == 'sha1':
        hashpath = os.path.join(local_folder_name, filename.rsplit(".",2)[0])
      else:
        hashpath = os.path.join(local_folder_name, filename.rsplit(".",1)[0])
      parse_hashes(filepath, hashpath)
    elif os.path.isfile(".".join([filepath, "checksum", "txt"])):
      parse_hashes(".".join([filepath, "checksum", "txt"]), filepath)
    elif 'jre' in filename and os.path.isfile(os.path.join(local_folder_name, "java.checksum.txt")):
      parse_hashes(os.path.join(local_folder_name, "java.checksum.txt"), filepath)

def scrape_elastic(page_to_scrape):
  import requests
  from bs4 import BeautifulSoup
  import re
  page = requests.get(page_to_scrape)
  if [[ page.status_code == requests.codes.ok ]]:
    soup = BeautifulSoup(page.text, 'html.parser')
    anchors = soup.find_all('a', href=re.compile("deb"))
    #print "Anchors: " + str(len(anchors))
    if len(anchors) == 0:
      anchors = soup.find_all('a', href=re.compile("linux.*.tar.gz"))
    for anchor in anchors:
      product = anchor['href'].split('/')[3]
      link = anchor['href']
      if args.list_only:
        if not "sha1" in link:
          print link.rsplit("/",1)[1]
      else:
        request_url_to_disk(link, product)
  else:
    print page.status_code

def scrape_java(page_to_scrape):
  # http://www.oracle.com/technetwork/java/javase/downloads/index.html
  #  http://www.oracle.com/ocom/groups/public/@ocom/documents/digitalasset/1612430.png
  #  http://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html
  import requests
  from bs4 import BeautifulSoup
  import re
  import os
  page = requests.get(page_to_scrape)
  if [[ page.status_code == requests.codes.ok ]]:
    soup = BeautifulSoup(page.text, 'html.parser')
    version_str = soup.find('h4').get_text()
    version_regex = re.search("(\d*)\sUpdate\s(\d*)$", version_str)
    version = version_regex.group(1) + "u" + version_regex.group(2)
    if args.list_only:
      #print version_str
      print "jre-" + version + "-linux-i586.tar.gz"
      print "jre-" + version + "-linux-x64.tar.gz"
    else:
      hashlink = "".join(["https://www.oracle.com/webfolder/s/digest/", version, "checksum.html"])
      for anchor in soup.find_all('a', href=True, string=True, title=re.compile("Download Java software for (Linux$|Linux x64$)")):
        link = anchor['href']
        hashfile = "java.checksum.txt"
        hashpath = os.path.join('java', hashfile)
        if not os.path.exists('java'):
          os.makedirs('java')
        soup2 = BeautifulSoup(requests.get(hashlink).text, 'html.parser')
        for row in soup2.find_all('tr'):
          for column in row.find_all('td'):
            search = re.search("jre\S*linux\S*.tar.gz", column.get_text())
            if search:
              #print row.get_text()
              with open(hashpath, 'ab') as binaryfile:
                binaryfile.write(row.get_text() + "\n")
        request_url_to_disk(link, 'java')
  else:
    print page.status_code

def scrape_nginx(page_to_scrape):
  import requests
  from bs4 import BeautifulSoup
  import re
  import os
  page = requests.get(page_to_scrape)
  if [[ page.status_code == requests.codes.ok ]]:
    soup = BeautifulSoup(page.text, 'html.parser')
    anchors = soup.find_all('a', href=re.compile("deb"))
    link = anchors[0]['href']
    if args.list_only:
      print link.rsplit("/",1)[1]
    else:
      hashfile = ".".join([link.rsplit("/",1)[1], "checksum", "txt"])
      hashpath = os.path.join('nginx', hashfile)
      if not os.path.exists('nginx'):
        os.makedirs('nginx')
      for tt in soup.find('table', id="pdownloadmeta").find_all('tt'):
        with open(hashpath, 'ab') as binaryfile:
          binaryfile.write(tt.get_text() + "\n")
      request_url_to_disk(link, 'nginx')

def download_config_kibana():
  import os
  link = 'https://gist.githubusercontent.com/thisismitch/8b15ac909aed214ad04a/raw/fc5025c3fc499ad8262aff34ba7fde8c87ead7c0/kibana4'
  if not os.path.exists(os.path.join('kibana', 'etc')):
    os.makedirs(os.path.join('kibana', 'etc'))
  request_url_to_disk(link, os.path.join('kibana', 'etc'))
  
def download_config_logstash():
  import os
  links = [
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-conn_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-dhcp_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-dns_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-files_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-http_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-notice_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/bro/bro-weird_log.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/log2timeline/logstash-log2timeline.conf'
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/web_logs/logstash-apache-combined.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/web_logs/logstash-apache-common.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/web_logs/logstash-iis6.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/web_logs/logstash-iis7.conf',
    'https://raw.githubusercontent.com/505Forensics/logstash-dfir/master/conf_files/web_logs/logstash-iis8.conf'
  ]
  if not os.path.exists(os.path.join('logstash', 'etc', 'ref')):
    os.makedirs(os.path.join('logstash', 'etc', 'ref'))
  for link in links:
    request_url_to_disk(link, os.path.join('logstash', 'etc', 'ref'))
  link = 'https://raw.githubusercontent.com/chrissanders/AppliedNSM/master/logstash-bro22-parse.conf'
  request_url_to_disk(link, os.path.join('logstash', 'etc'))

def parse_arguments():
  import argparse
  global args
  parser = argparse.ArgumentParser(
    prog='elk-airgap-download.py',
    description='Download ELK dependencies for offline installation.',
    epilog='Created by SkiTheSlicer (https://github.com/SkiTheSlicer/elk-airgap/)')
    #formatter_class=argparse.RawTextHelpFormatter)
  parser.add_argument('-l', '--list-only', 
                      help='List newest version(s) without downloading dependencies.',
                      action='store_true')
  parser.add_argument('-d', '--directory',
                      nargs='?', default='.',
                      help='Specify target download directory. Defaults to current.')
  parser.add_argument('-v', '--version',
                      help='Display version.',
                      action='version',
                      version='Build 2015-11-17')
                      #version='%(prog)s Build 2015-11-17')
  args = parser.parse_args()

#Download using requests and html scraping
def main():
  import os
  import sys
  parse_arguments()
  #if args.list_only:
    #print "listing only"
  check_lib_deps()
  if not os.path.exists(args.directory):
    print "ERROR: Path \"" + os.path.abspath(args.directory) + "\" doesn't exist"      
    sys.exit(1)
  for url in urls_to_scrape_elastic:
    scrape_elastic(url)
    if not args.list_only: print "\n"
  for url in urls_to_scrape_java:
    scrape_java(url)
    if not args.list_only: print "\n"
  for url in urls_to_scrape_nginx:
    scrape_nginx(url)
    if not args.list_only: print "\n"
  if not args.list_only:
    print "Downloading configuration files..."
    download_config_logstash()
    print "\n"
    download_config_kibana()
    print "\n"

if __name__ == "__main__":
  main()
