import sys, os, base64, datetime, re, pickle, hashlib, logging
from optparse import OptionParser
import xml.etree.cElementTree as xml
from collections import namedtuple
import ssl

import config

try:
    # Python 2
    import urllib2 as urlrequest
    import urllib2 as urlerror
except ImportError:
    # Python 3
    import urllib.request as urlrequest
    import urllib.error as urlerror

File = namedtuple('File', ['name', 'size', 'mtime', 'ctime', 'contenttype'])
PROPFIND = u'''<?xml version="1.0" encoding="utf-8"?>
<propfind xmlns="DAV:">
<allprop/>
</propfind>'''

def main():
    parser = OptionParser()
    parser.add_option("-p", "--pattern", dest="file_pattern", help="Regular expression file pattern to match against")
    parser.add_option("-d", "--persisdir", dest="persisdir", help="Directory to store state. This will override the config.py setting")
    parser.add_option("-k", "--insecure", action="store_true", dest="insecure", default=False, help="Skip certificate validation")
    parser.add_option("-s", "--silent", action="store_true", dest="set_state", default=False, help="Establish state without printing logs")
    (options, args) = parser.parse_args()
    
    if(options.insecure):
        ssl._create_default_https_context = ssl._create_unverified_context
    
    if(options.persisdir):
        config.PERSIS_DIR = options.persisdir
    
    app_path = os.path.join(os.getcwd())
    state_dir = os.path.join(app_path, config.PERSIS_DIR)

    if not options.file_pattern:
        print('Please profile a file pattern!')
        sys.exit(1)
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)
    
    persis_file = state_dir + "/" + hash_filename(options.file_pattern) + ".p"
    files_to_pull = get_file_list(options.file_pattern)
    pull_files(files_to_pull, persis_file, options.set_state)

def get_basic_auth():
    s = ('%s:%s' % (config.USER, config.PASSWORD))
    s = s.encode()
    return base64.b64encode(s).decode("utf-8")

def pull_files(files, persis_file, set_state):
    
    try:
        files_last_pull = pickle.load( open( persis_file, "rb" ) )
    except IOError:
        files_last_pull = {}
        
    for filename, size in files.items():
        content_range = 0
        if filename in files_last_pull:
            content_range = files_last_pull[filename]
        
        if str(content_range) == str(size):
            continue
            
        url = "https://" + config.DOMAIN + filename
        headers = {
            "Authorization": "Basic %s" % get_basic_auth(),
            "Range": "bytes= %s-" % content_range
        }
        
        req = urlrequest.Request(url, None, headers)
        try:
            response = urlrequest.urlopen(req)
            if ((response.getcode() == 200 or response.getcode() == 206)):
                if set_state is False:
                    print(response.read().decode("utf-8"))
            new_content_range = response.headers['content-range']
            new_content_range = new_content_range.split('/')[1]
            # logging.error("http success. filename = '%s', old range = '%s', new range = '%s'" %(filename, content_range, new_content_range))
        except (urlerror.HTTPError, urlerror.URLError) as e:
            new_content_range = content_range
            # logging.error("http error. filename = '%s', old range = '%s', new range = '%s'" %(filename, content_range, new_content_range))
        
        files[filename] = new_content_range
    
    pickle.dump( files, open( persis_file, "wb" ) )

def elem2file(elem):
    return File(
        prop(elem, 'href'),
        int(prop(elem, 'getcontentlength', 0)),
        prop(elem, 'getlastmodified', ''),
        prop(elem, 'creationdate', ''),
        prop(elem, 'getcontenttype', ''),
    )
    
def prop(elem, name, default=None):
    child = elem.find('.//{DAV:}' + name)
    return default if child is None else child.text
    
def get_file_list(file_pattern):
    url = "https://" + config.DOMAIN + config.PATH
    headers = { 
        "Authorization": "Basic %s" % get_basic_auth(),
        "Depth": "1"
    }
    req = urlrequest.Request(url, PROPFIND, headers)
    req.get_method = lambda: 'PROPFIND'
    response = urlrequest.urlopen(req)
    
    tree = xml.fromstring(response.read())
    allfiles = [elem2file(elem) for elem in tree.findall('{DAV:}response')]
    pattern = re.compile(file_pattern)
    files_to_pull = {}

    for filepath in allfiles:
        filename = os.path.basename(os.path.normpath(filepath.name))
        if pattern.match(filename):
            files_to_pull[filepath.name] = filepath.size

    if(len(files_to_pull) == 0):
        print('No files found!')
        sys.exit(1)
    return files_to_pull    
    
def hash_filename(value):
    d = hashlib.sha1(str.encode(value))
    d.digest()
    s = d.hexdigest()[0:10]
    s = base64.urlsafe_b64encode(('%s' % s).encode()).decode("utf-8").rstrip('=')
    return s
    
if __name__ == '__main__': main()