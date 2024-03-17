import time
from datetime import datetime
import argparse
import os 
import hashlib
import zlib
from collections import namedtuple
import operator
import struct
import enum
from typing import List
from pathlib import Path
import urllib.request
import requests
from requests.auth import HTTPBasicAuth


IndexEntry = namedtuple('IndexEntry',['ctime_s', 'ctime_n', 'mtime_s', 'mtime_n', 'dev', 'ino', 'mode', 'uid',
    'gid', 'size', 'sha1', 'flags', 'path',
])

class ObjectType(enum.Enum):
    commit = 1
    tree = 2
    blob = 3

def make_post(url,data, username,password):
    try:
        response = requests.post(url,data=data,
                        auth=HTTPBasicAuth(username=username, password=password),
                        headers={"Content-Type": "application/json"})
        print("RESPONSE", response)
    except Exception as e:
        print(e)
def http_requestt(url, username, password, data=None):
    """Make an authenticated HTTP request to given URL (GET by default, POST
    if "data" is not None).
    """
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, url, username, password)
    auth_handler = urllib.request.HTTPBasicAuthHandler(password_manager)
    opener = urllib.request.build_opener(auth_handler)
    f = opener.open(url, data=data)
    return f.read()


def get_object(hash):
    print("HASH: ", hash)

    obj_dir = os.path.join('.git', 'objects',hash[:2])
    objects = [ name for name in os.listdir(obj_dir) if name == hash[2:]]
    return os.path.join(obj_dir, objects[0])

def read_object(hash):
    path = get_object(hash)
    data = read_file(path)
    decompdata = zlib.decompress(data)
    nul_index = decompdata.index(b'\x00')
    header = decompdata[:nul_index]
    print(header)
    obj_type, size_str = header.decode().split()
    size = int(size_str)
    moredata = decompdata[nul_index + 1:]
    assert size == len(moredata), 'expected size {}, got {} bytes'.format(
            size, len(data))
    return (obj_type, moredata)

def read_tree(hash):
    obj_type, data = read_object(hash)
    assert obj_type == 'tree'
    i = 0 
    entries = []
    for _ in range(len(data)):
        end = data.find(b'\x00',i)
        if end ==-1:
            break
        ff = data[i:end].decode().split()
        digest = data[end + 1:end + 21]
        entries.append((ff[0],ff[1],digest.hex()))
        i = end + 1 + 20
    return entries

def find_missing_objects(local_hash, remote_hash):
    local_objects = find_commit_objects(local_hash)
    
    if remote_hash is None or remote_hash == '0000000000000000000000000000000000000000':
        return local_objects
    remote_objects = find_commit_objects(remote_hash)
    return local_objects - remote_objects
    # return local_objects

def find_tree_objects(tree_hash):
    objects = {tree_hash}
    print("Find tree objects(before): ",objects)
    for mode, path, hash in read_tree(tree_hash):
        objects.add(hash)
    return objects

def build_lines_data(lines):
    """Build byte string from given lines to send to server."""
    result = []
    for line in lines:
        result.append('{:04x}'.format(len(line) + 5).encode())
        result.append(line)
        result.append(b'\n')
    result.append(b'0000')
    return b''.join(result)

# def build_lines_data(lines):
#     """Build byte string from given lines to send to server."""
#     result = []
#     for line in lines:
#         result.append('{:04x}'.format(len(line) + 5).encode())
#         result.append(line)
#         result.append(b'\n')
#     result.append(b'0000')
#     return b''.join(result)

def find_commit_objects(hash):
    objects = {hash}
    obj_type, commit = read_object(hash)
    assert obj_type == 'commit'
    lines = commit.decode().splitlines()
    tree = next(l[5:45] for l in lines if l.startswith('tree '))
    objects.update(find_tree_objects(tree))
    return objects

def encode_pack_object(obj):
    """Encode a single object for a pack file and return bytes (variable-
    length header followed by compressed data bytes).
    """
    obj_type, data = read_object(obj)
    type_num = ObjectType[obj_type].value
    size = len(data)
    byte = (type_num << 4) | (size & 0x0f)
    size >>= 4
    header = []
    while size:
        header.append(byte | 0x80)
        byte = size & 0x7f
        size >>= 7
    header.append(byte)
    return bytes(header) + zlib.compress(data)

def create_pack(objects):
    """Create pack file containing all objects in given given set of SHA-1
    hashes, return data bytes of full pack file.
    """
    header = struct.pack('!4sLL', b'PACK', 2, len(objects))
    body = b''.join(encode_pack_object(o) for o in sorted(objects))
    contents = header + body
    sha1 = hashlib.sha1(contents).digest()
    data = contents + sha1
    return data

# def create_pack(objects):
#     """Create pack file containing all objects in given given set of SHA-1
#     hashes, return data bytes of full pack file.
#     """
#     header = struct.pack('!4sLL', b'PACK', 2, len(objects))
#     body = b''.join(encode_pack_object(o) for o in sorted(objects))
#     contents = header + body
#     sha1 = hashlib.sha1(contents).digest()
#     data = contents + sha1
#     return data
# def create_pack(objects):
#     header = struct.pack('!4sLL', b'PACK', 2, len(objects))
#     body = b''.join(encode_pack_object(o) for o in sorted(objects))
#     # for o in sorted(objects):
#     #     (encode_pack_object(o))
#     contents = header + body
#     sha1 = hashlib.sha1(contents).digest()
#     print("HEADER: ", header)
#     print("BODY: ", body)
#     print("HASH: ", sha1)
#     data = contents + sha1
#     return data

def install_authenticated_request_opener(url, username, password, data=None):
    password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_mgr.add_password(None, url, username, password)

    handler = urllib.request.HTTPBasicAuthHandler(password_mgr)

    # create "opener" (OpenerDirector instance)
    opener = urllib.request.build_opener(handler)

    # Install the opener.
    # Now all calls to urllib.request.urlopen use our opener.
    urllib.request.install_opener(opener)

def http_request(url, data=None):
    """Make an authenticated HTTP request to given URL (GET by default, POST
    if "data" is not None).
    """
    print("DATA IN HTTP REQUEST:",data )
    user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'
    headers = { 'User-Agent  : Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}
    html_request = urllib.request.Request(url)
    try:
        if data is None:
            result = urllib.request.urlopen(html_request,data)
            res = result.read()
        else:
            result = urllib.request.urlopen(html_request,data)
            res = result.read()
        return res
    except urllib.error.URLError as e:
        print("RRRRR: ", e)

def extract_remote_hash(res):
    lines = res.split()
    assert lines[0] == b'001f#'
    assert lines[1] == b'service=git-receive-pack'
    if lines[2][:40] == b'0' * 40:
        return None
    length = len(lines[2])
    hash = lines[2][length - 40:]
    ref = lines[3].split(b'\x00')[0]
    return (hash,ref)

def create_file(file_name: str, data: str) -> None:
    with open(file_name, 'wb') as f:
        f.write(data)
        f.close()

def read_file(path: str) -> bytes:
    with open(path, 'rb') as f:
        content = f.read()
    return content

def get_local_master_hash():
    """Get current commit hash (SHA-1 string) of local master branch."""
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    try:
        return read_file(master_path).decode().strip()
    except FileNotFoundError:
        return None
 
def write_tree():
    tree_entries = []
    for entry in read_index():
        mode_path = '{:o} {}'.format(entry.mode, entry.path).encode()
        tree_entry = mode_path + b'\x00' + entry.sha1
        tree_entries.append(tree_entry)
    return hash_object(b''.join(tree_entries), 'tree', True)

def commit(msg, author=None):
    # print("MSG: ",msg)
    tree = write_tree()
    print("tree: ", tree)
    parent = get_local_master_hash()
    if author is None:
        author = '{} <{}>'.format(
            os.environ['GIT_AUTHOR_NAME'], os.environ['GIT_AUTHOR_EMAIL'],read_file(os.path.join('.git', 'HEAD')).decode().rpartition('/')[-1])

    timestamp = int(time.mktime(time.localtime()))
    utc_offset = -time.timezone
    author_time = '{} {}{:02}{:02}'.format(
            timestamp,
            '+' if utc_offset > 0 else '-',
            abs(utc_offset) // 3600,
            (abs(utc_offset) // 60) % 60)
    lines = ['tree ' + tree]
    if parent:
        lines.append('parent ' + parent)
    lines.append('author {} {}'.format(author, author_time))
    lines.append('committer {} {}'.format(author, author_time))
    lines.append('')
    lines.append(msg)
    lines.append('')
    # print("LINES : ", lines)
    data = '\n'.join(lines).encode()
    # print("data : ", data)
    sha1 = hash_object(data, 'commit')
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    create_file(master_path, sha1.encode())
    print('committed to master: {:7}'.format(sha1))
    return sha1
    # df = read_file(Path.home()/'.gitconfig')
    # dd = df.decode()
    # print(dd.user)
    # print(author)


def read_index() -> List[str]:
    try:
        data = read_file(os.path.join('.git', 'index'))
    except Exception as e:
        return []
    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[-20:], 'invalid index checksum'
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])
    assert signature == b'DIRC', 'invalid index signature {}'.format(signature)
    assert version == 2, 'unknown index version {}'.format(version)
    entry_data = data[12:-20]
    entries = []
    i = 0
    while i + 62 < len(entry_data):
        end = i+62
        entry_head = struct.unpack('!LLLLLLLLLL20sH',entry_data[i:end])
        # print("entry_data: ", entry_data)
        path_end = entry_data.index(b'\x00',end)
        path = entry_data[end:path_end]
        entry = IndexEntry(*(entry_head + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    assert len(entries) == num_entries
    return entries

def write_index(entries: List[str]) -> None:
    packed_entries = []
    for entry in entries:
        entry_head = struct.pack('!LLLLLLLLLL20sH',
                entry.ctime_s, entry.ctime_n, entry.mtime_s, entry.mtime_n,
                entry.dev, entry.ino, entry.mode, entry.uid, entry.gid,
                entry.size, entry.sha1, entry.flags)
        
        path = entry.path.encode()
        length = ((62 + len(path) + 8) // 8) * 8
        packed_entry = entry_head + path + b'\x00' * (length - 62 - len(path))
        packed_entries.append(packed_entry)

    header = struct.pack('!4sLL', b'DIRC', 2, len(entries))
    all_data = header + b''.join(packed_entries)
    digest = hashlib.sha1(all_data).digest()
    create_file(os.path.join('.git', 'index'), all_data + digest)

def hash_object(data,object_type, write=True) -> str:
    """Compute object ID and optionally create an object from a file.

    Args:
        data: str. Name of git repository.
        object_type: str. Specify the type of object to be created.
        write: Write the object into the object database.
    
    Returns:
        str. Object ID.
    """
    header = "{} {}".format(object_type, len(data)).encode()
    full_data = header + b'\x00' + data
    hash = hashlib.sha1(full_data).hexdigest()

    if write:
        path = os.path.join('.git','objects',hash[:2], hash[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            create_file(path,zlib.compress(full_data))
    return hash

def status() -> None:
    """Show the working tree status."""
    paths = set()

    for root, dirs, files in os.walk('.'):
        dirs[:] = [d for d in dirs if d != '.git']
        for file in files:
            path = os.path.join(root, file)
            if path.startswith('./'):
                path = path[2:]
            paths.add(path)
    entries_by_path = {e.path: e for e in read_index()}
    entry_paths = set(entries_by_path)

    changed = {p for p in (paths & entry_paths) if hash_object(read_file(p), 'blob', write=False) != entries_by_path[p].sha1.hex()}
    new = paths.difference(entry_paths)
    deleted = entry_paths.difference(paths)
    changes_to_commit = entry_paths.difference(new,deleted)

    branch = read_file(os.path.join('.git', 'HEAD'))
    print("On branch", branch.decode().rpartition('/')[-1])
    print()
    if changes_to_commit:
        print('Changes to be committed:')
        for path in changes_to_commit:
            print('   ', path)
        print()
    if changed:
        print('changed files:')
        for path in changed:
            print('   ', path)
        print()
    if new:
        print('Untracked files:')
        for path in new:
            print('   ', path)
        print()
    if deleted:
        print('deleted files:')
        for path in deleted:
            print('   ', path)
        print()
    
    # return (sorted(changed), sorted(new), sorted(deleted))
def add(paths: list[str]):
    """Add file contents to the index.
    
    Args:
        paths: str. Files to add content from.
    """
    if not isinstance(paths, list):
        raise TypeError("Input must be a list.")
    all_entries = read_index()
    entries = [e for e in all_entries if e.path not in paths]
    for path in paths:
        sha1 = hash_object(read_file(path),'blob')
        st = os.stat(path)
        flags = len(path.encode())
        entry = IndexEntry( int(st.st_ctime),0, int(st.st_mtime), 0, st.st_dev,
                           st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
                           bytes.fromhex(sha1), flags, path)             

        entries.append(entry)
    entries.sort(key=operator.attrgetter('path'))
    write_index(entries)

def init(repo: str) -> None:
    """Create an empty Git repository.
    
    Args:
        repo: str. Name of git repository.
    """
    if not os.path.exists(repo):
        path = os.path.join(repo, '.git')
        os.makedirs(path)
        os.chdir(path)
        for dir in ['objects', 'objects/info', 'objects/pack', 'refs', 'refs/heads', 'hooks', 'branches']:
            os.makedirs(os.path.join(dir))
        create_file('HEAD', b'ref: refs/heads/master\n')
        create_file('description', b"Unnamed repository; edit this file 'description' to name the repository.")
        print("Initialized empty Git repository in", repo)  
    else:
        print("Directory already exists")

def push():
    install_authenticated_request_opener('https://github.com/deadex-ng/test3/info/refs?service=git-receive-pack','deadex-ng',token)
    data = http_request('https://github.com/deadex-ng/test3/info/refs?service=git-receive-pack')
    remote_hash, ref = extract_remote_hash(data)
    print("REMOTE HASH: ",  remote_hash.decode()[:])
    local_hash = get_local_master_hash()
    missing = find_missing_objects(local_hash, remote_hash.decode())
    print('updating remote master from {} to {} ({} object{})'.format(
            remote_hash or 'no commits', local_hash, len(missing),
            '' if len(missing) == 1 else 's'))
    data = create_pack(missing)
    print("DATA: ", data)
    lines = ['{} {} refs/heads/master\x00 report-status'.format(
        remote_hash or ('0' * 40), local_hash).encode()]
    data = build_lines_data(lines) + create_pack(missing)
    # url = git_url + '/git-receive-pack'
    response = http_requestt('http://github.com/deadex-ng/test3/info/refs?service=git-receive-pack', 'deadex-ng',token,data)
    # make_post('https://github.com/deadex-ng/test3/info/refs?service=git-receive-pack',
    #           data,
    #           'deadex-ng',
    #           token)
    print("response: ", response)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='PROG')
    sub_parsers = parser.add_subparsers(dest='command')
    sub_parsers.required = True

    sub_parser = sub_parsers.add_parser('init',
                                        help= 'Initiliaze new git repo')
    sub_parser.add_argument('repo', help ='drectory name for new repo')

    sub_parser = sub_parsers.add_parser('hash-object',
                                        help= 'Hash content of given path')
    sub_parser.add_argument('path', help ='path of file to hash')
    sub_parser.add_argument('-t', type = str, dest='type',help ='Specify type of objectto be created')
    sub_parser.add_argument('-w', action="store_true", dest='write' ,help ='Actually write the object into the object database.')

    sub_parser = sub_parsers.add_parser('add',
                                        help= 'Add file content to index')
    sub_parser.add_argument('path', nargs='+', help ='Files to add content from')

    sub_parser = sub_parsers.add_parser('status',
                                        help ='Show the working tree status')

    sub_parser = sub_parsers.add_parser('commit',
                                        help= 'Record changes to the repository')
    sub_parser.add_argument('-m', type = str, help ='The commit message')

    sub_parser = sub_parsers.add_parser('push',
                                        help ='Push to remote')
    args = parser.parse_args()

    if args.command == 'init':
        init(args.repo)
    elif args.command == 'hash-object':
        print(hash_object(read_file(args.path), args.type, args.write))
    elif args.command == 'add':
        add(args.path)
    elif args.command == 'status':
        status()
    elif args.command == 'commit':
        commit(args.m)
    elif args.command == 'push':
        push()