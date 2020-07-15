#! /usr/bin/env python3

import argparse, signal, sys, os, ssl, urllib.request, hashlib, queue, threading, time

# Disable SSL
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# User Agent
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
headers = {'User-Agent': user_agent}

# Create dictionary containing file hashes
default_file_hashes = {}

def get_file_hash(i, url, q):
    
    while True:
        default_file = q.get()
        request = urllib.request.Request(url=url + default_file, data=None, headers=headers)
        urllib.request.install_opener(urllib.request.build_opener())
        try:
            # Returns 200
            response = urllib.request.urlopen(request, context=ctx)
            html_response = response.read().decode('utf-8', 'ignore')
            hash_object = hashlib.sha256(html_response.encode('utf-8'))
            hash_digest = hash_object.hexdigest()
            default_file_hashes[default_file]=hash_digest

        except:
            # Not interested in non-200 responses
            #html_response = response.read().decode('utf-8', 'ignore')
            pass

        q.task_done()

def run(url, repo, extension, num_threads, verbose):

    # Define queue
    q = queue.Queue()

    # Cloning Repository
    repo_folder = repo.rsplit('/',1)[1]
    if not (os.path.isdir(repo_folder)):
        try: 
            if not (os.path.isdir(repo_folder)):
                os.system('git clone ' + repo + ' ' + repo_folder)
        except:
            print("Sorry I could not clone your repo :(")
            sys.exit(1)

    # Force to master branch - this is needed in case of multiple runs
    os.system("git -C " + repo_folder + " checkout master -f >/dev/null 2>&1")

    # Get releases
    releases = os.popen("git -C " + repo_folder + " tag |  sort -rbVu").read().splitlines()
    print("Number of releases: " + str(len(releases)))

    # Indexing default files
    try:
        output = os.popen("find " + repo_folder + " -type f -name '*." + extension + "' | sed 's|" + repo_folder + "||g'").read()
        default_files = output.splitlines()
    except:
        print("Problems with the provided extension. Something went wrong.")
        sys.exit(1)

    if not default_files:
        print("Not default files found. Something went wrong.")
        sys.exit(1)
    
    print("Number of default " + extension + " files found in the local repo: " + str(len(default_files)))

    # Define the number of threads
    print("Number of threads: " + str(num_threads))
    for i in range(num_threads):
        worker = threading.Thread(target=get_file_hash, args=(i, url, q))
        worker.setDaemon(True)
        worker.start()

    # Add all default files into the queue
    for default_file in default_files:
        q.put(default_file)

    while not q.empty() :
        sys.stdout.write("\r"+str(int((len(default_files) - q.qsize()) * 1.0 / len(default_files) * 100)) + "%")
        sys.stdout.flush()
    sys.stdout.write("\r")

    q.join()

    print("Checking hashes against local releases...")

    # Define a dictionary that will contain releases as keys and number of matches as values
    versions = {}

    # Go through releases and check previously calculated hashes against hashes in the local repo
    for r, release in enumerate(releases) :
        matches = 0
        os.system("git -C " + repo_folder + " checkout tags/" + release + ">/dev/null 2>&1")
        for file_name , file_hash in default_file_hashes.items() :
            file_path = repo_folder + file_name
            if os.path.isfile(file_path) :
                f = open(file_path, "rb")
                hash_object = hashlib.sha256(f.read())
                hash_digest = hash_object.hexdigest()

            if hash_digest == file_hash :
                matches = matches + 1
        
        if verbose :
            print("Version: " + str(release) + " Matches: " + str(matches))
        else :
            sys.stdout.write("\r" + str(int(100 * int(r + 1) / len(releases))) + "%")
            sys.stdout.flush()
        versions[release]=matches


	# Print top 5 discovered versions
    print("\nTop 5 discovered versions:")
    versions = sorted(versions.items(), key=lambda ver: ver[1], reverse=True)[:5]
    for version, hits in versions: print("Version: " + version + " Matches: " + str(hits))


def main():
    if sys.argv[1:]:
        examples = """Examples:
GitVersionFinder.py -u https://example.com:8080 -r https://github.com/example
GitVersionFinder.py -u https://example.com:8080 -r https://github.com/example -e txt
GitVersionFinder.py -u https://example.com:8080 -r https://github.com/example -e html -v
"""
        try:
            parser = argparse.ArgumentParser(description="GitVersionFinder - Attempts to discover version of the target application by comparing files", formatter_class=argparse.RawTextHelpFormatter, epilog=examples)
            parser.add_argument("-u", "--url", help="Target URL", required=True)
            parser.add_argument("-r", "--repo", help="Git repository", required=True)
            parser.add_argument("-v", "--verbose", help="Enable verbose mode", action="store_true", default=False)
            parser.add_argument("-t", "--threads", help="Set number of threads (Default 5)", metavar="", default=5)
            parser.add_argument("-e", "--extension", help="Set the extension to search in the local repo (Default js)", default="js", metavar="")
            args = parser.parse_args()
        except:
            sys.exit(1)
    else:
        print("No options provided. Run GitVersionFinder.py -h")
        sys.exit(1)
	
    run(args.url.rstrip('/'), args.repo.rstrip('/'), args.extension, int(args.threads), args.verbose)


if __name__ == "__main__":
    main()
