GitVersionFinder
======

GitVersionFinder - Attempts to discover version of the target application by comparing default files such as JavaScript files against those in the application's Git repository


Usage
=====

   usage: GitVersionFinder.py [-h] -u URL -r REPO [-v] [-t] [-e]
   
   GitVersionFinder - Attempts to discover version of the target application by comparing files
   
   optional arguments:
     -h, --help            show this help message and exit
     -u URL, --url URL     Target URL
     -r REPO, --repo REPO  Git repository
     -v, --verbose         Enable verbose mode
     -t , --threads        Set number of threads (Default 5)
     -e , --extension      Set the extension to search in the local repo (Default js)
   
   Examples:
   GitVersionFinder.py -u https://example.com:8080 -r https://github.com/example
   GitVersionFinder.py -u https://example.com:8080 -r https://github.com/example -e txt
   GitVersionFinder.py -u https://example.com:8080 -r https://github.com/example -e html -v  
