#!/usr/local/bin/python3
import os
import sys

try:
    import libarchive.public
except ImportError:
    raise Exception("Missing dependency: libarchive")

# Syntax:
# Arg1 : '--' (from Dockerfile)
# Arg2 : ACE file
# Arg3 : Maximum extracted files
# Arg4 : Maximum automatic analyzis

if len(sys.argv) != 5:
   raise Exception("Incorrect number of arguments ({})".format(len(sys.argv)))

target = sys.argv[2]
maximum_extracted_files = int(sys.argv[3])
maximum_automatic_analyses = int(sys.argv[4])

password_candidates = [""]

with open("/data/passwords_candidates.txt", "r") as f:
    for line in f:
        password_candidates.append(line.strip())

    try:
        entries = []
        with libarchive.public.file_reader(target, passphrases=password_candidates) as ar:
            for entry in ar:
                if entry.pathname != ".":
                    entries.append(entry.pathname)
    except libarchive.exception.ArchiveError:
        print("warning: Unable to extract the archive (password not known)")

should_extract = len(entries) <= maximum_extracted_files
should_analyze = len(entries) <= maximum_automatic_analyses

if should_extract:
    try:
        with libarchive.public.file_reader(target, passphrases=password_candidates) as ar:
            for entry in ar:
                if entry.pathname == ".":
                    continue
                filepath = os.path.join('/data/output/', entry.pathname)
                with open(filepath, "wb") as o:
                    for block in entry.get_blocks():
                        o.write(block)
                if os.path.isfile(filepath):
                    print(("should_analyze: {}".format(filepath)))
    except libarchive.exception.ArchiveError:
        print("warning: Unable to extract the archive (password not known)")
    except ValueError:
        print("warning: Unable to extract the archive (password not known ?)")
    if not should_analyze:
        print(("warning: Archive contains more than {} files ({}), so no analysis was automatically created.".format(
                maximum_automatic_analyses, len(entries))))
else:
    print(("warning: Archive contains more than {} files ({}), so they were not extracted.".format(
            maximum_extracted_files, len(entries))))
