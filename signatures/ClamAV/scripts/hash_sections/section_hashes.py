"""
https://stackoverflow.com/questions/20027990/how-can-i-get-text-section-from-pe-file-using-pefile
https://docs.python.org/2/library/hashlib.html
https://www.python.org/dev/peps/pep-0274/
"""

import pefile
import hashlib
import argparse

def get_cli_arguments():
    """
    Read command line arguments.
    """
    parser= argparse.ArgumentParser()
    parser.add_argument('-m', action="store_true", help='MD5 hashes of all sections')
    parser.add_argument('-s', action="store_true", help='SHA256 hashes of all sections')
    args = parser.parse_args()

    return args.m, args.s

def get_sections(filename):
    sections= {}
    pe= pefile.PE(filename)
    sections= {section.Name+'_'+str(section.SizeOfRawData): section.get_data() for section in pe.sections}
    return sections

def hash_sections_md5(sections):
    md5_sections= {key: hashlib.md5(value).hexdigest() for key, value in sections.items()}
    return md5_sections

def hash_sections_sha256(sections):
    sha256_sections= {key: hashlib.sha256(value).hexdigest() for key, value in sections.items()}
    return sha256_sections

if __name__ == "__main__":

    """
    Edit this according to the name of the file you are analyzing
    """
    filename= '3.exe'

    sections= {}
    md5_sections= {}
    sha256_sections= {}

    md5, sha256= get_cli_arguments()
    sections= get_sections(filename)
    md5_sections= hash_sections_md5(sections)
    sha256_sections= hash_sections_sha256(sections)

    if md5 and sha256:
        print 'Dont try and compute both MD5 and SHA256 hashes'
        exit(0)
    elif not md5 and not sha256:
        print 'Please add either the -m or -s switches to the script'
        exit(0)
    elif md5:
        for k,v in md5_sections.items():
            (name, size) = k.split('_')
            print size+':'+v+':'+'UNKNOWN_'+name
    elif sha256:
        for k,v in sha256_sections.items():
            (name, size) = k.split('_')
            print size+':'+v+':'+'UNKNOWN_'+name
