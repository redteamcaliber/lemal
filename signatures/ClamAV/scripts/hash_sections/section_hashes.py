"""
https://stackoverflow.com/questions/20027990/how-can-i-get-text-section-from-pe-file-using-pefile
https://docs.python.org/2/library/hashlib.html
https://www.python.org/dev/peps/pep-0274/
"""

import pefile
import hashlib

def get_sections(filename):
    sections= {}
    pe= pefile.PE(filename)
    sections= {section.Name+'_'+str(section.Misc_VirtualSize): section.get_data() for section in pe.sections}
    return sections

def hash_sections_md5(sections):
    md5_sections= {key: hashlib.md5(value).hexdigest() for key, value in sections.items()}
    return md5_sections

def hash_sections_sha256(sections):
    md5_sections= {key: hashlib.sha256(value).hexdigest() for key, value in sections.items()}
    return sha256_sections

if __name__ == "__main__":
    filename= '3.exe'
    sections= {}
    md5_sections= {}
    sha256_sections= {}

    sections= get_sections(filename)
    md5_sections= hash_sections_md5(sections)
    sha256_sections= hash_sections_sha256(sections)

    for k,v in md5_sections.items():
        (name, size) = k.split('_')
        print size+':'+v+':'+'UNKNOWN_'+name
