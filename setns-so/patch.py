# https://lief.quarkslab.com/doc/latest/tutorials/08_elf_bin2lib.html#warning-for-glibc-2-29-users

import lief
import sys
import os

path = sys.argv[1]
os.rename(path, path + ".old")

bin_ = lief.parse(path + ".old")
bin_[lief.ELF.DYNAMIC_TAGS.FLAGS_1].remove(lief.ELF.DYNAMIC_FLAGS_1.PIE)
bin_.write(path)

os.system("chmod +x " + path)
