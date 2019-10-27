import subprocess

root = 'C:/Users/localhost/Documents/GitHub/'
exe = root + 'llvm-project/build/Debug/bin/llvm-pdbutil.exe'
real = root + 'PdbGen/PDBTest/x64/Debug/PDBTest.pdb'
fake = root + 'PdbGen/Generated/PDBTest.pdb'

real_out = subprocess.run([exe, 'pdb2yaml', '--all', real], capture_output=True)
with open('Generated/real.yaml', 'wb') as f:
    f.write(real_out.stdout)

fake_out = subprocess.run([exe, 'pdb2yaml', '--all', fake], capture_output=True)
with open('Generated/fake.yaml', 'wb') as f:
    f.write(fake_out.stdout)

import shutil

shutil.copy(root + 'PdbGen/PdbTest/x64/Debug/PdbTest.exe', root + 'PdbGen/Generated/PdbTest.exe')
shutil.copy(root + 'PdbGen/PdbTest/Main.cpp', root + 'PdbGen/Generated/Main.cpp')
