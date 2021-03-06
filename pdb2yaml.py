import subprocess

root = 'C:/Users/localhost/Documents/GitHub/'
exe = root + 'llvm-project/build/Debug/bin/llvm-pdbutil.exe'
real = root + 'PdbGen/PdbTest/Debug/_PdbTest.pdb'
fake = root + 'PdbGen/Generated/PdbTest.pdb'

real_out = subprocess.run([exe, 'dump', '--all', real], capture_output=True)
if real_out.stderr:
    print('Real: ', real_out.stderr)
    exit()
fake_out = subprocess.run([exe, 'dump', '--all', fake], capture_output=True)
if fake_out.stderr:
    print('Fake: ', fake_out.stderr)
    exit()

with open('Generated/fake.yaml', 'wb') as f:
    f.write(fake_out.stdout)
with open('Generated/real.yaml', 'wb') as f:
    f.write(real_out.stdout)


import shutil

shutil.copy(root + 'PdbGen/PdbTest/Debug/PdbTest.exe', root + 'PdbGen/Generated/PdbTest.exe')
shutil.copy(root + 'PdbGen/PdbTest/Debug/_PdbTest.pdb', root + 'PdbGen/Generated/_PdbTest.pdb')
shutil.copy(root + 'PdbGen/PdbTest/Main.cpp', root + 'PdbGen/Generated/Main.cpp')

