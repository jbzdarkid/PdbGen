Fork of PdbGen -- attempting to get these things working:
- [X] line numbers
- [X] function names
- [X] local variables
- [ ] function arguments
- [ ] type information
- [ ] static strings

PDBTest is the project I'm using as a mock project -- it has a real PDB which I can inspect and compare the generated PDB against.

PdbGen is the project which creates PDBs. It is used with permission under the MIT license.

This project relies on LLVM to create PDBs.

At some point, I will extract LLVM libraries and include them in this project. Until then, please update PdbGen/LLVMPDB.props to point to your LLVM installation.

LLVM is licensed under Apache 2 (with LLVM extensions). Please see [https://github.com/llvm/llvm-project/tree/master/llvm](here) for a full license.

This project is licensed under Apache 2. Please see LICENSE.TXT for more information.
