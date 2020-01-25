def parse(data):
  output = '''
def test():
  bytes = [
'''
  for line in data.split('\n'):
    if line.count('|') != 3:
      continue
    addr, bytes, asm, comment = line.split('|')
    asm = asm.strip()
    bytes = bytes.strip()
    bytes = bytes.replace(':', '').replace(' ', '')
    
    output += '    '
    for i in range(0, len(bytes), 2):
      output += '0x' + bytes[i:i+2] + ', '
    output += '# ' + asm + '\n'
  output += '''  ]
  parser = Parser(bytes)
  parser.parse(0x00)
  parser.print_out()
  '''
  with open('out.txt', 'w') as f:
    f.write(output)

data = """
00401010 <pdbtest._main>                       | 55                       | push ebp                                                                      | Main.cpp:1
00401011                                       | 8BEC                     | mov ebp,esp                                                                   |
00401013                                       | 83EC 08                  | sub esp,8                                                                     |
00401016                                       | 56                       | push esi                                                                      |
00401017                                       | C745 F8 01000000         | mov dword ptr ss:[ebp-8],1                                                    | Main.cpp:2
0040101E                                       | 8B45 F8                  | mov eax,dword ptr ss:[ebp-8]                                                  | Main.cpp:3
00401021                                       | 8D4400 03                | lea eax,dword ptr ds:[eax+eax+3]                                              |
00401025                                       | 99                       | cdq                                                                           |
00401026                                       | 83E2 03                  | and edx,3                                                                     |
00401029                                       | 03C2                     | add eax,edx                                                                   |
0040102B                                       | C1F8 02                  | sar eax,2                                                                     |
0040102E                                       | 6B4D F8 05               | imul ecx,dword ptr ss:[ebp-8],5                                               |
00401032                                       | 83C1 06                  | add ecx,6                                                                     |
00401035                                       | 2BC1                     | sub eax,ecx                                                                   |
00401037                                       | 8945 FC                  | mov dword ptr ss:[ebp-4],eax                                                  |
0040103A                                       | 8B55 FC                  | mov edx,dword ptr ss:[ebp-4]                                                  | Main.cpp:4
0040103D                                       | C1E2 02                  | shl edx,2                                                                     |
00401040                                       | 6BCA 03                  | imul ecx,edx,3                                                                |
00401043                                       | 8B45 FC                  | mov eax,dword ptr ss:[ebp-4]                                                  |
00401046                                       | 99                       | cdq                                                                           |
00401047                                       | BE 03000000              | mov esi,3                                                                     |
0040104C                                       | F7FE                     | idiv esi                                                                      |
0040104E                                       | 6BD2 0A                  | imul edx,edx,A                                                                |
00401051                                       | 03CA                     | add ecx,edx                                                                   |
00401053                                       | 894D FC                  | mov dword ptr ss:[ebp-4],ecx                                                  |
00401056                                       | 33C0                     | xor eax,eax                                                                   | Main.cpp:5
00401058                                       | 5E                       | pop esi                                                                       |
00401059                                       | 8BE5                     | mov esp,ebp                                                                   |
0040105B                                       | 5D                       | pop ebp                                                                       |
0040105C                                       | C3                       | ret                                                                           |
"""
if __name__ == '__main__':
  parse(data)