from Parser import Parser

def test1():
  bytes = [
    0x55, # push ebp
    0x8B, 0xEC, # mov ebp, esp
    0x51, # push ecx
    0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00, # mov [ebp-4], 1
    0x8B, 0x45, 0xFC, # mov eax, [ebp-4]
    0x83, 0xC0, 0x01, # add eax, 1
    0x89, 0x45, 0xFC, # mov [ebp-4], eax
    0x8B, 0x45, 0xFC, # mov eax, [ebp-4]
    0x8B, 0xE5, # mov esp, ebp
    0x5D, # pop ebp
    0xC3, # ret

    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

    0x55, # push ebp
    0x8B, 0xEC, # mov ebp, esp
    0x51, # push ecx
    0xC7, 0x45, 0xFC, 0x02, 0x00, 0x00, 0x00, # mov [ebp-4], 2
    0x8B, 0x45, 0xFC, # mov eax, [ebp-4]
    0x83, 0xE8, 0x01, # sub eax, 1
    0x89, 0x45, 0xFC, # mov [ebp-4], eax
    0x8B, 0x45, 0xFC, # mov eax, [ebp-4]
    0x8B, 0xE5, # mov esp, ebp
    0x5D, # pop ebp
    0xC3, # ret

    0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

    0x55, # push ebp
    0x8B, 0xEC, # mov ebp, esp
    0xE8, 0xB8, 0xFF, 0xFF, 0xFF, # call Parser()
    0xE8, 0xD3, 0xFF, 0xFF, 0xFF, # call bar()
    0x33, 0xC0, # xor eax, eax
    0x5D, # pop ebp
    0xC3, # ret
    0xCC, # int3
    0xCC, # int3
    0xCC, # int3
  ]
  parser = Parser(bytes)
  parser.parse(0x40)

def test2():
  bytes = [
    0x55, # push ebp
    0x8B, 0xEC, # mov ebp, esp
    0x83, 0xEC, 0x28, # sub esp, 28
    0xC7, 0x45, 0xDC, 0x01, 0x00, 0x00, 0x00, # mov [ebp-24], 1
    0xC7, 0x45, 0xE4, 0x02, 0x00, 0x00, 0x00, # mov [ebp-1C], 2
    0xC7, 0x45, 0xFC, 0x03, 0x00, 0x00, 0x00, # mov [ebp-4], 3
    0xC7, 0x45, 0xF8, 0x04, 0x00, 0x00, 0x00, # mov [ebp-8], 4
    0xC7, 0x45, 0xF4, 0x05, 0x00, 0x00, 0x00, # mov [ebp-C], 5
    0xC7, 0x45, 0xF0, 0x06, 0x00, 0x00, 0x00, # mov [ebp-10], 6
    0xC7, 0x45, 0xEC, 0x07, 0x00, 0x00, 0x00, # mov [ebp-14], 7
    0xC7, 0x45, 0xE8, 0x08, 0x00, 0x00, 0x00, # mov [ebp-18], 8
    0xC7, 0x45, 0xE0, 0x09, 0x00, 0x00, 0x00, # mov [ebp-20], 9
    0xC7, 0x45, 0xD8, 0x0A, 0x00, 0x00, 0x00, # mov [ebp-28], A
    0x8B, 0x45, 0xE4, # eax = [ebp - 1C]
    0x03, 0x45, 0xFC, # add eax, [ebp-4]
    0x89, 0x45, 0xDC, # mov [ebp-24], eax
    0x8B, 0x4D, 0xFC, # mov ecx, [ebp-4]
    0x2B, 0x4D, 0xF8, # sub ecx, [ebp-8]
    0x89, 0x4D, 0xE4, # mov [ebp-1C], ecx
    0x8B, 0x55, 0xF8, # mov edx, [ebp-8]
    0x0F, 0xAF, 0x55, 0xF4, # imul edx, [ebp-C]
    0x89, 0x55, 0xFC, # mov [ebp-4], edx
    0x8B, 0x45, 0xF4, # mov eax, [ebp-C]
    0x99, # cdq
    0xF7, 0x7D, 0xF0, # idiv [ebp-10]
    0x89, 0x45, 0xF8, # mov [ebp-8], eax
    0x8B, 0x45, 0xF0, # mov eax, [ebp-10]
    0x99, # cdq
    0xF7, 0x7D, 0xEC, # idiv [ebp-14]
    0x89, 0x55, 0xF4, # mov [ebp-C], edx
    0x8B, 0x45, 0xEC, # mov eax, [ebp-14]
    0x33, 0x45, 0xE8, # xor eax, [ebp-18]
    0x89, 0x45, 0xF0, # mov [ebp-10], eax
    0x8B, 0x4D, 0xE8, # mov ecx, [ebp-18]
    0x23, 0x4D, 0xE0, # and ecx, [ebp-20]
    0x89, 0x4D, 0xEC, # mov [ebp-14], ecx
    0x8B, 0x55, 0xE0, # mov edx, [ebp-20]
    0x0B, 0x55, 0xD8, # or edx, [ebp-28]
    0x89, 0x55, 0xE8, # mov [ebp-18], edx
    0x33, 0xC0, # xor eax, eax
    0x8B, 0xE5, # mov esp, ebp
    0x5D, # pop ebp
    0xC3, # ret
  ]
  parser = Parser(bytes)
  parser.parse(0x0)

def test3():
  bytes = [
    0x55, # push ebp
    0x8B, 0xEC, # ebp = esp
    0x83, 0xEC, 0x10, # esp -= 0x10
    0xC7, 0x45, 0xF0, 0x01, 0x00, 0x00, 0x00, # local_10 = 1
    0xC7, 0x45, 0xF8, 0x02, 0x00, 0x00, 0x00, # local_8 = 2
    0xC7, 0x45, 0xF4, 0x03, 0x00, 0x00, 0x00, # local_C = 3
    0x83, 0x7D, 0xF0, 0x04, # cmp local_10, 4
    0x7E, 0x1E, # jle +0x1E
    0x83, 0x7D, 0xF8, 0x03, # cmp local_8, 3
    0x7D, 0x16, # jge +0x16
    0x83, 0x7D, 0xF4, 0x02, # cmp local_4, 0x5
    0x75, 0x09, # jne +0x09
    0xC7, 0x45, 0xFC, 0x05, 0x00, 0x00, 0x00, # local_4 = 5
    0xEB, 0x07, # jmp +0x07
    0xC7, 0x45, 0xFC, 0x04, 0x00, 0x00, 0x00, # local_4 = 4
    0xEB, 0x25, # jmp +0x25
    0x83, 0x7D, 0xF8, 0x05, # cmp local_8, 5
    0x7F, 0x09, # jg +0x09
    0xC7, 0x45, 0xFC, 0x03, 0x00, 0x00, 0x00, # local_4 = 3
    0xEB, 0x16, # jmp +0x16
    0x83, 0x7D, 0xF4, 0x07, # cmp local_C, 7
    0x74, 0x09, # je +0x09
    0xC7, 0x45, 0xFC, 0x02, 0x00, 0x00, 0x00, # local_4 = 2
    0xEB, 0x07, # jmp +0x07
    0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00, # local_4 = 1
    0x33, 0xC0, # xor eax, eax
    0x8B, 0xE5, # mov esp, ebp
    0x5D, # pop ebp
    0xC3, # ret
  ]
  parser = Parser(bytes)
  parser.parse(0x0)
  parser.print_out()

def test4():
  bytes = [
    0x56, # push esi
    0x8B, 0xF1, # mov esi, ecx
    0x83, 0xFE, 0x01, # cmp esi, 1
    0x75, 0x04, # jne +0x04
    0x8B, 0xC1, # mov eax, ecx
    0x5E, # pop esi
    0xC3, # ret
    0x8D, 0x4E, 0xFF, # lea ecx, [esi-1]
    0xE8, 0xEC, 0xFF, 0xFF, 0xFF, # call factorial()
    0x0F, 0xAF, 0xC6, # imul eax, esi
    0x5E, # pop esi
    0xC3, # ret

    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

    0x55, # push ebp
    0x8B, 0xEC, # mov ebp, esp
    0x83, 0xE4, 0xF8, # and esp, 0xFFFFFFF8 (sanity check)
    0x68, 0xB0, 0x13, 0xA0, 0x00, # push 0xB013A000
    0xB9, 0x13, 0x00, 0x00, 0x00, # mov ecx, 13
    0xE8, 0xCB, 0xFF, 0xFF, 0xFF, # call factorial()
    0xB9, 0x09, 0x00, 0x00, 0x00, # mov ecx, 0
    0x8D, 0x04, 0x80, # lea eax, eax + eax*4
    0xC1, 0xE0, 0x02, # shl eax, 2
    0x50, # push eax
    0xE8, 0xBA, 0xFF, 0xFF, 0xFF, # call factorial()
    0xB9, 0x04, 0x00, 0x00, 0x00, # mov ecx, 4
    0x8D, 0x04, 0x80, # lea eax, eax + eax*4
    0x03, 0xC0, # add eax, eax
    0x50, # push eax
    0xE8, 0xAA, 0xFF, 0xFF, 0xFF, # call factorial()
    0xBA, 0x48, 0x31, 0xA0, 0x00, # mov edx, 0x00A03148
    0x8D, 0x04, 0x80, # lea eax, eax + eax*4
    0x33, 0xC0, # xor eax, eax
    0x8B, 0xE5, # mov esp, ebp
    0x5D, # pop ebp
    0xC3, # ret
  ]
  parser = Parser(bytes)
  parser.parse(0x20)
  parser.print_out()

def test5():
  bytes = [
    0x55, # push ebp
    0x8B, 0xEC, # mov ebp, esp
    0x83, 0xEC, 0x08, # sub esp, 8
    0xC7, 0x45, 0xFC, 0x01, 0x00, 0x00, 0x00,
    0xC7, 0x45, 0xF8, 0x01, 0x00, 0x00, 0x00,
    0x83, 0x7D, 0xFC, 0x00,
    0x75, 0x0F,
    0x83, 0x7D, 0xF8, 0x00,
    0x75, 0x09,
    0xC7, 0x45, 0xFC, 0x06, 0x00, 0x00, 0x00,
    #0xEB, 0x1C,
    #0x83, 0x7D, 0xFC, 0x01,
    #0x74, 0x06,
    #0x83, 0x6D, 0xF8, 0x01,
    #0x75, 0x09,
    #0xC7, 0x45, 0xFC, 0x07, 0x00, 0x00, 0x00,
    #0xEB, 0x07,
    #0xC7, 0x45, 0xFC, 0x08, 0x00, 0x00, 0x00,
    
    0xEB, 0x07,
    0xC7, 0x45, 0xFC, 0x08, 0x00, 0x00, 0x00,
    
    0x33, 0xC0,
    0x8B, 0xE5,
    0x5D,
    0xC3,
  ]
  parser = Parser(bytes)
  parser.parse(0x0)

if __name__ == '__main__':
  test5()
