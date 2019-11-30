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
    0xE8, 0xB8, 0xFF, 0xFF, 0xFF, # call foo()
    0xE8, 0xD3, 0xFF, 0xFF, 0xFF, # call bar()
    0x33, 0xC0, # xor eax, eax
    0x5D, # pop ebp
    0xC3, # ret
    0xCC, # int3
    0xCC, # int3
    0xCC, # int3
  ]
  foo = Foo(bytes)
  foo.parse(0x40)

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
  Foo(bytes).parse(0)
  
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
  Foo(bytes).parse(0)

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
  Foo(bytes).parse(0x20)
    
  
class Foo:
  def __init__(self, bytes):
    self.print_bytes = False
    self.ebp_esp = 0 # Value of ebp - esp
    self.bytes = bytes
    self.functions = {}
    self.unparsed_functions = []
    self.pending_jumps = {}
    self.flags = {}
    self.scopes = {}
    
  def _print(self, *args, **kwargs):
    print('# ' + '  ' * sum(self.scopes.values()), end='')
    # print('# ', end='')
    print(*args, **kwargs)
    
  def read_byte(self):
    byte = self.bytes[self.addr]
    if self.print_bytes:
      self._print(hex(byte) + ', ', end='')
    self.addr += 1
    return byte

  def read_signed_byte(self):
    byte = self.read_byte()
    if byte >= 0x80:
      byte -= 0x100
    return byte
    
  def read_unsigned_int(self):
    # TODO: Assumed LE
    i = int.from_bytes(self.bytes[self.addr:self.addr+4], 'little')
    self.addr += 4
    if self.print_bytes:
      self._print(hex(i) + ', ', end='')
    return i

  def read_signed_int(self):
    i = self.read_unsigned_int()
    if i >= 0x80000000:
      i -= 0x100000000
    return i

  def read_ebp_rel(self):
    b = self.read_signed_byte()
    if b > 0:
      return 'arg_%X' % b
    else:
      return 'local_%X' % -b
      
  def read_esp_rel(self):
    b = self.read_signed_byte() - self.ebp_esp
    if b > 0:
      return 'arg_%X' % b
    else:
      return 'local_%X' % -b
  
  ### These ones set flags
  # General note on CF and OF flags:
  # CF is set for unsigned overflows, e.g. 0xFF + 0x01 -> 0x00 (CF=1)
  # OF is set for signed overflows, e.g. 0x7F + 0x01 -> 0x80 (OF=1)
  # Note that inc and dec DO NOT modify the CF. For some reason.
  
  # Re: Jumps
  # The terms "less" and "greater" are used for comparisons of signed integers and the terms "above" and "below" are used for unsigned integers.

  def sub(self, dst, src):
    self._print(f'{dst} -= {src}')
    self.flags = {
      'ZF': f'{dst} == 0',
      'SF': f'{dst} < 0'
    }

  def add(self, dst, src):
    self._print(f'{dst} += {src}')
    self.flags = {
      'ZF': f'{dst} == 0'
    }

  def mul(self, dst, src):
    self._print(f'{dst} *= {src}')
    self.flags = {
      'ZF': f'{dst} == 0',
      'SF': f'{dst} < 0'
    }

  def xor(self, dst, src):
    if dst == src:
      self.mov(dst, '0')
    else:
      self._print(f'{dst} ^= {src}')
    self.flags = {
      'ZF': f'{dst} == 0',
      'SF': f'{dst} < 0'
    }
    
  def _and(self, dst, src):
    if src == 0:
      self.mov(dst, '0')
    else:
      self._print(f'{dst} &= {hex(src)}')
    self.flags = {
      'ZF': f'{dst} == 0',
      'SF': f'{dst} < 0'
    }

  def _or(self, dst, src):
    if src == 0xFF:
      self.mov(dst, '-1')
    else:
      self._print(f'{dst} |= {src}')
    self.flags = {
      'ZF': f'{dst} == 0',
      '!ZF': f'{dst} != 0',
      'SF': f'{dst} <= 0',
      '!SF': f'{dst} > 0'
    }
    
  # Both test eax, eax and cmp eax, eax will set SF=1 if eax < 0
  def cmp(self, dst, src):
    # self._print(f'cmp {dst}, {src}')
    self.flags = {
      'ZF': f'{dst} == {src}',
      '!ZF': f'{dst} != {src}',
      'SF': f'{dst} <= {src}',
      '!SF': f'{dst} > {src}'
    }
    
  def test(self, dst, src):
    self._print(f'test {dst}, {src}')
    self.flags = {
      'ZF': f'{dst} == {src}'
    }
  
  def dec(self, dst):
    self.sub(dst, '1')
    
  def inc(self, dst):
    self.add(dst, '1')

  ### These ones do not

  def div(self, src):
    self._print(f'edx = eax % {src}; eax = eax / {src}')
    # Does not set flags, I guess because it's ambiguous
    
  def mov(self, dst, src):
    if dst == 'ebp' and src == 'esp':
      self.ebp_esp = 0
    elif dst == 'esp' and src == 'ebp':
      self.ebp_esp = 0

    if isinstance(src, int):
      self._print(f'{dst} = {hex(src)}')
    else:
      self._print(f'{dst} = {src}')
    
  def ret(self):
    self._print('return')
      
  def call(self, addr):
    if addr not in self.functions:
      name = 'func%04d' % len(self.functions)
      self.functions[addr] = name
      self.unparsed_functions.append(addr)
    self._print(f'call {self.functions[addr]}')

  def push(self, src):
    self.sub('esp', '4')
    self.ebp_esp -= 4
    self.mov('[esp]', src)
  
  def pop(self, src):
    self.mov(src, '[esp]')
    self.add('esp', '4')
    self.ebp_esp += 4
    
  def cdq(self):
    self._print('edx = (eax < 0) ? -1 : 0')
    
  def shl(self, dst, amt):
    self.mov(dst, f'{dst} * {2 ** amt}')
  
  def jump(self, cond, amt):
    assert(amt > 0) # TODO: Handle loops (aka backwards jumps)
    self.pending_jumps[self.addr + amt] = True
    if cond is not None:
      # self._print(f'if ({cond}) ' + '{')
      pass
    else:
      # self._print('} else {')
      pass
    
    if cond is not None:
      # self._print(f'if ({cond}) goto label_{self.addr + amt}')
      self._print(f'if (!({cond})) ' + '{')
      if (self.addr + amt) not in self.scopes:
        self.scopes[self.addr + amt] = 0
      self.scopes[self.addr + amt] += 1
    else:
      if self.addr in self.scopes:
        # We need to pre-empt the label from being created, and re-open another scope
        del self.scopes[self.addr]
        self._print('} else {')
        if (self.addr + amt) not in self.scopes:
          self.scopes[self.addr + amt] = 0
        self.scopes[self.addr + amt] += 1
  
  def parse(self, start_addr):
    name = 'func%04d' % len(self.functions)
    self.functions[start_addr] = name
    self.unparsed_functions.append(start_addr)
    while 1:
      self.parse_function()
      if len(self.unparsed_functions) == 0:
        break

  def read_registers(self, reversed=False):
    byte = self.read_byte()
    if byte == 0xC0:
      dst, src = 'eax', 'eax'
    elif byte == 0x45:
      dst, src = 'eax', self.read_ebp_rel()
    elif byte == 0x4D:
      dst, src = 'ecx', self.read_ebp_rel()
    elif byte == 0x55:
      dst, src = 'edx', self.read_ebp_rel()
    elif byte == 0xC1:
      dst, src = 'eax', 'ecx'
    elif byte == 0xC6:
      dst, src = 'eax', 'esi'
    elif byte == 0xE5:
      dst, src = 'esp', 'ebp'
    elif byte == 0xEC:
      dst, src = 'ebp', 'esp'
    elif byte == 0xF1:
      dst, src = 'esi', 'ecx'
    else:
      self._print('Failed to parse byte: ' + hex(byte))
      exit(1)
      
    if not reversed:
      return [dst, src]
    else:
      return [src, dst]
  
  def parse_function(self):
    self.addr = self.unparsed_functions.pop(0)
    self._print(f'\nFunction {self.functions[self.addr]} at address {hex(self.addr)}')
  
    while 1:
      if self.addr in self.scopes:
        while self.scopes[self.addr] > 0:
          self.scopes[self.addr] -= 1
          self._print('}')
        del self.scopes[self.addr]
    
      byte = self.read_byte()
      
      if byte == 0x03:
        self.add(*self.read_registers())
      
      elif byte == 0x0B:
        self._or(*self.read_registers())

      # 0x0F is for 2-byte opcodes
      elif byte == 0x0F:
        if self.read_byte() == 0xAF:
          self.mul(*self.read_registers())
      
      elif byte == 0x23:
        self._and(*self.read_registers())
      
      elif byte == 0x2B:
        self.sub(*self.read_registers())
      
      elif byte == 0x33:
        self.xor(*self.read_registers())
        
      elif byte == 0x50:
        self.push('eax')

      elif byte == 0x51:
        self.push('ecx')

      elif byte == 0x55:
        self.push('ebp')

      elif byte == 0x56:
        self.push('esi')

      elif byte == 0x5D:
        self.pop('ebp')

      elif byte == 0x5E:
        self.pop('esi')

      elif byte == 0x68:
        self.push(self.read_unsigned_int())

      elif byte == 0x74: # je
        self.jump(f'{self.flags["ZF"]}', self.read_signed_byte())

      elif byte == 0x75: # jne
        self.jump(f'{self.flags["!ZF"]}', self.read_signed_byte())

      elif byte == 0x7D: # jge
        self.jump(f'{self.flags["!SF"]} || {self.flags["ZF"]}', self.read_signed_byte())

      elif byte == 0x7E: # jle
        self.jump(f'{self.flags["SF"]} || {self.flags["ZF"]}', self.read_signed_byte())

      elif byte == 0x7F: # jg
        self.jump(f'{self.flags["!SF"]}', self.read_signed_byte())

      elif byte == 0x83:
        byte = self.read_byte()
        if byte == 0x7D:
          self.cmp(self.read_ebp_rel(), self.read_signed_byte())
        elif byte == 0xC0:
          self.add('eax', self.read_byte())
        elif byte == 0xE4:
          self._and('esp', self.read_byte())
        elif byte == 0xE8:
          self.sub('eax', self.read_byte())
        elif byte == 0xEC:
          self.sub('esp', self.read_byte())
        elif byte == 0xFE:
          self.cmp('esi', self.read_byte())

      elif byte == 0x89:
        self.mov(*self.read_registers(reversed=True))
 
      elif byte == 0x8B:
        self.mov(*self.read_registers())

      elif byte == 0x8D:
        byte = self.read_byte()
        if byte == 0x04:
          byte = self.read_byte()
          if byte == 0x80:
            self.mov('eax', 'eax + eax*4')
        elif byte == 0x4E:
          self.mov('ecx', f'esi + {self.read_signed_byte()}')

      elif byte == 0x99:
        self.cdq()

      elif byte == 0xB9:
        self.mov('ecx', self.read_signed_int())
        
      elif byte == 0xBA:
        self.mov('edx', self.read_unsigned_int())
        
      elif byte == 0xC1:
        byte = self.read_byte()
        if byte == 0xE0:
          self.shl('eax', self.read_byte())

      elif byte == 0xC3:
        self.ret()
        if not self.scopes:
          break # No pending jumps after this return, stop parsing

      elif byte == 0xC7:
        if self.read_byte() == 0x45:
          self.mov(self.read_ebp_rel(), self.read_signed_int())

      elif byte == 0xE8:
        # Relative near call
        relative_addr = self.read_signed_int()
        self.call(self.addr + relative_addr) # Relative to the next call, so evaluate after reading
      
      elif byte == 0xEB: # jmp
        self.jump(None, self.read_signed_byte())
      
      elif byte == 0xF7:
        if self.read_byte() == 0x7D:
          self.div(self.read_ebp_rel())
      
      else:
        self._print('Failed to parse byte: ' + hex(byte))
        exit(1)
    
  
if __name__ == '__main__':
  test3()
