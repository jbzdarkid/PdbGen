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

class Foo:
  def __init__(self, bytes):
    self.ebp_offset = 0
    self.bytes = bytes
    self.functions = {}
    self.unparsed_functions = []
    
  def read_byte(self):
    byte = self.bytes[self.addr]
    print(hex(byte) + ', ', end='')
    self.addr += 1
    return byte

  def read_signed_byte(self):
    byte = self.read_byte()
    if byte >= 0x80:
      byte -= 0x100
    return byte
    
  def read_signed_int(self):
    # TODO: Assumed LE
    i = int.from_bytes(self.bytes[self.addr:self.addr+4], 'little')
    print(hex(i) + ', ', end='')
    if i >= 0x80000000:
      i -= 0x100000000
    self.addr += 4
    return i
  
  def sub(self, dst, src):
    print(f'# {dst} -= {src}')

  def add(self, dst, src):
    print(f'# {dst} += {src}')
    
  def mov(self, dst, src):
    print(f'# {dst} = {src}')
    
  def ret(self):
    print('# return')
  
  def call(self, addr):
    if addr not in self.functions:
      name = 'func%04d' % len(self.functions)
      self.functions[addr] = name
      self.unparsed_functions.append(addr)
    print(f'# call {self.functions[addr]}')

  def push(self, src):
    self.sub('esp', '4')
    self.ebp_offset -= 4 # Hack?
    self.mov('[esp]', src)
  
  def pop(self, src):
    self.mov(src, '[esp]')
    self.add('esp', '4')
    self.ebp_offset += 4
  
  def parse(self, start_addr):
    name = 'func%04d' % len(self.functions)
    self.functions[start_addr] = name
    self.unparsed_functions.append(start_addr)
    while 1:
      self.parse_function()
      if len(self.unparsed_functions) == 0:
        break

  
  def parse_function(self):
    self.addr = self.unparsed_functions.pop(0)
    print(f'\nFunction {self.functions[self.addr]} at address {hex(self.addr)}')
  
    while 1:
      byte = self.read_byte()
      if byte == 0x55:
        self.push('ebp')
      elif byte == 0x51:
        self.push('ecx')

      elif byte == 0x5D:
        self.pop('ebp')

      elif byte == 0x83:
        byte = self.read_byte()
        if byte == 0xE8:
          self.sub('eax', self.read_byte())
        elif byte == 0xC0:
          self.add('eax', self.read_byte())

      elif byte == 0x89:
        if self.read_byte() == 0x45:
          self.mov('[ebp%+d]' % self.read_signed_byte(), 'eax')

      elif byte == 0x8B:
        byte = self.read_byte()
        if byte == 0xEC:
          self.mov('ebp', 'esp')
          self.ebp_offset = 0
        elif byte == 0xE5:
          self.mov('esp', 'ebp')
        elif byte == 0x45:
          self.mov('eax', '[ebp%+d]' % self.read_signed_byte())

      elif byte == 0xC3:
        self.ret()
        break

      elif byte == 0xC7:
        if self.read_byte() == 0x45:
          dst = '[ebp%+d]' % self.read_signed_byte()
          src = self.read_signed_int()
          self.mov(dst, src)

      elif byte == 0xE8:
        # Relative near call
        relative_addr = self.read_signed_int()
        self.call(self.addr + relative_addr) # Relative to the next call, so evaluate after reading
          
    
  
if __name__ == '__main__':
  test1()
