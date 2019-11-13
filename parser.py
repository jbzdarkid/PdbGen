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
  
class Foo:
  def __init__(self, bytes):
    self.ebp_esp = 0 # Value of ebp - esp
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
    
  def set_flags(self, reg):
    self.flags = {
      # 'OF': f'{reg} > 0xFFFFFFFF',
      'SF': f'{reg} < 0',
      'ZF': f'{reg} == 0',
      # 'AF': '', # carry out of low-4 bits?
      # 'CF': f'{reg} carry into most sign. bit',
      # 'PF': f'{reg} has an even number of 1 bits',
    }
  
  def read_ebp_rel(self):
    b = self.read_signed_byte()
    if b > 0:
      return 'arg_%x' % b
    else:
      return 'local_%x' % -b
      
  def read_esp_rel(self):
    b = self.read_signed_byte() - self.ebp_esp
    if b > 0:
      return 'arg_%x' % b
    else:
      return 'local_%x' % -b
  
  def sub(self, dst, src):
    print(f'# {dst} -= {src}')
    self.set_flags(dst)

  def add(self, dst, src):
    print(f'# {dst} += {src}')
    self.set_flags(dst)

  def mul(self, dst, src):
    print(f'# {dst} *= {src}')
    self.set_flags(dst)

  def div(self, src):
    print(f'# edx = eax % {src}; eax = eax / {src}')
    # Does not set flags, I guess because it's ambiguous
    
  def mov(self, dst, src):
    if dst == 'ebp' and src == 'esp':
      self.ebp_esp = 0
    elif dst == 'esp' and src == 'ebp':
      self.ebp_esp = 0

    print(f'# {dst} = {src}')
    
  def ret(self):
    print('# return')
    
  def xor(self, dst, src):
    if dst == src:
      self.mov(dst, '0')
    else:
      print(f'# {dst} ^= {src}')
    self.set_flags(dst)
    
  def _and(self, dst, src):
    if src == 0:
      self.mov(dst, '0')
    else:
      print(f'# {dst} &= {src}')
    self.set_flags(dst) # OF and CF cleared, SF/ZF/PF set to result, AF undefined

  def _or(self, dst, src):
    if src == 0xFF:
      self.mov(dst, '-1')
    else:
      print(f'# {dst} |= {src}')
    self.set_flags(dst) # OF and CF cleared, SF/ZF/PF set to result, AF undefined
  
  def call(self, addr):
    if addr not in self.functions:
      name = 'func%04d' % len(self.functions)
      self.functions[addr] = name
      self.unparsed_functions.append(addr)
    print(f'# call {self.functions[addr]}')

  def push(self, src):
    self.sub('esp', '4')
    self.ebp_esp -= 4
    self.mov('[esp]', src)
  
  def pop(self, src):
    self.mov(src, '[esp]')
    self.add('esp', '4')
    self.ebp_esp += 4
    
  def cdq(self):
    print('# edx = (eax < 0) ? -1 : 0')
  
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
    elif byte == 0xE5:
      dst, src = 'esp', 'ebp'
    elif byte == 0xEC:
      dst, src = 'ebp', 'esp'
    else:
      raise
      
    if not reversed:
      return [dst, src]
    else:
      return [src, dst]
  
  def parse_function(self):
    self.addr = self.unparsed_functions.pop(0)
    print(f'\nFunction {self.functions[self.addr]} at address {hex(self.addr)}')
  
    while 1:
      byte = self.read_byte()
      
      if byte == 0x03:
        self.add(*self.read_registers())
      
      elif byte == 0x0B:
        self._or(*self.read_registers())

      elif byte == 0x0F:
        if self.read_byte() == 0xAF:
          self.mul(*self.read_registers())
      
      elif byte == 0x23:
        self._and(*self.read_registers())
      
      elif byte == 0x2B:
        self.sub(*self.read_registers())
      
      elif byte == 0x33:
        self.xor(*self.read_registers())
        
      elif byte == 0x51:
        self.push('ecx')

      elif byte == 0x55:
        self.push('ebp')

      elif byte == 0x5D:
        self.pop('ebp')

      elif byte == 0x83:
        byte = self.read_byte()
        if byte == 0xE8:
          self.sub('eax', self.read_byte())
        elif byte == 0xEC:
          self.sub('esp', self.read_byte())
        elif byte == 0xC0:
          self.add('eax', self.read_byte())

      elif byte == 0x89:
        self.mov(*self.read_registers(reversed=True))
 
      elif byte == 0x8B:
        self.mov(*self.read_registers())

      elif byte == 0x99:
        self.cdq()
      
      elif byte == 0xC3:
        self.ret()
        break

      elif byte == 0xC7:
        if self.read_byte() == 0x45:
          dst = self.read_ebp_rel()
          src = self.read_signed_int()
          self.mov(dst, src)

      elif byte == 0xE8:
        # Relative near call
        relative_addr = self.read_signed_int()
        self.call(self.addr + relative_addr) # Relative to the next call, so evaluate after reading
      
      elif byte == 0xF7:
        if self.read_byte() == 0x7D:
          self.div(self.read_ebp_rel())
      
      else:
        print('Failed to parse byte: ' + hex(byte))
        exit(1)
    
  
if __name__ == '__main__':
  test2()
