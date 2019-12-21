class Function:
  def __init__(self, addr, name=''):
    self.addr = addr
    self.name = name
    self.lines = []

  def add_line(self, addr):
    self.lines.append(Line(addr))

  def print_out(self):
    print('')
    print(f'Function {self.name} at address {hex(self.addr)}')
    for line in self.lines:
      line.print_out()

class Line:
  def __init__(self, addr):
    self.addr = addr
    self.comment = ''

  def print_out(self, indent=0):
    print('// ' + '  ' * indent, end='')
    print(self.comment)

class Parser:
  def __init__(self, bytes):
    self.print_bytes = False
    self.ebp_esp = 0 # Value of ebp - esp
    self.bytes = bytes
    self.functions = {}
    self.unparsed_functions = []
    self.flags = {}
    self.pending_jumps = []

  def print_out(self):
    for addr in sorted(self.functions.keys()):
      self.functions[addr].print_out()

  def add_function(self, addr):
    func = Function(addr, 'func%04d' % len(self.functions))
    self.functions[addr] = func
    self.unparsed_functions.append(func)

  def _print(self, *args):
    self.active_func.lines[-1].comment = str(*args)

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

  def set_flags(self, dst, src):
    self.flags = {
      'ZF':  f'{dst} == {src}',
      '!ZF': f'{dst} != {src}',
      'SF':  f'{dst} <= {src}',
      '!SF': f'{dst} > {src}',
    }

  def sub(self, dst, src):
    self._print(f'{dst} -= {src}')
    self.set_flags(dst, '0')

  def add(self, dst, src):
    self._print(f'{dst} += {src}')
    self.set_flags(dst, '0')

  def mul(self, dst, src):
    self._print(f'{dst} *= {src}')
    self.set_flags(dst, '0')

  def xor(self, dst, src):
    if dst == src:
      self.mov(dst, '0')
    else:
      self._print(f'{dst} ^= {src}')
    self.set_flags(dst, '0')

  def _and(self, dst, src):
    if src == 0:
      self.mov(dst, '0')
    else:
      self._print(f'{dst} &= {hex(src)}')
    self.set_flags(dst, '0')

  def _or(self, dst, src):
    if src == 0xFF:
      self.mov(dst, '-1')
    else:
      self._print(f'{dst} |= {src}')
    self.set_flags(dst, '0')

  # Both test eax, eax and cmp eax, eax will set SF=1 if eax < 0
  def cmp(self, dst, src):
    # self._print(f'cmp {dst}, {src}')
    self.set_flags(dst, src)

  def test(self, dst, src):
    self._print(f'test {dst}, {src}')
    self.set_flags(dst, src)

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
      self.add_function(addr)
    self._print(f'call {self.functions[addr].name}')

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
    assert(amt > 0)
    if cond == 'jmp':
      self._print(f'goto {self.addr + amt}')
      return
    elif cond == 'je':
      self._print(f'if ({self.flags["ZF"]}) goto {self.addr + amt}')
    elif cond == 'jne':
      self._print(f'if ({self.flags["!ZF"]}) goto {self.addr + amt}')
    elif cond == 'jge':
      self._print(f'if ({self.flags["!SF"]} || {self.flags["ZF"]}) goto {self.addr + amt}')
    elif cond == 'jle':
      self._print(f'if ({self.flags["SF"]} || {self.flags["ZF"]}) goto {self.addr + amt}')
    elif cond == 'jg':
      self._print(f'if ({self.flags["!SF"]}) goto {self.addr + amt}')

    self.pending_jumps.append(self.addr + amt)

  def parse(self, start_addr):
    self.add_function(start_addr)
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
    self.active_func = self.unparsed_functions.pop(0)
    self.addr = self.active_func.addr

    while 1:
      self.active_func.add_line(self.addr)
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

      elif byte == 0x74:
        self.jump('je', self.read_signed_byte())

      elif byte == 0x75:
        self.jump('jne', self.read_signed_byte())

      elif byte == 0x7D:
        self.jump('jge', self.read_signed_byte())

      elif byte == 0x7E:
        self.jump('jle', self.read_signed_byte())

      elif byte == 0x7F:
        self.jump('jg', self.read_signed_byte())

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
        # Jumps which land immediately after return are part of the same function
        if self.addr in self.pending_jumps:
          self.pending_jumps.remove(self.addr)
        else:
          # Far jumps to another function (e.g. tail call elision) should be parsed as separate functions.
          while len(self.pending_jumps) > 0:
            self.add_function(self.pending_jumps.pop())
          break

      elif byte == 0xC7:
        if self.read_byte() == 0x45:
          self.mov(self.read_ebp_rel(), self.read_signed_int())

      elif byte == 0xE8:
        # Relative near call
        relative_addr = self.read_signed_int()
        self.call(self.addr + relative_addr) # Relative to the next call, so evaluate after reading

      elif byte == 0xEB:
        self.jump('jmp', self.read_signed_byte())

      elif byte == 0xF7:
        if self.read_byte() == 0x7D:
          self.div(self.read_ebp_rel())

      else:
        self._print('Failed to parse byte: ' + hex(byte))
        exit(1)
