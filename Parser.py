class Condition:
  def __init__(self, a, cond, b):
    self.a = a
    self.cond = cond
    self.b = b

  def neg(self):
    if self.cond == '&&':
      return Condition(self.a.neg(), '||', self.b.neg())
    elif self.cond == '||':
      return Condition(self.a.neg(), '&&', self.b.neg())
    else:
      cond_inv = {
        '==': '!=',
        '!=': '==',
        '<': '>=',
        '<=': '>',
        '>=': '<',
        '>': '<='
      }[self.cond]
      return Condition(self.a, cond_inv, self.b)

  def __repr__(self):
    return f'Condition({self.a}, {self.cond}, {self.b})'
  def __str__(self):
    return f'({self.a} {self.cond} {self.b})'

class Function:
  def __init__(self, addr, name=''):
    self.addr = addr
    self.name = name
    self.lines = []
    self.vars = {}
    self.read_vars = set()
    self.write_vars = set()

  def add_line(self, addr):
    self.lines.append(Line(addr))

  def get_index_for_addr(self, addr):
    for i, line in enumerate(self.lines):
      if line.addr == addr:
        return i
    return None

  # @Cleanup: I want a boolean closes_scope and opens_scope on the Line class.
  def interleaves_scope(self, start, end):
    scope_depth = 0
    for line in self.lines[start:end]:
      if line.type == 'scope_end' or line.type == 'else' or line.type == 'elseif':
        if scope_depth == 0:
          return True # Attempting to close a scope which was opened before start
        scope_depth -= 1
      if line.type == 'if' or line.type == 'else' or line.type == 'elseif':
        scope_depth += 1
    return scope_depth != 0

  # @Audit: Ensure that all of these postprocs are issuing instructions at the first address.
  def postproc(self, functions):
    self.postproc_cmpreplace() # @Future: Use a tmp variable to ensure that all cmps are replaceable.
    self.postproc_ifinversion()
    self.postproc_mergeif()
    self.postproc_ifinversion()
    self.postproc_else()
    self.postproc_elseif()

    self.postproc_call(functions)

  def postproc_cmpreplace(self):
    i = 0
    while i < len(self.lines):
      cmp_line = self.lines[i-1]
      jmp_line = self.lines[i]
      i += 1

      if cmp_line.type == 'cmp' and jmp_line.type == 'jmp':
        cmp_line.type = 'if'
        dst, src = cmp_line.flags
        cmp_line.cond = Condition(dst, jmp_line.cond, src)
        target = self.lines[i].addr # @Bug: What if this if is at the end of a function?
        cmp_line.target = target

        jmp_line.comment = f'goto {jmp_line.target}'

        line = Line(-1)
        line.comment = '}'
        line.type = 'scope_end'
        self.lines.insert(i, line)

  def postproc_ifinversion(self):
    i = 0
    while i < len(self.lines):
      if_line = self.lines[i-2]
      jmp_line = self.lines[i-1]
      scp_line = self.lines[i]
      i += 1

      if if_line.type == 'if' and jmp_line.type == 'jmp' and scp_line.type == 'scope_end':
        index = self.get_index_for_addr(jmp_line.target)
        if index is None:
          continue # sanity
        if self.interleaves_scope(i, index):
          continue

        if_line.target = jmp_line.target
        if_line.cond = if_line.cond.neg()

        line = Line(jmp_line.target)
        line.comment = '}'
        line.type = 'scope_end'
        self.lines.insert(index, line)

        self.lines.pop(i-1) # scp_line
        self.lines.pop(i-2) # jmp_line
        i -= 2

  def postproc_mergeif(self):
    i = 0
    while i < len(self.lines):
      line1 = self.lines[i-1]
      line2 = self.lines[i]
      i += 1

      if line1.type == 'if' and line2.type == 'if' and line1.target == line2.target:
        index = self.get_index_for_addr(line1.target)
        if index == None:
          # Should be impossible, but if we can't find a scope end for this if, don't try and merge.
          continue

        self.lines.pop(index)
        line1.cond = Condition(line1.cond, '&&', line2.cond)
        self.lines.pop(i-1)
        i -= 1

  def postproc_else(self):
    i = 0
    while i < len(self.lines):
      jmp_line = self.lines[i-1]
      scp_line = self.lines[i]
      i += 1

      if jmp_line.type == 'jmp' and scp_line.type == 'scope_end':
        if jmp_line.target < jmp_line.addr:
          continue # Not an `else` if it goes backwards
        if jmp_line.cond != None:
          continue # Must be an unconditional jump

        index = self.get_index_for_addr(jmp_line.target)
        if index == None:
          continue # Jump goes outside this function, ignore it.
        if self.interleaves_scope(i, index):
          continue

        # Insert a line which doesn't really have an address. Or something.
        line = Line(jmp_line.target)
        line.comment = '}'
        line.type = 'scope_end'
        self.lines.insert(index, line)

        jmp_line.type = 'else'
        jmp_line.comment = '} else {'
        self.lines.pop(i-1)
        i -= 1

  def postproc_elseif(self):
    i = 0
    while i < len(self.lines):
      else_line = self.lines[i-1]
      if_line = self.lines[i]
      i += 1

      if else_line.type == 'else' and if_line.type == 'if':
        index = self.get_index_for_addr(else_line.target)
        if index == None:
          continue # sanity

        has_toplevel_code = False
        scope_depth = 0
        for line in self.lines[i-1:index]:
          if line.type == 'if' or line.type == 'else' or line.type == 'elseif':
            scope_depth += 1
          elif scope_depth == 0:
            has_toplevel_code = True
            break
          elif line.type == 'scope_end' or line.type == 'else' or line.type == 'elseif':
            scope_depth -= 1
        if has_toplevel_code:
          continue

        else_line.type = 'elseif'
        # @Cleanup: We might need to merge ifs between elseif and if so, serializing this is bad.
        else_line.comment = f'}} else if {if_line.cond} {{'
        self.lines.pop(index)
        self.lines.pop(i-1)
        i -= 1
  
  def postproc_call(self, functions):
    i = 0
    while i < len(self.lines):
      call_line = self.lines[i]
      i += 1
      
      if call_line.type == 'call':
        target_func = functions[call_line.target]
        
        call_line.comment = f'eax = {target_func.name}('
        call_line.comment += ', '.join(target_func.read_vars)
        call_line.comment += ')'

  def print_out(self):
    print('')
    print(f'// Address {hex(self.addr)}')
    print(f'void {self.name}() {{')
    indent = 1
    for line in self.lines:
      if line.type == 'scope_end' or line.type == 'else' or line.type == 'elseif':
        indent -= 1
      line.print_out(indent)
      if line.type == 'if' or line.type == 'else' or line.type == 'elseif':
        indent += 1
    print('}')

TAB_SIZE = 2
class Line:
  def __init__(self, addr):
    self.addr = addr
    self.comment = ''
    self.type = ''

  def print_out(self, indent):
    # print(str(self.addr) + '\t', end='')
    print(' ' * indent * TAB_SIZE, end='')
    if self.type == 'if':
      print(f'if {self.cond} {{')
    else:
      print(self.comment)

  def __str__(self):
    return f'Line({self.addr}, {self.type}, {self.comment})'

class Parser:
  def __init__(self, bytes):
    self.print_bytes = False
    self.ebp_esp = 0 # Value of ebp - esp
    self.stored_ebp_esp = 0 # Value of ebp - esp as of the most recent jmp instruction
    self.bytes = bytes
    self.functions = {}
    self.unparsed_functions = []
    self.pending_jumps = set()

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
      print(hex(byte) + ', ', end='')
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
      print(hex(i) + ', ', end='')
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
    self.mov(dst, f'{dst} - {src}')
    # self._print(f'{dst} -= {src}')
    # self.active_func.lines[-1].flags = (dst, '0')

  def add(self, dst, src):
    self._print(f'{dst} += {src}')
    self.active_func.lines[-1].flags = (dst, '0')

  def mul(self, dst, src):
    self._print(f'{dst} *= {src}')
    self.active_func.lines[-1].flags = (dst, '0')

  def xor(self, dst, src):
    if dst == src:
      self.mov(dst, 0)
    else:
      self._print(f'{dst} ^= {src}')
    self.active_func.lines[-1].flags = (dst, '0')

  def _and(self, dst, src):
    if src == 0:
      self.mov(dst, '0')
    else:
      self._print(f'{dst} &= {hex(src)}')
    self.active_func.lines[-1].flags = (dst, '0')

  def _or(self, dst, src):
    if src == 0xFF:
      self.mov(dst, '-1')
    else:
      self._print(f'{dst} |= {src}')
    self.active_func.lines[-1].flags = (dst, '0')

  # Both test eax, eax and cmp eax, eax will set SF=1 if eax < 0
  def cmp(self, dst, src):
    self._print(f'cmp {dst}, {src}')
    self.active_func.lines[-1].type = 'cmp'
    self.active_func.lines[-1].flags = (dst, src)

  def test(self, dst, src):
    self._print(f'test {dst}, {src}')
    self.active_func.lines[-1].flags = (dst, src)

  def dec(self, dst):
    self.sub(dst, '1')

  def inc(self, dst):
    self.add(dst, '1')

  def div(self, src):
    self._print(f'edx = eax % {src}; eax = eax / {src}')
    # Does not set flags, I guess because it's ambiguous

  def mov(self, dst, src):
    # @Hack? This isn't quite the right idea, though.
    # if dst == 'ebp' and src == 'esp':
    #   self.ebp_esp = 0
    # elif dst == 'esp' and src == 'ebp':
    #   self.ebp_esp = 0

    if dst == '[esp]':
      if self.ebp_esp <= 0:
        dst = f'local_{-self.ebp_esp}'
      else:
        dst = f'arg_{self.ebp_esp}'

    if src == '[esp]':
      if self.ebp_esp <= 0:
        src = f'local_{-self.ebp_esp}'
      else:
        src = f'arg_{self.ebp_esp}'

    if isinstance(src, int):
      self._print(f'{dst} = {hex(src)}')
    else:
      self._print(f'{dst} = {src}')

    if isinstance(src, str):
      # @Hack: Removes "+1" or "*4" or whatever suffix.
      src = src.split(' ', 1)[0]
      if src not in self.active_func.vars:
        self.active_func.read_vars.add(src)
        self.active_func.vars[src] = 'orig_' + src

      self.active_func.vars[dst] = self.active_func.vars[src]
    else:
      # Immediate value
      self.active_func.vars[dst] = src

  def ret(self):
    self._print(f'return')
    # Returns often are preceeded by popping a bunch of callee-saved variables.
    # To accomodate for that, we restore the ebp-esp offset as of the previous jump.
    self.ebp_esp = self.stored_ebp_esp
    
    for var in self.active_func.vars:
      if self.active_func.vars[var] != 'orig_' + var:
        self.active_func.write_vars.add(var)

  def call(self, addr):
    if addr not in self.functions:
      self.add_function(addr)
    self._print(f'call {self.functions[addr].name}')
    self.active_func.lines[-1].type = 'call'
    self.active_func.lines[-1].target = addr
    # @Future: Some functions do not have a 0 ebp-esp
    # self.ebp_esp += self.functions[addr].ebp_esp

  def push(self, src):
    self.ebp_esp -= 4
    self.mov('[esp]', src)

  def pop(self, src):
    self.mov(src, '[esp]')
    self.ebp_esp += 4
  
  def cdq(self):
    self._print('edx = (eax < 0) ? -1 : 0')

  def shl(self, dst, amt):
    self.mov(dst, f'{dst} * {2 ** amt}')

  def jump(self, cond, amt):
    target = self.addr + amt
    self._print(f'{cond} {target}')
    self.stored_ebp_esp = self.ebp_esp
    self.active_func.lines[-1].type = 'jmp'
    self.active_func.lines[-1].target = target
    self.active_func.lines[-1].cond = {
      'je': '==',
      'jne': '!=',
      'jl': '<',
      'jle': '<=',
      'jge': '>=',
      'jg': '>',
      'jmp': None,
    }[cond]

    if amt > 0:
      # Jump to (potentially) later in this function
      self.pending_jumps.add(target)
    elif target < self.active_func.addr:
      # Jump to before this function, indicates another function
      self.add_function(target)
    else:
      # Jump to earlier in this function
      pass

  def parse(self, start_addr):
    self.add_function(start_addr)
    while 1:
      self.parse_function()
      if len(self.unparsed_functions) == 0:
        break
    for function in self.functions.values():
      function.postproc(self.functions)

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
      print('Failed to parse byte: ' + hex(byte))
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
      # Jumps which land inside the same function
      if self.addr in self.pending_jumps:
        self.pending_jumps.remove(self.addr)

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
            self.mov('eax', 'eax + 4 * eax')
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
        print('Failed to parse byte: ' + hex(byte))
        exit(1)
