
def parse_page():

	f = open('openrisc-arch-1.1-rev0.txt', 'r').read()
	d = f.split('OpenRISC 1000 Architecture Manual')
	d = filter(lambda x: "opcode" in x, d)
	d = map(lambda x: x[x.rfind("Right")+5:x.find("Description")].split('\n'), d)

	inst = list()

	for x in d:

		if len(x) < 4 or x[-4] != 'Format:':
			continue

		new_inst = dict()
		# name and format
		new_inst['format'] = x[-3]
		new_inst['name'] = x[-3][:x[-3].find(' ')]


		# number of bits
		bits = filter(lambda x: x[-5:] == " bits" or  x[-4:] == " bit" , x)
		new_inst['bits'] = map(lambda x: int(x[:x.find(' ')]), bits)[::-1]

		# values
		values = filter(lambda x: x in ['A', 'B', 'C', 'D', 'I', 'K', 'L', 'N', 'reserved'] or x[:6] == "opcode", x)
		assert(len(values) == len(new_inst['bits']))
		new_inst['values'] = values[::-1]

		inst.append(new_inst)

	return inst


def gen_instructions(inst):
	inst_str = list()
	
	for i in inst:

		nb_CF_USE = len(set(filter(lambda x: x in ['A', 'B', 'C', 'D', 'I', 'K', 'L', 'N'] , i['values'])))

		features = " | ".join(['CF_USE%i' % (j+1) for j in range(nb_CF_USE)])
		if not features:
			features = "0"
		str_ins = "{'name': '%s', 'feature': %s, 'cmt': '%s'}" % (i['name'], features, i['format'])
		inst_str.append(str_ins)
	
	return "["+",\n".join(inst_str)+"]"

mask_dict = set()
def get_mask_val(bmask, shiftl, shiftr):
	global mask_dict
	mask_dict.add((bmask, shiftl, shiftr))
	return "op_m%i_sl%i_sr%i" % (bmask, shiftl, shiftr)

def gen_masks():
	global mask_dict
	return "\n".join(map(lambda x: "op_m%i_sl%i_sr%i = ((opcode & 0x%x) >> %i)" % (x[0], x[1], x[2], ((1 << x[0])-1) << x[1], x[2]), mask_dict))

def parse_inst(insts):

	for i in insts:

		cur_bit = 0
		cond = list()
		op = list()

		for j, nb_bit in enumerate(i['bits']):
			
			cur_op = i['values'][j]

			# immediate
			if cur_op in ['I', 'K', 'L']: 
				# if immediate in two part
				if 'I' in i['values'][j+1:]:
					# get index of this one
					index = i['values'][j+1:].index('I')
					# compute start offset
					start_off = cur_bit + nb_bit + sum(i['bits'][j+1:j+1+index])
					# compute size of the second part of I
					size = i['bits'][index]

					imm = {'type': 'o_imm', 'dtyp': 'dt_word', 'value': 'SIGNEXT(%s | %s, %i)' % (get_mask_val(nb_bit, cur_bit, cur_bit), get_mask_val(size, start_off, start_off-cur_bit-nb_bit), nb_bit+size)}

					# I is ok, we have handled it
					i['values'][j+1+index] = "_"
				else:
					if cur_op in ['K', 'L']:
						imm = {'type': 'o_imm', 'dtyp': 'dt_word', 'value': '%s' % (get_mask_val(nb_bit, cur_bit, cur_bit))}
					else:
						imm = {'type': 'o_imm', 'dtyp': 'dt_word', 'value': 'SIGNEXT(%s, %i)' % (get_mask_val(nb_bit, cur_bit, cur_bit), nb_bit)}

				# if this is a displacement
				if 'I(rA)' in i['format']:
					regA = i['values'].index('A')
					# compute start offset
					start_off = sum(i['bits'][:regA])
					size = i['bits'][regA]

					imm = {'type': 'o_displ', 'addr': imm['value'], 'reg': '%s' % (get_mask_val(size, start_off, start_off))}
					i['values'][regA] = "_"
				
				op.append(imm)

			# register
			elif cur_op in ['A', 'B', 'C', 'D']:
				reg = {'type': 'o_reg', 'dtyp': 'dt_word', 'reg': '%s' % (get_mask_val(nb_bit, cur_bit, cur_bit))}
				op.append(reg)

			# near
			elif cur_op in ['N']: 
				near = {'type': 'o_near', 'dtyp': 'dt_word', 'addr': 'cmd.ea + 4*SIGNEXT(%s, %i)' % (get_mask_val(nb_bit, cur_bit, cur_bit), nb_bit)}
				op.append(near)

			# opcode value	
			elif cur_op[:6] == "opcode":
				
				v = int(cur_op[7:], 16)
				cond.append("(%s == 0x%x)" % (get_mask_val(nb_bit, cur_bit, cur_bit), v))
			
			# reserved
			elif cur_op == "reserved":
				pass

			elif cur_op == "_":
				# already handled
				pass

			else:
				# problem
				print "problem"
				print cur_op
				exit(0)				
			
			cur_bit += nb_bit

		
		if i['name'] in ['l.sw', 'l.swa']:
			i['op'] = op
		else:
			i['op'] = op[::-1]

		i['cond_str'] = cond
		i['itype_str'] = "cmd.itype = self.inames['%s']" % (i['name'])

	return insts


def gen_ana(insts):
	ana_str = """
def _ana(self):
    cmd = self.cmd
    opcode = self._read_cmd_dword()
    %s
""" % gen_masks()

	for i in insts:

		cur_i_str = ''
		cur_i_str += "elif "+" and ".join(i['cond_str'])+":\n"
		cur_i_str += '    '+i['itype_str']+'\n' 
		for nb, op_dict in enumerate(i['op']):
			for _type, _val in op_dict.iteritems():
				cur_i_str += "    cmd[%i].%s = %s\n" % (nb, _type, _val)

		
		ana_str += cur_i_str
	
	return ana_str


d = parse_page()
d = parse_inst(d)

print gen_instructions(d)
print gen_ana(d)