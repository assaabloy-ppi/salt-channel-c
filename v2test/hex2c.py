import sys

if len(sys.argv) < 2:
	print 'Error'

if len(sys.argv[1]) % 2 != 0:
	print 'Error'

i = 0
k = 1
while i < len(sys.argv[1]):
	sys.stdout.write('0x%c%c' % (sys.argv[1][i], sys.argv[1][i+1]))
	if k % 8 == 0:
		if i < len(sys.argv[1])-2:
			sys.stdout.write(',\r\n')
		else:
			sys.stdout.write('\r\n')
	else:
		if i < len(sys.argv[1])-2:
			sys.stdout.write(', ')
		else:
			sys.stdout.write('\r\n')
	i += 2
	k += 1