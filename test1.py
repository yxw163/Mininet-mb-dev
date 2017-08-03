A = {
	'h1': 
		{'s3': 
			{1: 
				{
					'port2': 1, 
					'node1': 'h1', 
					'port1': 0, 
					'node2': 's3'
				}
			}
		}, 's4': {'s3': {1: {'port2': 1, 'node1': 's3', 'port1': 2, 'node2': 's4'}}, 'h2': {}},
    's3': {'h1': {1: {'port2': 1, 'node1': 'h1', 'port1': 0, 'node2': 's3'}}, 's4': {1: {'port2': 1, 'node1': 's3', 'port1': 2, 'node2': 's4'}}}, 'h2': {'s4': {}}}
if __name__ == '__main__':
	A.iteritems()