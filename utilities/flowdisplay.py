#!/usr/bin/python3

import struct

path = "flow_rec"				#path to the flow record file.

x = struct.Struct('16s16sHHI')	#Structure definition of flow records to be read. Ref: https://docs.python.org/3/library/struct.html
#16s - 16 byte source IP field	(s - char array)
#16s - 16 byte dest IP field
#HH - Two port numbers field	(H - unsigned short field)
#I - First packet offset field	(I - unsigned int field)

with open(path,"rb") as f:		#Open the file in binary read mode
	
	print("Flow record file opened for reading")
	result = []
	
	while True:
		buf = f.read(x.size)	#Read a flow record of size = sizeof(struct)

		if len(buf) != x.size:	#If incomplete record read, exit
			break
		
		record = list(x.unpack_from(buf))	#Separate the fields of flow record and store them in a list variable
		
		record[0] = str(record[0][:(record[0].find(b'\0'))])	#Since IP addr may occupy less than 16 bytes, we need to truncate it,
		record[1] = str(record[1][:(record[1].find(b'\0'))])	#To remove garbage value at the end
		
		result.append(record)									#Finally, add this flow record to list of flow records
j = 0
for i in result:
	print(str(j) + ' ' + str(i) + '\n')
	j += 1
