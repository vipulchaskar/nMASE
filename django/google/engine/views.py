from django.shortcuts import render
from django.http import HttpResponse
from searchfunctionnew import search, get_flow
from subprocess import check_output
from engine.models import Query
import datetime as dt
import struct
import os
import re
import urllib
import time
import socket
import json
import nmap
import xml.etree.ElementTree as ET

curwd = '../../'
curslot = ''
SCORE_HIT_INCR = 5

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
path_flowrec = os.path.join(BASE_DIR, 'flow_rec')				#path to the flow record file.
path_packetcap = os.path.join(BASE_DIR, 'packetcap.capture')
path_errorfile = os.path.join(BASE_DIR, curwd, 'errors')

eth_length = 14

threshold = 60


#x = struct.Struct('16s16sHHI')	#Structure definition of flow records to be read. Ref: https://docs.python.org/3/library/struct.html
#y = struct.Struct('IIHcI')	#Structure definition of packet header records to be read. Ref: https://docs.python.org/3/library/struct.html

#16s - 16 byte source IP field	(s - char array)
#16s - 16 byte dest IP field
#HH - Two port numbers field	(H - unsigned short field)
#I - First packet offset field	(I - unsigned int field)
'''Structure of header:
header[0] : Timestamp (4 bytes)
header[1] : ID (4 bytes)
header[2] : Length (2 bytes)
header[3] : Direction (1 byte)
header[4] : Next Offset (4 bytes)
'''
def extract_header(packet):
  '''
  Takes a packet and returns 3 things : protocol, application layer data, data_size
  protocol is 1 for TCP and 2 for UDP
  '''

  ip_header = packet[14:20+14]						#Extract IP header
  iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)	#and unpack it
  version_ihl = iph[0]
  ihl = version_ihl & 0xF
  iph_length = ihl * 4 								#Extract IP header length
  protocol = iph[6]									#Extract protocol type
  
    
  if protocol == 6:									#Transport protocol is TCP
    t = iph_length + 14								#Get TCP header fields
    tcp_header = packet[t:t+20]

    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)	#Unpack TCP headers
    
    doff_reserved = tcph[4]							#Calculate TCP header length
    tcph_length = doff_reserved >> 4

    h_size = 14 + iph_length + tcph_length * 4 		#Calculate total length
    data_size = len(packet) - h_size

    #Get data from the packet
    r = re.compile(b"^(.*?)\x0D\x0A\x0D\x0A",re.DOTALL)	#RE to take off only HTTP headers
    m = r.match(packet[h_size:])

    if m:												#If RE matched, decode only HTTP headers
        try:
            data = str(m.group(1).decode("utf-8"))
            return 1, data, data_size
        except:
            return 5,5,5

    try:												#Otherwise, decode all application layer data
      data = str(packet[h_size:].decode("utf-8"))
      return 1, data, data_size
    except:
      return 5,5,5

  elif protocol==17:									#If transport protocol is UDP
    h_size = eth_length + iph_length + 8 				#Calculate total length
    data_size = len(packet) - h_size
    m = packet[h_size :]								#Take off only application layer data

    return 2,m,data_size



'''
Check if the user has already fired this query. If query is present,
increase its hit count, Otherwise make entry in database
'''
def check_query(query, id):
	if id is None:
		id=0

	q = ""

	q = Query.objects.filter(query=query, user_id=id)
	if q:
		q[0].hits = q[0].hits + 1
		q[0].save()
		return 1
	return 0

'''
Function to render homepage and perform query processing.
'''
def homepage(request):
	context = {}

	#Fetch last 3 queries performed by current user. Required for news feed
	try:
		news = Query.objects.filter(user_id=request.user.id).order_by('-id')[:3]
		context["news"] = news
	except:
		pass

	#Fetch 3 most frequent queries performed by current user. Required for news feed
	try:
		freqqueries = Query.objects.filter(user_id=request.user.id).order_by('-hits')[:3]
		context["freqqueries"] = freqqueries
	except:
		pass

	starttime = dt.datetime.now()

	#Fetch the errors from error log file. Required for news feed
	feederrors = []
	with open(path_errorfile,"r") as error_file:
		feederrors = error_file.readlines()
		context["feederrors"] = feederrors

	try:
		context["fromlogout"] = request.GET['fromlogout']
	except:
		pass

	#Get the query and date-time from the request
	try:
		query = request.GET['Query'].lower()
		folder = request.GET['Query_date']
		datetime = request.GET['datetime']
		date = str(int(datetime[0:2]))
	except:
		return render(request,'engine/home.html', context)

	#If the query is not null, check if it has already been entered 
	#in database. If not, enter in database along with user ID.
	#If it is present, increase the number of hits for query.
	context["query"] = query
	if query!="":
		retval = check_query(request.GET['Query'], request.user.id)

		if retval==0:
			if request.user.is_authenticated():
				q = Query(query = request.GET['Query'],user_id = request.user.id)
			else:
				q = Query(query = request.GET['Query'])
			q.save()

	#If both date and time given in slot, validate the existence of slot folder
	#Otherwise, validate the existence of only date folder
	if folder=='':
		print("there")
		hour = str(int(datetime[11:13]))
		context["slot"] = date + '/' + hour + '/'

		if not os.path.isdir(curwd + context["slot"]):
			context["slot_not_existing"] = "Doesn't exist"
			return render(request,'engine/home.html',context)
	else:
		print("here")
		context["slot"] = folder + '/'

		if not os.path.isdir(curwd + context["slot"]):
			context["slot_not_existing"] = "Doesn't exist"
			return render(request,'engine/home.html',context)

	flag = 0

	#Find source indicator keyword in query
	srckw = re.search("(from|by)", query)
	if srckw:
		srckwpos = srckw.start()
	else:
		srckwpos = -1

	#Find destination indicator keyword in query
	dstkw = re.search("(to|towards)", query)
	if dstkw:
		dstkwpos = dstkw.start()
	else:
		dstkwpos = -1

	#Find between indicator keyword in query
	btwnkw = re.search("between", query)
	if btwnkw:
		btwnkwpos = btwnkw.start()
		btwnkwflag = 0
	else:
		btwnkwpos = -1

	iplist = []
	ipregex = re.compile(r".*?(\d{1,3}|\*)\.(\d{1,3}|\*)\.(\d{1,3}|\*)\.(\d{1,3}|\*).*?")	#RegEx to detect IP address
	
	for ip in ipregex.finditer(query):								#For each instance of IP address found in query,

		curip = ("S",)												#By default IP address will go into source IP list
		
		#If between keyword is present, mark first instance of IP as S and second one as D
		if btwnkwpos != -1 and btwnkwpos < ip.start(1):
			context["between"] = 1
			if btwnkwflag==1:
				curip = ("D",)
			if btwnkwflag==0:
				curip = ("S",)
				btwnkwflag = 1
		else:															#Handle different cases of query based on relative position
																		#of source and destination keywords.
			if ip.start(1) > dstkwpos and srckwpos==-1:					#Handles the case - "Traffic TO A.B.C.D"
				curip = ("D",)
			elif ip.start(1) > dstkwpos and ip.start(1) < srckwpos:		#Handles the case - "Traffic TO A.B.C.D FROM W.X.Y.Z"
				curip = ("D",)
			elif ip.start(1) > dstkwpos and srckwpos < dstkwpos:		#Handles the case - "Traffic FROM W.X.Y.Z TO A.B.C.D"
				curip = ("D",)
		
		for i in range(1,5):											#Validate the IP address and add it to a tuple
			try:
				octet = int(ip.group(i))
				
				if octet<0 or octet>255:
					flag = 1
				else:
					curip += (octet,)
			except:
				curip += (-1,)

		iplist.append(curip)											#Append this tuple to list of IP addresses

	ipregex = re.compile(r'ip.*?(\d{1,3}(?:.)?)(\d{1,3}(?:.)?)?(\d{1,3}(?:.)?)?(\d{1,3}(?:.)?)?')
																		#RE to match partial IP addresses
	for ip in ipregex.finditer(query):									#For each partially matched IP address
		if ip.groups()[3] == None:
			curip = ("S",)												#By default IP address will go into source IP list
		
			#If between keyword is present, mark first instance of IP as S and second one as D
			if btwnkwpos != -1 and btwnkwpos < ip.start(1):
				context["between"] = 1
				if btwnkwflag==1:
					curip = ("D",)
				if btwnkwflag==0:
					curip = ("S",)
					btwnkwflag = 1
			else:															#handle different cases of query based on relative 
																			#position of source and destination keywords
				if ip.start(1) > dstkwpos and srckwpos==-1:					#Handles the case - "Traffic TO A.B.C.D"
					curip = ("D",)
				elif ip.start(1) > dstkwpos and ip.start(1) < srckwpos:		#Handles the case - "Traffic TO A.B.C.D FROM W.X.Y.Z"
					curip = ("D",)
				elif ip.start(1) > dstkwpos and srckwpos < dstkwpos:		#Handles the case - "Traffic FROM W.X.Y.Z TO A.B.C.D"
					curip = ("D",)
			print(ip.start(1))
		
			for i in range(1,5):											#Validate IP address and add it to list of tuples
				try:
					octet = int(ip.group(i).replace(".",""))
				
					if octet<0 or octet>255:
						flag = 1
					else:
						curip += (octet,)
				except:
					curip += (-1,)

			iplist.append(curip)											#Add this tuple to IP address list.


	if flag==1:
		return HttpResponse("There is some issue with IP address, please go back and fix it")
	context["ip"] = iplist													#Add IP address list to context
	ajax_ip = []
	for ele in iplist:
		ajax_ip.append(str(str(ele[1]) + '.' + str(ele[2]) + '.' + str(ele[3]) + '.' + str(ele[4])))
	context["ajax_ip"] = ajax_ip

	portlist = []
	portregex = re.compile(r".*?(port|:).*?(\d{1,5}).*?")					#RegEx to find port number
	btwnkwflag = 0
	
	for port in portregex.finditer(query):							#For each instance of port number in query

		curport = ("S",)											#By default, port number will go into source port list

		#If between keyword is present, mark first instance of IP as S and second one as D
		if btwnkwpos != -1 and btwnkwpos < port.start(1):
			if btwnkwflag==1:
				curport = ("D",)
			if btwnkwflag==0:
				curport = ("S",)
				btwnkwflag = 1
		else:															#Handle different cases of query based on relative position
																		#of source and destination keywords
			if port.start(1) > dstkwpos and srckwpos==-1:				#Handles the case - "Traffic TO PORT X"
				curport = ("D",)
			elif port.start(1) > dstkwpos and port.start(1) < srckwpos:	#Handles the case - "Traffic TO PORT X FROM Y"
				curport = ("D",)
			elif port.start(1) > dstkwpos and srckwpos < dstkwpos:		#Handles the case - "Traffic FROM Y TO PORT X"
				curport = ("D",)

		port = int(port.group(2))										#Validate port number
		
		curport += (port,)

		if port < 0 or port > 65535:
			flag = 1

		portlist.append(curport)											#Add it to list of port numbers
	
	if flag==1:
		return HttpResponse("There is some issue with port number, please go back and fix it")
	context["port"] = portlist 												#Add port number list to context

	emailregex = re.match(r".*?([\w\d\.-_]+@[\w\d\.-]+).*?",query, flags=0)	#RE to match email address in query
	if emailregex:
		email = emailregex.group(1)
		context["email"] = email 											#Add email to context if found

	protoregex = re.match(r".*?(http|ftp|smtp|dns).*?",query, flags=0)		#RE to match protocol in query
	if protoregex:
		proto = protoregex.group(1)
		context["proto"] = proto 											#Add protocol to context if found
	
	urlregex = re.match(r".*?([\w\d\.-]+\.(com|org|net|in|us|edu|gov)[^\s]*).*?", query, flags=0)	#backup - \w\d\.-/\?&=\+%
	if urlregex:															#RE to match URL
		url = urlregex.group(1)
		context["url"] = url 												#Add URL to context if found

	fileregex = re.match(r".*?file[\s:-]+([\w\d/_\.-]+).*?", query, flags=0)	#RE to match file name
	if fileregex:
		filename = fileregex.group(1)
		context["file"] = filename												#Add filename to context if found

	print(context)
	
	#Perform actual search, with context passed as parameter. Result list and datasets for 3 graphs are returned.
	results, protopie, sipgraph, dipgraph = search(context)

	context['results'] = results											#Add results and datasets to context
	context['protopie'] = protopie
	context['sipgraph'] = sipgraph
	context['dipgraph'] = dipgraph

	endtime = dt.datetime.now()
	timediff = endtime-starttime											#Calculate how much time required to return results
																			#and append it to context
	timestr = str(len(results)) + " results in " + str(timediff.seconds) + "." + str(timediff.microseconds) + " seconds"
	context['page_speed'] = timestr	

	return render(request,'engine/results.html', context)					#Return the results page along with results

#-----------------------------------------------------------------------------------------------------
'''
start of processing of packet view 
Accepts flow ID, paths to flow record and aggregate metadata file, current slot
and generates related flows for given flow
'''
def get_related_flows(flow_id, path_flowrec, path_aggrmetadata, curslot):

  related_flows = []
  
  with open(path_flowrec,"rb") as flow_file:
    flow_record = get_flow(flow_file, int(flow_id))

    if flow_record:

      results = []
      sip = flow_record[0].split('.')
      dip = flow_record[1].split('.')
      sport = str(flow_record[2])
      dport = str(flow_record[3])

      bitmap_search_command = ['./bitmap_search_comp_new', sip[0], sip[1], sip[2], sip[3], '0', dip[0], dip[1], dip[2], dip[3], dport, curslot]
      #print("This is the bitmap search command. " + str(bitmap_search_command))
      try:
      	output = check_output(bitmap_search_command, cwd = curwd, universal_newlines=True)
      except:
      	output = ""
      	
      print(output)
      results.extend([int(x)-1 for x in output.split()])

      json_data = open(path_aggrmetadata)
      data = json.load(json_data)

      #print("These are the matching results - " + str(results))

      if results:
        for matching_flow_id in results:
          if matching_flow_id != int(flow_id):
            oneresult = [matching_flow_id]
            matching_flow_record = get_flow(flow_file, int(matching_flow_id))

            aggrinfo = data[str(matching_flow_id)]

            if matching_flow_record:			#REMOVED: AND FLAG==0
              oneresult.append(matching_flow_record[0] + ':' + str(matching_flow_record[2]) + ' connected to ' + matching_flow_record[1] + ':' + str(matching_flow_record[3]) + ' through ' + aggrinfo['tprotocol'] + '. ' + aggrinfo['init_time'])
              related_flows.append(oneresult)

      json_data.close()
  return related_flows


def three(request):
  context_dict={}
  show_result = False
  if request.method == 'GET':

    if len(request.GET['flowid'])!=0:
      show_result = True
    else:
      show_result = False
  context_dict = {'show_result':show_result}
  curslot = request.GET["slot"]
  context_dict['curslot'] = curslot

  #print ('here is show result',show_result)

  path_packetcap = os.path.join(curwd, curslot, 'packetcap.capture')
  path_flowrec = os.path.join(curwd, curslot, 'flow_rec')
  path_aggrmetadata = os.path.join(curwd, curslot, 'aggr.json')

  flow_id = str(request.GET['flowid'])

  json_aggr = open(path_aggrmetadata, "r+")
  aggrmetadata = json.load(json_aggr)

  newscore = aggrmetadata[flow_id]["score"]
  newscore += SCORE_HIT_INCR
  aggrmetadata[flow_id]["score"] = newscore

  json_aggr.seek(0)
  json.dump(aggrmetadata, json_aggr, indent='\t')
  json_aggr.close()

  if show_result == True:
    temp_list = call_thirdView(flow_id, path_packetcap, path_flowrec)
    context_dict['packet_records'] = []
    context_dict['packet_records'].extend(temp_list)

  related_flows = get_related_flows(flow_id, path_flowrec, path_aggrmetadata, curslot)
  if related_flows:
  	print(related_flows)
  	context_dict['related_flows'] = related_flows

  #end if for show_result
  return render(request,'engine/third_view.html',context_dict)



def call_thirdView(flow_id, path_packetcap, path_flowrec):
  '''
  this function will read the packet capture file and then 
  return the packet charactertics in form of array of list
  
  '''
  context_list = []
  list_packets = []
  count = 0
  #get the offset from the flow file
  offset = get_offset(int(flow_id), path_flowrec)
  #start processing the packetfile
  #and the collect all information in a list 
  #one list will contain a packets information 
  #concat all list to get all information
  with open(path_packetcap,'rb') as packet_file:
    while(1):
      record,next_offset = get_packet(offset,packet_file)
      context_list.append(record)
      if next_offset == offset:
        break
      offset = next_offset


    #end of while loop
  #end with open packet_file
  return context_list


def get_packet(offset , packet_file):
  '''
  this function will return a string 
  having all the required fields extracted from 
  packet in the string form. Used for packet view
  '''
  packet_struct = struct.Struct('IIHcI')
  packet_file.seek(int(offset))
  packet_buffer = packet_file.read(packet_struct.size)
  packet_record = list(packet_struct.unpack_from(packet_buffer))
  next_offset = packet_record[4]
  temp = ''
  
  #Processing of custom prefix header
  ttime = 'Time:' + (time.ctime(packet_record[0]))
  ID =  str(packet_record[1])
  Dir = ''

  if packet_record[3] == '\x00':
    Dir = 'source'
  else:
    Dir = 'destination'
  temp = ttime + '_' + ID + '_' + Dir + '_'
 
  #Read the packet and extract application layer data 
  packet = packet_file.read(packet_record[2])
  transport_proto,app_layer_data,app_layer_data_size = extract_header(packet)
  
  ip_header = packet[14:20+14]
  iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
  temp = temp + '_'
  '''
  process IP header breaking it to its feilds
  '''
  #for ele in iph:
  #  temp = temp + str(ele) + '_'
  version_ihl = iph[0]
  version = 'version:' + str(version_ihl >> 4)
  ihl = version_ihl & 0xF
  iph_length = 'Header Length:' + str(ihl * 4)
  ttl = 'ttl:' + str(iph[5])  
  protocol = 'protcol:' + str(iph[6])
  s_addr = 'sip:' + str(socket.inet_ntoa(iph[8]))
  d_addr = 'dip:' + str(socket.inet_ntoa(iph[9]));
  
  temp = temp + version + '_' + iph_length + '_' + ttl + '_' + protocol + '_' + s_addr + '_' + d_addr + '_'
  '''
  ending of IP processing 
  '''
  version_ihl = iph[0]
  ihl = version_ihl & 0xF
  iph_length = ihl * 4
  #add here protocol detection code if needed
  protocol = iph[6]
  #if protocol is tcp
  if protocol == 6:
    t = iph_length + 14
    tcp_header = packet[t:t+20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = 14 + iph_length + tcph_length * 4
    data_size = len(packet) - h_size
    #r = re.compile(b"^(.*?)\x0D\x0A\x0D\x0A",re.DOTALL)
    #m = r.match(packet[h_size:])
    data = str(packet[h_size:]) #it was data='' earlier
    #if m:
    #  data = str(m.group(1).decode("utf-8"))
      #return 1, data, data_size
    #try:
    #  data = str(packet[h_size:].decode("utf-8"))
    #except:
      #do nothing
    #  print('get lost')
    #get all tcp header data
    temp = temp + '_'
    '''
    processing of TCP data
    '''
    #for ele in tcph:
    #  temp = temp + str(ele) + '_'
    source_port = 'sourceport:' + str(tcph[0])
    dest_port = 'destport:' + str(tcph[1])
    sequence = 'sequence:' + str(tcph[2])
    acknowledgement = 'ack:' + str(tcph[3])
    doff_reserved = (tcph[4])
    tcph_length = doff_reserved >> 4
    tcph_length *= 4
    tcph_length = 'length:' + str(tcph_length)

    temp = temp + source_port + '_' + dest_port + '_' + sequence + '_' + acknowledgement + '_' + tcph_length + '_'
    '''
    end of TCP 
    '''
    '''
    adding application data
    '''
    temp = temp + '_'
    if data_size!=0:
      temp = temp + data

  elif protocol==17:
    #add udp code here
    u = iph_length + 14
    udp_header = packet[u:u+8]
    udph = struct.unpack('!HHHH' , udp_header)

    h_size = u + 8
    data_size = len(packet) - h_size
    data = packet[h_size:]

    temp = temp + '_'
    '''
    processing of UDP 
    '''
    #for ele in udph:
    #  temp = temp + str(ele) + '_'
    source_port = 'sourceport:' + str(udph[0])
    dest_port = 'dport:' + str(udph[1])
    temp = temp + source_port + '_' + dest_port + '_'
    '''
    end of UDP processing 
    '''
    '''
    adding application data
    '''
    temp = temp + '_'
    if data_size!=0:
      temp = temp + str(data)


  layers = temp.split('__')
  for idx,val in enumerate(layers):
    layers[idx] = layers[idx].split('_')
  return layers,next_offset

def get_offset(flow_id, path_flowrec):
  '''
  this function returns required flow record 
  from the flow file of corresponding flow_id
  '''
  with open(path_flowrec,'rb') as flow_file:
    flow_struct = struct.Struct('16s16sHHI')
    struct_size = flow_struct.size
    flow_file.seek(flow_id*struct_size)
    flow_record = list(flow_struct.unpack_from(flow_file.read(struct_size)))
    flow_file.close
    
    return flow_record[4]

#Store the uploaded file and run first and second module on it
def fileup(request):
	if request.FILES:
		handle_uploaded_file(request.FILES['file'])
		check_output(['./import.out'], cwd = curwd, universal_newlines=True)
		check_output(['python3','application_data_engine.py','0/0/'], cwd = curwd, universal_newlines=True)

	return render(request,'engine/fileup.html')

#Write the uploaded file to disk
def handle_uploaded_file(f):
	with open("../../import.pcap","wb+") as dest:
		for chunk in f.chunks():
			dest.write(chunk)

def epra_ip(request):
	ping_ip = request.POST.get('ping_ip',False)
	context_dict = {}
	time_start = dt.datetime.now()
	if ping_ip:
		nm = nmap.PortScanner()
		nm.scan(ping_ip,'22')
		try:
			context_dict['status'] = nm[ping_ip].state()
		
			context_dict['hostname'] = nm[ping_ip].hostname()
			context_dict['ping_result'] = 'info'
			print (nm[ping_ip].state(),nm[ping_ip].hostname())
		except:
			context_dict['ping_result'] = 'warning'
			context_dict['hostname'] = " "
			context_dict['status'] = 'unknown IP'
			
	time_end = dt.datetime.now()
	time_diff = time_end - time_start
	time_str = ""
	time_str = 'records in ' + str(time_diff.seconds) + '.' + str(time_diff.microseconds)
	context_dict['page_speed'] = time_str
	context_dict['ip'] = ping_ip
	return HttpResponse(json.dumps(context_dict))
