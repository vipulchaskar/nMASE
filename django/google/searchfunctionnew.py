from subprocess import check_output
import struct
import os
import json
import time
import datetime
from errorcodes import httpcodes, ftpcodes, smtpcodes
import operator

curwd = '../../'										#Current working directory, which is project's root folder

SCORE_MATCH_INCR = 500									#Factor to increase score based on matching with query
SCORE_DATE_DECR = 1 									#Factor to decrease score based on how old it is

def get_flow(flow_file,flow_id):
  '''
  This function returns required flow record 
  from the flow file of corresponding flow_id
  '''
  try:
    flow_struct = struct.Struct('16s16sHHI')
    struct_size = flow_struct.size
    flow_file.seek(flow_id*struct_size)

    record = list(flow_struct.unpack_from(flow_file.read(struct_size)))
    record[0] = str(record[0][:(record[0].find(b'\0'))].decode("utf-8"))	#Since IP addr may occupy less than 16 bytes, we need to truncate it,
    record[1] = str(record[1][:(record[1].find(b'\0'))].decode("utf-8"))
    return record
  except:
    return []

def converttime(timeinsec):
	'''
	Returns time in hh:mm format from integer format
	'''
	timeinsec += 5*60*60 + 30*60
	timeestruct = time.localtime(timeinsec)

	return str(timeestruct.tm_hour) + ":" + str(timeestruct.tm_min)

def converttostring(metadata_dict):
	'''
	Converts metadata of a particular flow from JSON format to string
	'''
	output = " "

	if type(metadata_dict) == type(str()):
		return metadata_dict

	protocol = metadata_dict["protocol"]

	output += "Protocol : <b>" + metadata_dict["protocol"] + "</b><br><br>\\n"
	output += "Host : <b>" + metadata_dict["host"] + "</b><br><br>\\n"
	output += "Started at : " + metadata_dict["init_time"] + "<br><br>\\n"
	output += "Data usage : " + str(metadata_dict["usage"]) + " bytes<br><br>\\n"

	if protocol == "HTTP":
		output += "Records:<br><br>\\n"
		
		for record in metadata_dict["records"]:
			if record["type"] == "request":
				output += "Req: "
			elif record["type"] == "response":
				output += "Resp: "			
			output += str(record["message"]) + " "
			
			if record["message"] in httpcodes:
				output += httpcodes[record["message"]] + " "
			if "URL" in record:
				output += "<b>" + record["URL"] + "</b>"
			if "attack" in record and record["attack"] != "None":
				output += " <b><span style='color:red'>" + record["attack"] + " Attack!</b></span>"
			output += " " + converttime(record["timestamp"]) + "<br><br>\\n" 

	elif protocol == "FTP":
		output += "Records:<br><br>\\n"

		for record in metadata_dict["records"]:
			if record["type"] == "request":
				output += "Req: "
			elif record["type"] == "response":
				output += "Resp: "
			output += record["message"] + " "
			
			if record["type"] == "response" and int(record["message"]) in ftpcodes:
				output += ftpcodes[int(record["message"])] + " "
			if "argument" in record:
				output += "<b>" + record["argument"] + "</b> "
			output += " " + converttime(record["timestamp"]) + "<br><br>\\n"
	
	elif protocol == "SMTP":
		output += "Records:<br><br>\\n"
		
		for record in metadata_dict["records"]:
			if record["type"] == "request":
				output += "Req: "
			elif record["type"] == "response":
				output += "Resp: "
			output += record["message"] + " "
			
			if record["type"] == "response" and int(record["message"]) in smtpcodes:
				output += smtpcodes[int(record["message"])] + " "
			if "argument" in record:
				output += "<b>" + record["argument"] + "</b> "
			output += " " + converttime(record["timestamp"]) + "<br><br>\\n"
	
	elif protocol == "DNS":
		output += "Records:<br><br>\\n"
		
		for record in metadata_dict["records"]:
			if record["type"] == "request":
				output += "Req: "
			elif record["type"] == "response":
				output += "Resp: "

			if record["type"] == "request":
				output += record["type"] + " <b>" + record["message"] + "</b> flags:" + str(record["flags"]) + " qtype: " + str(record["qtype"]) + " " + converttime(record["timestamp"]) + "<br><br>\\n"
			else:
				output += record["type"] + " <b>" + record["message"] + "</b> flags:" + str(record["flags"]) + " " + converttime(record["timestamp"]) + "<br><br>\\n"

	return output

def search(context):
	'''
	The main search function which accepts query in intermediate form and performs
	search on bitmap indexes and JSON files
	'''

	retresults = []											#List of search results returned
	results = []											#List of results returned from bitmap search
	slotlist = []											#List of slots to be searched in
	slotpath = context["slot"]								#Current slot path provided
	
	if len(slotpath) <= 3:									#If only date provided,
		for x in range(0,24):								#Search which hour slots are present
			if os.path.isdir(curwd + slotpath + str(x) + '/'):
				slotlist.append(slotpath + str(x) + '/')	#And add them to list of slots
	else:
		slotlist = [slotpath]								#Else, add the only time slot provided

	#Extract application layer fields from the context
	if "proto" in context:
		proto = context["proto"]
	else:
		proto = None
	if "email" in context:
		email = context["email"]
	else:
		email = None
	if "url" in context:
		url = context["url"]
	else:
		url = None
	if "file" in context:
		filename = context["file"]
	else:
		filename = None

	sip = []
	sport = []
	dip = []
	dport = []

	#bitmap_search_command = ['./bitmap_search_comp_new', '-1', '-1', '-1', '-1', '0', '-1', '-1', '-1', '-1', '0', curslot]

	#Convert IP address and port number to required internal form
	for ip in context['ip']:
		if ip[0] == 'S':
			sip.append((str(ip[1]), str(ip[2]), str(ip[3]), str(ip[4])))
		elif ip[0] == 'D':
			dip.append((str(ip[1]), str(ip[2]), str(ip[3]), str(ip[4])))

	for port in context['port']:
		if port[0] == 'S':
			sport.append(str(port[1]))
		elif port[0] == 'D':
			dport.append(str(port[1]))

	maximum = max(len(sip), len(sport), len(dip), len(dport))

	for curslot in slotlist:									#For each slot in the list of slots to be searched upon
		results = []

		for i in range(0,maximum):								#For each set of IP address and port numbers to be searched on bitmap,
			bitmap_search_command = ['./bitmap_search_comp_new', '-1', '-1', '-1', '-1', '0', '-1', '-1', '-1', '-1', '0', curslot]
																#Initial bitmap command

			try:												#Populate bitmap command with Source IP
				bitmap_search_command[1:5] = [sip[i][0], sip[i][1], sip[i][2], sip[i][3]]
			except:
				if len(sip) != 0:
					bitmap_search_command[1:5] = [sip[0][0], sip[0][1], sip[0][2], sip[0][3]]

			try:												#Populate bitmap command with Source port
				bitmap_search_command[5] = sport[i]
			except:
				if len(sport) != 0 and len(sport) > len(sip):
					bitmap_search_command[5] = sport[0]

			try:												#Populate bitmap command with Destination IP
				bitmap_search_command[6:10] = [dip[i][0], dip[i][1], dip[i][2], dip[i][3]]
			except:
				if len(dip) != 0:
					bitmap_search_command[6:10] = [dip[0][0], dip[0][1], dip[0][2], dip[0][3]]

			try:												#Populate bitmap command with Destination port
				bitmap_search_command[10] = dport[i]
			except:
				if len(dport) != 0 and len(dport) > len(dip):
					bitmap_search_command[10] = dport[0]

			#Execute the bitmap search command
			output = check_output(bitmap_search_command, cwd = curwd, universal_newlines=True)
			results.extend([int(x)-1 for x in output.split()])	#Store the resulting flow IDs in results

			temp = bitmap_search_command[6:11]					#Swap the source and destination IP-port
			bitmap_search_command[6:11] = bitmap_search_command[1:6]
			bitmap_search_command[1:6] = temp

																#And execute bitmap search again
			output = check_output(bitmap_search_command, cwd = curwd, universal_newlines=True)
			results.extend([int(x)-1 for x in output.split()])	#Store the resulting flow IDs in results
		
		path_aggrjson = os.path.join(curwd, curslot, 'aggr.json')	#Define the filenames + path for required files
		path_flowrec = os.path.join(curwd, curslot, 'flow_rec')
		path_metajson = os.path.join(curwd, curslot, 'metadata.json')

		json_data = open(path_aggrjson)								#Open and read aggregate metadata json file
		data = json.load(json_data)

		json_metadata = open(path_metajson)							#Open and read metadata json file
		metadata = json.load(json_metadata)

		protopie = {"HTTP":0, "FTP":0, "SMTP":0, "DNS":0}			#Initialize the datasets required to generate graphs
		sipgraph = {}
		dipgraph = {}

		with open(path_flowrec, "rb") as flow_file:
			if results:												#If bitmap search returned results,
				iterator = results 									#Iterate only on those flows,
			else:													#Else,
				iterator = [int(x) for x in data.keys()]			#Iterate on all flows
		
			for flow_id in iterator:								#For each flow in results

				flag = 0											#Initialize variables
				oneresult = [flow_id]
				summary = ""
				metadata_string = ""
				
				flowrecord = get_flow(flow_file, flow_id)			#Get the flow record
				aggrinfo = data[str(flow_id)]						#Read aggregate metadata of that flow

				if "protocol" in aggrinfo:							
					summary += aggrinfo["protocol"] + " connection."	#Store application layer protocol in result summary
					protopie[aggrinfo["protocol"]] += aggrinfo["usage"]	#Update data for pie chart
				
				score = aggrinfo["score"]								#Get the score of that flow
				flowdatetime = datetime.datetime.strptime(aggrinfo["init_time"], "%a %b %d %H:%M:%S %Y")
				curdatetime = datetime.datetime.today()
				score -= ((curdatetime - flowdatetime).days)*SCORE_DATE_DECR	#Adjust the score based on how old it is

				#If protocol given in query, if it matches with current flow, mention this in summary and increase score
				if proto:
					if "protocol" in aggrinfo and proto.upper()==aggrinfo['protocol']:
						summary += " <b>" + proto + "</b> protocol found."
						score += SCORE_MATCH_INCR
					else:
						flag = 1

				#If URL given in query, if current flow has same URL in it, mention this in summary and increase score
				#Separate the URL into domain name and path, and try to match both or either of them
				if url:
					slashpos = url.find('/')
					if slashpos == -1:
						domain = url[:]
						path = None
					else:
						domain = url[:slashpos]
						path = url[slashpos:]

					if ("host" in aggrinfo and domain in aggrinfo["host"]):
						if path:
							if path in aggrinfo["aggr"]["URL"]:
								summary += " URL <b>" + url + "</b> found."
								score += SCORE_MATCH_INCR
							else:
								flag = 1
						else:
							summary += " Domain <b>" + domain + "</b> found."
							score += SCORE_MATCH_INCR
					elif ("domain" in aggrinfo["aggr"] and domain in aggrinfo["aggr"]["domain"] and path==None):
						summary += " Domain <b>" + domain + "</b> found."
						score += SCORE_MATCH_INCR
					else:
						flag = 1

				#If email given in query, and if current flow has it, mention this in summary and increase score
				if email:
					if ("argument" in aggrinfo["aggr"] and email in aggrinfo["aggr"]["argument"]):
						summary += " Email address <b>" + email + "</b> found."
						score += SCORE_MATCH_INCR
					else:
						flag = 1

				#If filename given in query, and if current flow has it, mention this in summary and increase score
				#Search for file name both in filename fields and URL fields
				if filename:
					if ("argument" in aggrinfo["aggr"] and filename in aggrinfo["aggr"]["argument"]):
						summary += " File <b>" + filename + "</b> found."
						score += SCORE_MATCH_INCR
					elif ("URL" in aggrinfo["aggr"] and filename in aggrinfo["aggr"]["URL"]):
						summary += " File <b>" + filename + "</b> Found."
						score += SCORE_MATCH_INCR
					else:
						flag = 1

				summary += " " + str(aggrinfo["usage"]) + " bytes transferred in Flow ID"

				try:												#Get the metadata of current flow, if it is present
					metadata_string = metadata[str(flow_id)]
				except:
					metadata_string = "No metadata present."

				metadata_string = converttostring(metadata_string)	#Convert this metadata to string representation

				if flowrecord:										#If flowrecord is found,
					oneresult.append(flowrecord[0] + ':' + str(flowrecord[2]) + ' connected to ' + flowrecord[1] + ':' + str(flowrecord[3]) + ' through ' + aggrinfo['tprotocol'])
					oneresult.append(summary)						#Combine all the parts of a search result to oneresult
					oneresult.append(metadata_string)
					oneresult.append(score)
					oneresult.append(curslot)

					retresults.append(oneresult)					#And append it to list of results to be returned

					if flowrecord[0] not in sipgraph:				#Update source IP distribution graph if source IP is present
						sipgraph[flowrecord[0]] = 1
					else:
						sipgraph[flowrecord[0]] += 1

					if flowrecord[1] not in dipgraph:				#Update destination IP distribution graph if destination IP present
						dipgraph[flowrecord[1]] = 1
					else:
						dipgraph[flowrecord[1]] += 1

		for key,value in protopie.items():							#Convert values in protocol pie chart dataset from bytes to KBs
			protopie[key] = round(value/1024,2)

	#Sort results in decreasing order of score,
	#Sort source IP graph dataset in decreasing order and return top 4 results
	#Sort destination IP graph dataset in decreasing order and return top 7 results
	#Return search results, protocol pie chart dataset, source IP graph dataset, destination IP graph dataset
	return sorted(retresults, key=lambda retresults: retresults[4], reverse=True), protopie, sorted(sipgraph.items(), key=operator.itemgetter(1), reverse=True)[0:4], sorted(dipgraph.items(), key=operator.itemgetter(1), reverse=True)[0:7]

#----------STRUCTURE OF RETRESULTS------
'''
	[
		[FLOWID, "Title1", "Summary1", "Metadata string 1", SCORE, SLOTPATH],
		[FLOWID, "Title2", "Summary2", "Metadata string 2", SCORE, SLOTPATH],
		[FLOWID, "Title3", "Summary3", "Metadata string 3", SCORE, SLOTPATH],
	]
'''