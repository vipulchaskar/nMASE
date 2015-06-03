'''
Requires a flow record file and a packet capture file in the path provided.
First, it determines the application layer protocol of each flow. It can be one of these - HTTP, FTP, SMTP, DNS, Unknown.
Then it generates two JSON files - one for metadata and one for aggregate metadata.

USAGE:
user~$ python3 metadata_extractor.py <path_to_slot>
EXAMPLE:
user~$ python3 metadata_extractor.py 0/0/
user~$ python3 metadata_extractor.py 12/30/
'''
import struct
import os
import re
import sys
import json
import tempfile
import time
import math
from urllib.parse import quote_plus

BASE_DIR = os.path.dirname(os.path.dirname(__file__))         #path to current directory.
path_errorfile = os.path.join(BASE_DIR, 'errors')             #path to errors/attack log file.
path_attackfile = os.path.join(BASE_DIR, 'attack.txt')        #path to attack patterns file.

flow_struct = struct.Struct('16s16sHHI')                      #structure of flow record
packet_struct = struct.Struct('IIHcI')                        #structure of custom packet header

threshold = 60                                                #threshold probability in determining application layer protocol

SCORE_DEFAULT = 1000                                          #initial score
SCORE_APP_INCR = 10                                           #application data present
SCORE_PROB_INCR = 50                                          #problem present in flow
SCORE_ERR_INCR = 25                                           #error present in flow

def main():
  '''
  The main function which will initaite the 
  process of determining protocol and constructing json
  '''
  root = {}                                                   #root of metadata json
  roota = {}                                                  #root of aggregate metadata json

  with open(path_packetcap,"rb") as packet_file, open(path_flowrec,"rb") as flow_file, open(path_errorfile,"a") as error_file:
      
    flow_id = 0

    flow_record_list = []
  
    while True:                                           
      buf = flow_file.read(flow_struct.size)                  #Read a flow record of size = sizeof(struct)

      if len(buf) != flow_struct.size:                        #If incomplete record read, exit
        break
    
      record = list(flow_struct.unpack_from(buf))             #Separate the fields of flow record and store them in a list variable
    
      record[0] = str(record[0][:(record[0].find(b'\0'))].decode("utf-8"))  #Since IP addr may occupy less than 16 bytes, we need to truncate it,
      record[1] = str(record[1][:(record[1].find(b'\0'))].decode("utf-8"))  #To remove garbage value at the end
    
      offset = record[4]                                       #Store the offset to first packet

      flag=0
      tproto = 0

      for i in range(0,10):                                     #Iterate through first 10 packets

        weightages = {"HTTP":0, "FTP":0, "SMTP":0, "DNS":0}     #Initial weightages
          
        packet_file.seek(offset)                                #Jump to the offset of current packet

        buf1 = packet_file.read(packet_struct.size)             #Read a packet header of size = sizeof(struct)

        if len(buf1) != packet_struct.size:                     #If incomplete record read, exit
          break

        '''Structure of header:
        header[0] : Timestamp (4 bytes)
        header[1] : ID (4 bytes)
        header[2] : Length (2 bytes)
        header[3] : Direction (1 byte)
        header[4] : Next Offset (4 bytes)
         '''
        header = list(packet_struct.unpack_from(buf1))          #Unpack packet header 

        packet = packet_file.read(header[2])                    #Read a packet

        tproto, data, data_size = extract_header(packet)        #Extract only application layer data from packet

        if tproto>=3:                                           #If transport protocol other than TCP or UDP,
          record.append("Unknown")                              #Application protocol is unknown
          flag=1
          break

        if tproto==1 and (record[2]==80 or record[3]==80):      #Inspect port numbers and increase corresponding probability
          weightages["HTTP"] += 10
        if tproto==1 and (record[2]==21 or record[3]==21):
          weightages["FTP"] += 40
        if tproto==1 and (record[2]==25 or record[3]==25):
          weightages["SMTP"] += 40
        if tproto==2 and (record[2]==53 or record[3]==53):
          flags = int.from_bytes(data[2:4], byteorder='big')
          qc = int.from_bytes(data[4:6], byteorder='big')
          ac = int.from_bytes(data[6:8], byteorder='big')
          ansc = int.from_bytes(data[8:10], byteorder='big')
          arc = int.from_bytes(data[10:12], byteorder='big')

          if 0<qc<10 and 0<=ac<20 and 0<=ansc<20 and 0<=arc<20: #If all the DNS fields match,
            flag=1
            record.append("DNS")                                #Flow is a DNS flow
            break

        if data and (data_size != 0):                           #If application data found
            
          if tproto == 1:                                       #And transport protocol is TCP

            #Try matching REs of HTTP, FTP and SMTP
            http = re.match(r'^((GET|POST|OPTIONS|HEAD|PUT|DELETE|CONNECT) (.*?) HTTP/1.[01]\s+Host:)|(HTTP/1.[01] \d\d\d (.*?)(.*)Date:)',data, re.DOTALL)
            ftp = re.match(r'^([.]{3,6} (.*))|(\d\d\d (.*))',data,re.DOTALL)
            smtp = re.match(r'^((HELO|EHLO|MAIL FROM:|RCPT TO:|DATA) (.*))|(\d\d\d (.*))',data,re.DOTALL)

            #And increase corresponding probability if matched
            if http:
              weightages["HTTP"] += 60
            if ftp:
              weightages["FTP"] += 35
            if smtp:
              weightages["SMTP"] += 35

        #If probability crosses threshold value, label the flow with corresponding protocol and break
        if weightages["HTTP"] >= threshold:
          record.append("HTTP")
          flag=1
          break
        if weightages["FTP"] >= threshold:
          record.append("FTP")
          flag=1
          break
        if weightages["SMTP"] >= threshold:
          record.append("SMTP")
          flag=1
          break

        if header[4] == offset:                                 #If last packet, exit
          break
        
        offset = header[4]                                      #Else, take offset of next packet

      if flag==0:
        record.append("Unknown data")                           #If none of the protocols matched

      flow_record_list.append(record)                           #Finally, add this flow record to list of flow records

    
    for flow_record in flow_record_list:                        #Iterate over flow records

      if not flow_record:                                       #If incomplete record read, exit
          break

      source_address = flow_record[0]                           #Extract flow record fields
      destination_address = flow_record[1]
      source_port = flow_record[2]
      destination_port = flow_record[3]
      
      packet_file.seek(flow_record[4])                          #Jump to first packet
      packet_count = 1                                          #Initialize variables
      flow_usage = 0
      offset = -1
      records = []
      aggr = {}
      tprotocol = ''
      score = SCORE_DEFAULT
      
      while True:

        record = {}                                             #Initialize record dictionary
        
        packet_buffer = packet_file.read(packet_struct.size)    #Read prefix header of first packet
        packet_record = list(packet_struct.unpack_from(packet_buffer))
        
        if packet_count == 1:                                   #Record starting time for first packet
          init_time = time.ctime(packet_record[0])
        
        packet = packet_file.read(packet_record[2])             #Read actual packet and extract application layer data
        transport_proto,app_layer_data,app_layer_data_size = extract_header(packet)
        if tprotocol == '':
          if transport_proto == 1:
           tprotocol = "TCP"
          else:
           tprotocol = "UDP"

        protocol = "Unknown"                                    

        if ("Unknown" not in flow_record[5]) and (packet_count==1): #Increase score if application data present
          score += SCORE_APP_INCR
        
        if app_layer_data!=5 and flow_record[5]=="HTTP":            #If HTTP Present,
          
          protocol = 'HTTP'

          m = re.match(r'^(GET|POST|OPTIONS|HEAD|PUT|DELETE|CONNECT) (.*?) ',app_layer_data, flags=0) #RE to match HTTP Request
          n = re.match(r'^HTTP/1.[01] (.*?) ',app_layer_data, flags=0)                                #RE to match HTTP Response

          if m:                                   #If HTTP Request, extract type, request, URL and Host field
            record["type"] = "request"
            record["message"] = m.group(1)
            record["URL"] = m.group(2)

            if "URL" not in aggr:
              aggr["URL"] = [m.group(2)]
            elif m.group(2) not in aggr["URL"]:
              aggr["URL"].append(m.group(2))

            host = re.search(r'Host: (.+)',app_layer_data, flags=0)   
            try:  
              host = host.group(1).strip()
            except:
              host = destination_address

            malicious = "None"

            attacks = file_read()                             #Read attack patterns file
            for key in attacks:
              patterns = attacks[key]
              for pattern in patterns:
                if pattern in m.group(2):                     #If an attack pattern matches,
                  print(pattern, " ", m.group(2))
                  malicious = key                             #Mark it and increase score
                  score += SCORE_PROB_INCR
                  print('error detected ' + key)
                  break

            record["attack"] = malicious                      #Append attack type (if present)

            record["timestamp"] = packet_record[0]            #Append timestamp
          
          elif n:                                 #If HTTP Response, extract type, response, server and content type fields
            record["type"] = "response"
            record["message"] = int(n.group(1))
            server = re.search(r'Server: (.+)',app_layer_data, flags=0)       #Get server field
            if server:
              server_name = server.group(1)
            else:
              server_name = "-"
            record["server"] = server_name
            
            ctype = re.search(r'Content-Type: (.+)',app_layer_data, flags=0)  #Get Content-Type field
            if ctype:
              ctype_name = ctype.group(1)
            else:
              ctype_name = "-"
            record["content_type"] = ctype_name

            if "content_type" not in aggr:
              aggr["content_type"] = [ctype_name]
            elif ctype_name not in aggr["content_type"]:
              aggr["content_type"].append(ctype_name)
          
            record["timestamp"] = packet_record[0]

        if app_layer_data!=5 and flow_record[5]=="DNS":                        #If DNS present,
          
          protocol = 'DNS'

          flags = int.from_bytes(app_layer_data[2:4], byteorder='big')        #Separate the fields
          qc = int.from_bytes(app_layer_data[4:6], byteorder='big')
          ac = int.from_bytes(app_layer_data[6:8], byteorder='big')
          ansc = int.from_bytes(app_layer_data[8:10], byteorder='big')
          arc = int.from_bytes(app_layer_data[10:12], byteorder='big')

          curbyte = 12
          for q in range(qc):                                                  #For each DNS question present inside packet
            question = []
            count = app_layer_data[curbyte]

            while count != 0:                                                  #Extract the DNS Question
              question.append(str(app_layer_data[curbyte+1:curbyte+1+count].decode("utf-8")))
              curbyte = curbyte + 1 + count
              count = app_layer_data[curbyte]

            qstring = '.'.join(question)
            qtype = int.from_bytes(app_layer_data[curbyte+1:curbyte+3], byteorder='big')  #Extract qtype header
            
            #A small fix for adjusting the source and destination IP addresses properly    
            if source_port==53:
              host = source_address
            else:
              host = destination_address

            if "domain" not in aggr:                  #Append DNS question to domain
              aggr["domain"] = [qstring]
            elif qstring not in aggr["domain"]:
              aggr["domain"].append(qstring)

            if ac==0 and ansc==0 and arc==0:          #If DNS Question, store corresponding fields
              record["type"] = "request"
              record["message"] = qstring
              record["flags"] = flags
              record["qtype"] = qtype
              record["timestamp"] = packet_record[0]
            else:                                     #If DNS Answer, store corresponding fields
              record["type"] = "response"
              record["message"] = qstring
              record["flags"] = flags
              record["timestamp"] = packet_record[0]

        if app_layer_data!=5 and flow_record[5]=="FTP":   #If FTP Present,
          
          protocol = 'FTP'

          m = re.match(r'^(\d{3}) ',app_layer_data, flags=0)                  #RE to match FTP Response
          n = re.match(r'^([A-Za-z]{4})(.*?)$',app_layer_data, flags=0)       #RE to match FTP Request

          host = destination_address
            
          if m:                                   #If FTP Response, extract type, message and timestamp
            record["type"] = "response"
            record["message"] = m.group(1)
            record["timestamp"] = packet_record[0]

            if m.group(1)[0]=='5':      #FTP Response code 5XX indicates error. Hence, increase the score
              score += SCORE_ERR_INCR
              error_file.write(init_time + " FTP error " + str(m.group(1)) + " detected.\n")
          
          elif n:                                 #If FTP Request, extract type, message, argument and timestamp
            record["type"] = "request"
            record["message"] = n.group(1)
            record["argument"] = n.group(2).strip()
            record["timestamp"] = packet_record[0]

            if "command" not in aggr:
              aggr["command"] = [n.group(1)]
            elif n.group(1) not in aggr["command"]:
              aggr["command"].append(n.group(1))
            if "argument" not in aggr:
              aggr["argument"] = [n.group(2).strip()]
            elif n.group(2).strip() not in aggr["argument"]:
              aggr["argument"].append(n.group(2).strip())

        if app_layer_data!=5 and flow_record[5]=="SMTP":      #If SMTP Present,
          
          protocol = 'SMTP'
          
          app_layer_data = app_layer_data.lower()                                                 #Convert data to lowercase
          m = re.match(r'^(\d{3}) ',app_layer_data, flags=0)                                      #RE to match SMTP Response
          n = re.match(r'^(helo|mail from:|rcpt to:|data|quit)(.*?)$', app_layer_data, flags=0)   #RE to match SMTP Request

          host = destination_address

          if m:                                   #If SMTP Response, extract type, message and timestamp
            record["type"] = "response"
            record["message"] = m.group(1)
            record["timestamp"] = packet_record[0]

            if m.group(1)[0]=='5':      #SMTP Response code 5XX indicates error. Hence, increase the score
              score += SCORE_ERR_INCR
              error_file.write(init_time + " SMTP " + str(m.group(1)) + " error detected.\n")

          elif n:                                  #If SMTP Request, extract type, message, argument and timestamp
            record["type"] = "request"
            record["message"] = n.group(1)
            record["argument"] = n.group(2).strip()
            record["timestamp"] = packet_record[0]

            if "command" not in aggr:
              aggr["command"] = [n.group(1)]
            elif n.group(1) not in aggr["command"]:
              aggr["command"].append(n.group(1))
            if "argument" not in aggr:
              aggr["argument"] = [n.group(2).strip()]
            elif n.group(2).strip() not in aggr["argument"]:
              aggr["argument"].append(n.group(2).strip())

        packet_count +=1
        flow_usage += packet_record[2]            #Add the size to flow usage

        if offset == packet_record[4]:            #If last packet, then break
          break
        offset = packet_record[4]                 #Else, take offset of next packet
        packet_file.seek(offset)
        
        if record:    #If record is created, then only insert (we dont want records to be created for packets having no app layer data)
          records.append(record)
      
      score += int(math.log(flow_usage))          #Take log of total usage in bytes and add it to score
      
      try:
        host
      except:
        host = destination_address
      #Preparation for writing  to json file
      if protocol != "Unknown" and records:
        id_tag = {}
        id_val = flow_id 
        id_tag['init_time'] = init_time
        id_tag['usage'] = flow_usage
        id_tag['protocol'] = protocol
        id_tag['score'] = score
        id_tag['records'] = []
        id_tag['records'] = records
        id_tag['host'] = host
        root[id_val] = {}
        root[id_val].update(id_tag)

        id_taga = {}
        id_taga['init_time'] = init_time
        id_taga['usage'] = flow_usage
        id_taga['protocol'] = protocol
        id_taga['tprotocol'] = tprotocol
        id_taga['score'] = score
        id_taga['aggr'] = aggr
        id_taga['host'] = host
        roota[id_val] = {}
        roota[id_val].update(id_taga)

      else:
        id_taga = {}
        id_val = flow_id
        id_taga['init_time'] = init_time
        id_taga['usage'] = flow_usage
        id_taga['score'] = score
        id_taga['tprotocol'] = tprotocol
        id_taga['aggr'] = aggr
        roota[id_val] = {}
        roota[id_val].update(id_taga)

      flow_id += 1
      print("Flow record " + str(flow_id) + " done.")

    with open(path_metajson,"w") as json_file, open(path_aggrjson,"w") as aggr_file:  #Dump the created JSON data to JSON files
      json.dump(root,json_file,indent='\t')
      json.dump(roota,aggr_file,indent='\t')
      

def get_flow(flow_file,flow_id):
  '''
  this function returns required flow record 
  from the flow file of corresponding flow_id
  '''
  try:
    struct_size = flow_struct.size
    flow_file.seek(flow_id*struct_size)

    return list(flow_struct.unpack_from(flow_file.read(struct_size)))
  except:
    return []

def extract_header(packet):
  '''
  Takes a packet and returns 3 things - transport protocol, application data and application data size
  first return value is 1 for TCP and 2 for UDP
  '''

  ip_header = packet[14:20+14]                          #Remove IP header
  iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
  version_ihl = iph[0]
  ihl = version_ihl & 0xF
  iph_length = ihl * 4
  protocol = iph[6]  
    
  if protocol == 6:                                     #If transport protocol is TCP
    t = iph_length + 14
    tcp_header = packet[t:t+20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = 14 + iph_length + tcph_length * 4
    data_size = len(packet) - h_size                    #Remove transport header

    r = re.compile(b"^(.*?)\x0D\x0A\x0D\x0A",re.DOTALL) #RE to remove encoded data in case of HTTP.
    m = r.match(packet[h_size:])
    
    if m:                                               #If RE Matched, only decode the HTTP headers
      try:
        data = str(m.group(1).decode("utf-8"))
        return 1, data, data_size
      except:
        return 5,5,5

    try:                                                #Decode the application layer data, for all other protocols
      data = str(packet[h_size:].decode("utf-8"))
      return 1, data, data_size
    except:
      return 5,5,5

  elif protocol==17:                                    #If transport protocol is UDP
    h_size = 14 + iph_length + 8
    data_size = len(packet) - h_size
    m = packet[h_size :]                                #Remove transport header
    return 2,m,data_size


def file_read():
  '''
  This function reads attack patterns file and
  stores the patterns in a dictionary keyed by attack type.
  Then returns the generated dictionary
  '''
  attack_file = open('attack.txt',"r")
  content = attack_file.readlines()
  attacks = []
  types = []
  count = 0
  
  for i,x in enumerate(content):
    content[i] = content[i].rstrip()
    attacks.append(content[i].split(":"))
    attacks[count][1] = quote_plus(attacks[count][1])
    types.append(attacks[count][0])
    count = count + 1
  
  values = set(map(lambda x:x[0],attacks))
  group_attacks = [[y[1] for y in attacks if y[0]==x] for x in values]
  attack_dict = {}
  
  for i,ele in enumerate(group_attacks):
    for items in attacks:
      if ele[0] in items[1]:
        attack_dict[items[0]] = group_attacks[i]

  return attack_dict


if __name__ == '__main__':
  if len(sys.argv) == 2:
    path_flowrec = os.path.join(BASE_DIR, sys.argv[1], 'flow_rec')            #path to the flow record file.
    path_packetcap = os.path.join(BASE_DIR, sys.argv[1], 'packetcap.capture') #path to packet capture file.
    path_metajson = os.path.join(BASE_DIR, sys.argv[1], 'metadata.json')      #path to metadata json file
    path_aggrjson = os.path.join(BASE_DIR, sys.argv[1], 'aggr.json')          #path to aggregate metadata json file.
    main()
  else:
    print("Incorrect number of arguments supplied.")