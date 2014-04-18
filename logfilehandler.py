#The MIT License (MIT)
#
#Copyright (c) 2014 Robert Abela
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

#See: https://github.com/robert-abela/kfsensor-logparser

import xml.sax.handler
import xml.sax
from datetime import datetime

MAX_QUEUE_SIZE = 5 #max entries in queue
QUEUE_INTERVAL = 10 #seconds

ROOT_ELEMENT_NAME = 'log'

def make_time(timestamp):
    timestamp_ms = timestamp +'000' #pad for microseconds
    return datetime.strptime(timestamp_ms, '%Y-%m-%d %H:%M:%S:%f')
    
def append(field, data):
    if field is None:
        return data
    else:
        return field + data
    
debug_on = False
def dbg(debug_message):
    if debug_on:
        print(debug_message)

class LogFileEvent():
    def __init__(self):
        self.id = None
        self.type = None
        self.desc = None
        self.action = None
        self.name = None
        self.protocol = None
        self.severity = None
        self.domain = None
        self.client_ip = None
        self.client_port = None
        self.host_ip = None
        self.bindip = None
        self.host_port = None
        self.closedby = None
        self.start = None
        self.recbytes = None
        self.received = None

    def __str__( self ):
        str_rep = ''
        if self.id is not None:
            str_rep += 'id:          ' + self.id + '\n'
        if self.type is not None:
            str_rep += 'type:        ' + self.type + '\n'
        if self.desc is not None:
            str_rep += 'desc:        ' + self.desc + '\n'
        if self.action is not None:
            str_rep += 'action:      ' + self.action + '\n'
        if self.name is not None:
            str_rep += 'name:        ' + self.name + '\n'
        if self.protocol is not None:
            str_rep += 'protocol:    ' + self.protocol + '\n'
        if self.severity is not None:
            str_rep += 'severity:    ' + self.severity + '\n'
        if self.domain is not None:
            str_rep += 'domain:      ' + self.domain + '\n'
        if self.client_ip is not None:
            str_rep += 'client_ip:   ' + self.client_ip + '\n'
        if self.client_port is not None:
            str_rep += 'client_port: ' + self.client_port + '\n'
        if self.host_ip is not None:
            str_rep += 'host_ip:     ' + self.host_ip + '\n'
        if self.bindip is not None:
            str_rep += 'bindip:      ' + self.bindip + '\n'
        if self.host_port is not None:
            str_rep += 'host_port:   ' + self.host_port + '\n'
        if self.closedby is not None:
            str_rep += 'closedby:    ' + self.closedby + '\n'
        if self.start is not None:
            str_rep += 'start:       ' + self.start + '\n'
        if self.recbytes is not None:
            str_rep += 'recbytes:    ' + self.recbytes + '\n'

        return str_rep
 
class EventQueue():
    def __init__(self):
        self.__time_deltas = []
        self.__last_event = None
        self.__in_a_burst = False

    def addEvent(self, event):
        burst_event = None
        
        if self.__last_event is not None:
            old_time = make_time(self.__last_event.start)
            time = make_time(event.start)
            delta_seconds = (time - old_time).total_seconds()
            if self.isQueueFull():
                total_time = 0
                
                #Calculate the total of time intervals
                for t in self.__time_deltas:
                    total_time += t
 
                if total_time < QUEUE_INTERVAL:
                    if not self.__in_a_burst:
                        self.__print_burst(old_time)
                        burst_event = self.__last_event
                        self.__in_a_burst = True
                else:
                    self.__in_a_burst = False
                
                #remove first one since queue is full
                self.__time_deltas = self.__time_deltas[1:]
            
            #add to queue: difference between current and previous time
            self.__time_deltas.append(delta_seconds)
        else:
            #Add 0 seconds to queue since this is the first event
            self.__time_deltas.append(0)
        
        self.__last_event = event
        return burst_event
    
    def getQueueSize(self):
        return len(self.__time_deltas)
        
    def isQueueFull(self):
        return self.getQueueSize() == MAX_QUEUE_SIZE
    
    def getLastEvent(self):
        return self.__last_event
        
    def __print_burst(self, time):
        dbg(str(MAX_QUEUE_SIZE)+' events in less than '+
              str(QUEUE_INTERVAL)+' second(s) around: '+str(time))
 
class LogFileHandler(xml.sax.handler.ContentHandler):
    def __init__(self, file):
        self.inchild = ''
        self.events_map = {}
        self.current_event = None
        self.__parse(file)

    def __parse(self, file):
        '''
        Parses the log file passed in the constructor
        return: None
        '''
        parser = xml.sax.make_parser()
        parser.setContentHandler(self)
        try:
            parser.parse(file)
        except xml.sax.SAXParseException as error:
            print("Error: {0}".format(error))
        
        
    def readAttribute(self, name, attributes):
        '''
        Checks if an attribute with the given name is in the attributes 
        dictionary and if present returns it
        Return: a string or None
        '''
        if name in attributes.keys():
            return attributes[name]
        else:
            return None
        
    def startElement(self, name, attributes):
        '''
        SAX Parsing: A new element is found.
        return: None
        '''
        
        self.inchild = '' #Reset child marker
        
        if name == ROOT_ELEMENT_NAME:
            print('------ STARTED PARSING ------')
        elif name == 'event':
            #Create a new event and populate its fields
            self.current_event = LogFileEvent()
            curr_id = self.readAttribute('id', attributes)
            self.current_event.id = curr_id.rjust(10, '0')
            self.current_event.type = self.readAttribute('type', attributes)
            self.current_event.desc = self.readAttribute('desc', attributes)
            self.current_event.action = self.readAttribute('action', attributes)
            self.current_event.name = self.readAttribute('name', attributes)
            self.current_event.protocol = self.readAttribute('protocol', attributes)
            self.current_event.severity = self.readAttribute('severity', attributes)
        elif name == 'client':
            self.current_event.domain = self.readAttribute('domain', attributes)
            self.current_event.client_ip = self.readAttribute('ip', attributes)
            self.current_event.client_port = self.readAttribute('port', attributes)
        elif name == 'host':
            self.current_event.server_ip = self.readAttribute('ip', attributes)
            self.current_event.bindip = self.readAttribute('bindip', attributes)
            self.current_event.server_port = self.readAttribute('port', attributes)
        elif name == 'connection':
            self.current_event.closedby = self.readAttribute('closedby', attributes)
        else:
            self.inchild = name #keep track of child element name
 
    def characters(self, data):
        '''
        SAX Parsing: Text is found
        return: None
        '''
        if data is None:
            return

        if self.inchild == 'start':
            self.current_event.start = append(self.current_event.start, data)
            #ignore characters after the 23rd
            self.current_event.start = self.current_event.start[:23]
        elif self.inchild == 'recBytes':
            self.current_event.recbytes = append(self.current_event.recbytes, data)
        elif self.inchild == 'received':
            self.current_event.received = append(self.current_event.received, data)
                    
    def endElement(self, name):
        '''
        SAX Parsing: Element closing
        return: None
        '''
        if name == ROOT_ELEMENT_NAME:
            print('------ FINISHED PARSING ------')
        elif name == 'event':
            self.events_map[self.current_event.id] = self.current_event
            self.current_event = None
            self.inchild = '' #Reset child marker
            
    def __getSortedKeys(self):
        '''
        Returns the event ids sorted
        return: a list of strings representing the ids of the events
        '''
        return sorted(self.events_map)
        
    def getAllEvents(self):
        '''
        Returns all the events in the log file, ordered by ID
        return: a list of LogFileEvent objects
        '''
        all_events_sorted = []
        for key in self.__getSortedKeys():
            event = self.events_map[key]
            if len(event.start) == 23:
                all_events_sorted.append(event)
            else:
                print('Warning: skipping event', event.id, 'with date(', event.start,')')
                
        return all_events_sorted
        
    def filterEvents(self, f):
        '''
        Returns all the events in the log file, after the filter (f) has been
        applied. For an event to match the filter all the fields need to match.
        return: a list of LogFileEvent objects, ordered by ID.
        '''
        filtered = []
        
        for key in self.__getSortedKeys():
            event = self.events_map[key]
            
            if ((f.id is not None and event.id != f.id) or
                (f.type is not None and event.type != f.type) or
                (f.desc is not None and event.desc != f.desc) or
                (f.action is not None and event.action != f.action) or
                (f.name is not None and event.name != f.name) or
                (f.protocol is not None and event.protocol != f.protocol) or
                (f.severity is not None and event.severity != f.severity) or
                (f.domain is not None and event.domain != f.domain) or
                (f.client_ip is not None and event.client_ip != f.client_ip) or
                (f.client_port is not None and event.client_port != f.client_port) or
                (f.host_ip is not None and event.host_ip != f.host_ip) or
                (f.bindip is not None and event.bindip != f.bindip) or
                (f.host_port is not None and event.host_port != f.host_port) or
                (f.closedby is not None and event.closedby != f.closedby) or
                (f.start is not None and event.start != f.start) or
                (f.recbytes is not None and event.recbytes != f.recbytes)):
                continue
            
            filtered.append(event)
                
        return filtered

    def getBursts(self, events, all_ips=True):
        '''
        Goes through a list of events and filters out only the events that 
        happened in a burst. A burst is defined by a number of events 
        (MAX_QUEUE_SIZE) in  given number of seconds (QUEUE_INTERVAL). 
        Basically the algorithm is to keep a fixed size queue with every entry
        being the time difference between 2 events. Once the queue is filled
        the times are added and if the total is larger than QUEUE_INTERVAL the 
        current event is added to the list that will be returned.
        return: a list of LogFileEvent objects, ordered by ID.
        '''
        all_queues = {}
        burst_events = []
        
        for event in events:
            queue = self.__get_event_queue(all_queues, event, all_ips)
            #print('adding Event', event.id, event.start)
            burst_event = queue.addEvent(event)
            if burst_event is not None:
                burst_events.append(burst_event)
        
        return burst_events
    
    def __get_event_queue(self, queues, event, all_ips):
        if all_ips == True:
            if len(queues) == 0:
                queues['all_ips'] = EventQueue()
            return queues['all_ips']
        else:
            queue = queues.get(event.client_ip)
            if queue is not None:
                return queue
            new_queue = EventQueue()
            queues[event.client_ip] = new_queue
            return new_queue
    
    def getBurstsOld(self, events):
        '''
        Goes through a list of events and filters out only the events that 
        happened in a burst. A burst is defined by a number of events 
        (MAX_QUEUE_SIZE) in  given number of seconds (QUEUE_INTERVAL). 
        Basically the algorithm is to keep a fixed size queue with every entry
        being the time difference between 2 events. Once the queue is filled
        the times are added and if the total is larger than QUEUE_INTERVAL the 
        current event is added to the list that will be returned.
        return: a list of LogFileEvent objects, ordered by ID.
        '''
        old_time = None
        queue = []
        burst_events = []
        previous_event = None
        
        for event in events:
            timestamp = event.start+'000' #pad for microseconds
            time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S:%f')
        
            if old_time is not None:
                if len(queue) == MAX_QUEUE_SIZE: #Queue is full
                    total_time = 0
                    
                    #Calculate the total of time intervals
                    for t in queue:
                        total_time += t

                    if total_time < QUEUE_INTERVAL:
                        if time != old_time:
                            burst_events.append(previous_event)
                    
                    #remove first one since queue is full
                    queue = queue [1:]
                
                #add to queue: difference between current and previous time
                queue.append((time - old_time).total_seconds())
            else:
                #Add 0 seconds to queue since this is the first event
                queue.append(0)

            #update old time
            old_time = time
            previous_event = event
        
        return burst_events