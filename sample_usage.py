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

import logfilehandler

#Step 1. Parse a log file
handler = logfilehandler.LogFileHandler('test1.log')

#Step 2. Run a filter to keep only the events that match the given filter
logfilter = logfilehandler.LogFileEvent()
logfilter.name = 'ICMP Echo Request'
filtered_by_step_2 = handler.filterEvents(logfilter)

print('--------------', len(filtered_by_step_2), 'events after step 2 --------------')
for event in filtered_by_step_2:
    print(event.id, event.client_ip, event.start, event.recbytes, 'bytes')

#Step 3. Remove other elements form the list of filtered events
filtered_by_step_3 = []

for event in filtered_by_step_2:
    if event.recbytes is not None and int(event.recbytes) > 1497:
        filtered_by_step_3.append(event)

print()
print()
print('--------------', len(filtered_by_step_3), 'events after step 3 --------------')
for event in filtered_by_step_3:
    print(event.id, event.client_ip, event.start, event.recbytes, 'bytes')

#Step 4. Look for bursts in the list
bursts = handler.getBursts(filtered_by_step_3, False)
print()
print(len(bursts), 'bursts found')

#Step 5. Print bursts
for event in bursts:
    print('Burst at:',event.start, 'from', event.client_ip)