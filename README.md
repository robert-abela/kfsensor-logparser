kfsensor-logparser
==================

A small Python tool that parses a kfsensor XML format log, filters it and detects bursts.

Below is a small description of how this library can be used after it is imported:

Step 1. Parse a log file 

Step 2. Run a filter to keep only the events that match the given filter

Step 3. Remove other elements form the list of filtered events (optional)

Step 4. Look for bursts in the list (optional) 

Step 5. Print events

Step 1. Parse a log file
-------------------------
handler = logfilehandler.LogFileHandler('test1.log')

Step 2. Run a filter to keep only the events that match the given filter
-------------------------------------------------------------------------
logfilter = logfilehandler.LogFileEvent()
logfilter.name = 'ICMP Echo Request'
filtered_by_step_2 = handler.filterEvents(logfilter)

print('--------------', len(filtered_by_step_2), 'events after step 2 --------------')
for event in filtered_by_step_2:
    print(event.id, event.client_ip, event.start, event.recbytes, 'bytes')

Step 3. Remove other elements form the list of filtered events
---------------------------------------------------------------
filtered_by_step_3 = []

for event in filtered_by_step_2:
    if event.recbytes is not None and int(event.recbytes) > 1497:
        filtered_by_step_3.append(event)

print()
print()
print('--------------', len(filtered_by_step_3), 'events after step 3 --------------')
for event in filtered_by_step_3:
    print(event.id, event.client_ip, event.start, event.recbytes, 'bytes')

Step 4. Look for bursts in the list
------------------------------------
bursts = handler.getBursts(filtered_by_step_3, False)
print()
print(len(bursts), 'bursts found')

Step 5. Print bursts
---------------------
for event in bursts:
    print('Burst at:',event.start, 'from', event.client_ip)
