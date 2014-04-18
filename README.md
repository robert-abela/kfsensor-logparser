kfsensor-logparser
==================

A small Python tool that parses a kfsensor XML format log, filters it and detects bursts. Below is a small description of how this library can be used after it is imported:

1. Parse a log file 
2. Run a filter to keep only the events that match the given filter
3. Remove other elements form the list of filtered events (optional)
4. Look for bursts in the list (optional) 
5. Print events

Refer to Readme Wiki page or sample_usage.py for a sample usage template.
