SMPTE ST 2110-20 dissector
=========================

Wireshark dissector in Lua for SMPTE ST 2110-20 data in RTP

to use in Wireshark:

1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua

2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
   and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
   should list "ST2110-20.lua" 

3) In Wireshark Preferences, under "Protocols/ST2110-20", set dynamic payload type

4) Capture packets of ST 2110-20

5) "Decode As" those UDP packets as RTP

6) You will now see the ST 2110-20 Data dissection of the RTP payload
