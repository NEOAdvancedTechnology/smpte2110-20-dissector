-- Lua Dissector for ST 2110-20
-- Author: Thomas Edwards (thomas.edwards@fox.com)
--
-- to use in Wireshark:
-- 1) Ensure your Wireshark works with Lua plugins - "About Wireshark" should say it is compiled with Lua
-- 2) Install this dissector in the proper plugin directory - see "About Wireshark/Folders" to see Personal
--    and Global plugin directories.  After putting this dissector in the proper folder, "About Wireshark/Plugins"
--    should list "ST2110-20.lua" 
-- 3) In Wireshark Preferences, under "Protocols", set st2110-20 as dynamic payload type being used
-- 4) Capture packets of ST 2110-20
-- 5) "Decode As" those UDP packets as RTP
-- 6) You will now see the ST 2110-20 Data dissection of the RTP payload
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
--
------------------------------------------------------------------------------------------------  
do  
    local st2110-20 = Proto("st2110-20", "ST 2110-20")  
     
    local prefs = st2110-20.prefs  
    prefs.dyn_pt = Pref.uint("ST 2110-20 dynamic payload type", 0, "The value > 95")  
 
    local F = st2110-20.fields

    F.ESN = ProtoField.uint16("st2110-20.ExtendedSequenceNumber","Extended Sequence Number",base.HEX,nil)
    F.Length = ProtoField.uint16("st2110-20.Length","Length",base.DEC,nil)
    F.FID = ProtoField.bool("st2110-20.FID","Field Identification",8,{"Second field","First field"},0x80)
    F.LineNo = ProtoField.uint16("st2110-20.LineNo","Line Number",base.DEC,nil,0x7FFF)
    F.Cont = ProtoField.bool("st2110-20.Cont","Continuation",8,{"Yes","No"},0x80)
    F.Offset = ProtoField.uint16("st2110-20.Offset","Offset",base.DEC,nil,0x7FFF)
    F.Video_Data=ProtoField.bytes("st2110-20.Video_Data","Video Data")
 
    function st2110-20.dissector(tvb, pinfo, tree)
        local subtree = tree:add(st2110-20, tvb(),"ST 2110-20 Data")  
        subtree:add(F.ESN, tvb(0,2)) 
        local Offset=0
        local ScanLines=0
        local LineLength={}
        local ADataOffset={}
        local DataOffset=0
	local totalLength=0
        repeat
            ScanLines=ScanLines+1
            LineLength[ScanLines]=tvb(Offset+2,2):uint()
	    totalLength=totalLength+LineLength[ScanLines]
            ADataOffset[ScanLines]=DataOffset
            DataOffset=DataOffset+LineLength[ScanLines]
            local Cont=tvb(Offset+6,1):bitfield(0,1)
            Offset=Offset+6
        until Cont==0
        local HDRLen=Offset+2
        local i
	if totalLength % 180 = 0 then subtree:append_text("Sample Row Data Segments length sum multiple of 180 - GPM?") end
        Offset=0
        for i=1,ScanLines do
            subtree:add(F.Length, tvb(Offset+2,2))
            subtree:add(F.FID,tvb(Offset+4,1))
            subtree:add(F.LineNo,tvb(Offset+4,2))
            subtree:add(F.Cont,tvb(Offset+6,1))
            subtree:add(F.Offset,tvb(Offset+6,2))
            Offset=Offset+6
            subtree:add(F.Video_Data,tvb(HDRLen+ADataOffset[i],LineLength[i]))
        end
    end  
  
    -- register dissector to dynamic payload type dissectorTable  
    local dyn_payload_type_table = DissectorTable.get("rtp_dyn_payload_type")  
    dyn_payload_type_table:add("st2110-20", st2110-20)  
  
    -- register dissector to RTP payload type
    local payload_type_table = DissectorTable.get("rtp.pt")  
    local old_dissector = nil  
    local old_dyn_pt = 0  
    function st2110-20.init()  
        if (prefs.dyn_pt ~= old_dyn_pt) then
            if (old_dyn_pt > 0) then
                if (old_dissector == nil) then
                    payload_type_table:remove(old_dyn_pt, st2110-20)  
                else
                    payload_type_table:add(old_dyn_pt, old_dissector)  
                end  
            end  
            old_dyn_pt = prefs.dyn_pt
            old_dissector = payload_type_table:get_dissector(old_dyn_pt)  
            if (prefs.dyn_pt > 0) then  
                payload_type_table:add(prefs.dyn_pt, st2110-20)  
            end  
        end   
    end  
end
