----------------------------------------
-- script-name: codesys3.lua
-- CODESYS 3 over TCP and UDP, little endian
-- Place into /home/$USER/.local/lib/wireshark/plugins
-- On Windows, place into %APPDATA%\Wireshark\plugins
-- Ctrl+Shift+L to hot reload
-- Ref: https://wiki.wireshark.org/LuaAPI/
----------------------------------------

-- Tag-related functions
-- Decoders are adapted from https://www.tenable.com/security/research/tra-2020-04
function s_tag_decode_int(data, pos)
    local max = 0xffffffff
    local lshift = 0
    local dlen = string.len(data)

    local val = 0
    local t = 0
    while true do
        if (pos > dlen) then
            return nil
        end

        t = string.byte(string.sub(data, pos, pos))
        if (bit32.band(t, 0x7f) > max) then
            return nil
        end

        val = val + (bit32.lshift(bit32.band(t, 0x7f), lshift))
        pos = pos + 1
        lshift = lshift + 7
        max = bit32.rshift(max, 7)

        if (bit32.band(t, 0x80) == 0) then
            break
        end
    end
    return {val, pos}
end

function parse_tag_to_list(data, pos)
    -- Tag id
    local ret 
    ret = s_tag_decode_int(data, pos)
    if ret == nil then
        return nil
    end

    local id = ret[1]
    pos = ret[2]

    -- Tag length
    ret = s_tag_decode_int(data, pos)
    if ret == nil then
        return nil
    end 

    local size = ret[1]
    pos = ret[2]

    -- Tag  value
    local value = string.sub(data, pos, pos+size-1)

    -- [+] stop
    if (string.len(value) < size) then
        return nil
    end
    if (string.len(value) == 0) then
        return nil
    end

    pos = pos + size

    return {id, value, pos}
end

function byte_string_to_hex(input)
    local hexstr = "0123456789abcdef"
    local out_hex = ""
    for i = 1, #input do
        local num = string.byte(string.sub(input, i, i))
        local ms = bit32.rshift(num, 4)
        local ls = bit32.band(num, 0x0F)
        out_hex = out_hex .. string.sub(hexstr, ms + 1, ms + 1) .. string.sub(hexstr, ls + 1, ls + 1) .. " " 
    end
    return out_hex
end    

function decimalToHex(num)
    if num == 0 then
        return '0'
    end
    local neg = false
    if num < 0 then
        neg = true
        num = num * -1
    end
    local hexstr = "0123456789abcdef"
    local result = ""
    while num > 0 do
        local n = bit32.band(num, 0x0F)
        result = string.sub(hexstr, n + 1, n + 1) .. result
        num = bit32.rshift(num, 4)
    end
    result = "0x" .. result
    if neg then
        result = '-' .. result
    end
    return result
end

function repeat_str(s, n) 
    local out = ""
    if n == 0 then 
        return out
    end
    for i=1,n do 
        out = out .. s
    end
    return out
end    

function parse_tags_to_list(data)
    local dlen = string.len(data)
    local pos = 1
    local tags = {}
    while (pos <= dlen) do
        local ret = parse_tag_to_list(data, pos)
        if ret == nil then
            return nil
        end
        local id = ret[1]
        local value = ret[2]
        pos = ret[3]
        table.insert(tags, {id, value})
    end    
    return tags
end

function recursive(data, i, log)
    local res = parse_tags_to_list(data)
    if res == nil then
        log = log .. ' ' .. byte_string_to_hex(data)
        return log
    end
    for _, t in pairs(res) do
        local id = t[1]
        local value = t[2]
        local padding = repeat_str("----", i) 
        log = log .. "\n" .. padding .. "[" .. decimalToHex(id) .. "]"
        log = recursive(value, i+1, log)
    end
    return log
end

function recursive_tags(data, root_tag)
    local res = parse_tags_to_list(data)
    if res == nil then
        root_tag:add(byte_string_to_hex(data))
        return
    end
    for _, t in pairs(res) do
        local id = t[1]
        local value = t[2]
        local new_tag = root_tag:add("[" .. decimalToHex(id) .. "]")
        recursive_tags(value, new_tag)
    end
    return
end

function pretty_format_tag_tree(tagslist)
    return recursive(tagslist, 0, "")
end

function string.sfromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
-- End of tag-related functions

-- Protocol
local d = require('debug')
codesys = Proto("CODESYS_3", "CODESYS 3 Stack")

-- Fields
---- L2 Block Driver
bd_magic = ProtoField.bytes("codesys3.l2.magic", "bd_magic")
bd_length = ProtoField.uint16("codesys3.l2.length", "bd_length")

-- L3 (Datagram/Router)
d_magic = ProtoField.bytes("codesys3.l3.d_magic", "d_magic")
d_hops = ProtoField.uint16("codesys3.l3.d_hops", "d_hops")
d_packet_params = ProtoField.bytes("codesys3.l3.d_packet_params", "d_packet_params")
d_service_id = ProtoField.bytes("codesys3.l3.d_service_id", "d_service_id")
d_message_id = ProtoField.bytes("codesys3.l3.d_message_id", "d_message_id")
d_lengths = ProtoField.bytes("codesys3.l3.d_lengths", "d_lengths")
d_sender = ProtoField.bytes("codesys3.l3.d_sender", "d_sender")
d_receiver = ProtoField.bytes("codesys3.l3.d_receiver", "d_receiver")

-- L4 Channel
ch_command_id = ProtoField.bytes("codesys3.l4.ch_command_id", "ch_command_id")
chflags = ProtoField.bytes("codesys3.l4.chflags", "chflags")
chan_id = ProtoField.bytes("codesys3.l4.chan_id", "chan_id")
blk_num = ProtoField.uint16("codesys3.l4.blk_num", "blk_num")
ack_num = ProtoField.uint16("codesys3.l4.ack_num", "ack_num")
remaining_data_size = ProtoField.uint16("codesys3.l4.remaining_data_size", "remaining_data_size")
checksum = ProtoField.uint16("codesys3.l4.checksum", "checksum")
remaining_data = ProtoField.bytes("codesys3.l4.remaining_data", "remaining_data")


---- L7 Services
protocol_id = ProtoField.bytes("codesys3.l7.protocol_id", "protocol_id")
header_size = ProtoField.uint16("codesys3.l7.header_size", "header_size")
service_id = ProtoField.bytes("codesys3.l7.service_id", "service_id", base.DASH)
cmd_id = ProtoField.bytes("codesys3.l7.cmd_id", "cmd_id", base.DASH)
session_id = ProtoField.bytes("codesys3.l7.session_id", "session_id")
cmd_name = ProtoField.string("codesys3.l7.cmd_name", "cmd_name")
service_name = ProtoField.string("codesys3.l7.service_name", "service_name")


payload_size = ProtoField.uint16("codesys3.l7.payload_size", "payload_size")
additional_data = ProtoField.bytes("codesys3.l7.additional_data", "additional_data", base.SPACE)
payload_data = ProtoField.bytes("codesys3.l7.payload_data", "payload_data", base.SPACE)

codesys.fields = {
    bd_magic, bd_length, -- L2
    d_magic, d_hops, d_packet_params, d_service_id, d_message_id, d_lengths, d_sender, d_receiver, -- L3
    ch_command_id, chflags, chan_id, blk_num, ack_num, remaining_data_size, checksum, remaining_data,   -- L4
    protocol_id, header_size, service_id, cmd_id, cmd_name, service_name, session_id, payload_size, additional_data, payload_data -- L7
}

m_bd_length = 0

getL7CmdName = function(service_id, cmd_id)
    --CmpDevice
    if service_id == 0x01 then
        local commands = {
            [0x01] = "GetTargetIdent",
            [0x02] = "Login",
            [0x03] = "Logout",
            [0x0a] = "SessionCreate",
            [0x04] = "ResetOrigin",
            [0x05] = "EchoService",
            [0x06] = "SetOperatingMode",
            [0x07] = "GetOperatingMode",
            [0x08] = "InteractiveLogin",
            [0x09] = "RenameNode",
            [0x0b] = "ResetOriginGetConfig",
        }
        return commands[cmd_id] or 'Unknown'


    --CmpApp
elseif service_id == 0x02 then

    local commands = {
        [0x01] = "Login",
        [0x02] = "Logout",
        [0x03] = "CreateApp",
        [0x04] = "DeleteApp",
        [0x05] = "Download",
        [0x06] = "OnlineChange",
        [0x07] = "DeviceDownload",
        [0x08] = "CreateDevApp",
        [0x10] = "Start",
        [0x11] = "Stop",
        [0x12] = "Reset",
        [0x13] = "SetBP",
        [0x14] = "ReadStatus",
        [0x15] = "DeleteBP",
        [0x16] = "ReadCallStack",
        [0x17] = "GetAreaOffset",
        [0x18] = "ReadAppList",
        [0x19] = "SetNextStatement",
        [0x20] = "ReleaseForceList",
        [0x21] = "UploadForceList",
        [0x22] = "SingleCycle",
        [0x23] = "CreateBootProject",
        [0x24] = "ReInitApp",
        [0x25] = "ReadAppStateList",
        [0x26] = "LoadBootApp",
        [0x27] = "RegisterBootApp",
        [0x28] = "CheckFileConsistency",
        [0x29] = "ReadAppInfo",
        [0x30] = "DownloadCompact",
        [0x31] = "ReadProjectInfo",
        [0x32] = "DefineFlow",
        [0x33] = "ReadFlowValues",
        [0x34] = "DownloadEncrypted",
        [0x35] = "ReadAppContent",
        [0x36] = "SaveRetains",
        [0x37] = "RestoreRetains",
        [0x38] = "GetAreaAddress",
        [0x39] = "LeaveExecpointsActive",
        [0x40] = "ClaimExecpointsForApp",
    }
    return commands[cmd_id] or 'Unknown'

    --CmpIecVarAccess
elseif service_id == 0x09 then

    local commands = {
        [0x01] = "RegisterVarList",
        [0x02] = "UnRegisterVarList",
        [0x03] = "ReadVarList",
        [0x04] = "WriteVarList",
        [0x05] = "ReadVars",
        [0x06] = "WriteVars",
        [0x07] = "GetRootNodes",
        [0x08] = "GetChildrenNodes",
        [0x09] = "GetTypes",
        [0x0a] = "GetAddressInfo",
        [0x0b] = "RemoveVarsFromList",

    }

    return commands[cmd_id] or 'Unknown'


    --CmpLog
elseif service_id == 0x05 then

    local commands = {
        [0x01] = "GetEntries",
        [0x02] = "GetComponentNames",
        [0x03] = "GetLoggerList",
    }

    return commands[cmd_id] or 'Unknown'

    --CmpMonitor2
elseif service_id == 0x1b then

    local commands = {
        [0x01] = "Read",
        [0x02] = "Write",
    }

    return commands[cmd_id] or 'Unknown'

    --CmpFileTransfer
elseif service_id == 0x08 then

    local commands = {
        [0x01] = "GetFileInfo",
        [0x02] = "StartDownload",
        [0x03] = "RestartDownload",
        [0x04] = "Download",
        [0x05] = "StartUpload",
        [0x06] = "RestartUpload",
        [0x07] = "Upload",
        [0x08] = "End",
        [0x09] = "Cancel",
        [0x0a] = "SafeSignature",
        [0x0b] = "GetSafeSignature",
        [0x0c] = "GetDirInfo",
        [0x0d] = "CancelGetDirInfo",
        [0x0e] = "DeleteFile",
        [0x0f] = "RenameFile",
        [0x10] = "CreateDir",
        [0x11] = "DeleteDir",
        [0x12] = "RenameDir",
        [0x14] = "SyncFileTransfer",
    
    }

    return commands[cmd_id] or 'Unknown'

    --CmpTraceMgr
elseif service_id == 0x0f then

    local commands = {
        [0x01] = "PacketReadList",
        [0x02] = "PacketCreate",
        [0x03] = "PacketDelete",
        [0x04] = "PacketComplete",
        [0x05] = "PacketOpen",
        [0x06] = "PacketClose",
        [0x07] = "PacketRead",
        [0x08] = "PacketGetState",
        [0x09] = "PacketGetConfig",
        [0x0a] = "PacketStart",
        [0x0b] = "PacketStop",
        [0x0c] = "PacketRestart",
        [0x0d] = "RecordAdd",
        [0x0e] = "RecordRemove",
        [0x0f] = "RecordGetConfig",
        [0x10] = "RecordResetTrigger",
        [0x11] = "PacketStore",
        [0x12] = "PacketRestore",
        [0x13] = "GetConfigFromFile",

    }

    return commands[cmd_id] or 'Unknown'

else
    return 'Other'
end

end


processL7 = function(buf, pos, pos_end, subtree)
    print('L7 starts at ' .. tostring(pos) .. ' ends at ' .. pos_end)
    local layerlen = pos_end - pos

    -- L7 (Services)
    local subtree_l7 = subtree:add(codesys, buf(pos, layerlen), "Layer 7 (Services)")
    subtree_l7:add_le(protocol_id, buf(pos + 0, 2))
    subtree_l7:add_le(header_size, buf(pos + 2, 2))

    local services = {
        [0x18] = "CmpAlarmManager",
        [0x02] = "CmpApp",
        [0x12] = "CmpAppBP",
        [0x13] = "CmpAppForce",
        [0x1d] = "CmpCodeMeter",
        [0x1f] = "CmpCoreDump",
        [0x01] = "CmpDevice",
        [0x08] = "CmpFileTransfer",
        [0x09] = "CmpIecVarAccess",
        [0x0b] = "CmpIoMgr",
        [0x05] = "CmpLog",
        [0x03] = "CmpMonitor",
        [0x1b] = "CmpMonitor2",
        [0x22] = "CmpOpenSSL",
        [0x06] = "CmpSettings",
        [0x0f] = "CmpTraceMgr",
        [0x0c] = "CmpUserMgr",
        [0x04] = "CmpVisuServer",
        [0x11] = "PlcShell",
        [0x07] = "SysEthernet",
        [0x81] = "Response to CmpDevice", --00000001 -> 10000001 
        [0x82] = "Response to CmpApp",
        [0x83] = "Response to CmpMonitor",
        [0x85] = "Response to CmpLog",
        [0x88] = "Response to CmpFileTransfer",
        [0x8f] = "Response to CmpTraceMgr",
        [0x9b] = "Response to CmpMonitor2",
        [0x89] = "Response to  CmpIecVarAccess",
        [0x91] = "Response to PlcShell",
    }
    local m_service_name = ''
    local m_service_id = 0x0
    -- local m_service_id = buf(pos + 4, 2)
    m_service_id = buf(pos + 4, 2):le_uint()
    print("Service id: " .. m_service_id)
    if services[m_service_id] then
        m_service_name = services[m_service_id]
    else
        m_service_name = 'Other'
    end
    print("Service name: " .. m_service_name)

    subtree_l7:add_le(service_id, buf(pos + 4, 2)):append_text(" (" .. m_service_name .. ")")

    local m_cmd_name=''
    local m_cmd_id = buf(pos + 6, 2):le_uint()

    m_cmd_name = getL7CmdName(m_service_id, m_cmd_id)
    subtree_l7:add_le(cmd_id, buf(pos + 6, 2)):append_text(" (" .. m_cmd_name  .. ")")

    subtree_l7:add_le(service_name, buf(pos + 4, 2), m_service_name)
    subtree_l7:add_le(cmd_name, buf(pos + 6, 2), m_cmd_name)

    subtree_l7:add_le(session_id, buf(pos + 8, 4))
    subtree_l7:add_le(payload_size, buf(pos + 12, 4))
    subtree_l7:add_le(additional_data, buf(pos + 16, 4))
    local m_payload_size = buf(pos + 12, 4):le_uint()
    print('Payload size: ' .. m_payload_size)

    -- Fragmentation (currently not supported)
    --m_bd_length=511
    --if m_bd_length < 512 then

    subtree_l7:add_le(payload_data, buf(pos + 20))

    -- Parse service tags
    print('Tags:')
    hexstr_payload = buf:bytes(pos + 20):tohex()
    str_hexstr_payload=(hexstr_payload):sfromhex()
    print(pretty_format_tag_tree(str_hexstr_payload))


    -- Add tags subtree
    local subtree_tags = subtree:add(codesys, buf(pos + 20), "Service Tags")
    recursive_tags(str_hexstr_payload, subtree_tags)
    return
end

-- Called for every packet. buf is tvb
function codesys.dissector(buf, pinfo, tree)
    local status, err = pcall(function()
        pktlen = buf:reported_length_remaining()
        if pktlen == 0 then
            return
        end

    -- Set column and common subtree
    pinfo.cols.protocol = codesys.name
    local subtree = tree:add(codesys, buf(), "CODESYS V3")

    local first = tostring(buf(0, 1))
    print("\n=== Packet start: " .. first .. " len: " .. pktlen)


    -- Find 'c5' of L3 (Datagram/Router)
    local l3_start = nil
    local b
    for i = 0, pktlen - 2 do
        b = tostring(buf(i, 1))
        if b == 'c5' then
            l3_start = i
            break
        end
    end

    -- Find L7 (Services)
    local l7_start = nil
    local b
    for i = 0, pktlen - 2 do
        b = buf(i, 2):uint()
        if b == 0x55cd or b == 0x7557 then
            l7_start = i
            break
        end
    end

    -- Find L2 (Block Driver)
    local m_magic = tostring(buf(0, 4))
    if m_magic == '000117e8' then
        local subtree_l2 = subtree:add(codesys, buf(0, 8), "Layer 2 (Block Driver)")
        subtree_l2:add_le(bd_magic, buf(0, 4))
        m_bd_length=buf(4, 4):int()
        subtree_l2:add_le(bd_length, buf(4, 4))
    end

    -- Find L3 (Datagram/Router)
    l3_end = l3_start
    if l3_start then
        print('L3 starts at ' .. l3_start)
        local subtree_l3 = subtree:add(codesys, buf(l3_start, math.min(24, pktlen - l3_start)), "Layer 3 (Datagram/Router)")
        subtree_l3:add_le(d_magic, buf(l3_start, 1))
        subtree_l3:add_le(d_hops, buf(l3_start + 1, 1))
        subtree_l3:add_le(d_packet_params, buf(l3_start + 2, 1))
        m_d_service_id = buf(l3_start + 3, 1):le_uint()
        local d_service_name = ''
        if m_d_service_id == 0x40 then
            d_service_name = 'CmpChannelMgr - 0x40'
        elseif m_d_service_id == 0x01 or m_d_service_id == 0x02 then
            d_service_name = 'AddressService - 01 or 02'
        elseif m_d_service_id == 0x03 or m_d_service_id == 0x04 then
            d_service_name = 'NetworkService - 01 or 02'
        else
            d_service_name = 'Other'
        end
        subtree_l3:add_le(d_service_id, buf(l3_start + 3, 1)):append_text(" (" .. d_service_name .. ")")
        subtree_l3:add_le(d_message_id, buf(l3_start + 4, 1))

        local  m_d_lengths = buf:bytes(l3_start + 5, 1):tohex()
        subtree_l3:add_le(d_lengths, buf(l3_start + 5, 1))
        -- [port] d1 58 [ip] ac 10 59 81 [num 33667] 83 83
        if m_d_lengths == '43' then
            -- Sender 6, Receiver 8
            subtree_l3:add_le(d_sender, buf(l3_start + 6, 6)) --todo
            subtree_l3:add_le(d_receiver, buf(l3_start + 12, 8)) --todo
            l3_end = l3_start + 20
        elseif m_d_lengths == '34' then
            -- Sender 8, Receiver 6
            subtree_l3:add_le(d_sender, buf(l3_start + 6, 8)) --todo
            subtree_l3:add_le(d_receiver, buf(l3_start + 14, 6)) --todo
            l3_end = l3_start + 20
        end

    end

    -- Find L4 (Channel)
    local l4_start = nil
    if l3_start then

        if l7_start then
            endsearch = l7_start
        else
            endsearch = pktlen - 2
        end

        local b
        for i = l3_end, endsearch do
            b = tostring(buf(i, 1))
            if b == 'c2' or b == 'c3' or b == 'c4' or b == '01'or b == '02' or b == '03' or b == '04' then
                l4_start = i
                break
            end
        end
    end

    if l4_start then
        local l4_len = nil
        local subtree_l4 = nil
        print('L4 starts at ' .. l4_start)
        if l7_start then
            l4_len = l7_start - 8 - (l4_start - l3_start)
            subtree_l4 = subtree:add(codesys, buf(l4_start, l4_len), "Layer 4 (Channel)")
        else
            subtree_l4 = subtree:add(codesys, buf(l4_start), "Layer 4 (Channel)")
        end
        local m_ch_command_id = tostring(buf(l4_start, 1))
        local m_ch_command_name = ''
        if m_d_service_id == '40' and m_ch_command_id == 'c2' then
            m_ch_command_name = 'GET_INFO'
        elseif m_d_service_id == '40' and m_ch_command_id == 'c3' then
            m_ch_command_name = 'OPEN_CHANNEL'
        elseif m_d_service_id == '40' and m_ch_command_id == '83' then
            m_ch_command_name = 'Response to OPEN_CHANNEL'
        elseif m_d_service_id == '40' and m_ch_command_id == 'c4' then
            m_ch_command_name = 'CLOSE_CHANNEL'
        elseif m_d_service_id == '40' and m_ch_command_id == '01' then
            m_ch_command_name = 'BLK transmission'
        elseif m_d_service_id == '40' and m_ch_command_id == '02' then
            m_ch_command_name = 'ACK'   
        elseif m_d_service_id == '40' and m_ch_command_id == '03' then
            m_ch_command_name = 'Keepalive'
        else
            m_ch_command_name = 'Other'
        end

        -- Flags
        -- 0x01 = hex(0b00000001) = continue prev
        

        local m_ch_flags = tostring(buf(l4_start + 1, 1))

        if m_ch_flags == '00' then
             -- 0x00 = hex(0b00000000)
             m_ch_flags_desc = "Response, Remaining"
         elseif m_ch_flags == '01' then
             -- 0x01 = hex(0b00000001)
             m_ch_flags_desc = "Response, First"
         elseif m_ch_flags == '80' then
            -- 0x80 = hex(0b10000000) =
            m_ch_flags_desc = "Request, Remaining"
        elseif m_ch_flags == '81' then
             -- 0x81 = hex(0b10000001)
             m_ch_flags_desc = "Request, First"
         else
            m_ch_flags_desc = 'Other'
        end

        -- Check if BLK fragmented (cmd=01, flags = 00 or 80  
        if m_d_service_id == '40' and m_ch_command_id == '01' and (m_ch_flags == '00' or m_ch_flags == '80') then
            subtree_l4:add_le(ch_command_id, buf(l4_start, 1)):append_text(" (" .. m_ch_command_name .. ")")
            subtree_l4:add_le(chflags, buf(l4_start + 1, 1)):append_text(" (" .. m_ch_flags_desc .. ")")
            subtree_l4:add_le(chan_id, buf(l4_start + 2, 2))
            subtree_l4:add_le(blk_num, buf(l4_start + 4, 4))
            subtree_l4:add_le(ack_num, buf(l4_start + 8, 4))
            subtree_l4:add_le(remaining_data, buf(l4_start + 12))
        elseif m_d_service_id == '40' and m_ch_command_id == 'c1' or m_ch_command_id == 'c2' 
            or m_ch_command_id == 'c3' or m_ch_command_id =='c4' 
            or m_ch_command_id =='c5' then 
                subtree_l4:add_le(ch_command_id, buf(l4_start, 1)):append_text(" (" .. m_ch_command_name .. ")")
                subtree_l4:add_le(chflags, buf(l4_start + 1, 1)):append_text(" (" .. m_ch_flags_desc .. ")")
                subtree_l4:add_le(chan_id, buf(l4_start + 2, 2))
            elseif m_d_service_id == '40' and (m_ch_command_id == '02' or m_ch_command_id == '03' or m_ch_command_id == '04') then
               subtree_l4:add_le(ch_command_id, buf(l4_start, 1)):append_text(" (" .. m_ch_command_name .. ")")    
           elseif m_d_service_id == '01' or m_d_service_id == '02' or m_d_service_id == '03' or m_d_service_id == '04' then
             -- Adress/Network service
             subtree_l4:add_le(ch_command_id, buf(l4_start, 1)):append_text(" (" .. m_ch_command_name .. ")")
         else 
            subtree_l4:add_le(ch_command_id, buf(l4_start, 1)):append_text(" (" .. m_ch_command_name .. ")")
            subtree_l4:add_le(chflags, buf(l4_start + 1, 1)):append_text(" (" .. m_ch_flags_desc .. ")")
            subtree_l4:add_le(chan_id, buf(l4_start + 2, 2))
            subtree_l4:add_le(blk_num, buf(l4_start + 4, 4))
            subtree_l4:add_le(ack_num, buf(l4_start + 8, 4))
            subtree_l4:add_le(remaining_data_size, buf(l4_start + 12, 4))
            subtree_l4:add_le(checksum, buf(l4_start + 16, 4))
        end

-- remaining_data_size = ProtoField.uint16("codesys3.l4.remaining_data_size", "remaining_data_size")
-- checksum = ProtoField.uint16("codesys3.l4.checksum", "checksum")
-- remaining_data = ProtoField.uint16("codesys3.l4.remaining_data", "remaining_data")

end

    -- Finally, handle L7 data
    if l7_start then
        processL7(buf, l7_start, pktlen, subtree)
    end
    print("===\n")
end)

-- Handling dissecting errors
if not status then
    print('Failed to dissect this CODESYS3 packet:', err)
end
end

-- Register transports and ports
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1217, codesys)
tcp_port:add(11740, codesys)

local udp_port = DissectorTable.get("udp.port")
udp_port:add(1740, codesys)
udp_port:add(1741, codesys)
udp_port:add(1742, codesys)
udp_port:add(1743, codesys)