codesysv3_protocol = Proto("codesysv3",  "CodeSys V3")

tcp_magic = ProtoField.uint32("codesysv3.tcp_header.magic", "TCP Magic", base.HEX)
tcp_length = ProtoField.uint32("codesysv3.tcp_header.length", "TCP Length", base.DEC)


magic = ProtoField.uint8("codesysv3.datagram.magic", "Magic", base.HEX)
hop_count = ProtoField.uint8("codesysv3.datagram.hop_info.hop_count", "Hop Count", base.DEC, nil,  0xF8)
header_length = ProtoField.uint8("codesysv3.datagram.hop_info.length", "Header Length", base.DEC, nil, 0x07)

priority = ProtoField.uint8("codesysv3.datagram.packet_info.priority", "Priority", base.DEC, {
    [0] = "Low",
    [1] = "Normal",
    [2] = "High",
    [3] = "Emergency",
}, 0xC0)
signal = ProtoField.uint8("codesysv3.datagram.packet_info.signal", "Signal", base.DEC, {[0] = "False", [1] = "True"}, 0x40)
type_address = ProtoField.uint8("codesysv3.datagram.packet_info.type_address", "Type Address", base.HEX, {
    [0] = "Full Address",
    [1] = "Relative Address"
}, 0x10)
length_data_block = ProtoField.uint8("codesysv3.datagram.packet_info.length_data_block", "Length Data Block", base.HEX, nil, 0x0F)

local datagram_layer_services = {
    [1] = "AddressNotification Request",
    [2] = "AddressNotification Response",
    [3] = "NS Server",
    [4] = "NS Client",
    [64] = "Channel Manager",
}

service_id = ProtoField.uint8("codesysv3.datagram.service_id", "Service ID", base.HEX, datagram_layer_services)
message_id = ProtoField.uint8("codesysv3.datagram.message_id", "Message ID", base.HEX)

receiver_length = ProtoField.uint8("codesysv3.datagram.lengths.receiver_length", "Receiver Length", base.DEC)
sender_length = ProtoField.uint8("codesysv3.datagram.lengths.sender_length", "Sender Length", base.DEC)


receiver_tcp_address = ProtoField.ipv4("codesysv3.datagram.receiver.tcp_address", "Receiver TCP Address")
receiver_tcp_port = ProtoField.uint16("codesysv3.datagram.receiver.tcp_port", "Receiver TCP Port", base.DEC)
sender_tcp_port = ProtoField.uint16("codesysv3.datagram.sender.tcp_port", "Sender TCP Port", base.DEC)
sender_tcp_address = ProtoField.ipv4("codesysv3.datagram.sender.tcp_address", "Sender TCP Address")


receiver_udp_address = ProtoField.string("codesysv3.datagram.receiver.udp_address", "Receiver UDP Address")
receiver_udp_port = ProtoField.uint16("codesysv3.datagram.receiver.udp_port", "Receiver UDP Port", base.DEC)
sender_udp_port = ProtoField.uint16("codesysv3.datagram.sender.udp_port", "Sender UDP Port", base.DEC)
sender_udp_address = ProtoField.string("codesysv3.datagram.sender.udp_address", "Sender UDP Address")

ns_server_subcmd = ProtoField.uint8("codesysv3.nsserver.subcmd", "subcmd", base.HEX, {
    [0xc201] = "Resolve Address Request",
    [0xc202] = "Resolve Name Request",
})
ns_server_version = ProtoField.uint8("codesysv3.nsserver.version", "Version", base.HEX)
ns_server_msg_id = ProtoField.uint8("codesysv3.nsserver.msg_id", "Message ID", base.HEX)
ns_server_msg_data = ProtoField.bytes("codesysv3.nsserver.msg_data", "Message Data")

ns_client_subcmd = ProtoField.uint8("codesysv3.nsserver.subcmd", "subcmd", base.HEX, {
    [0xc280] = "DeviceInfo",
})
ns_client_version = ProtoField.uint8("codesysv3.nsclient.version", "Version", base.HEX)
ns_client_msg_id = ProtoField.uint8("codesysv3.nsclient.msg_id", "Message ID", base.HEX)

ns_client_max_channels = ProtoField.uint16("codesysv3.nsclient.max_channels", "Max Channels", base.DEC)
ns_client_byte_order = ProtoField.uint8("codesysv3.nsclient.byte_order", "Byte Order", base.DEC,
{
    [0] = "Big Endianness",
    [1] = "Little Endianness"
})
ns_client_node_name_length = ProtoField.uint16("codesysv3.nsclient.node_name_length", "Node Name Length", base.DEC)
ns_client_device_name_length = ProtoField.uint16("codesysv3.nsclient.device_name_length", "Device Name Length", base.DEC)
ns_client_vendor_name_length = ProtoField.uint16("codesysv3.nsclient.vendor_name_length", "Vendor Name Length", base.DEC)
ns_client_serial_length = ProtoField.uint16("codesysv3.nsclient.serial_length", "Serial Length", base.DEC)
ns_client_target_type = ProtoField.uint32("codesysv3.nsclient.target_type", "Target Type", base.DEC)
ns_client_target_id = ProtoField.uint32("codesysv3.nsclient.target_id", "Target ID", base.DEC)
ns_client_target_version = ProtoField.string("codesysv3.nsclient.target_version", "Firmware Version")
ns_client_node_name = ProtoField.string("codesysv3.nsclient.node_name", "Node Name", base.UNICODE)
ns_client_device_name = ProtoField.string("codesysv3.nsclient.device_name", "Device Name", base.UNICODE)
ns_client_vendor_name = ProtoField.string("codesysv3.nsclient.vendor_name", "Vendor Name", base.UNICODE)
ns_client_serial = ProtoField.string("codesysv3.nsclient.plc_serial", "Serial")
padding = ProtoField.bytes("codesysv3.padding", "Padding")

local channel_layer_types = {
    [0x01] = "Application Block",
    [0x02] = "Application Ack",
    [0x03] = "Keep Alive",
    [0xc2] = "GetInfo",
    [0xc3] = "OpenChannel Request",
    [0xc4] = "CloseChannel",
    [0x83] = "OpenChannel Response",
}

channel_type = ProtoField.uint8("codesysv3.channel.type", "Type", base.HEX, channel_layer_types)
channel_flags = ProtoField.uint8("codesysv3.channel.flags", "Flags", base.HEX)
channel_version = ProtoField.uint16("codesysv3.channel.version", "Version", base.HEX)
channel_reason = ProtoField.uint16("codesysv3.channel.channel_reason", "Reason", base.HEX, {
    [0] = "OK"
})
channel_channel_id = ProtoField.uint16("codesysv3.channel.channel_id", "Channel ID", base.HEX)
channel_checksum = ProtoField.uint32("codesysv3.channel.checksum", "Checksum(CRC32)", base.HEX)
channel_msg_id = ProtoField.uint32("codesysv3.channel.msg_id", "Msg ID", base.HEX)
channel_max_channels = ProtoField.uint32("codesysv3.channel.max_channels", "Max Channels", base.DEC)
channel_receiver_buffer_size = ProtoField.uint32("codesysv3.channel.receiver_buf_size", "Receiver Buffer Size", base.HEX)

channel_blk_id = ProtoField.uint32("codesysv3.channel.blk_id", "BLK ID", base.HEX)
channel_ack_id = ProtoField.uint32("codesysv3.channel.ack_id", "ACK ID", base.HEX)
channel_remaining_data_size = ProtoField.uint32("codesysv3.channel.remain_data_size", "Remaining Data Size", base.DEC)
channel_flags_is_request = ProtoField.uint8("codesysv3.channel.flags.is_request", "Is Request", base.HEX, {[1] = "True", [0] = "False"}, 0x80)
channel_flags_is_first_payload = ProtoField.uint8("codesysv3.channel.flags.is_first_payload", "Is First Payload", base.HEX, {[1] = "True", [0] = "False"}, 0x01)


service_protocol_id = ProtoField.uint16("codesysv3.service.protocol_id", "Protocol ID", base.HEX, {
    [0xcd55] = "Normal",
    [0x7557] = "Secure"
})

local service_cmd_values = {
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
    [0x1b] = "CmpMonitor",
    [0x22] = "CmpOpenSSL",
    [0x06] = "CmpSettings",
    [0x0f] = "CmpTraceMgr",
    [0x0c] = "CmpUserMgr",
    [0x04] = "CmpVisuServer",
    [0x11] = "PlcShell",
    [0x07] = "SysEthernet",
    
}

service_header_size = ProtoField.uint16("codesysv3.service.header_size", "Header Size", base.DEC)
service_cmd_group = ProtoField.uint16("codesysv3.service.cmd_group", "Cmd Group", base.HEX, 
service_cmd_values , 0x7f)

local subcmd_device = {
    [1] = "Info",
    [2] = "Login",
    [3] = "Logout",
    [4] = "Reset Origin Device",
    [5] = "Echo",
    [6] = "Set Operating Mode",
    [7] = "Get Operating Mode",
    [8] = "Interactive Login",
    [9] = "Rename Node",
    [10] = "Session Create"
}

local subcmd_app = {
    [1] = "Login",
	[2] = "Logout",
    [3] = "Create Application",
	[4] = "Delete",
	[5] = "Download",
	[6] = "Online Change",
    [7] = "Device Download",
    [8] = "Create Dev App",
	[16] = "Start",
	[17] = "Stop",
    [18] = "Reset",
	[19] = "SetBreakPoint",
	[20] = "GetStatus",
    [21] = "Delete BP",
    [22] = "Read Call Stack",
    [23] = "Get Area Offset",
	[24] = "Application List",
    [25] = "Set Next Statement",
    [32] = "Release Force List",
    [33] = "Upload Force List",
    [34] = "Single Cycle",
    [35] = "Create Boot Project",
    [36] = "Reinit Application",
	[37] = "Application State List",
    [38] = "Load Boot App",
    [39] = "Register Boot Application",
    [40] = "Check FIle Consistency",
	[41] = "Read Application Info",
    [48] = "Download Compact",
    [49] = "Read Project Info",
    [50] = "Define Flow",
    [51] = "Read Flow Values",
    [52] = "Download Encrypted",
	[53] = "Read Application Content",
    [54] = "Save Retains",
    [55] = "Resotre Retains",
    [56] = "Get Area Address",
    [57] = "Leace Execpoints Active",
    [64] = "Claim  Execpoints for Application",

}

local subcmd_files = {
    [0x12] = "Rename Directory",
	[0x11] = "Delete Directory",
	[0x10] = "Create Directory",
	[0x0f] = "Rename File",
	[0x0e] = "Delete File",
	[0x01] = "FileExist",
	[0x03] = "Open File For Write",
	[0x02] = "Open File For Write",
	[0x04] = "File Write",
	[0x05] = "Open File For Read",
	[0x06] = "Open File For Read",
	[0x07] = "File Read",
	[0x08] = "File Close",
	[0x09] = "File Close",
	[0x0a] = "File Read",
	[0x0b] = "File Read",
	[0x0c] = "Files List",
	[0x0d] = "File Read",
}

local subcmd_certificates = {
    [0x01] = "Import",
	[0x02] = "Export",
	[0x03] = "Delete",
	[0x04] = "Move",
	[0x05] = "List",
	[0x06] = "ListUseCases",
	[0x07] = "CreateSelfSignedCertificate",
	[0x09] = "GetStatus",
}

local subcmd_log = {
    [0x01] = "GetEntries",
	[0x02] = "GetComponentNames",
	[0x03] = "LoggerList",
}

local subcmd_plc_shell = {
    [0x01] = "Execute"
}


local subcmd_monitor = {
    [1] = "Read",
    [2] = "Write"
}

service_is_response = ProtoField.uint16("codesysv3.service.is_response", "Is Response", base.HEX, {[1] = "True", [0] = "False"}, 0x80)
service_subcmd = ProtoField.uint16("codesysv3.service.subcmd", "subcmd", base.HEX)
service_session_id = ProtoField.uint32("codesysv3.service.session_id", "Session ID", base.HEX)
service_content_size = ProtoField.uint32("codesysv3.service.content_size", "Content Size", base.DEC)
service_additional_data = ProtoField.uint32("codesysv3.service.additional_data", "Additional Data", base.HEX)


tag_id = ProtoField.uint32("codesysv3.tags.id", "ID", base.HEX)
tag_type = ProtoField.uint16("codesysv3.tags.type", "Type", base.HEX, {[1] = "Parent", [0] = "Data"}, 0x80)
tag_size = ProtoField.uint32("codesysv3.tags.size", "Size", base.DEC)
tag_data = ProtoField.bytes("codesysv3.tags.data", "Data")


codesysv3_protocol.fields = {tcp_magic, tcp_length, magic, hop_count, header_length, priority, signal, type_address, length_data_block, 
service_id, message_id, receiver_length, sender_length, receiver_tcp_address, receiver_tcp_port, sender_tcp_address, sender_tcp_port,
ns_server_subcmd, ns_server_version, ns_server_msg_id, ns_server_msg_data,
ns_client_subcmd, ns_client_version, ns_client_msg_id,
ns_client_max_channels, ns_client_byte_order, ns_client_node_name_length, ns_client_device_name_length, ns_client_vendor_name_length,
ns_client_target_type, ns_client_target_id, ns_client_target_version, ns_client_node_name, ns_client_device_name, ns_client_vendor_name,
ns_client_serial_length, ns_client_serial, padding, channel_type, channel_flags, channel_version, channel_msg_id, channel_receiver_buffer_size, channel_checksum,
channel_channel_id, channel_reason, channel_max_channels, channel_blk_id, channel_ack_id, channel_remaining_data_size, channel_flags_is_request, channel_flags_is_first_payload
,service_protocol_id, service_additional_data, service_cmd_group, service_content_size, service_header_size, service_subcmd, service_session_id, service_is_response
, tag_id, tag_type, tag_size, tag_data, receiver_udp_address, sender_udp_address, receiver_udp_port, sender_udp_port
}
function codesysv3_protocol.init ()
    fragments = {}
end
local function has_enough_data(buffer, offset, n)
    return buffer:len() - offset >= n
end

local function dissect_tag_val(buffer, offset)
    local toffset = offset
    local val = 0
    local shift = 0
    local finish = false
    while not finish and has_enough_data(buffer, toffset, 1) do
        local b = buffer(toffset, 1):uint()      
        val = bit.bor(bit.lshift(bit.band(b, 0x7f), shift), val)
        toffset = toffset + 1
        shift = shift + 7
        if bit.band(b, 0x80) == 0 then
            finish = true
        end
    end
    return val, toffset - offset
end

local function dissect_tag_header(buffer, offset)
   local tag_id_val, tag_id_length = dissect_tag_val(buffer, offset)
   offset = offset + tag_id_length
   local tag_size_val, tag_size_length = dissect_tag_val(buffer, offset)
   return tag_id_val, tag_id_length, tag_size_val, tag_size_length
end
local  dissect_tags_layer
local function dissect_tag(buffer, offset, tree)
    if not has_enough_data(buffer, offset, 1) then
        return buffer:len()
    end
    local tag_id_val, tag_id_length, tag_size_val, tag_size_length = dissect_tag_header(buffer, offset)
    local is_parent = tag_id_val >= 0x80
    local tag_type_val = "Data"
    local header_size = tag_id_length + tag_size_length

    if is_parent then
        tag_type_val = "Parent"
    end
    
    if has_enough_data(buffer, offset + header_size, tag_size_val) then
       
        local subtree = tree:add(codesysv3_protocol, buffer(offset, header_size + tag_size_val), string.format("%s Tag ID(0x%04x)", tag_type_val, tag_id_val))
        subtree:add_le(tag_id, buffer(offset, tag_id_length), tag_id_val)
        subtree:add_le(tag_type, buffer(offset, 1))
        subtree:add_le(tag_size, buffer(offset + tag_id_length, tag_size_length), tag_size_val)
        offset = offset + header_size

        if tag_size_val > 0 then
                if is_parent then
                    return dissect_tags_layer(buffer, subtree, offset, tag_size_val)
                else
                    subtree:add_le(tag_data, buffer(offset, tag_size_val))
                    offset = offset + tag_size_val
                end
             
               
        end
    else
        offset = buffer:len()
    end
        
    return offset
end

local function add_str_to_field(strs, val, field, unknown_str)
    name = strs[val]
    if(name ~= nil) then
          -- Supported command
            field:append_text("[".. name .. "]")
      else
          -- Command unknownנ
          field:append_text(unknown_str)
      end
  end

function dissect_tags_layer(buffer, tree, offset, length)
    soffset = offset
    print("Tag")
    while length > 0 and has_enough_data(buffer, soffset, length)  do
        offset = dissect_tag(buffer, offset, tree)
        length = length - (offset - soffset)
        soffset = offset

    end
    
    return offset
end 

local function dissect_udp_ip(buffer, address, offset, format)
    local ip_address = ""
    local port = 0
    local ip_address_parts = {}
    for c in string.gmatch(address,  "%d+") do
        table.insert(ip_address_parts, c)
    end
    if format  then
        port = 1740 + buffer(offset, 1):uint()
        ip_address = string.format("%d.%d.%d.%d", ip_address_parts[1], ip_address_parts[2], ip_address_parts[3], buffer(offset + 1, 1):uint())
    else
        for i = 1, 4, 1 do
            local b = buffer(offset + i - 1, 1):uint()
            local c = b
            if b == 0 then
                c = ip_address_parts[i]
            end
            ip_address = ip_address .. c
            if i < 4 then
                ip_address = ip_address.."."
            end
        end
    end

    return ip_address, port

end

local function add_info(pinfo, values, exists_format, non_exists_format, val)
    if values[val] ~= nil then
        pinfo.cols['info']:append(string.format(exists_format, values[val], val))
    else
        pinfo.cols['info']:append(string.format(non_exists_format, val))
    end
end

local function dissect_codesys_service(buffer, pinfo, tree, offset)
    if has_enough_data(buffer, offset, 20) then
        local subtree = tree:add(codesysv3_protocol, buffer(offset), "Service Layer")
        subtree:add_le(service_protocol_id, buffer(offset , 2))
        subtree:add_le(service_header_size, buffer(offset + 2, 2))
        local header_size = buffer(offset + 2, 2):le_uint()
        subtree:add_le(service_cmd_group, buffer(offset + 4, 2))
        local cmd_group = bit.band(buffer(offset + 4, 2):le_uint(), 0x7f)
        
        add_info(pinfo, service_cmd_values, ", Service(CMP: %s(%d)", ", Service(CMP: %d", cmd_group)
        subtree:add_le(service_is_response, buffer(offset + 4, 2))
        subcmd_field = subtree:add_le(service_subcmd, buffer(offset + 6, 2))
        subcmd = buffer(offset + 6, 2):le_uint()
        subtree:add_le(service_session_id, buffer(offset + 8, 4))
        subtree:add_le(service_content_size, buffer(offset + 12, 4))
        local content_size = buffer(offset + 12, 4):le_uint()
        if header_size == 16 then
            subtree:add_le(service_additional_data, buffer(offset + 16, 4))
        end

        if header_size ==  16 or header_size == 12 then
            if cmd_group == 1 then
                add_str_to_field(subcmd_device, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_device, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            elseif  cmd_group == 0x8 then
                add_str_to_field(subcmd_files, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_files, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            elseif  cmd_group == 0x22 then
                add_str_to_field(subcmd_certificates, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_certificates, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            elseif  cmd_group == 5 then
                add_str_to_field(subcmd_log, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_log, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            elseif  cmd_group == 2 then
                add_str_to_field(subcmd_app, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_app, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            elseif  cmd_group == 0x1b then
                add_str_to_field(subcmd_monitor, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_monitor, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            elseif  cmd_group == 0x11 then
                add_str_to_field(subcmd_plc_shell, subcmd, subcmd_field, "[Unknown command]")
                add_info(pinfo, subcmd_plc_shell, ", cmd: %s(%d))", ", cmd: %d)", subcmd)
            end
            if bit.band(buffer(offset + 4, 2):le_uint(), 0x80) ~= 0 then
                pinfo.cols['info']:append(", Response")
            else
                pinfo.cols['info']:append(", Request")
            end

          
            local tagstree = tree:add(codesysv3_protocol, buffer(offset + header_size + 4), "Tags Layer")
             -- Add 4 to the offset(2 for the protocol id and 2 for the content length)
            return dissect_tags_layer(buffer, tagstree, offset + header_size + 4, content_size) 
        end
        
    end

    return buffer:len()

end

local function dissect_codesys_channel(buffer, pinfo, tree, offset)
    if has_enough_data(buffer, offset, 2) then
        local subtree = tree:add(codesysv3_protocol, buffer(offset), "Channel Layer")

        subtree:add(channel_type, buffer(offset, 1))
        type = buffer(offset, 1):uint()
        add_info(pinfo, channel_layer_types, ", Channel(%s(%d))", ", Channel(%d)", type)
        subtree:add(channel_flags, buffer(offset + 1, 1))
        offset = offset + 2
        if bit.band(type, 0x80) ~= 0 and has_enough_data(buffer, offset, 6) then
            subtree:add_le(channel_version, buffer(offset, 2))
            subtree:add_le(channel_checksum, buffer(offset + 2, 4))

            if has_enough_data(buffer, offset + 6, 8) and type == 0xc3 then
                subtree:add_le(channel_msg_id, buffer(offset + 6, 4))
                subtree:add_le(channel_receiver_buffer_size, buffer(offset + 10, 4))
            elseif has_enough_data(buffer, offset + 6, 12) and type == 0x83 then
                subtree:add_le(channel_msg_id, buffer(offset + 6, 4))
                subtree:add_le(channel_reason, buffer(offset + 10, 2))
                subtree:add_le(channel_channel_id, buffer(offset + 12, 2))  
                subtree:add_le(channel_receiver_buffer_size, buffer(offset + 14, 4))
                pinfo.cols['info']:append(string.format(", (Channel: 0x%04x)", buffer(offset + 12, 2):le_uint()))
            elseif has_enough_data(buffer, offset + 6, 4) and type == 0xc4 then
                subtree:add_le(channel_channel_id, buffer(offset + 6, 2))
                subtree:add_le(channel_reason, buffer(offset + 8, 2))
                pinfo.cols['info']:append(string.format(", (Channel: 0x%04x)", buffer(offset + 6, 2):le_uint()))
            elseif has_enough_data(buffer, offset + 6, 4) and type == 0xc2 then
                subtree:add_le(channel_max_channels, buffer(offset + 6, 2))
            end  
            
        elseif type == 1 and has_enough_data(buffer, offset + 6, 18) then
            subtree:add(channel_flags_is_request, buffer(offset - 1, 1))
            subtree:add(channel_flags_is_first_payload, buffer(offset - 1, 1))
            subtree:add_le(channel_channel_id, buffer(offset, 2))
            subtree:add_le(channel_blk_id, buffer(offset + 2, 4))
            subtree:add_le(channel_ack_id, buffer(offset + 6, 4))

            pinfo.cols['info']:append(string.format(", (Channel: 0x%04x, BLK ID:0x%08x, ACK ID: 0x%08x)", buffer(offset, 2):le_uint(), buffer(offset + 2, 4):le_uint(), buffer(offset + 6, 4):le_uint()))


            local is_first_packet = bit.band(buffer(offset - 1, 1):uint(), 0x01) ~= 0
            local next_layer_data = nil
            local segment_size = nil
            if is_first_packet then
                subtree:add_le(channel_remaining_data_size, buffer(offset + 10, 4))
                subtree:add_le(channel_checksum, buffer(offset + 14, 4))
                next_layer_data = offset + 18
                segment_size = buffer(offset + 10, 4):le_uint()
            else
                next_layer_data = offset + 10
                segment_size = buffer(offset + 10):len()
            end
            if is_first_packet and has_enough_data(buffer, offset + 18, segment_size) then
                return dissect_codesys_service(buffer, pinfo, tree, offset + 18)
            else
                local key = ("%s:%i:%s:%i:%i:%i"):format(pinfo.src, pinfo.src_port, pinfo.dst, pinfo.dst_port,buffer(offset, 2):le_uint(), buffer(offset + 6, 4):le_uint())
                local blk_id = buffer(offset + 2, 4):le_uint()
                if fragments[key] == nil then
                    fragments[key] = {["total_size"] = 0, ["segs"] = {}, ["blk_id"] = 0, ["collected_size"] = 0}
                end
                if is_first_packet then
                    fragments[key]["total_size"] = segment_size
                    fragments[key]["blk_id"] = blk_id
                end
                
                if fragments[key]["segs"][blk_id] == nil then
                    fragments[key]["segs"][blk_id] = buffer(next_layer_data):bytes()
                    fragments[key]["collected_size"] = fragments[key]["collected_size"] + buffer(next_layer_data):len()
                end
                if fragments[key]["collected_size"] == fragments[key]["total_size"] and fragments[key]["total_size"] >0 then
                    local complete_service_layer = ByteArray.new()
                    local count = 0
                    for i = fragments[key]["blk_id"], blk_id, 1 do
                        complete_service_layer = complete_service_layer..fragments[key]["segs"][i]
                        count = count + 1
                    end
                    if fragments[key]["total_size"] == complete_service_layer:len() then
                        local newtvb = ByteArray.tvb(complete_service_layer, "Defragmented Service Layer")
                        return dissect_codesys_service(newtvb, pinfo, tree, 0)
                    end 
                end
            end
        
            


        elseif type == 2 and has_enough_data(buffer, offset, 6)  then
            subtree:add_le(channel_channel_id, buffer(offset, 2))
            subtree:add_le(channel_blk_id, buffer(offset + 2, 4))
            pinfo.cols['info']:append(string.format(", (Channel: 0x%04x, BLK ID:0x%08x)", buffer(offset, 2):le_uint(), buffer(offset + 2, 4):le_uint()))
        elseif type == 3 and has_enough_data(buffer, offset, 2)  then
            subtree:add_le(channel_channel_id, buffer(offset, 2))
            pinfo.cols['info']:append(string.format(", (Channel: 0x%04x)", buffer(offset, 2):le_uint()))
        end
    end
    
    return buffer:len()
end 


local function dissect_codesys_nsserver(buffer, pinfo, tree, offset)
    if has_enough_data(buffer, offset, 8) then
        local subtree = tree:add(codesysv3_protocol, buffer(offset), "NS Server")
        subtree:add_le(ns_server_subcmd, buffer(offset, 2))
        subtree:add_le(ns_server_version, buffer(offset + 2, 2))
        subtree:add_le(ns_server_msg_id, buffer(offset + 4, 4))
        if has_enough_data(buffer, offset + 8, 1) then
            subtree:add(ns_server_msg_data, buffer(offset + 8))
        end
    end

    return buffer:len()
end 

local function dissect_codesys_nsclient(buffer, pinfo, tree, offset)
    if has_enough_data(buffer, offset, 8) then
        local subtree = tree:add(codesysv3_protocol, buffer(offset), "NS Client")
        subtree:add_le(ns_client_subcmd, buffer(offset, 2))
        subtree:add_le(ns_client_version, buffer(offset + 2, 2))
        subtree:add_le(ns_client_msg_id, buffer(offset + 4, 4))
        local version = buffer(offset + 2, 2):le_uint()
        offset = offset +  8
        if has_enough_data(buffer, offset + 8, 24) and (version == 0x103 or version == 0x400) then
            subtree:add_le(ns_client_max_channels, buffer(offset, 2)) 
            subtree:add_le(ns_client_byte_order, buffer(offset + 2, 1)) 
            local node_name_offset = buffer(offset + 4, 2):uint()
            subtree:add_le(ns_client_node_name_length, buffer(offset + 6, 2)) 
            local node_name_length = buffer(offset + 6, 2):le_uint() * 2 + 2
            subtree:add_le(ns_client_device_name_length, buffer(offset + 8, 2)) 
            local device_name_length = buffer(offset + 8, 2):le_uint() * 2 + 2
            subtree:add_le(ns_client_vendor_name_length, buffer(offset + 10, 2)) 
            local vendor_name_length = buffer(offset + 10, 2):le_uint() * 2 + 2

            subtree:add_le(ns_client_target_type, buffer(offset + 12, 4)) 
            subtree:add_le(ns_client_target_id, buffer(offset + 16, 4)) 
            local firmware = string.format("V%d.%d.%d.%d", buffer(offset + 23, 1):uint(),
                                                        buffer(offset + 22, 1):uint(),
                                                        buffer(offset + 21, 1):uint(), 
                                                        buffer(offset + 20, 1):uint())

            subtree:add(ns_client_target_version, firmware) 
            subtree:add(ns_client_serial_length, buffer(offset + 28, 1)) 
            local serial_length = buffer(offset + 28, 1):le_uint()
            offset = offset + 40 + node_name_offset
            if has_enough_data(buffer, offset, node_name_length) then 
                subtree:add_le(ns_client_node_name, buffer(offset, node_name_length), buffer(offset, node_name_length):le_ustring())
            end
            offset = offset + node_name_length  
            if has_enough_data(buffer, offset, device_name_length) then 
                subtree:add_le(ns_client_device_name, buffer(offset, device_name_length), buffer(offset, device_name_length):le_ustring())
            end
            offset = offset + device_name_length  
            if has_enough_data(buffer, offset, vendor_name_length) then 
                subtree:add_le(ns_client_vendor_name, buffer(offset, vendor_name_length), buffer(offset, vendor_name_length):le_ustring())
            end
            offset = offset + vendor_name_length  
            if has_enough_data(buffer, offset, serial_length) then 
                subtree:add(ns_client_serial, buffer(offset, serial_length))
            end

        end
    end

    return buffer:len()
end 


local function dissect_codesys_pdu(buffer, pinfo, tree, offset, is_udp)
    
    
    if has_enough_data(buffer, offset, 6) then
        local lengths_byte = buffer(offset + 5, 1):uint()
        local address_length = bit.rshift(lengths_byte, 4) * 2 +  bit.band(lengths_byte, 0x0F) * 2
        local subtree = tree:add(codesysv3_protocol, buffer(offset, 6 + address_length), "Datagram Layer")


        subtree:add(magic, buffer(offset, 1))

        local hopsubtree = subtree:add(codesysv3_protocol, buffer(offset + 1, 1), string.format("Hop Info Byte(0x%x)", buffer(offset + 1, 1):uint()))
        hopsubtree:add(hop_count, buffer(offset + 1, 1))
        hopsubtree:add(header_length, buffer(offset + 1, 1))

        local packetinfosubtree = subtree:add(codesysv3_protocol, buffer(offset + 2, 1), string.format("Packet Info Byte(0x%x)", buffer(offset + 2, 1):uint()))
        packetinfosubtree:add(priority, buffer(offset + 2, 1))
        packetinfosubtree:add(signal, buffer(offset + 2, 1))
        packetinfosubtree:add(type_address, buffer(offset + 2, 1))
        packetinfosubtree:add(length_data_block, buffer(offset + 2, 1))

        subtree:add(service_id, buffer(offset + 3, 1))
        local service = buffer(offset + 3, 1):uint()
        subtree:add(message_id, buffer(offset + 4, 1))
        pinfo.cols['info']:clear()
        add_info(pinfo, datagram_layer_services, "Datagram(%s(%d))", "Datagram(%d)", service)
        local address_lengths = subtree:add(codesysv3_protocol, buffer(offset + 5, 1), string.format("Packet Info Byte(0x%x)", lengths_byte))
        address_lengths:add(sender_length, bit.rshift(lengths_byte, 4) * 2)
        address_lengths:add(receiver_length, bit.band(lengths_byte, 0x0F) * 2)
        local sender_len = bit.rshift(lengths_byte, 4) * 2
        local receiver_len = bit.band(lengths_byte, 0x0F) * 2
        local address_tree = subtree:add(codesysv3_protocol, buffer(offset + 6, address_length), "Network Addresses")
        if not is_udp then
           
            if receiver_len >= 5 and has_enough_data(buffer, offset + 6, receiver_len) then
                address_tree:add(receiver_tcp_port, buffer(offset + 6, 2))
                address_tree:add(receiver_tcp_address, buffer(offset + 8, 4))
            end

            if sender_len >= 5 and has_enough_data(buffer, offset + 6 + receiver_len, sender_len) then
                address_tree:add(sender_tcp_port, buffer(offset + 6 + receiver_len, 2))
                address_tree:add(sender_tcp_address, buffer(offset + 8 + receiver_len, 4))
            end

        else
            local short_format = (receiver_len < 4 and receiver_len > 0) or (sender_len < 4 and sender_len > 0)
            if receiver_len > 0 and has_enough_data(buffer, offset + 6, receiver_len) then
                local ip_address, port = dissect_udp_ip(buffer, tostring(pinfo.dst), offset + 6, short_format)
                if short_format then
                    address_tree:add(receiver_udp_address, buffer(offset + 7, 1), ip_address)
                    address_tree:add(receiver_udp_port, buffer(offset + 6, 1), port)
                else
                    address_tree:add(receiver_udp_address, buffer(offset + 6, 4), ip_address)
                end


            end
            if sender_len > 0 and has_enough_data(buffer, offset + 6 + receiver_len, sender_len) then
                
                local ip_address, port = dissect_udp_ip(buffer, tostring(pinfo.src), offset + 6 + receiver_len, short_format)
                if short_format then
                    address_tree:add(sender_udp_address, buffer(offset + receiver_len + 7, 1), ip_address)
                    address_tree:add(sender_udp_port, buffer(offset + 6 + receiver_len, 1), port)
                else
                    address_tree:add(sender_udp_address, buffer(offset + 6 + receiver_len, 4), ip_address)
                end
            end
        end

        offset = offset +  6 + address_length
        padding_len = math.fmod(offset, 4)
        if padding_len ~= 0 then
            subtree:add(padding, buffer(offset, padding_len))
            offset = offset + padding_len
        end
        if service == 3 then
            return dissect_codesys_nsserver(buffer, pinfo, tree, offset)
            
        elseif service == 4 then
            return dissect_codesys_nsclient(buffer, pinfo, tree, offset)
        
        elseif service == 64 then
            return dissect_codesys_channel(buffer, pinfo, tree, offset)
        end
        
    end
    return buffer:len() 
end

local function dissect_codesys_udp(buffer, pinfo, tree)
    pinfo.cols.protocol = codesysv3_protocol.name
  
    local subtree = tree:add(codesysv3_protocol, buffer(), "CodeSys V3 Protocol UDP")
 
    return dissect_codesys_pdu(buffer, pinfo, subtree, 0, true)
end

local function dissect_codesys_tcp(buffer, pinfo, tree)
    pinfo.cols.protocol = codesysv3_protocol.name
  
    local subtree = tree:add(codesysv3_protocol, buffer(), "CodeSys V3 Protocol TCP")
    local subtree_tcp = subtree:add(codesysv3_protocol, buffer(), "Block Driver Layer")
    if buffer:len() >= 8 then
        subtree_tcp:add(tcp_magic, buffer(0, 4))
        subtree_tcp:add_le(tcp_length, buffer(4, 4))
        return dissect_codesys_pdu(buffer, pinfo, subtree, 8, false)
    end
    return buffer:len()
end

local function get_codesysv3_length(tvbuf, pktinfo, offset)
    return tvbuf(4, 4):le_uint()
end 

function codesysv3_protocol.dissector(buffer, pinfo, tree)
    if buffer:len() >= 8 and buffer(0, 4):uint() == 0x000117e8  then
        dissect_tcp_pdus(buffer, tree, 8, get_codesysv3_length, dissect_codesys_tcp)
        return buffer:len()
    elseif buffer:len() >= 5 and buffer(0, 1):uint() == 0xc5  then 
        return dissect_codesys_udp(buffer, pinfo, tree)
    end

    return 0
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(11740, codesysv3_protocol)
tcp_port:add(11741, codesysv3_protocol)
tcp_port:add(11742, codesysv3_protocol)
tcp_port:add(11743, codesysv3_protocol)


local udp_port = DissectorTable.get("udp.port")
udp_port:add(1740, codesysv3_protocol)
udp_port:add(1741, codesysv3_protocol)
udp_port:add(1742, codesysv3_protocol)
udp_port:add(1743, codesysv3_protocol)