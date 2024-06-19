-- Define the TCP port to be parsed
local tcp_port = 8000
-- Define a new protocol dissector
local my_proto = Proto("wfa_tlv", "WFA Control Agent TLV Protocol")

-- Define the fields with value_string for field1 and gi to handle enum-like behavior
local type_value_string = {
    [73] = "WFA_STA_SET_RFEATURE_TLV",
    [47] = "WFA_STA_DISCONNECT_TLV"
}

local gi_value_string = {
    [0] = "HE_GI_NONE",
    [1] = "HE_GI_0_8",
    [2] = "HE_GI_1_6",
    [3] = "HE_GI_3_2"
}

local f_field1 = ProtoField.uint16("wfa_tlv.field1", "Field 1 (Type Identifier)", base.DEC, type_value_string, 0xFFFF)
local f_field2 = ProtoField.uint16("wfa_tlv.field2", "Field 2 (Length)", base.DEC)
local f_intf_name = ProtoField.string("wfa_tlv.intf_name", "Interface Name")
local f_prog = ProtoField.string("wfa_tlv.prog", "Program")
local f_uapsd = ProtoField.uint32("wfa_tlv.uapsd", "UAPSD", base.DEC)
local f_peer = ProtoField.string("wfa_tlv.peer", "Peer")
local f_padding1 = ProtoField.bytes("wfa_tlv.padding1", "Padding 1")
local f_tpktimer = ProtoField.uint32("wfa_tlv.tpktimer", "TPK Timer", base.DEC)
local f_chswitchmode = ProtoField.string("wfa_tlv.chswitchmode", "Channel Switch Mode")
local f_offchnum = ProtoField.int32("wfa_tlv.offchnum", "Off Channel Number")
local f_secchoffset = ProtoField.string("wfa_tlv.secchoffset", "Secondary Channel Offset")
local f_gi = ProtoField.uint32("wfa_tlv.gi", "Guard Interval", base.DEC, gi_value_string, 0xFFFFFFFF)
local f_mbo_non_pref_chan_valid = ProtoField.bool("wfa_tlv.mbo_non_pref_chan_valid", "MBO Non-pref Chan Valid")
local f_padding2 = ProtoField.bytes("wfa_tlv.padding2", "Padding 2")
local f_clear = ProtoField.uint8("wfa_tlv.clear", "Clear", base.DEC)
local f_op_class = ProtoField.uint8("wfa_tlv.op_class", "Operating Class", base.DEC)
local f_channel = ProtoField.uint8("wfa_tlv.channel", "Channel", base.DEC)
local f_preference = ProtoField.uint8("wfa_tlv.preference", "Preference", base.DEC)
local f_reason = ProtoField.uint8("wfa_tlv.reason", "Reason", base.DEC)
local f_padding3 = ProtoField.bytes("wfa_tlv.padding3", "Padding 3")

-- Add fields to the protocol fields list
my_proto.fields = {f_field1, f_field2, f_intf_name, f_prog, f_uapsd, f_peer, f_padding1, f_tpktimer, f_chswitchmode, f_offchnum, f_secchoffset, f_gi, f_mbo_non_pref_chan_valid, f_padding2, f_clear, f_op_class, f_channel, f_preference, f_reason, f_padding3}

-- Parse WFA_STA_SET_RFEATURE_TLV
local function dissect_wfa_sta_set_rfeature(buffer, pinfo, tree, offset)
    local subtree = tree:add(my_proto, buffer(offset), "WFA STA SET RFEATURE TLV Data")

    -- Parse Interface Name (16 bytes)
    subtree:add(f_intf_name, buffer(offset, 16):stringz())
    offset = offset + 16

    -- Parse Program (8 bytes)
    subtree:add(f_prog, buffer(offset, 8):stringz())
    offset = offset + 8

    -- Parse UAPSD (4 bytes)
    subtree:add_le(f_uapsd, buffer(offset, 4))
    offset = offset + 4

    -- Parse Peer (18 bytes)
    subtree:add(f_peer, buffer(offset, 18):stringz())
    offset = offset + 18

    -- Skip 2 bytes padding
    subtree:add(f_padding1, buffer(offset, 2))
    offset = offset + 2

    -- Parse TPK Timer (4 bytes)
    subtree:add_le(f_tpktimer, buffer(offset, 4))
    offset = offset + 4

    -- Parse Channel Switch Mode (16 bytes)
    subtree:add(f_chswitchmode, buffer(offset, 16):stringz())
    offset = offset + 16

    -- Parse Off Channel Number (4 bytes)
    subtree:add_le(f_offchnum, buffer(offset, 4))
    offset = offset + 4

    -- Parse Secondary Channel Offset (16 bytes)
    subtree:add(f_secchoffset, buffer(offset, 16):stringz())
    offset = offset + 16

    -- Parse Guard Interval (4 bytes) using the enum-like value string
    subtree:add_packet_field(f_gi, buffer(offset, 4), ENC_LITTLE_ENDIAN)
    offset = offset + 4

    -- Parse MBO Non-pref Chan Valid (1 byte)
    subtree:add_le(f_mbo_non_pref_chan_valid, buffer(offset, 1))
    offset = offset + 1

    -- Skip 3 bytes padding
    subtree:add(f_padding2, buffer(offset, 3))
    offset = offset + 3

    -- Parse MBO Non-pref Chan
    subtree:add_le(f_clear, buffer(offset, 1))
    offset = offset + 1
    subtree:add_le(f_op_class, buffer(offset, 1))
    offset = offset + 1
    subtree:add_le(f_channel, buffer(offset, 1))
    offset = offset + 1
    subtree:add_le(f_preference, buffer(offset, 1))
    offset = offset + 1
    subtree:add_le(f_reason, buffer(offset, 1))
    offset = offset + 1

    -- Skip 3 bytes padding at the end
    subtree:add(f_padding3, buffer(offset, 3))
end

-- Placeholder for WFA_STA_DISCONNECT_TLV parser, add specific parsing logic as needed
local function dissect_wfa_sta_disconnect(buffer, pinfo, tree, offset)
    local subtree = tree:add(my_proto, buffer(offset), "WFA STA DISCONNECT TLV Data")
    -- Parse fields as needed, assuming the disconnect TLV contains only one simple field here
    -- subtree:add(f_some_field, buffer(offset, 2):le_uint())
    -- offset = offset + 2
end

-- Main TLV parser
function my_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = my_proto.name
    local subtree = tree:add(my_proto, buffer(), "WFA TLV Data")

    local offset = 0

    -- Check if there is enough data
    if buffer:len() < 116 then  -- A total of 116 bytes is needed
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough data for the required fields")
        return
    end

    -- Parse Field 1 (Type Identifier) using little-endian format
    local field1_value = buffer(offset, 2):le_uint() -- Read Field 1 in little-endian format
    subtree:add_packet_field(f_field1, buffer(offset, 2), ENC_LITTLE_ENDIAN)
    offset = offset + 2

    -- Parse Field 2 (Length) using little-endian format
    local field2_value = buffer(offset, 2):le_uint() -- Read Field 2 in little-endian format
    subtree:add_packet_field(f_field2, buffer(offset, 2), ENC_LITTLE_ENDIAN)
    offset = offset + 2

    -- Choose different parsing paths based on the value of Field 1
    if field1_value == 73 then  -- WFA_STA_SET_RFEATURE_TLV
        dissect_wfa_sta_set_rfeature(buffer, pinfo, subtree, offset)
    elseif field1_value == 47 then  -- WFA_STA_DISCONNECT_TLV
        dissect_wfa_sta_disconnect(buffer, pinfo, subtree, offset)
    else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Unknown TLV type")
    end
end

-- Register the dissector to the specific port
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(tcp_port, my_proto)
