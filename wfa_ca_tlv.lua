-- 创建一个新的Dissector
local tcp_port = 8000
local my_proto = Proto("wfa_tlv", "WFA Control Agent TLV Protocol")

-- 定义字段
local f_field1 = ProtoField.uint16("wfa_tlv.field1", "Field 1", base.DEC)
local f_field2 = ProtoField.uint16("wfa_tlv.field2", "Field 2", base.DEC)
local f_intf_name = ProtoField.string("wfa_tlv.intf_name", "Interface Name")
local f_prog = ProtoField.string("wfa_tlv.prog", "Program")
local f_uapsd = ProtoField.uint32("wfa_tlv.uapsd", "UAPSD", base.DEC)
local f_peer = ProtoField.string("wfa_tlv.peer", "Peer")
local f_padding1 = ProtoField.bytes("wfa_tlv.padding1", "Padding 1")
local f_tpktimer = ProtoField.uint32("wfa_tlv.tpktimer", "TPK Timer", base.DEC)
local f_chswitchmode = ProtoField.string("wfa_tlv.chswitchmode", "Channel Switch Mode")
local f_offchnum = ProtoField.int32("wfa_tlv.offchnum", "Off Channel Number")
local f_secchoffset = ProtoField.string("wfa_tlv.secchoffset", "Secondary Channel Offset")
local f_gi = ProtoField.string("wfa_tlv.gi", "Guard Interval")
local f_mbo_non_pref_chan_valid = ProtoField.bool("wfa_tlv.mbo_non_pref_chan_valid", "MBO Non-pref Chan Valid")
local f_padding2 = ProtoField.bytes("wfa_tlv.padding2", "Padding 2")
local f_clear = ProtoField.uint8("wfa_tlv.clear", "Clear", base.DEC)
local f_op_class = ProtoField.uint8("wfa_tlv.op_class", "Operating Class", base.DEC)
local f_channel = ProtoField.uint8("wfa_tlv.channel", "Channel", base.DEC)
local f_preference = ProtoField.uint8("wfa_tlv.preference", "Preference", base.DEC)
local f_reason = ProtoField.uint8("wfa_tlv.reason", "Reason", base.DEC)
local f_padding3 = ProtoField.bytes("wfa_tlv.padding3", "Padding 3")

my_proto.fields = {f_field1, f_field2, f_intf_name, f_prog, f_uapsd, f_peer, f_padding1, f_tpktimer, f_chswitchmode, f_offchnum, f_secchoffset, f_gi, f_mbo_non_pref_chan_valid, f_padding2, f_clear, f_op_class, f_channel, f_preference, f_reason, f_padding3}

-- GI值映射
local gi_map = {
    [0] = "HE_GI_NONE",
    [1] = "HE_GI_0_8",
    [2] = "HE_GI_1_6",
    [3] = "HE_GI_3_2"
}

-- WFA_STA_SET_RFEATURE_TLV解析器
local function dissect_wfa_sta_set_rfeature(buffer, pinfo, tree, offset)
    local subtree = tree:add(my_proto, buffer(offset), "WFA STA SET RFEATURE TLV Data")

    -- 解析interface name（16字节）
    subtree:add(f_intf_name, buffer(offset, 16):stringz())
    offset = offset + 16

    -- 解析prog（8字节）
    subtree:add(f_prog, buffer(offset, 8):stringz())
    offset = offset + 8

    -- 解析uapsd（4字节）
    subtree:add_le(f_uapsd, buffer(offset, 4))
    offset = offset + 4

    -- 解析peer（18字节）
    subtree:add(f_peer, buffer(offset, 18):stringz())
    offset = offset + 18

    -- 跳过2字节填充
    subtree:add(f_padding1, buffer(offset, 2))
    offset = offset + 2

    -- 解析tpktimer（4字节）
    subtree:add_le(f_tpktimer, buffer(offset, 4))
    offset = offset + 4

    -- 解析chswitchmode（16字节）
    subtree:add(f_chswitchmode, buffer(offset, 16):stringz())
    offset = offset + 16

    -- 解析offchnum（4字节）
    subtree:add_le(f_offchnum, buffer(offset, 4))
    offset = offset + 4

    -- 解析secchoffset（16字节）
    subtree:add(f_secchoffset, buffer(offset, 16):stringz())
    offset = offset + 16

    -- 解析gi（4字节）
    local gi_value = buffer(offset, 4):le_uint()
    local gi_string = gi_map[gi_value] or "UNKNOWN"
    subtree:add(f_gi, buffer(offset, 4)):append_text(" (" .. gi_string .. ")")
    offset = offset + 4

    -- 解析mbo_non_pref_chan_valid（1字节）
    subtree:add_le(f_mbo_non_pref_chan_valid, buffer(offset, 1))
    offset = offset + 1

    -- 跳过3字节填充
    subtree:add(f_padding2, buffer(offset, 3))
    offset = offset + 3

    -- 解析mbo_non_pref_chan
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

    -- 跳过末尾3字节填充
    subtree:add(f_padding3, buffer(offset, 3))
end

-- WFA_STA_DISCONNECT_TLV解析器（占位，具体解析逻辑可以根据需求添加）
local function dissect_wfa_sta_disconnect(buffer, pinfo, tree, offset)
    local subtree = tree:add(my_proto, buffer(offset), "WFA STA DISCONNECT TLV Data")
    -- 根据需求解析字段
    -- 这里假设disconnect TLV只包含一个简单的字段
    -- subtree:add(f_some_field, buffer(offset, 2):le_uint())
    -- offset = offset + 2
end

-- TLV解析器
function my_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = my_proto.name
    local subtree = tree:add(my_proto, buffer(), "WFA TLV Data")

    local offset = 0

    -- 检查是否有足够的数据
    if buffer:len() < 116 then  -- 总共需要116字节
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Not enough data for the required fields")
        return
    end

    -- 解析field1
    local field1 = buffer(offset, 2):le_uint()
    subtree:add_le(f_field1, buffer(offset, 2))
    offset = offset + 2

    -- 解析field2
    subtree:add_le(f_field2, buffer(offset, 2))
    offset = offset + 2

    -- 根据field1的值选择不同的解析路径
    if field1 == 73 then  -- WFA_STA_SET_RFEATURE_TLV
        dissect_wfa_sta_set_rfeature(buffer, pinfo, subtree, offset)
    elseif field1 == 47 then  -- WFA_STA_DISCONNECT_TLV
        dissect_wfa_sta_disconnect(buffer, pinfo, subtree, offset)
    else
        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "Unknown TLV type")
    end
end

-- 注册到特定端口
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(tcp_port, my_proto)

