-- Modified from https://github.com/expressvpn/lightway/blob/main/lightway-core/wireshark/lightway.lua

-- Place in personal plugin directory:
---- /Users/<username>/.local/lib/wireshark/plugins/ (MacOS)
---- C:\Users\<username>\AppData\Roaming\Wireshark\plugins\ (Windows)

lightway_protocol        = Proto("Lightway-UDP", "Lightway Protocol")

identifier               = ProtoField.uint16("lightway.identifier", "identifier", base.HEX)
major_version            = ProtoField.uint8("lightway.major_version", "major_version", base.DEC)
minor_version            = ProtoField.uint8("lightway.minor_version", "minor_version", base.DEC)
aggressive_mode          = ProtoField.uint8("lightway.aggressive_mode", "aggressive_mode", base.DEC)
expresslane              = ProtoField.uint8("lightway.expresslane", "expresslane", base.DEC)
reserved                 = ProtoField.uint16("lightway.reserved", "reserved", base.HEX)
session_id               = ProtoField.uint64("lightway.session_id", "session_id", base.HEX)

lightway_protocol.fields = { identifier, major_version, minor_version, aggressive_mode, expresslane, reserved, session_id }

function lightway_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    local subtree = tree:add(lightway_protocol, buffer(), "Lightway Protocol Data")

    subtree:add(identifier, buffer(0, 2))
    subtree:add(major_version, buffer(2, 1))
    subtree:add(minor_version, buffer(3, 1))
    subtree:add(aggressive_mode, buffer(4, 1))
    subtree:add(expresslane, buffer(5, 1))
    subtree:add(reserved, buffer(6, 2))
    subtree:add(session_id, buffer(8, 8))

    local lw_offset = 16

    -- Call Chained DTLS Dissector
    local dtls_dissector = Dissector.get("dtls")

    local length = buffer:len() - lw_offset
    dtls_dissector(buffer:range(lw_offset, length):tvb(), pinfo, tree)

    pinfo.cols.protocol = lightway_protocol.name
end

local udp_port = DissectorTable.get("udp.port")

-- UDP port to associate lightway protocol
udp_port:add(40890, lightway_protocol)
