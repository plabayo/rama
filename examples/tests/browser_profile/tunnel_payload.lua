-- Decode complete WebSocket streams in Python. Native dissection of frames
-- split over TLS records or H2/H3 DATA can abort the enclosing TLS follow tap.
local tunnel = Proto("rama_ws_tunnel", "WebSocket tunnel payload (independently verified)")
local payload = ProtoField.bytes("rama_ws_tunnel.data", "Tunnel bytes")
tunnel.fields = {payload}
function tunnel.dissector(buffer, info, tree)
    tree:add(tunnel, buffer()):add(payload, buffer())
end
local upgrades = DissectorTable.get("http.upgrade")
upgrades:remove("websocket", Dissector.get("websocket"))
upgrades:add("websocket", tunnel)
