local userPayload = ARGV[1]

if not userPayload then
    return 'No json data'
end

local req = cjson.decode(userPayload)

if not req.towns then
    return 'No such key: towns'
end

local result = {}
for _, townid in pairs(req.towns) do
    result[#result + 1] = redis.call('GET', 'town:' .. tostring(townid))
end

return result
