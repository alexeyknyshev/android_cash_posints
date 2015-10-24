local userPayload = ARGV[1]

if not userPayload then
    return 'No json data'
end

local req = cjson.decode(userPayload)

if not req.banks then
    return 'No such key: banks'
end

local result = {}
for _, bankid in pairs(req.banks) do
    result[#result + 1] = redis.call('GET', 'bank:' .. tostring(bankid))
end

return result
