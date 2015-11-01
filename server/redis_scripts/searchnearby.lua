local geoset = KEYS[1]
local reqPayload = ARGV[1]

if not geoset then
    return 'No geoset specified'
end

if not reqPayload then
    return 'No json data'
end

local req = cjson.decode(reqPayload)

if not req.longitude then
    return 'No such longitude'
end

if not req.latitude then
    return 'No such latitude'
end

if not req.radius then
    return 'No such radius'
end

if req.radius <= 0 then
    return 'Search radius must be positive'
end

return redis.call('GEORADIUS', geoset, req.longitude, req.latitude, req.radius, 'm')
