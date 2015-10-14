local reqPayload = ARGV[1]

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

if not req.radius > 0 then
    return 'Search radius must be positive'
end

return redis.call('GEORADIUS', 'cashpoints', req.longitude, req.latitude, req.radius, 'm')
