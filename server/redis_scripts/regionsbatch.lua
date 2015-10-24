local result = {}
local regionIds = redis.call('ZRANGE', 'regions', 0, -1)
for _, regionId in pairs(regionIds) do
    result[#result + 1] = redis.call('GET', 'region:' .. tostring(regionId))
end
return result
