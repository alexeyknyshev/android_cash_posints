local login = ARGV[1]
local uuid_old = ARGV[2]
local uuid_new = ARGV[3]

if not login then 
    return 'No login'
end

if login == '' then
    return 'Empty login'
end

local sessionKey = 'user:' .. user.login .. ':session'

-- uuid_old is not valid => drop session
if not uuid_old then
    redis.call('DEL', sessionKey)
    return 'No uuid_old'
end

-- uuid_new is not valid => drop session
if not uuid_new then
    redis.call('DEL', sessionKey)
    return 'No uuid_new'
end

-- uuid is not valid => drop session
if uuid_old == '' then
    redis.call('DEL', sessionKey)
    return 'No uuid'
end

-- uuid is not valid => drop session
if uuid_new == '' then
    redis.call('DEL', sessionKey)
    return 'No uuid'
end

-- validate old session key
local sessionKeyVal = redis.call('GET', sessionKey)
if sessionKeyVal == nil then
    return 'User is not logged in'
end

if sessionKeyVal ~= uuid_old then
    return 'Session keys do not match'
end

-- after this timeout user will be automatically logged out
local UUID_TTL = redis.call('HGET', 'settings', 'uuid_ttl') or 250
redis.call('SETEX', sessionKey, UUID_TTL, uuid_new)

return ''
