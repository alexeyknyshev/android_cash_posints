local userPayload = ARGV[1]

if not userPayload then
    return 'No json data'
end

local user = cjson.decode(userPayload)

if not user.login then
    return 'No such key: login'
end

if not user.password then
    return 'No such key: password'
end

local loginLen = string.len(user.login)
local USER_LOGIN_MIN_LEN = tonumber(redis.call('HGET', 'settings', 'user_login_min_length')) or 4
if loginLen < USER_LOGIN_MIN_LEN then
    return 'User login must be ' .. tostring(USER_LOGIN_MIN_LEN) .. ' characters at least'
end

local passwordLen = string.len(user.password)
local USER_PASSWORD_MIN_LEN = tonumber(redis.call('HGET', 'settings', 'user_password_min_length')) or 4
if passwordLen < USER_PASSWORD_MIN_LEN then
    return 'User password must be ' .. tostring(USER_PASSWORD_MIN_LEN) .. ' characters at least'
end

-- check login is alpha numeric
local s, e = string.find(user.login, "[_%a][_%w]*")
if not s or s > 1 then
    return 'User login contains invalid character at: ' .. tostring(1)
end

if e ~= loginLen then
    return 'User login contains invalid character at: ' .. tostring(e + 1)
end

-- check password is alpha numeric
s, e = string.find(user.password, "[_%w]+")
if not s or s > 1 then
    return 'User password contains invalid character at: ' .. tostring(1)
end

if e ~= passwordLen then
    return 'User password contains invalid character at: ' .. tostring(e + 1)
end

-- check user already exists
if redis.call('EXISTS', 'user:' .. user.login) == 1 then
  return 'User with already exists: ' .. user.login
end

-- save user data
redis.call('SET', 'user:' .. user.login, userPayload)

return ''
