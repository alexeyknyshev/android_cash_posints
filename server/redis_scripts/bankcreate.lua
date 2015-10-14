local bankPayload = ARGV[1]

if not bankPayload then
    return 'No json data'
end

local bank = cjson.decode(bankPayload)

if not bank.name then
    return 'No such bank.name'
end

if not bank.name_tr then
    return 'No such bank.name_tr'
end

if string.len(bank.name) == 0 then
    return 'Empty bank.name'
end

if string.len(bank.name_tr) == 0 then
    return 'Empty bank.name_tr'
end

if redis.call('HEXISTS', 'bank_ids', bank.name_tr) == 1 then
    return 'Bank is already exists: ' .. bank.name_tr
end

local bankId = redis.call('INCR', 'bank_next_id')
redis.call('HMSET', 'bank_ids', bank.name, bankId)
redis.call('SET', 'bank:' .. bankId, bankPayload)

return ""
