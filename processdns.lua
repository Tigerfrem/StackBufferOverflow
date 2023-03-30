-- My script seems to work on my machine with suricata
-- It's able to detect the dns traffic based on my if else statement
-- However, I am not sure why ATHINA doesn't like it
-- See code below (I would appreciate any feedbacks)

function init (args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end


function log2(x) return math.log(x) / math.log(2) end

function getEntropy (X)
    local X_without_periods = X:gsub("%.+", "")
    local N, count, sum, i = X_without_periods:len(), {}, 0
    
    --[[if X:find("%sCNAME%s") then
        return 0
    end]]--

    for char = 1, N do
	i = X_without_periods:sub(char, char)
        if count[i] then
            count[i] = count[i] + 1
        else
            count[i] = 1
        end
    end
    for n_i, count_i in pairs(count) do
        sum = sum + count_i / N * log2(count_i / N)
    end
    return -sum
end

function getMaxEntropy(X)
    local X_no_periods = X:gsub("%.", "")
    sum = log2(#X_no_periods)
    return sum
end

function match (args)
    local payload = tostring(args["payload"])
    for word in string.gmatch(payload, "[*%w%.]+") do
	print(word)
        local entropy = getEntropy(word)
	local max_entropy = getMaxEntropy(word)
	local percent = entropy/max_entropy
        if entropy > 3 and percent >= 0.85 then
		return 1
        end
    end
    return 0
end


-- These were some test cases that worked well.


--print(getEntropy("example.com"))

--print(log2(10))

--print(getMaxEntropy("example.com"))
