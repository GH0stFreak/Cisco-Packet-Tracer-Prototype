#!lua

function conan_premake_tmerge(dst, src)
    for k, v in pairs(src) do
        if type(v) == "table" then
            if type(conandeps[k] or 0) == "table" then
                conan_premake_tmerge(dst[k] or {}, src[k] or {})
            else
                dst[k] = v
            end
        else
            dst[k] = v
        end
    end
    return dst
end
