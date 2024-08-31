#!lua
include "conan_spdlog.premake5.lua"
include "conan_fmt.premake5.lua"

function conan_setup_build(conf, pkg)
    if conf == nil then
        filter { "configurations:debug", "architecture:x86_64" }
            conan_setup_build("debug_x86_64")
        filter {}
        filter { "configurations:release", "architecture:x86_64" }
            conan_setup_build("release_x86_64")
        filter {}
    elseif pkg == nil then
        for k,v in pairs(conandeps[conf]) do
            conan_setup_build(conf, k)
        end
    else

        includedirs(conandeps[conf][pkg]["includedirs"])
        bindirs(conandeps[conf][pkg]["bindirs"])
        defines(conandeps[conf][pkg]["defines"])

    end
end


function conan_setup_link(conf, pkg)
    if conf == nil then
        filter { "configurations:debug", "architecture:x86_64" }
            conan_setup_link("debug_x86_64")
        filter {}
        filter { "configurations:release", "architecture:x86_64" }
            conan_setup_link("release_x86_64")
        filter {}
    elseif pkg == nil then
        for k,v in pairs(conandeps[conf]) do
            conan_setup_link(conf, k)
        end
    else

        libdirs(conandeps[conf][pkg]["libdirs"])
        links(conandeps[conf][pkg]["libs"])
        links(conandeps[conf][pkg]["system_libs"])
        links(conandeps[conf][pkg]["frameworks"])

    end
end


function conan_setup(conf, pkg)
    conan_setup_build(conf, pkg)
    conan_setup_link(conf, pkg)
end
