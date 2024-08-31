#!lua

include "conanutils.premake5.lua"

t_conandeps = {}
t_conandeps["release_x86_64"] = {}
t_conandeps["release_x86_64"]["spdlog"] = {}
t_conandeps["release_x86_64"]["spdlog"]["includedirs"] = {"C:/Users/karan/.conan2/p/spdloa736e9ace9ccd/p/include"}
t_conandeps["release_x86_64"]["spdlog"]["libdirs"] = {"C:/Users/karan/.conan2/p/spdloa736e9ace9ccd/p/lib"}
t_conandeps["release_x86_64"]["spdlog"]["bindirs"] = {"C:/Users/karan/.conan2/p/spdloa736e9ace9ccd/p/bin"}
t_conandeps["release_x86_64"]["spdlog"]["libs"] = {"spdlog"}
t_conandeps["release_x86_64"]["spdlog"]["system_libs"] = {}
t_conandeps["release_x86_64"]["spdlog"]["defines"] = {"SPDLOG_FMT_EXTERNAL", "SPDLOG_COMPILED_LIB"}
t_conandeps["release_x86_64"]["spdlog"]["cxxflags"] = {}
t_conandeps["release_x86_64"]["spdlog"]["cflags"] = {}
t_conandeps["release_x86_64"]["spdlog"]["sharedlinkflags"] = {}
t_conandeps["release_x86_64"]["spdlog"]["exelinkflags"] = {}
t_conandeps["release_x86_64"]["spdlog"]["frameworks"] = {}

if conandeps == nil then conandeps = {} end
conan_premake_tmerge(conandeps, t_conandeps)
