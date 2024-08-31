#!lua

include "conanutils.premake5.lua"

t_conandeps = {}
t_conandeps["debug_x86_64"] = {}
t_conandeps["debug_x86_64"]["spdlog"] = {}
t_conandeps["debug_x86_64"]["spdlog"]["includedirs"] = {"C:/Users/karan/.conan2/p/b/spdlocc2ebcb4e6623/p/include"}
t_conandeps["debug_x86_64"]["spdlog"]["libdirs"] = {"C:/Users/karan/.conan2/p/b/spdlocc2ebcb4e6623/p/lib"}
t_conandeps["debug_x86_64"]["spdlog"]["bindirs"] = {"C:/Users/karan/.conan2/p/b/spdlocc2ebcb4e6623/p/bin"}
t_conandeps["debug_x86_64"]["spdlog"]["libs"] = {"spdlogd"}
t_conandeps["debug_x86_64"]["spdlog"]["system_libs"] = {}
t_conandeps["debug_x86_64"]["spdlog"]["defines"] = {"SPDLOG_FMT_EXTERNAL", "SPDLOG_COMPILED_LIB"}
t_conandeps["debug_x86_64"]["spdlog"]["cxxflags"] = {}
t_conandeps["debug_x86_64"]["spdlog"]["cflags"] = {}
t_conandeps["debug_x86_64"]["spdlog"]["sharedlinkflags"] = {}
t_conandeps["debug_x86_64"]["spdlog"]["exelinkflags"] = {}
t_conandeps["debug_x86_64"]["spdlog"]["frameworks"] = {}

if conandeps == nil then conandeps = {} end
conan_premake_tmerge(conandeps, t_conandeps)
