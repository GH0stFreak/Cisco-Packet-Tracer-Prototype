#!lua

include "conanutils.premake5.lua"

t_conandeps = {}
t_conandeps["release_x86_64"] = {}
t_conandeps["release_x86_64"]["fmt"] = {}
t_conandeps["release_x86_64"]["fmt"]["includedirs"] = {"C:/Users/karan/.conan2/p/fmta98cbeb106603/p/include"}
t_conandeps["release_x86_64"]["fmt"]["libdirs"] = {"C:/Users/karan/.conan2/p/fmta98cbeb106603/p/lib"}
t_conandeps["release_x86_64"]["fmt"]["bindirs"] = {"C:/Users/karan/.conan2/p/fmta98cbeb106603/p/bin"}
t_conandeps["release_x86_64"]["fmt"]["libs"] = {"fmt"}
t_conandeps["release_x86_64"]["fmt"]["system_libs"] = {}
t_conandeps["release_x86_64"]["fmt"]["defines"] = {}
t_conandeps["release_x86_64"]["fmt"]["cxxflags"] = {}
t_conandeps["release_x86_64"]["fmt"]["cflags"] = {}
t_conandeps["release_x86_64"]["fmt"]["sharedlinkflags"] = {}
t_conandeps["release_x86_64"]["fmt"]["exelinkflags"] = {}
t_conandeps["release_x86_64"]["fmt"]["frameworks"] = {}

if conandeps == nil then conandeps = {} end
conan_premake_tmerge(conandeps, t_conandeps)
