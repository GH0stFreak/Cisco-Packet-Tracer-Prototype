#!lua

include "conanutils.premake5.lua"

t_conandeps = {}
t_conandeps["debug_x86_64"] = {}
t_conandeps["debug_x86_64"]["fmt"] = {}
t_conandeps["debug_x86_64"]["fmt"]["includedirs"] = {"C:/Users/karan/.conan2/p/b/fmt97a8ce6146394/p/include"}
t_conandeps["debug_x86_64"]["fmt"]["libdirs"] = {"C:/Users/karan/.conan2/p/b/fmt97a8ce6146394/p/lib"}
t_conandeps["debug_x86_64"]["fmt"]["bindirs"] = {"C:/Users/karan/.conan2/p/b/fmt97a8ce6146394/p/bin"}
t_conandeps["debug_x86_64"]["fmt"]["libs"] = {"fmtd"}
t_conandeps["debug_x86_64"]["fmt"]["system_libs"] = {}
t_conandeps["debug_x86_64"]["fmt"]["defines"] = {}
t_conandeps["debug_x86_64"]["fmt"]["cxxflags"] = {}
t_conandeps["debug_x86_64"]["fmt"]["cflags"] = {}
t_conandeps["debug_x86_64"]["fmt"]["sharedlinkflags"] = {}
t_conandeps["debug_x86_64"]["fmt"]["exelinkflags"] = {}
t_conandeps["debug_x86_64"]["fmt"]["frameworks"] = {}

if conandeps == nil then conandeps = {} end
conan_premake_tmerge(conandeps, t_conandeps)
