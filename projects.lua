BOOK_CODE_PATH = "E:/book-code"
THIRD_PARTY = "E:/book-code/3rdparty"
WORK_PATH = os.getcwd()
includeexternal (BOOK_CODE_PATH .. "/premake-vs-include.lua")


workspace "CryptoAPI-examples"
    language "C++"
    location "build/%{_ACTION}/%{wks.name}"    
    if _ACTION == "vs2015" then
        toolset "v140_xp"
    elseif _ACTION == "vs2013" then
        toolset "v120_xp"
    end

    
    group "gtest"


        project "gtest"            
            removeconfigurations "TRACE*"   
            kind "StaticLib"     
            defines { "GTEST_HAS_PTHREAD=0", "_HAS_EXCEPTIONS=1" }            
            files
            {
            
                "%{THIRD_PARTY}/googletest/googletest/src/gtest-all.cc"
                     
                               
            }             
            includedirs
            {
               
                "%{THIRD_PARTY}/googletest/googletest/include",
                "%{THIRD_PARTY}/googletest/googletest"
            }
            
        
    

        project "gtest_main"     
            removeconfigurations "TRACE*"   
            kind "StaticLib"     
            defines { "GTEST_HAS_PTHREAD=0", "_HAS_EXCEPTIONS=1" }            
            files
            {
            
                "%{THIRD_PARTY}/googletest/googletest/src/gtest-all.cc",
                "%{THIRD_PARTY}/googletest/googletest/src/gtest_main.cc"
                  
                               
            }             
            includedirs
            {
               
                "%{THIRD_PARTY}/googletest/googletest/include",
                "%{THIRD_PARTY}/googletest/googletest"
            }
            
        
            
    
   

        project "gmock"         
            removeconfigurations "TRACE*"   
            kind "StaticLib"     
            defines { "GTEST_HAS_PTHREAD=0", "_HAS_EXCEPTIONS=1" }            
            files
            {
            
                "%{THIRD_PARTY}/googletest/googletest/src/gtest-all.cc",
                "%{THIRD_PARTY}/googletest/googlemock/src/gmock-all.cc"      
                               
            }             
            includedirs
            {
               
                "%{THIRD_PARTY}/googletest/googletest/include",
                "%{THIRD_PARTY}/googletest/googletest",
                "%{THIRD_PARTY}/googletest/googlemock/include",
                "%{THIRD_PARTY}/googletest/googlemock"

            }
            
        
    
    

        project "gmock_main"   
            removeconfigurations "TRACE*"   
            kind "StaticLib"     
            defines { "GTEST_HAS_PTHREAD=0", "_HAS_EXCEPTIONS=1" }            
            files
            {
            
                
                "%{THIRD_PARTY}/googletest/googletest/src/gtest-all.cc",
                "%{THIRD_PARTY}/googletest/googlemock/src/gmock-all.cc",
                "%{THIRD_PARTY}/googletest/googlemock/src/gmock_main.cc"
                               
            }             
            includedirs
            {       
               
                "%{THIRD_PARTY}/googletest/googletest/include",
                "%{THIRD_PARTY}/googletest/googletest",
                "%{THIRD_PARTY}/googletest/googlemock/include",
                "%{THIRD_PARTY}/googletest/googlemock"

            }

    group "glog"
        project "glog"            
            removeconfigurations "TRACE*"   
            kind "StaticLib"
            defines { "GOOGLE_GLOG_DLL_DECL=", "HAVE_SNPRINTF" }
            files
            {
                "%{THIRD_PARTY}/glog-master/src/logging.cc",
                "%{THIRD_PARTY}/glog-master/src/windows/port.cc",
                "%{THIRD_PARTY}/glog-master/src/raw_logging.cc",
                "%{THIRD_PARTY}/glog-master/src/utilities.cc",
                "%{THIRD_PARTY}/glog-master/src/vlog_is_on.cc",
                ------------------------------------------------------------------------------------------------------------
                "%{THIRD_PARTY}/glog-master/src/base/commandlineflags.h",
                "%{THIRD_PARTY}/glog-master/src/windows/config.h",
                "%{THIRD_PARTY}/glog-master/src/base/googleinit.h",
                "%{THIRD_PARTY}/glog-master/src/windows/glog/log_severity.h",
                "%{THIRD_PARTY}/glog-master/src/windows/glog/logging.h",
                "%{THIRD_PARTY}/glog-master/src/base/mutex.h",
                "%{THIRD_PARTY}/glog-master/src/windows/port.h",
                "%{THIRD_PARTY}/glog-master/src/windows/glog/raw_logging.h",
                "%{THIRD_PARTY}/glog-master/src/windows/glog/stl_logging.h",
                "%{THIRD_PARTY}/glog-master/src/utilities.h",
                "%{THIRD_PARTY}/glog-master/src/windows/glog/vlog_is_on.h"
            }
            vpaths 
            { 
                ["Header Files"] = {"**.h", "**.hpp"},
                ["Source Files"] = {"**.c", "**.cpp"}
            }
            includedirs
            {
                "%{THIRD_PARTY}/glog-master/src/windows",
                            
            }

    group "gflags"
        project "gflags"      
            removeconfigurations "TRACE*"   
            kind "StaticLib"
            characterset "MBCS"
            defines { "GFLAGS_IS_A_DLL=0" }
            files
            {
                "%{THIRD_PARTY}/gflags-master/src/**.cc",
                "%{THIRD_PARTY}/gflags-master/src/**.h",
                "%{THIRD_PARTY}/gflags-master/bin/include/gflags/**.h",
            }
            vpaths 
            { 
                ["Header Files"] = {"**.h", "**.hpp"},
                ["Source Files"] = {"**.c", "**.cpp", "**.cc"}
            }
            includedirs
            {
                "%{THIRD_PARTY}/gflags-master/bin/include/gflags",
                "%{THIRD_PARTY}/gflags-master/bin/include",
                            
            }

        project "gflags_nothreads"        
            removeconfigurations "TRACE*"   
            kind "StaticLib"
            characterset "MBCS"
            defines { "GFLAGS_IS_A_DLL=0", "NO_THREADS" }
            files
            {
                "%{THIRD_PARTY}/gflags-master/src/**.cc",
                "%{THIRD_PARTY}/gflags-master/src/**.h",
                "%{THIRD_PARTY}/gflags-master/bin/include/gflags/**.h",
            }
            vpaths 
            { 
                ["Header Files"] = {"**.h", "**.hpp"},
                ["Source Files"] = {"**.c", "**.cpp", "**.cc"}
            }
            includedirs
            {
                "%{THIRD_PARTY}/gflags-master/bin/include/gflags",
                "%{THIRD_PARTY}/gflags-master/bin/include",
                            
            }

    group "tcmalloc"
        project "libtcmalloc_minimal"     
            removeconfigurations "TRACE*"   
            kind "SharedLib"
            characterset "MBCS"
            defines { "LIBTCMALLOC_MINIMAL_EXPORTS" }
            files
            {
                "%{THIRD_PARTY}/gperftools-master/src/central_freelist.cc",
                "%{THIRD_PARTY}/gperftools-master/src/base/dynamic_annotations.c",
                "%{THIRD_PARTY}/gperftools-master/src/heap-profile-table.cc",
                "%{THIRD_PARTY}/gperftools-master/src/symbolize.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/ia32_modrm_map.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/ia32_opcode_map.cc",
                "%{THIRD_PARTY}/gperftools-master/src/common.cc",
                "%{THIRD_PARTY}/gperftools-master/src/internal_logging.cc",
                "%{THIRD_PARTY}/gperftools-master/src/base/logging.cc",
                "%{THIRD_PARTY}/gperftools-master/src/base/low_level_alloc.cc",
                "%{THIRD_PARTY}/gperftools-master/src/malloc_extension.cc",
                "%{THIRD_PARTY}/gperftools-master/src/malloc_hook.cc",
                "%{THIRD_PARTY}/gperftools-master/src/memory_region_map.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/mini_disassembler.cc",
                "%{THIRD_PARTY}/gperftools-master/src/page_heap.cc",
                "%{THIRD_PARTY}/gperftools-master/src/sampler.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/patch_functions.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/port.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/preamble_patcher.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/preamble_patcher_with_stub.cc",
                "%{THIRD_PARTY}/gperftools-master/src/windows/system-alloc.cc",
                "%{THIRD_PARTY}/gperftools-master/src/raw_printer.cc",
                "%{THIRD_PARTY}/gperftools-master/src/span.cc",
                "%{THIRD_PARTY}/gperftools-master/src/stacktrace.cc",
                "%{THIRD_PARTY}/gperftools-master/src/stack_trace_table.cc",
                "%{THIRD_PARTY}/gperftools-master/src/static_vars.cc",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock.cc",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock_internal.cc",
                "%{THIRD_PARTY}/gperftools-master/src/base/sysinfo.cc",
                "%{THIRD_PARTY}/gperftools-master/src/thread_cache.cc",
                "%{THIRD_PARTY}/gperftools-master/src/fake_stacktrace_scope.cc",
                ------------------------------------------------------------------------------------------------------------
                "%{THIRD_PARTY}/gperftools-master/src/addressmap-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/basictypes.h",
                "%{THIRD_PARTY}/gperftools-master/src/central_freelist.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/commandlineflags.h",
                "%{THIRD_PARTY}/gperftools-master/src/windows/config.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/googleinit.h",
                "%{THIRD_PARTY}/gperftools-master/src/gperftools/heap-checker.h",
                "%{THIRD_PARTY}/gperftools-master/src/heap-profile-table.h",
                "%{THIRD_PARTY}/gperftools-master/src/symbolize.h",
                "%{THIRD_PARTY}/gperftools-master/src/gperftools/heap-profiler.h",
                "%{THIRD_PARTY}/gperftools-master/src/common.h",
                "%{THIRD_PARTY}/gperftools-master/src/internal_logging.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/linked_list.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/logging.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/low_level_alloc.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops-internals-arm-gcc.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops-internals-linuxppc.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops-internals-macosx.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops-internals-x86-msvc.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops-internals-x86.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock_internal.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock_linux-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock_posix-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/spinlock_win32-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/gperftools/malloc_extension.h",
                "%{THIRD_PARTY}/gperftools-master/src/gperftools/malloc_hook.h",
                "%{THIRD_PARTY}/gperftools-master/src/malloc_hook-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/atomicops-internals-x86-msvc.h",
                "%{THIRD_PARTY}/gperftools-master/src/memory_region_map.h",
                "%{THIRD_PARTY}/gperftools-master/src/windows/mini_disassembler.h",
                "%{THIRD_PARTY}/gperftools-master/src/windows/mini_disassembler_types.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/mutex.h",
                "%{THIRD_PARTY}/gperftools-master/src/packed-cache-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/page_heap.h",
                "%{THIRD_PARTY}/gperftools-master/src/page_heap_allocator.h",
                "%{THIRD_PARTY}/gperftools-master/src/pagemap.h",
                "%{THIRD_PARTY}/gperftools-master/src/windows/port.h",
                "%{THIRD_PARTY}/gperftools-master/src/windows/preamble_patcher.h",
                "%{THIRD_PARTY}/gperftools-master/src/gperftools/profiler.h",
                "%{THIRD_PARTY}/gperftools-master/src/raw_printer.h",
                "%{THIRD_PARTY}/gperftools-master/src/sampler.h",
                "%{THIRD_PARTY}/gperftools-master/src/span.h",
                "%{THIRD_PARTY}/gperftools-master/src/gperftools/stacktrace.h",
                "%{THIRD_PARTY}/gperftools-master/src/stacktrace_config.h",
                "%{THIRD_PARTY}/gperftools-master/src/stacktrace_win32-inl.h",
                "%{THIRD_PARTY}/gperftools-master/src/stack_trace_table.h",
                "%{THIRD_PARTY}/gperftools-master/src/static_vars.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/stl_allocator.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/sysinfo.h",
                "%{THIRD_PARTY}/gperftools-master/src/system-alloc.h",
                "%{THIRD_PARTY}/gperftools-master/src/tcmalloc.h",
                "%{THIRD_PARTY}/gperftools-master/src/base/thread_annotations.h",
                "%{THIRD_PARTY}/gperftools-master/src/thread_cache.h",
            }
            vpaths 
            { 
                ["Header Files"] = {"**.h", "**.hpp"},
                ["Source Files"] = {"**.c", "**.cpp", "**.cc"}
            }
            includedirs
            {
                "%{THIRD_PARTY}/gperftools-master/src",
                "%{THIRD_PARTY}/gperftools-master/src/windows"
                            
            }

--    function include_win32_common()
--        files { 
--            "api/win32_common.h",
--            "api/win32_common.cpp"
--        }
--        filter "files:api/win32_common.cpp"
--            flags { "NoPCH" }    
--    end

    

    group "test"       
        

        create_console_project("wincrypt-api-test", "src")
            includedirs
            {
                "%{THIRD_PARTY}/googletest/googletest/include",
                "%{THIRD_PARTY}/googletest/googletest",
                "%{THIRD_PARTY}/googletest/googlemock/include",
                "%{THIRD_PARTY}/googletest/googlemock"
            }
            links
            {
                "gtest",
                "crypt32.lib",
                "winhttp.lib"
            }

        create_console_project("CreateSignature", "src")
            includedirs
            {
                "src/CryptoApi"
            }
            links
            {
                
                "crypt32.lib",
                
            }
           
        create_console_project("CryptoApiTest", "src")
            includedirs
            {
                "src/CryptoApi",
                "%{THIRD_PARTY}/googletest/googletest/include",
                "%{THIRD_PARTY}/googletest/googletest",
                "%{THIRD_PARTY}/googletest/googlemock/include",
                "%{THIRD_PARTY}/googletest/googlemock"
            }
            links
            {
                "gtest",
                "crypt32.lib",                
            }


        create_console_project("test-base64", "src")
        create_console_charset_project("rsa_tool", "src", "mbcs")
        create_console_charset_project("base64", "src", "mbcs")
        create_console_charset_project("rsa_key_encode", "src", "mbcs")
        create_console_charset_project("rsa_key_decode", "src", "mbcs")

        create_console_charset_project("dsa_gen", "src", "mbcs")
        create_console_charset_project("rsa_gen", "src", "mbcs")
        
        create_console_project("rsacert", "src")
            links
            {
                
                "crypt32.lib",                
            }
        create_console_project("rsakey", "src")
        create_console_project("sessionkey", "src")

        create_console_project("signhash", "src")
            links
            {
                
                "crypt32.lib",                
            }

        create_console_charset_project("rsa-sign-file", "src", "mbcs")
            includedirs
            {
                
                "%{THIRD_PARTY}/gflags-master/bin/include",
                            
            }
            links
            {
                "gflags",
                "shlwapi.lib",
                "crypt32.lib",     
            }

        create_console_project("test-atl-crypt", "src")
            includedirs
            {
                
                "%{THIRD_PARTY}/gflags-master/bin/include",
                "C:/WinDDK/7600.16385.1/inc/atl71"            
            }
            links
            {
                "gflags",
                "shlwapi.lib",
                "crypt32.lib",                
            }

        create_console_project("rc4", "src")
            links
            {
                
                "crypt32.lib",                
            }     

        create_console_project("hash_sha512", "src")
            links
            {
                
                "crypt32.lib",                
            }   
            
        create_console_project("rsa2048", "src")
            links
            {
                
                "crypt32.lib",                
            }  
            
        create_console_project("aes256", "src")
            links
            {
                
                "crypt32.lib",                
            }  
            