#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include "MinHook/MinHook.h"
#include "spdlog/spdlog.h"

namespace ChoomAudioGuards
{
    namespace NullGuard
    {
        using Fn = void(__fastcall*)(void*, void**, void*, void*);
        static Fn original = nullptr;
        static std::atomic<std::uint64_t> skipped{ 0 };

        static void __fastcall Hook(void* self, void** obj, void* arg, void* hash)
        {
            if (obj == nullptr)
            {
                const auto n = ++skipped;
                if (n <= 20)
                {
                    spdlog::warn(
                        "NULLGUARD FUN_140a0e300 skipped null object: caller=0x{:X} self=0x{:X} hash=0x{:X} count={}",
                        reinterpret_cast<std::uintptr_t>(_ReturnAddress()),
                        reinterpret_cast<std::uintptr_t>(self),
                        reinterpret_cast<std::uintptr_t>(hash),
                        n);
                }
                return;
            }
            original(self, obj, arg, hash);
        }

        static void Install()
        {
            const auto base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
            const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->FileHeader.TimeDateStamp != 0x6A4CB898u)
            {
                spdlog::info("NULLGUARD not installed: exe timestamp 0x{:08X} is not 1.0.15.4 (0x6A4CB898)", nt->FileHeader.TimeDateStamp);
                return;
            }
            // Fingerprint the crash site: 48 8B 03 | 8B D7 | 48 8B CB | FF 10
            const std::uint8_t expected[] = { 0x48, 0x8B, 0x03, 0x8B, 0xD7, 0x48, 0x8B, 0xCB, 0xFF, 0x10 };
            if (std::memcmp(base + 0xA0E38D, expected, sizeof(expected)) != 0)
            {
                spdlog::warn("NULLGUARD not installed: code at +0xA0E38D does not match the expected bytes");
                return;
            }
            void* target = base + 0xA0E300;
            if (MH_CreateHook(target, reinterpret_cast<void*>(&Hook), reinterpret_cast<void**>(&original)) != MH_OK || MH_EnableHook(target) != MH_OK)
            {
                spdlog::warn("NULLGUARD MinHook create/enable failed");
                return;
            }
            spdlog::info("NULLGUARD installed on FUN_140a0e300");
        }
    } // NullGuard

    // Skip the view update before it changes render state if obj+0x10 is null.
    // Otherwise FUN_141E1C4A0 receives an invalid context offset.
    namespace ViewGuard
    {
        using Fn = void(__fastcall*)(std::uintptr_t, std::uintptr_t, std::uintptr_t, std::uintptr_t);
        static Fn original = nullptr;
        static std::atomic<std::uint64_t> skipped{ 0 };

        // Keep SEH separate from objects requiring C++ unwinding.
        static std::uintptr_t ReadContext(std::uintptr_t obj)
        {
            __try
            {
                return obj ? *reinterpret_cast<const std::uintptr_t*>(obj + 0x10) : 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }
        }

        static void __fastcall Hook(std::uintptr_t obj, std::uintptr_t a2, std::uintptr_t a3, std::uintptr_t a4)
        {
            const std::uintptr_t context = ReadContext(obj);
            if (obj != 0 && context == 0)
            {
                const auto n = ++skipped;
                if (n <= 20)
                {
                    spdlog::warn("VIEWGUARD FUN_141E01FA0 skipped: obj=0x{:X} +0x10 is null (count={})", obj, n);
                    spdlog::default_logger()->flush();
                }
                return;
            }
            original(obj, a2, a3, a4);
        }

        static void Install()
        {
            const auto base = reinterpret_cast<std::uint8_t*>(GetModuleHandleW(nullptr));
            const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
            if (nt->FileHeader.TimeDateStamp != 0x6A4CB898u)
            {
                spdlog::info("VIEWGUARD not installed: exe is not 1.0.15.4");
                return;
            }
            // Check the call at +0x1E0201C targets FUN_141E1C4A0 or FUN_141A6D4E0.
            const std::uint8_t* call = base + 0x1E0201C;
            std::int32_t rel = 0;
            std::memcpy(&rel, call + 1, sizeof(rel));
            const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(call + 5) + rel;
            const std::uintptr_t want1 = reinterpret_cast<std::uintptr_t>(base) + 0x1E1C4A0;
            const std::uintptr_t want2 = reinterpret_cast<std::uintptr_t>(base) + 0x1A6D4E0;
            if (call[0] != 0xE8 || (target != want1 && target != want2))
            {
                spdlog::warn("VIEWGUARD not installed: call site at +0x1E0201C does not match (byte={:02X} target=0x{:X})", call[0], target);
                return;
            }
            void* fn = base + 0x1E01FA0;
            if (MH_CreateHook(fn, reinterpret_cast<void*>(&Hook), reinterpret_cast<void**>(&original)) != MH_OK || MH_EnableHook(fn) != MH_OK)
            {
                spdlog::warn("VIEWGUARD MinHook create/enable failed");
                return;
            }
            spdlog::info("VIEWGUARD installed on FUN_141E01FA0 (call target 0x{:X})", target);
        }
    } // ViewGuard

    void Install(bool nullGuard, bool viewGuard)
    {
        if (nullGuard)
            NullGuard::Install();
        if (viewGuard)
            ViewGuard::Install();
    }
}
