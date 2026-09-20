# Provenance and third-party notices

- Base: user-supplied `IHHook-v0_73-FOLDER-REPLACEMENT.zip`, audio bridge and guard
  implementations. IHHook's MIT notice is included as `LICENSE-IHHook.txt`.
  These existing notices do not assign a new license to user-authored additions.
- Loading pattern reviewed against
  https://github.com/Yazed0071/MGSV_HookSample at commit
  `82c6b95681c054d11a8882f0d1b596ee72d53dca`. This package uses its own bootstrap;
  it does not copy the sample's other features or Lua address bindings.
- MinHook: copied from the supplied project. Its BSD-style notices remain in
  `vendor/MinHook` source/header files, including the HDE disassembler notices.
- spdlog and its bundled fmt: copied from the supplied project. Copyright and
  license notices remain in the vendor files. The bundled fmt `format.h` has
  one compatibility change: use its existing portable pointer helpers instead
  of the MSVC-specific `stdext::checked_array_iterator` branch.
- `src/MGSV_HRIR_KU100.h`: unchanged derivative of Benjamin Bernschuetz / TH Koeln
  Neumann KU 100 HRIR data, CC BY-SA 3.0. Attribution and processing description
  remain in the header. License: https://creativecommons.org/licenses/by-sa/3.0/
- `src/MIT_KEMAR_HRIR_48K_128_360.h`: unchanged derivative of Gardner & Martin's
  MIT KEMAR normal-pinna measurements. Attribution remains in its header.
