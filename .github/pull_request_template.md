## Değişiklik Özeti
- Bu PR'ın çözdüğü sorunu veya eklediği özelliği açıklayın.

## Mimari Kontrol Listesi
- [ ] Public başlıklarda (`include/tessera/**`) `<Windows.h>` sızıntısı yok (`tessera_header_self_containment` geçti).
- [ ] Katman izolasyonu (`L0 -> L0.5 -> L1 -> L2 -> L3`) korundu (`tessera_test_standalone_consumers` geçti).
- [ ] `x64-debug`, `x64-release`, `x86-debug` ve `x86-release` preset'lerinde tüm testler geçti.
- [ ] Yeni özellikler için birim testleri eklendi.
