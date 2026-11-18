// Static MSVC-ABI RTTI fixture: a diamond with one shared virtual base.
// It is parsed from file bytes and is never loaded by a Windows loader.
struct VBase { virtual int value() { return 1; } int base_data; };
struct VLeft : virtual VBase { virtual int left() { return 2; } int left_data; };
struct VRight : virtual VBase { virtual int right() { return 3; } int right_data; };
struct VDiamond : VLeft, VRight { virtual int diamond() { return 4; } int diamond_data; };

VDiamond g_virtual_diamond;

extern "C" __declspec(dllexport) VBase* as_virtual_base(VDiamond* p) { return p; }
extern "C" __declspec(dllexport) VLeft* as_virtual_left(VDiamond* p) { return p; }
extern "C" __declspec(dllexport) VRight* as_virtual_right(VDiamond* p) { return p; }

extern "C" int _fltused = 0;
