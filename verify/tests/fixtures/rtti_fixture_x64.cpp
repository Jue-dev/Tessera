#include <typeinfo>
struct Base { virtual int f() { return 1; } int a; };
struct Left { virtual int l() { return 2; } int b; };
struct Derived : Base, Left { int c; virtual int f() override { return 3; } virtual int d() { return 4; } };
struct VBase { virtual int v() { return 5; } int x; };
struct VDerived : virtual VBase { int y; virtual int v() override { return 6; } };
Derived d;
VDerived v;
extern "C" __declspec(dllexport) Base* make_base(Derived* p) { return p; }
extern "C" __declspec(dllexport) VBase* make_vbase(VDerived* p) { return p; }
extern "C" void entry() { (void)make_base(&d); (void)make_vbase(&v); }
struct Plain { char pad[0x10]; int x; int y; };
extern "C" __declspec(dllexport) auto* get_plain_type() { return &typeid(Plain); }
extern "C" __declspec(dllexport) __declspec(noinline) int sum_plain(Plain* p) {
    Plain* volatile this_spill = p;
    return this_spill->x + this_spill->y;
}
extern "C" __declspec(dllexport) int read_derived(Derived* p) { return p->a + p->b + p->c; }
type_info::~type_info() {}
extern "C" int _fltused = 0;
