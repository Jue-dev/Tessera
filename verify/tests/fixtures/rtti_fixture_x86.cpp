#include <typeinfo>
struct Base32 { virtual int f(){return 1;} int a; };
struct Side32 { virtual int s(){return 2;} int b; };
struct Multi32 : Base32, Side32 { int c; virtual int f() override{return 3;} virtual int g(){return 4;} };
struct VBase32 { virtual int v(){return 5;} int x; };
struct VDerived32 : virtual VBase32 { int y; virtual int v() override{return 6;} };
Multi32 g_multi;
VDerived32 g_virtual;
extern "C" __declspec(dllexport) Base32* as_base(Multi32*p){return p;}
extern "C" __declspec(dllexport) VBase32* as_vbase(VDerived32*p){return p;}
