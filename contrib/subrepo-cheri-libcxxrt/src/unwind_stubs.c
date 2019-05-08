#include "unwind.h"

// Empty unwind stubs for CheriABI until we have a proper unwind library

_Unwind_Reason_Code _Unwind_RaiseException (struct _Unwind_Exception * e) { return _URC_NO_REASON; }
_Unwind_Reason_Code _Unwind_ForcedUnwind (struct _Unwind_Exception * e,
						 _Unwind_Stop_Fn f, void *p) { return _URC_NO_REASON; }
void _Unwind_Resume (struct _Unwind_Exception * e) { }
void _Unwind_DeleteException (struct _Unwind_Exception *e) { }
uintptr_t _Unwind_GetGR (struct _Unwind_Context *e, int i) { return 0; }
void _Unwind_SetGR (struct _Unwind_Context * c, int i, uintptr_t l) { }
uintptr_t _Unwind_GetIP (struct _Unwind_Context *g) { return 0; }
uintptr_t _Unwind_GetIPInfo (struct _Unwind_Context *c, int *i) { return 0; }
void _Unwind_SetIP (struct _Unwind_Context *c, uintptr_t l) { }
uintptr_t _Unwind_GetLanguageSpecificData (struct _Unwind_Context *c) { return 0; }
uintptr_t _Unwind_GetRegionStart (struct _Unwind_Context *c) { return 0; }

_Unwind_Reason_Code
	  _Unwind_Resume_or_Rethrow (struct _Unwind_Exception *e) { return _URC_NO_REASON; }

uintptr_t _Unwind_GetDataRelBase (struct _Unwind_Context *c) { return 0; }

uintptr_t _Unwind_GetTextRelBase (struct _Unwind_Context *c) { return 0; }

typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn) (struct _Unwind_Context *,
						 void *);

_Unwind_Reason_Code _Unwind_Backtrace (_Unwind_Trace_Fn f, void *v) { return _URC_NO_REASON; }
