//go:build z3cgo

package smt

/*
#cgo LDFLAGS: -lz3
#include <stdlib.h>
#include <z3.h>
*/
import "C"

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"axiom/pkg/policyir"
)

func EvalPolicyZ3Cgo(policy *policyir.PolicySetIR, ctx Context, opts Z3Options) (*AxiomFailure, error) {
	converted, labelMap, failure, err := prepareZ3Constraints(policy, ctx)
	if err != nil || failure != nil {
		return failure, err
	}
	if len(converted) == 0 {
		return nil, nil
	}
	core, err := runZ3CoreCgo(converted, opts)
	if err != nil {
		return nil, err
	}
	if len(core) == 0 {
		return nil, nil
	}
	for _, label := range core {
		if cons, ok := labelMap[label]; ok {
			return &AxiomFailure{Axiom: policyir.Axiom{ID: cons.AxiomID}, Constraint: cons, Facts: MinimalFacts(cons.Expr, ctx)}, nil
		}
	}
	first := core[0]
	if cons, ok := labelMap[first]; ok {
		return &AxiomFailure{Axiom: policyir.Axiom{ID: cons.AxiomID}, Constraint: cons, Facts: MinimalFacts(cons.Expr, ctx)}, nil
	}
	return nil, nil
}

func runZ3CoreCgo(constraints []z3Constraint, opts Z3Options) ([]string, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	cfg := C.Z3_mk_config()
	ctx := C.Z3_mk_context(cfg)
	C.Z3_del_config(cfg)
	defer C.Z3_del_context(ctx)

	solver := C.Z3_mk_solver(ctx)
	C.Z3_solver_inc_ref(ctx, solver)
	defer C.Z3_solver_dec_ref(ctx, solver)

	params := C.Z3_mk_params(ctx)
	C.Z3_params_inc_ref(ctx, params)
	defer C.Z3_params_dec_ref(ctx, params)

	prodKey := C.CString("produce-unsat-cores")
	prodSym := C.Z3_mk_string_symbol(ctx, prodKey)
	C.free(unsafe.Pointer(prodKey))
	C.Z3_params_set_bool(ctx, params, prodSym, C.bool(true))

	if timeout > 0 {
		ms := C.uint(timeout.Milliseconds())
		key := C.CString("timeout")
		sym := C.Z3_mk_string_symbol(ctx, key)
		C.free(unsafe.Pointer(key))
		C.Z3_params_set_uint(ctx, params, sym, ms)
	}
	C.Z3_solver_set_params(ctx, solver, params)

	script := buildSMTAssertions(constraints)
	cscript := C.CString(script)
	C.Z3_solver_from_string(ctx, solver, cscript)
	C.free(unsafe.Pointer(cscript))
	if code := C.Z3_get_error_code(ctx); code != C.Z3_OK {
		msg := C.Z3_get_error_msg(ctx, code)
		return nil, fmt.Errorf("z3 parse error: %s", C.GoString(msg))
	}

	status := C.Z3_solver_check(ctx, solver)
	switch status {
	case C.Z3_L_TRUE:
		return nil, nil
	case C.Z3_L_FALSE:
		core := C.Z3_solver_get_unsat_core(ctx, solver)
		sz := int(C.Z3_ast_vector_size(ctx, core))
		labels := make([]string, 0, sz)
		for i := 0; i < sz; i++ {
			ast := C.Z3_ast_vector_get(ctx, core, C.uint(i))
			label := strings.TrimSpace(C.GoString(C.Z3_ast_to_string(ctx, ast)))
			if label != "" {
				labels = append(labels, label)
			}
		}
		return labels, nil
	default:
		reason := strings.TrimSpace(C.GoString(C.Z3_solver_get_reason_unknown(ctx, solver)))
		if reason == "" {
			reason = "unknown"
		}
		return nil, fmt.Errorf("z3 unknown: %s", reason)
	}
}
