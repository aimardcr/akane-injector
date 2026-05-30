/*
 * akane bootstrap stub.
 *
 * Lives in akane_injector (the controller binary), not in the payload.
 * The injector mem_writes these bytes into a small target-side "boot
 * region" allocated separately from the user's .so, so any .so can be
 * injected without modification.
 *
 * Position-independent: no GOT, no PLT, no global accesses; everything
 * is reached through the saved_state pointer in x0.
 *
 * Saved-state buffer (must match exec.c):
 *   off 0   .. 240  -> regs[0..30]   (x0..x30)
 *   off 248         -> sp
 *   off 256         -> pc
 *   off 264         -> pstate
 *   ... pt_regs tail
 *   off 384         -> init_array_addr  (0 = none)
 *   off 392         -> init_array_count
 *   off 400         -> pthread_create_addr (target VA, 0 = skip)
 *   off 408         -> tid storage (written by pthread_create)
 *   off 512         -> done flag (bootstrap writes 1 here just before
 *                      branching back; controller polls and detaches the
 *                      boot region once it sees the flag set).
 *
 * Boot blob layout (one RX page):
 *   akane_bootstrap_start ... bootstrap code
 *   akane_init_runner     ... worker that walks .init_array
 *   akane_bootstrap_end
 *
 * The dl* hooks that were here previously have moved to a separate
 * runtime library (libakane_runtime.so) injected alongside the payload.
 * The bootstrap stub is back to its minimum: hijack-resume + worker
 * thread spawn for init_array.
 *
 * Flow:
 *   1. pthread_create(&tid, NULL, init_runner, &saved_state[384])
 *      Worker thread iterates init_array off the hijacked thread so a
 *      blocking constructor never ANRs the host app.
 *   2. Set done flag to 1.
 *   3. Restore syscall-return-preserved regs (x0, x19..x30, sp) and
 *      branch back to original pc.
 *
 * The boot region must outlive the worker thread (init_runner reads
 * from saved_state and executes from this same blob), so the controller
 * detaches the region instead of unmapping it.
 */

.section .text.akane_bootstrap, "ax"
.balign 16
.global akane_bootstrap_start
.global akane_bootstrap_end
.global akane_init_runner

akane_bootstrap_start:
	// x0 = saved_state ptr
	stp	x29, x30, [sp, #-48]!
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x29, sp

	mov	x19, x0                         // saved_state ptr

	// Spawn worker thread for init_array iteration:
	//   pthread_create(&tid, NULL, akane_init_runner, &saved_state[384])
	ldr	x9, [x19, #400]                 // pthread_create target VA
	cbz	x9, 2f                          // skip if not provided

	add	x0, x19, #408                   // &tid storage
	mov	x1, #0                          // attr = NULL
	adr	x2, akane_init_runner           // start_routine (PIC)
	add	x3, x19, #384                   // arg = &{init_addr, count}
	blr	x9
2:

	// Restore + resume.
	mov	x0, x19
	ldr	x1, [x0, #256]                  // saved pc
	ldr	x2, [x0, #248]                  // saved sp
	mov	sp, x2

	ldp	x19, x20, [x0, #152]
	ldp	x21, x22, [x0, #168]
	ldp	x23, x24, [x0, #184]
	ldp	x25, x26, [x0, #200]
	ldp	x27, x28, [x0, #216]
	ldp	x29, x30, [x0, #232]

	// Signal completion. Controller polls this byte and detaches the
	// boot region once it's set, so no [akane:N] handle remains.
	mov	w9, #1
	str	w9, [x0, #512]

	ldr	x0, [x0, #0]

	br	x1

// Worker thread entry. Iterates the .init_array on a fresh thread so
// the hijacked main thread is freed in microseconds.
//   x0 = saved_state + 384  (the worker descriptor)
//        +0   init_array_addr (8B)
//        +8   init_array_count (8B)
//        +16  pthread_create_addr (unused here, bootstrap reads it)
//        +24  tid storage (unused here)
//        +40  linker_register_addr (8B, 0 = skip)
.balign 16
akane_init_runner:
	stp	x29, x30, [sp, #-48]!
	stp	x19, x20, [sp, #16]
	stp	x21, x22, [sp, #32]
	mov	x29, sp

	// Optional: register payload in bionic's solist BEFORE running
	// init_array, so libraries that introspect via solist (Frida) see
	// the gadget when their constructors call detect_location.
	ldr	x9, [x0, #40]                   // linker_register_addr
	cbz	x9, 7f
	mov	x21, x0                         // preserve worker arg
	blr	x9
	mov	x0, x21                         // restore for the loads below
7:

	ldr	x19, [x0, #0]                   // init_array_addr (target VA)
	ldr	x20, [x0, #8]                   // count

	cbz	x19, 5f
	cbz	x20, 5f
	mov	x21, #0
4:
	cmp	x21, x20
	b.ge	5f
	ldr	x9, [x19, x21, lsl #3]
	cbz	x9, 6f
	mov	x0, #0
	mov	x1, #0
	mov	x2, #0
	blr	x9
6:
	add	x21, x21, #1
	b	4b
5:
	mov	x0, #0
	ldp	x21, x22, [sp, #32]
	ldp	x19, x20, [sp, #16]
	ldp	x29, x30, [sp], #48
	ret

akane_bootstrap_end:

.section .note.GNU-stack, "", %progbits
