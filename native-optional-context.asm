; Source: live-optional-context.json, read-only current-device code
; Each range is independently hashed in the source JSON.

; FUNCTION 0x18bdd9c END 0x18be0b0 SHA256 34e2c2c4c41c8be13a4dbdad472400c68861b020c254220ac3182af2e38779da
18bdd9c: stp x29, x30, [sp, #-0x40]!
18bdda0: str x23, [sp, #0x10]
18bdda4: stp x22, x21, [sp, #0x20]
18bdda8: stp x20, x19, [sp, #0x30]
18bddac: mov x29, sp
18bddb0: ldr x8, [x1]
18bddb4: mov x20, x0
18bddb8: mov x0, x1
18bddbc: mov x19, x1
18bddc0: ldr x8, [x8, #0x110]
18bddc4: blr x8
18bddc8: ldr x8, [x19]
18bddcc: str w0, [x20]
18bddd0: mov x0, x19
18bddd4: ldr x8, [x8, #0x128]
18bddd8: blr x8
18bdddc: ldr x8, [x19]
18bdde0: str x0, [x20, #8]
18bdde4: mov x0, x19
18bdde8: ldr x8, [x8, #0x110]
18bddec: blr x8
18bddf0: ldr x8, [x19]
18bddf4: str w0, [x20, #0x10]
18bddf8: mov x0, x19
18bddfc: ldr x8, [x8, #0xe0]
18bde00: blr x8
18bde04: and w8, w0, #1
18bde08: str wzr, [x20, #0x24]
18bde0c: mov x0, x19
18bde10: strb w8, [x20, #0x14]
18bde14: ldr x8, [x19]
18bde18: str wzr, [x20, #0x34]
18bde1c: str wzr, [x20, #0x44]
18bde20: str wzr, [x20, #0x54]
18bde24: ldr x8, [x8, #0x110]
18bde28: blr x8
18bde2c: cmp w0, #1
18bde30: b.lt #0x18bdf94
18bde34: mov w21, w0
18bde38: mov w22, #5
18bde3c: b #0x18bde58
18bde40: ldr x9, [x20, #0x48]
18bde44: add w10, w8, #1
18bde48: subs w21, w21, #1
18bde4c: str w10, [x20, #0x54]
18bde50: str w0, [x9, w8, sxtw #2]
18bde54: b.eq #0x18bdf94
18bde58: mov x0, x19
18bde5c: bl #0x1967c50
18bde60: ldp w9, w8, [x20, #0x20]
18bde64: cmp w8, w9
18bde68: b.ne #0x18bde94
18bde6c: lsl w9, w8, #1
18bde70: cmp w9, #0
18bde74: csel w1, w22, w9, eq
18bde78: cmp w8, w1
18bde7c: b.ge #0x18bde94
18bde80: mov x23, x0
18bde84: add x0, x20, #0x18
18bde88: bl #0xc493d8
18bde8c: ldr w8, [x20, #0x24]
18bde90: mov x0, x23
18bde94: ldr x9, [x20, #0x18]
18bde98: add w10, w8, #1
18bde9c: str w10, [x20, #0x24]
18bdea0: ldr x10, [x19]
18bdea4: str x0, [x9, w8, sxtw #3]
18bdea8: mov x0, x19
18bdeac: ldr x8, [x10, #0x110]
18bdeb0: blr x8
18bdeb4: ldp w9, w8, [x20, #0x30]
18bdeb8: cmp w8, w9
18bdebc: b.ne #0x18bdee8
18bdec0: lsl w9, w8, #1
18bdec4: cmp w9, #0
18bdec8: csel w1, w22, w9, eq
18bdecc: cmp w8, w1
18bded0: b.ge #0x18bdee8
18bded4: mov w23, w0
18bded8: add x0, x20, #0x28
18bdedc: bl #0x888fa8
18bdee0: ldr w8, [x20, #0x34]
18bdee4: mov w0, w23
18bdee8: ldr x9, [x20, #0x28]
18bdeec: add w10, w8, #1
18bdef0: str w10, [x20, #0x34]
18bdef4: ldr x10, [x19]
18bdef8: str w0, [x9, w8, sxtw #2]
18bdefc: mov x0, x19
18bdf00: ldr x8, [x10, #0x110]
18bdf04: blr x8
18bdf08: ldp w9, w8, [x20, #0x40]
18bdf0c: cmp w8, w9
18bdf10: b.ne #0x18bdf3c
18bdf14: lsl w9, w8, #1
18bdf18: cmp w9, #0
18bdf1c: csel w1, w22, w9, eq
18bdf20: cmp w8, w1
18bdf24: b.ge #0x18bdf3c
18bdf28: mov w23, w0
18bdf2c: add x0, x20, #0x38
18bdf30: bl #0x888fa8
18bdf34: ldr w8, [x20, #0x44]
18bdf38: mov w0, w23
18bdf3c: ldr x9, [x20, #0x38]
18bdf40: add w10, w8, #1
18bdf44: str w10, [x20, #0x44]
18bdf48: ldr x10, [x19]
18bdf4c: str w0, [x9, w8, sxtw #2]
18bdf50: mov x0, x19
18bdf54: ldr x8, [x10, #0x110]
18bdf58: blr x8
18bdf5c: ldp w9, w8, [x20, #0x50]
18bdf60: cmp w8, w9
18bdf64: b.ne #0x18bde40
18bdf68: lsl w9, w8, #1
18bdf6c: cmp w9, #0
18bdf70: csel w1, w22, w9, eq
18bdf74: cmp w8, w1
18bdf78: b.ge #0x18bde40
18bdf7c: mov w23, w0
18bdf80: add x0, x20, #0x48
18bdf84: bl #0x888fa8
18bdf88: ldr w8, [x20, #0x54]
18bdf8c: mov w0, w23
18bdf90: b #0x18bde40
18bdf94: ldr x8, [x19]
18bdf98: mov x0, x19
18bdf9c: ldr x8, [x8, #0x110]
18bdfa0: blr x8
18bdfa4: str w0, [x20, #0x58]
18bdfa8: mov w0, #0x50
18bdfac: bl #0x1c7c7a0
18bdfb0: mov x1, x19
18bdfb4: mov x21, x0
18bdfb8: bl #0x18baf64
18bdfbc: ldr x8, [x19]
18bdfc0: str x21, [x20, #0x60]
18bdfc4: mov x0, x19
18bdfc8: ldr x8, [x8, #0xe0]
18bdfcc: blr x8
18bdfd0: tbz w0, #0, #0x18bdfe8
18bdfd4: ldr x8, [x19]
18bdfd8: mov x0, x19
18bdfdc: ldr x8, [x8, #0x128]
18bdfe0: blr x8
18bdfe4: b #0x18bdfec
18bdfe8: mov x0, xzr
18bdfec: str x0, [x20, #0x68]
18bdff0: mov x0, x19
18bdff4: bl #0x1967c50
18bdff8: str x0, [x20, #0x70]
18bdffc: mov x0, x19
18be000: bl #0x1967c50
18be004: str x0, [x20, #0x78]
18be008: mov x0, x19
18be00c: bl #0x1967c50
18be010: ldr x8, [x19]
18be014: str x0, [x20, #0x80]
18be018: mov x0, x19
18be01c: str wzr, [x20, #0x94]
18be020: ldr x8, [x8, #0x110]
18be024: blr x8
18be028: cmp w0, #1
18be02c: b.lt #0x18be09c
18be030: mov w21, w0
18be034: mov w22, #5
18be038: b #0x18be054
18be03c: ldr x9, [x20, #0x88]
18be040: add w10, w8, #1
18be044: subs w21, w21, #1
18be048: str w10, [x20, #0x94]
18be04c: str w0, [x9, w8, sxtw #2]
18be050: b.eq #0x18be09c
18be054: ldr x8, [x19]
18be058: mov x0, x19
18be05c: ldr x8, [x8, #0x110]
18be060: blr x8
18be064: ldp w9, w8, [x20, #0x90]
18be068: cmp w8, w9
18be06c: b.ne #0x18be03c
18be070: lsl w9, w8, #1
18be074: cmp w9, #0
18be078: csel w1, w22, w9, eq
18be07c: cmp w8, w1
18be080: b.ge #0x18be03c
18be084: mov w23, w0
18be088: add x0, x20, #0x88
18be08c: bl #0x888fa8
18be090: ldr w8, [x20, #0x94]
18be094: mov w0, w23
18be098: b #0x18be03c
18be09c: ldp x20, x19, [sp, #0x30]
18be0a0: ldr x23, [sp, #0x10]
18be0a4: ldp x22, x21, [sp, #0x20]
18be0a8: ldp x29, x30, [sp], #0x40
18be0ac: ret 

; FUNCTION 0x18be0b0 END 0x18be280 SHA256 3c4615b22b4a5055ce604c7c04411aa906e606956c38e04551fbf0fd2ab0d087
18be0b0: stp x29, x30, [sp, #-0x40]!
18be0b4: str x23, [sp, #0x10]
18be0b8: stp x22, x21, [sp, #0x20]
18be0bc: stp x20, x19, [sp, #0x30]
18be0c0: mov x29, sp
18be0c4: ldr x8, [x1]
18be0c8: mov x19, x1
18be0cc: ldr w1, [x0]
18be0d0: mov x20, x0
18be0d4: mov x0, x19
18be0d8: ldr x8, [x8, #0x88]
18be0dc: blr x8
18be0e0: ldr x8, [x19]
18be0e4: ldr x1, [x20, #8]
18be0e8: mov x0, x19
18be0ec: ldr x8, [x8, #0xa8]
18be0f0: blr x8
18be0f4: ldr x8, [x19]
18be0f8: ldr w1, [x20, #0x10]
18be0fc: mov x0, x19
18be100: ldr x8, [x8, #0x88]
18be104: blr x8
18be108: ldr x8, [x19]
18be10c: ldrb w1, [x20, #0x14]
18be110: mov x0, x19
18be114: ldr x8, [x8, #0x40]
18be118: blr x8
18be11c: ldr x8, [x19]
18be120: ldr w21, [x20, #0x24]
18be124: mov x0, x19
18be128: ldr x8, [x8, #0x88]
18be12c: mov w1, w21
18be130: blr x8
18be134: cmp w21, #1
18be138: b.lt #0x18be1a8
18be13c: mov x22, xzr
18be140: ldr x8, [x20, #0x18]
18be144: mov x0, x19
18be148: ldr x1, [x8, x22, lsl #3]
18be14c: bl #0x1967af8
18be150: ldr x8, [x20, #0x28]
18be154: lsl x23, x22, #2
18be158: ldr x9, [x19]
18be15c: mov x0, x19
18be160: ldr w1, [x8, x23]
18be164: ldr x8, [x9, #0x88]
18be168: blr x8
18be16c: ldr x8, [x20, #0x38]
18be170: ldr x9, [x19]
18be174: mov x0, x19
18be178: ldr w1, [x8, x23]
18be17c: ldr x8, [x9, #0x88]
18be180: blr x8
18be184: ldr x8, [x20, #0x48]
18be188: ldr x9, [x19]
18be18c: mov x0, x19
18be190: ldr w1, [x8, x23]
18be194: ldr x8, [x9, #0x88]
18be198: blr x8
18be19c: add x22, x22, #1
18be1a0: cmp x21, x22
18be1a4: b.ne #0x18be140
18be1a8: ldr x8, [x19]
18be1ac: ldr w1, [x20, #0x58]
18be1b0: mov x0, x19
18be1b4: ldr x8, [x8, #0x88]
18be1b8: blr x8
18be1bc: ldr x0, [x20, #0x60]
18be1c0: mov x1, x19
18be1c4: bl #0x18bae58
18be1c8: ldr x21, [x20, #0x68]
18be1cc: ldr x8, [x19]
18be1d0: mov x0, x19
18be1d4: cmp x21, #0
18be1d8: ldr x8, [x8, #0x40]
18be1dc: cset w1, ne
18be1e0: blr x8
18be1e4: cbz x21, #0x18be1fc
18be1e8: ldr x8, [x19]
18be1ec: ldr x1, [x20, #0x68]
18be1f0: mov x0, x19
18be1f4: ldr x8, [x8, #0xa8]
18be1f8: blr x8
18be1fc: ldr x1, [x20, #0x70]
18be200: mov x0, x19
18be204: bl #0x1967af8
18be208: ldr x1, [x20, #0x78]
18be20c: mov x0, x19
18be210: bl #0x1967af8
18be214: ldr x1, [x20, #0x80]
18be218: mov x0, x19
18be21c: bl #0x1967af8
18be220: ldr x8, [x19]
18be224: ldr w1, [x20, #0x94]
18be228: mov x0, x19
18be22c: ldr x8, [x8, #0x88]
18be230: blr x8
18be234: ldr w8, [x20, #0x94]
18be238: cmp w8, #1
18be23c: b.lt #0x18be26c
18be240: mov x21, xzr
18be244: ldr x8, [x20, #0x88]
18be248: ldr x9, [x19]
18be24c: mov x0, x19
18be250: ldr w1, [x8, x21, lsl #2]
18be254: ldr x8, [x9, #0x88]
18be258: blr x8
18be25c: ldrsw x8, [x20, #0x94]
18be260: add x21, x21, #1
18be264: cmp x21, x8
18be268: b.lt #0x18be244
18be26c: ldp x20, x19, [sp, #0x30]
18be270: ldr x23, [sp, #0x10]
18be274: ldp x22, x21, [sp, #0x20]
18be278: ldp x29, x30, [sp], #0x40
18be27c: ret 

; FUNCTION 0x18be810 END 0x18be920 SHA256 609025a97dd09cb1dd1ee9c55e57a5cb39ab348a340f00a72ae4e71803f0ac5c
18be810: stp x29, x30, [sp, #-0x20]!
18be814: stp x20, x19, [sp, #0x10]
18be818: mov x29, sp
18be81c: ldr x8, [x1]
18be820: mov x19, x0
18be824: mov x0, x1
18be828: mov x20, x1
18be82c: ldr x8, [x8, #0x110]
18be830: blr x8
18be834: ldr x8, [x20]
18be838: str w0, [x19]
18be83c: mov x0, x20
18be840: ldr x8, [x8, #0x110]
18be844: blr x8
18be848: ldr x8, [x20]
18be84c: str w0, [x19, #4]
18be850: mov x0, x20
18be854: ldr x8, [x8, #0x110]
18be858: blr x8
18be85c: ldr x8, [x20]
18be860: str w0, [x19, #8]
18be864: mov x0, x20
18be868: ldr x8, [x8, #0x110]
18be86c: blr x8
18be870: ldr x8, [x20]
18be874: str w0, [x19, #0xc]
18be878: mov x0, x20
18be87c: ldr x8, [x8, #0x110]
18be880: blr x8
18be884: ldr x8, [x20]
18be888: str w0, [x19, #0x10]
18be88c: mov x0, x20
18be890: ldr x8, [x8, #0x110]
18be894: blr x8
18be898: ldr x8, [x20]
18be89c: str w0, [x19, #0x14]
18be8a0: mov x0, x20
18be8a4: ldr x8, [x8, #0x110]
18be8a8: blr x8
18be8ac: ldr x8, [x20]
18be8b0: str w0, [x19, #0x18]
18be8b4: mov x0, x20
18be8b8: ldr x8, [x8, #0x110]
18be8bc: blr x8
18be8c0: ldr x8, [x20]
18be8c4: str w0, [x19, #0x1c]
18be8c8: mov x0, x20
18be8cc: ldr x8, [x8, #0x110]
18be8d0: blr x8
18be8d4: ldr x8, [x20]
18be8d8: str w0, [x19, #0x20]
18be8dc: mov x0, x20
18be8e0: ldr x8, [x8, #0x110]
18be8e4: blr x8
18be8e8: ldr x8, [x20]
18be8ec: str w0, [x19, #0x24]
18be8f0: mov x0, x20
18be8f4: ldr x8, [x8, #0x110]
18be8f8: blr x8
18be8fc: ldr x8, [x20]
18be900: str w0, [x19, #0x28]
18be904: mov x0, x20
18be908: ldr x8, [x8, #0x110]
18be90c: blr x8
18be910: str w0, [x19, #0x2c]
18be914: ldp x20, x19, [sp, #0x10]
18be918: ldp x29, x30, [sp], #0x20
18be91c: ret 
