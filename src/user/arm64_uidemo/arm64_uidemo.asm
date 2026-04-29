
../../../build/bin/arm64/user/arm64_uidemo:     file format elf64-littleaarch64


Disassembly of section .text:

0000000000400000 <_start>:
  400000:	d280001d 	mov	x29, #0x0                   	// #0
  400004:	f94003f3 	ldr	x19, [sp]
  400008:	910023f4 	add	x20, sp, #0x8
  40000c:	aa1403e1 	mov	x1, x20
  400010:	aa1303e2 	mov	x2, x19
  400014:	91000442 	add	x2, x2, #0x1
  400018:	d37df043 	lsl	x3, x2, #3
  40001c:	8b030023 	add	x3, x1, x3
  400020:	aa0303e0 	mov	x0, x3
  400024:	9400013f 	bl	400520 <__libc_init_environ>
  400028:	aa1303e0 	mov	x0, x19
  40002c:	aa1403e1 	mov	x1, x20
  400030:	aa0303e2 	mov	x2, x3
  400034:	9400000b 	bl	400060 <main>
  400038:	94000002 	bl	400040 <exit>
  40003c:	d4200000 	brk	#0x0

0000000000400040 <exit>:
  400040:	d2800ba8 	mov	x8, #0x5d                  	// #93
  400044:	d4000001 	svc	#0x0
  400048:	d4200000 	brk	#0x0
	...

0000000000400060 <main>:
  400060:	90000001 	adrp	x1, 400000 <_start>
  400064:	d2800708 	mov	x8, #0x38                  	// #56
  400068:	92800c60 	mov	x0, #0xffffffffffffff9c    	// #-100
  40006c:	d2800042 	mov	x2, #0x2                   	// #2
  400070:	f940b421 	ldr	x1, [x1, #360]
  400074:	d2800003 	mov	x3, #0x0                   	// #0
  400078:	d4000001 	svc	#0x0
  40007c:	aa0003e4 	mov	x4, x0
  400080:	b6f80080 	tbz	x0, #63, 400090 <main+0x30>
  400084:	d2800ba8 	mov	x8, #0x5d                  	// #93
  400088:	d2800020 	mov	x0, #0x1                   	// #1
  40008c:	d4000001 	svc	#0x0
  400090:	93407c84 	sxtw	x4, w4
  400094:	d2801bc8 	mov	x8, #0xde                  	// #222
  400098:	d2800000 	mov	x0, #0x0                   	// #0
  40009c:	d2a00601 	mov	x1, #0x300000              	// #3145728
  4000a0:	d2800042 	mov	x2, #0x2                   	// #2
  4000a4:	d2800023 	mov	x3, #0x1                   	// #1
  4000a8:	d2800005 	mov	x5, #0x0                   	// #0
  4000ac:	d4000001 	svc	#0x0
  4000b0:	aa0003e3 	mov	x3, x0
  4000b4:	b140041f 	cmn	x0, #0x1, lsl #12
  4000b8:	540000e9 	b.ls	4000d4 <main+0x74>  // b.plast
  4000bc:	d2800728 	mov	x8, #0x39                  	// #57
  4000c0:	aa0403e0 	mov	x0, x4
  4000c4:	d4000001 	svc	#0x0
  4000c8:	d2800ba8 	mov	x8, #0x5d                  	// #93
  4000cc:	aa0203e0 	mov	x0, x2
  4000d0:	d4000001 	svc	#0x0
  4000d4:	5282eb26 	mov	w6, #0x1759                	// #5977
  4000d8:	52800001 	mov	w1, #0x0                   	// #0
  4000dc:	12800007 	mov	w7, #0xffffffff            	// #-1
  4000e0:	72ba36e6 	movk	w6, #0xd1b7, lsl #16
  4000e4:	5284e205 	mov	w5, #0x2710                	// #10000
  4000e8:	14000005 	b	4000fc <main+0x9c>
  4000ec:	11000421 	add	w1, w1, #0x1
  4000f0:	91001063 	add	x3, x3, #0x4
  4000f4:	7143003f 	cmp	w1, #0xc0, lsl #12
  4000f8:	540001c0 	b.eq	400130 <main+0xd0>  // b.none
  4000fc:	9ba67c22 	umull	x2, w1, w6
  400100:	b9000067 	str	w7, [x3]
  400104:	d36dfc42 	lsr	x2, x2, #45
  400108:	1b058442 	msub	w2, w2, w5, w1
  40010c:	7100005f 	cmp	w2, #0x0
  400110:	7a400824 	ccmp	w1, #0x0, #0x4, eq	// eq = none
  400114:	54fffec0 	b.eq	4000ec <main+0x8c>  // b.none
  400118:	d2800f88 	mov	x8, #0x7c                  	// #124
  40011c:	d4000001 	svc	#0x0
  400120:	11000421 	add	w1, w1, #0x1
  400124:	91001063 	add	x3, x3, #0x4
  400128:	7143003f 	cmp	w1, #0xc0, lsl #12
  40012c:	54fffe81 	b.ne	4000fc <main+0x9c>  // b.any
  400130:	d28003a8 	mov	x8, #0x1d                  	// #29
  400134:	aa0403e0 	mov	x0, x4
  400138:	d288c061 	mov	x1, #0x4603                	// #17923
  40013c:	d2800002 	mov	x2, #0x0                   	// #0
  400140:	d4000001 	svc	#0x0
  400144:	d2800728 	mov	x8, #0x39                  	// #57
  400148:	aa0403e0 	mov	x0, x4
  40014c:	d4000001 	svc	#0x0
  400150:	d2800ba8 	mov	x8, #0x5d                  	// #93
  400154:	d2800000 	mov	x0, #0x0                   	// #0
  400158:	d4000001 	svc	#0x0
  40015c:	52800000 	mov	w0, #0x0                   	// #0
  400160:	d65f03c0 	ret
  400164:	d503201f 	nop
  400168:	00402000 	.word	0x00402000
  40016c:	00000000 	.word	0x00000000

0000000000400170 <find_index>:
  400170:	f0000001 	adrp	x1, 403000 <g_env_count>
  400174:	91000022 	add	x2, x1, #0x0
  400178:	f9400026 	ldr	x6, [x1]
  40017c:	b4000346 	cbz	x6, 4001e4 <find_index+0x74>
  400180:	f9400448 	ldr	x8, [x2, #8]
  400184:	f100001f 	cmp	x0, #0x0
  400188:	1a9f17e7 	cset	w7, eq	// eq = none
  40018c:	d2800005 	mov	x5, #0x0                   	// #0
  400190:	f8657904 	ldr	x4, [x8, x5, lsl #3]
  400194:	f100009f 	cmp	x4, #0x0
  400198:	7a4018e0 	ccmp	w7, #0x0, #0x0, ne	// ne = any
  40019c:	540001e1 	b.ne	4001d8 <find_index+0x68>  // b.any
  4001a0:	39400082 	ldrb	w2, [x4]
  4001a4:	d2800001 	mov	x1, #0x0                   	// #0
  4001a8:	350000e2 	cbnz	w2, 4001c4 <find_index+0x54>
  4001ac:	1400000b 	b	4001d8 <find_index+0x68>
  4001b0:	6b02007f 	cmp	w3, w2
  4001b4:	54000121 	b.ne	4001d8 <find_index+0x68>  // b.any
  4001b8:	91000421 	add	x1, x1, #0x1
  4001bc:	38616882 	ldrb	w2, [x4, x1]
  4001c0:	340000c2 	cbz	w2, 4001d8 <find_index+0x68>
  4001c4:	38616803 	ldrb	w3, [x0, x1]
  4001c8:	35ffff43 	cbnz	w3, 4001b0 <find_index+0x40>
  4001cc:	7100f45f 	cmp	w2, #0x3d
  4001d0:	540000e0 	b.eq	4001ec <find_index+0x7c>  // b.none
  4001d4:	d503201f 	nop
  4001d8:	910004a5 	add	x5, x5, #0x1
  4001dc:	eb0600bf 	cmp	x5, x6
  4001e0:	54fffd81 	b.ne	400190 <find_index+0x20>  // b.any
  4001e4:	12800000 	mov	w0, #0xffffffff            	// #-1
  4001e8:	d65f03c0 	ret
  4001ec:	2a0503e0 	mov	w0, w5
  4001f0:	d65f03c0 	ret
  4001f4:	d503201f 	nop
  4001f8:	d503201f 	nop
  4001fc:	d503201f 	nop

0000000000400200 <set_pair>:
  400200:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
  400204:	910003fd 	mov	x29, sp
  400208:	b40016e0 	cbz	x0, 4004e4 <set_pair+0x2e4>
  40020c:	a90153f3 	stp	x19, x20, [sp, #16]
  400210:	aa0003f4 	mov	x20, x0
  400214:	a90363f7 	stp	x23, x24, [sp, #48]
  400218:	aa0103f7 	mov	x23, x1
  40021c:	39400001 	ldrb	w1, [x0]
  400220:	340016c1 	cbz	w1, 4004f8 <set_pair+0x2f8>
  400224:	528007a1 	mov	w1, #0x3d                  	// #61
  400228:	a9025bf5 	stp	x21, x22, [sp, #32]
  40022c:	2a0203f6 	mov	w22, w2
  400230:	aa0303f5 	mov	x21, x3
  400234:	940002d3 	bl	400d80 <strchr>
  400238:	b5001500 	cbnz	x0, 4004d8 <set_pair+0x2d8>
  40023c:	f10002ff 	cmp	x23, #0x0
  400240:	d0000000 	adrp	x0, 402000 <memmove+0xbf0>
  400244:	91002000 	add	x0, x0, #0x8
  400248:	a9046bf9 	stp	x25, x26, [sp, #64]
  40024c:	9a970017 	csel	x23, x0, x23, eq	// eq = none
  400250:	aa1403e0 	mov	x0, x20
  400254:	94000253 	bl	400ba0 <strlen>
  400258:	aa1503f9 	mov	x25, x21
  40025c:	aa0003f3 	mov	x19, x0
  400260:	aa1703e0 	mov	x0, x23
  400264:	9400024f 	bl	400ba0 <strlen>
  400268:	aa0003f8 	mov	x24, x0
  40026c:	b4000495 	cbz	x21, 4002fc <set_pair+0xfc>
  400270:	f0000013 	adrp	x19, 403000 <g_env_count>
  400274:	91000277 	add	x23, x19, #0x0
  400278:	910042e9 	add	x9, x23, #0x10
  40027c:	52800022 	mov	w2, #0x1                   	// #1
  400280:	085ffd21 	ldaxrb	w1, [x9]
  400284:	08037d22 	stxrb	w3, w2, [x9]
  400288:	35ffffc3 	cbnz	w3, 400280 <set_pair+0x80>
  40028c:	3707ffa1 	tbnz	w1, #0, 400280 <set_pair+0x80>
  400290:	aa1403e0 	mov	x0, x20
  400294:	97ffffb7 	bl	400170 <find_index>
  400298:	2a2003e1 	mvn	w1, w0
  40029c:	520002d6 	eor	w22, w22, #0x1
  4002a0:	6a417edf 	tst	w22, w1, lsr #31
  4002a4:	54000741 	b.ne	40038c <set_pair+0x18c>  // b.any
  4002a8:	37f80580 	tbnz	w0, #31, 400358 <set_pair+0x158>
  4002ac:	f94006e2 	ldr	x2, [x23, #8]
  4002b0:	d37d7c14 	ubfiz	x20, x0, #3, #32
  4002b4:	8b140041 	add	x1, x2, x20
  4002b8:	f8605840 	ldr	x0, [x2, w0, uxtw #3]
  4002bc:	eb19001f 	cmp	x0, x25
  4002c0:	54000080 	b.eq	4002d0 <set_pair+0xd0>  // b.none
  4002c4:	940001df 	bl	400a40 <free>
  4002c8:	f94006e1 	ldr	x1, [x23, #8]
  4002cc:	8b140021 	add	x1, x1, x20
  4002d0:	f9000039 	str	x25, [x1]
  4002d4:	91000273 	add	x19, x19, #0x0
  4002d8:	91004273 	add	x19, x19, #0x10
  4002dc:	089ffe7f 	stlrb	wzr, [x19]
  4002e0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4002e4:	52800000 	mov	w0, #0x0                   	// #0
  4002e8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4002ec:	a94363f7 	ldp	x23, x24, [sp, #48]
  4002f0:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4002f4:	a8c57bfd 	ldp	x29, x30, [sp], #80
  4002f8:	d65f03c0 	ret
  4002fc:	92800040 	mov	x0, #0xfffffffffffffffd    	// #-3
  400300:	cb180000 	sub	x0, x0, x24
  400304:	eb13001f 	cmp	x0, x19
  400308:	54000ca3 	b.cc	40049c <set_pair+0x29c>  // b.lo, b.ul, b.last
  40030c:	8b180260 	add	x0, x19, x24
  400310:	aa0003fa 	mov	x26, x0
  400314:	91000800 	add	x0, x0, #0x2
  400318:	94000196 	bl	400970 <malloc>
  40031c:	aa0003f9 	mov	x25, x0
  400320:	b4000be0 	cbz	x0, 40049c <set_pair+0x29c>
  400324:	aa1303e2 	mov	x2, x19
  400328:	aa1403e1 	mov	x1, x20
  40032c:	94000405 	bl	401340 <memcpy>
  400330:	528007a0 	mov	w0, #0x3d                  	// #61
  400334:	38336b20 	strb	w0, [x25, x19]
  400338:	91000673 	add	x19, x19, #0x1
  40033c:	aa1703e1 	mov	x1, x23
  400340:	aa1803e2 	mov	x2, x24
  400344:	8b130320 	add	x0, x25, x19
  400348:	940003fe 	bl	401340 <memcpy>
  40034c:	8b1a0321 	add	x1, x25, x26
  400350:	3900043f 	strb	wzr, [x1, #1]
  400354:	17ffffc7 	b	400270 <set_pair+0x70>
  400358:	f9400263 	ldr	x3, [x19]
  40035c:	f9400ef8 	ldr	x24, [x23, #24]
  400360:	91000860 	add	x0, x3, #0x2
  400364:	eb18001f 	cmp	x0, x24
  400368:	540001c8 	b.hi	4003a0 <set_pair+0x1a0>  // b.pmore
  40036c:	f94006f4 	ldr	x20, [x23, #8]
  400370:	b4000854 	cbz	x20, 400478 <set_pair+0x278>
  400374:	91000462 	add	x2, x3, #0x1
  400378:	8b030e83 	add	x3, x20, x3, lsl #3
  40037c:	f9000079 	str	x25, [x3]
  400380:	f9000262 	str	x2, [x19]
  400384:	f8227a9f 	str	xzr, [x20, x2, lsl #3]
  400388:	17ffffd3 	b	4002d4 <set_pair+0xd4>
  40038c:	089ffd3f 	stlrb	wzr, [x9]
  400390:	b5fffa95 	cbnz	x21, 4002e0 <set_pair+0xe0>
  400394:	aa1903e0 	mov	x0, x25
  400398:	940001aa 	bl	400a40 <free>
  40039c:	17ffffd1 	b	4002e0 <set_pair+0xe0>
  4003a0:	b40006f8 	cbz	x24, 40047c <set_pair+0x27c>
  4003a4:	d503201f 	nop
  4003a8:	b7f80738 	tbnz	x24, #63, 40048c <set_pair+0x28c>
  4003ac:	8b180318 	add	x24, x24, x24
  4003b0:	eb18001f 	cmp	x0, x24
  4003b4:	54ffffa8 	b.hi	4003a8 <set_pair+0x1a8>  // b.pmore
  4003b8:	d37df316 	lsl	x22, x24, #3
  4003bc:	aa1603e0 	mov	x0, x22
  4003c0:	9400016c 	bl	400970 <malloc>
  4003c4:	aa0003f4 	mov	x20, x0
  4003c8:	b4000620 	cbz	x0, 40048c <set_pair+0x28c>
  4003cc:	f9400260 	ldr	x0, [x19]
  4003d0:	91000262 	add	x2, x19, #0x0
  4003d4:	b4000980 	cbz	x0, 400504 <set_pair+0x304>
  4003d8:	f9400444 	ldr	x4, [x2, #8]
  4003dc:	d2800002 	mov	x2, #0x0                   	// #0
  4003e0:	b40003a4 	cbz	x4, 400454 <set_pair+0x254>
  4003e4:	d503201f 	nop
  4003e8:	f8627883 	ldr	x3, [x4, x2, lsl #3]
  4003ec:	f8227a83 	str	x3, [x20, x2, lsl #3]
  4003f0:	91000442 	add	x2, x2, #0x1
  4003f4:	eb00005f 	cmp	x2, x0
  4003f8:	54ffff81 	b.ne	4003e8 <set_pair+0x1e8>  // b.any
  4003fc:	8b000e83 	add	x3, x20, x0, lsl #3
  400400:	91000402 	add	x2, x0, #0x1
  400404:	f900007f 	str	xzr, [x3]
  400408:	8b020e80 	add	x0, x20, x2, lsl #3
  40040c:	8b1402c4 	add	x4, x22, x20
  400410:	eb02031f 	cmp	x24, x2
  400414:	54000089 	b.ls	400424 <set_pair+0x224>  // b.plast
  400418:	f800841f 	str	xzr, [x0], #8
  40041c:	eb04001f 	cmp	x0, x4
  400420:	54ffffc1 	b.ne	400418 <set_pair+0x218>  // b.any
  400424:	91000260 	add	x0, x19, #0x0
  400428:	39408004 	ldrb	w4, [x0, #32]
  40042c:	370004a4 	tbnz	w4, #0, 4004c0 <set_pair+0x2c0>
  400430:	d0000004 	adrp	x4, 402000 <memmove+0xbf0>
  400434:	f9400c84 	ldr	x4, [x4, #24]
  400438:	91000260 	add	x0, x19, #0x0
  40043c:	52800021 	mov	w1, #0x1                   	// #1
  400440:	f9000094 	str	x20, [x4]
  400444:	f9000414 	str	x20, [x0, #8]
  400448:	f9000c18 	str	x24, [x0, #24]
  40044c:	39008001 	strb	w1, [x0, #32]
  400450:	17ffffcb 	b	40037c <set_pair+0x17c>
  400454:	91000443 	add	x3, x2, #0x1
  400458:	f8227a9f 	str	xzr, [x20, x2, lsl #3]
  40045c:	eb03001f 	cmp	x0, x3
  400460:	54fffce0 	b.eq	4003fc <set_pair+0x1fc>  // b.none
  400464:	91000842 	add	x2, x2, #0x2
  400468:	f8237a9f 	str	xzr, [x20, x3, lsl #3]
  40046c:	eb00005f 	cmp	x2, x0
  400470:	54ffff21 	b.ne	400454 <set_pair+0x254>  // b.any
  400474:	17ffffe2 	b	4003fc <set_pair+0x1fc>
  400478:	b5fffa18 	cbnz	x24, 4003b8 <set_pair+0x1b8>
  40047c:	d2800118 	mov	x24, #0x8                   	// #8
  400480:	f100201f 	cmp	x0, #0x8
  400484:	54fff928 	b.hi	4003a8 <set_pair+0x1a8>  // b.pmore
  400488:	17ffffcc 	b	4003b8 <set_pair+0x1b8>
  40048c:	91000260 	add	x0, x19, #0x0
  400490:	91004000 	add	x0, x0, #0x10
  400494:	089ffc1f 	stlrb	wzr, [x0]
  400498:	b40003d5 	cbz	x21, 400510 <set_pair+0x310>
  40049c:	940001bd 	bl	400b90 <__errno_location@GLIBC_2.2.5>
  4004a0:	52800181 	mov	w1, #0xc                   	// #12
  4004a4:	b9000001 	str	w1, [x0]
  4004a8:	12800000 	mov	w0, #0xffffffff            	// #-1
  4004ac:	a94153f3 	ldp	x19, x20, [sp, #16]
  4004b0:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4004b4:	a94363f7 	ldp	x23, x24, [sp, #48]
  4004b8:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4004bc:	17ffff8e 	b	4002f4 <set_pair+0xf4>
  4004c0:	f9400400 	ldr	x0, [x0, #8]
  4004c4:	9400015f 	bl	400a40 <free>
  4004c8:	f9400263 	ldr	x3, [x19]
  4004cc:	91000462 	add	x2, x3, #0x1
  4004d0:	8b030e83 	add	x3, x20, x3, lsl #3
  4004d4:	17ffffd7 	b	400430 <set_pair+0x230>
  4004d8:	a94153f3 	ldp	x19, x20, [sp, #16]
  4004dc:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4004e0:	a94363f7 	ldp	x23, x24, [sp, #48]
  4004e4:	940001ab 	bl	400b90 <__errno_location@GLIBC_2.2.5>
  4004e8:	528002c1 	mov	w1, #0x16                  	// #22
  4004ec:	b9000001 	str	w1, [x0]
  4004f0:	12800000 	mov	w0, #0xffffffff            	// #-1
  4004f4:	17ffff80 	b	4002f4 <set_pair+0xf4>
  4004f8:	a94153f3 	ldp	x19, x20, [sp, #16]
  4004fc:	a94363f7 	ldp	x23, x24, [sp, #48]
  400500:	17fffff9 	b	4004e4 <set_pair+0x2e4>
  400504:	aa1403e3 	mov	x3, x20
  400508:	d2800022 	mov	x2, #0x1                   	// #1
  40050c:	17ffffbe 	b	400404 <set_pair+0x204>
  400510:	aa1903e0 	mov	x0, x25
  400514:	9400014b 	bl	400a40 <free>
  400518:	17ffffe1 	b	40049c <set_pair+0x29c>
  40051c:	d503201f 	nop

0000000000400520 <__libc_init_environ>:
  400520:	b40007c0 	cbz	x0, 400618 <__libc_init_environ+0xf8>
  400524:	f9400002 	ldr	x2, [x0]
  400528:	d2800001 	mov	x1, #0x0                   	// #0
  40052c:	b4000762 	cbz	x2, 400618 <__libc_init_environ+0xf8>
  400530:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
  400534:	910003fd 	mov	x29, sp
  400538:	a90153f3 	stp	x19, x20, [sp, #16]
  40053c:	a90363f7 	stp	x23, x24, [sp, #48]
  400540:	a9046bf9 	stp	x25, x26, [sp, #64]
  400544:	d503201f 	nop
  400548:	aa0103f7 	mov	x23, x1
  40054c:	91000421 	add	x1, x1, #0x1
  400550:	f8617802 	ldr	x2, [x0, x1, lsl #3]
  400554:	b5ffffa2 	cbnz	x2, 400548 <__libc_init_environ+0x28>
  400558:	91000af7 	add	x23, x23, #0x2
  40055c:	f0000019 	adrp	x25, 403000 <g_env_count>
  400560:	91000338 	add	x24, x25, #0x0
  400564:	aa0003f3 	mov	x19, x0
  400568:	d37df2fa 	lsl	x26, x23, #3
  40056c:	aa1a03e0 	mov	x0, x26
  400570:	94000100 	bl	400970 <malloc>
  400574:	f9000700 	str	x0, [x24, #8]
  400578:	b4000620 	cbz	x0, 40063c <__libc_init_environ+0x11c>
  40057c:	d100235a 	sub	x26, x26, #0x8
  400580:	a9025bf5 	stp	x21, x22, [sp, #32]
  400584:	8b1a027a 	add	x26, x19, x26
  400588:	d2800016 	mov	x22, #0x0                   	// #0
  40058c:	f9002bfb 	str	x27, [sp, #80]
  400590:	f9400260 	ldr	x0, [x19]
  400594:	94000183 	bl	400ba0 <strlen>
  400598:	91000415 	add	x21, x0, #0x1
  40059c:	aa1503e0 	mov	x0, x21
  4005a0:	940000f4 	bl	400970 <malloc>
  4005a4:	aa0003f4 	mov	x20, x0
  4005a8:	b4000100 	cbz	x0, 4005c8 <__libc_init_environ+0xa8>
  4005ac:	f9400261 	ldr	x1, [x19]
  4005b0:	aa1503e2 	mov	x2, x21
  4005b4:	d37df2db 	lsl	x27, x22, #3
  4005b8:	910006d6 	add	x22, x22, #0x1
  4005bc:	94000361 	bl	401340 <memcpy>
  4005c0:	f9400700 	ldr	x0, [x24, #8]
  4005c4:	f83b6814 	str	x20, [x0, x27]
  4005c8:	91002273 	add	x19, x19, #0x8
  4005cc:	eb1a027f 	cmp	x19, x26
  4005d0:	54fffe01 	b.ne	400590 <__libc_init_environ+0x70>  // b.any
  4005d4:	91000320 	add	x0, x25, #0x0
  4005d8:	f9000336 	str	x22, [x25]
  4005dc:	d0000002 	adrp	x2, 402000 <memmove+0xbf0>
  4005e0:	f9400c42 	ldr	x2, [x2, #24]
  4005e4:	f9400401 	ldr	x1, [x0, #8]
  4005e8:	f9402bfb 	ldr	x27, [sp, #80]
  4005ec:	f9000c17 	str	x23, [x0, #24]
  4005f0:	f836783f 	str	xzr, [x1, x22, lsl #3]
  4005f4:	f9000041 	str	x1, [x2]
  4005f8:	52800021 	mov	w1, #0x1                   	// #1
  4005fc:	39008001 	strb	w1, [x0, #32]
  400600:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400604:	a94153f3 	ldp	x19, x20, [sp, #16]
  400608:	a94363f7 	ldp	x23, x24, [sp, #48]
  40060c:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400610:	a8c67bfd 	ldp	x29, x30, [sp], #96
  400614:	d65f03c0 	ret
  400618:	d0000002 	adrp	x2, 402000 <memmove+0xbf0>
  40061c:	f9400c42 	ldr	x2, [x2, #24]
  400620:	f0000001 	adrp	x1, 403000 <g_env_count>
  400624:	91000020 	add	x0, x1, #0x0
  400628:	f900003f 	str	xzr, [x1]
  40062c:	f900005f 	str	xzr, [x2]
  400630:	f900041f 	str	xzr, [x0, #8]
  400634:	f9000c1f 	str	xzr, [x0, #24]
  400638:	d65f03c0 	ret
  40063c:	d0000000 	adrp	x0, 402000 <memmove+0xbf0>
  400640:	f9400c00 	ldr	x0, [x0, #24]
  400644:	f9000f1f 	str	xzr, [x24, #24]
  400648:	3900831f 	strb	wzr, [x24, #32]
  40064c:	f900033f 	str	xzr, [x25]
  400650:	f900001f 	str	xzr, [x0]
  400654:	a94153f3 	ldp	x19, x20, [sp, #16]
  400658:	a94363f7 	ldp	x23, x24, [sp, #48]
  40065c:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400660:	a8c67bfd 	ldp	x29, x30, [sp], #96
  400664:	d65f03c0 	ret
  400668:	d503201f 	nop
  40066c:	d503201f 	nop

0000000000400670 <getenv>:
  400670:	b4000440 	cbz	x0, 4006f8 <getenv+0x88>
  400674:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400678:	52800023 	mov	w3, #0x1                   	// #1
  40067c:	910003fd 	mov	x29, sp
  400680:	f9000bf3 	str	x19, [sp, #16]
  400684:	f0000013 	adrp	x19, 403000 <g_env_count>
  400688:	91000269 	add	x9, x19, #0x0
  40068c:	91004121 	add	x1, x9, #0x10
  400690:	085ffc22 	ldaxrb	w2, [x1]
  400694:	08047c23 	stxrb	w4, w3, [x1]
  400698:	35ffffc4 	cbnz	w4, 400690 <getenv+0x20>
  40069c:	3707ffa2 	tbnz	w2, #0, 400690 <getenv+0x20>
  4006a0:	97fffeb4 	bl	400170 <find_index>
  4006a4:	37f801c0 	tbnz	w0, #31, 4006dc <getenv+0x6c>
  4006a8:	f9400521 	ldr	x1, [x9, #8]
  4006ac:	f8605820 	ldr	x0, [x1, w0, uxtw #3]
  4006b0:	b4000160 	cbz	x0, 4006dc <getenv+0x6c>
  4006b4:	528007a1 	mov	w1, #0x3d                  	// #61
  4006b8:	940001b2 	bl	400d80 <strchr>
  4006bc:	b4000100 	cbz	x0, 4006dc <getenv+0x6c>
  4006c0:	91000400 	add	x0, x0, #0x1
  4006c4:	91000273 	add	x19, x19, #0x0
  4006c8:	91004273 	add	x19, x19, #0x10
  4006cc:	089ffe7f 	stlrb	wzr, [x19]
  4006d0:	f9400bf3 	ldr	x19, [sp, #16]
  4006d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
  4006d8:	d65f03c0 	ret
  4006dc:	d2800000 	mov	x0, #0x0                   	// #0
  4006e0:	91000273 	add	x19, x19, #0x0
  4006e4:	91004273 	add	x19, x19, #0x10
  4006e8:	089ffe7f 	stlrb	wzr, [x19]
  4006ec:	f9400bf3 	ldr	x19, [sp, #16]
  4006f0:	a8c27bfd 	ldp	x29, x30, [sp], #32
  4006f4:	d65f03c0 	ret
  4006f8:	d65f03c0 	ret
  4006fc:	d503201f 	nop

0000000000400700 <secure_getenv>:
  400700:	17ffffdc 	b	400670 <getenv>
  400704:	d503201f 	nop
  400708:	d503201f 	nop
  40070c:	d503201f 	nop

0000000000400710 <__secure_getenv>:
  400710:	17fffffc 	b	400700 <secure_getenv>
  400714:	d503201f 	nop
  400718:	d503201f 	nop
  40071c:	d503201f 	nop

0000000000400720 <setenv>:
  400720:	7100005f 	cmp	w2, #0x0
  400724:	d2800003 	mov	x3, #0x0                   	// #0
  400728:	1a9f07e2 	cset	w2, ne	// ne = any
  40072c:	17fffeb5 	b	400200 <set_pair>

0000000000400730 <putenv>:
  400730:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400734:	910003fd 	mov	x29, sp
  400738:	b4000380 	cbz	x0, 4007a8 <putenv+0x78>
  40073c:	528007a1 	mov	w1, #0x3d                  	// #61
  400740:	a90153f3 	stp	x19, x20, [sp, #16]
  400744:	aa0003f4 	mov	x20, x0
  400748:	9400018e 	bl	400d80 <strchr>
  40074c:	f100001f 	cmp	x0, #0x0
  400750:	aa0003f3 	mov	x19, x0
  400754:	fa401284 	ccmp	x20, x0, #0x4, ne	// ne = any
  400758:	540001c0 	b.eq	400790 <putenv+0x60>  // b.none
  40075c:	aa0003e1 	mov	x1, x0
  400760:	f90013f5 	str	x21, [sp, #32]
  400764:	aa1403e3 	mov	x3, x20
  400768:	aa1403e0 	mov	x0, x20
  40076c:	39400275 	ldrb	w21, [x19]
  400770:	52800022 	mov	w2, #0x1                   	// #1
  400774:	3800143f 	strb	wzr, [x1], #1
  400778:	97fffea2 	bl	400200 <set_pair>
  40077c:	39000275 	strb	w21, [x19]
  400780:	a94153f3 	ldp	x19, x20, [sp, #16]
  400784:	f94013f5 	ldr	x21, [sp, #32]
  400788:	a8c37bfd 	ldp	x29, x30, [sp], #48
  40078c:	d65f03c0 	ret
  400790:	94000100 	bl	400b90 <__errno_location@GLIBC_2.2.5>
  400794:	528002c1 	mov	w1, #0x16                  	// #22
  400798:	b9000001 	str	w1, [x0]
  40079c:	12800000 	mov	w0, #0xffffffff            	// #-1
  4007a0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4007a4:	17fffff9 	b	400788 <putenv+0x58>
  4007a8:	940000fa 	bl	400b90 <__errno_location@GLIBC_2.2.5>
  4007ac:	528002c1 	mov	w1, #0x16                  	// #22
  4007b0:	b9000001 	str	w1, [x0]
  4007b4:	12800000 	mov	w0, #0xffffffff            	// #-1
  4007b8:	17fffff4 	b	400788 <putenv+0x58>
  4007bc:	d503201f 	nop

00000000004007c0 <unsetenv>:
  4007c0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
  4007c4:	910003fd 	mov	x29, sp
  4007c8:	b40006e0 	cbz	x0, 4008a4 <unsetenv+0xe4>
  4007cc:	a90153f3 	stp	x19, x20, [sp, #16]
  4007d0:	aa0003f4 	mov	x20, x0
  4007d4:	39400001 	ldrb	w1, [x0]
  4007d8:	34000641 	cbz	w1, 4008a0 <unsetenv+0xe0>
  4007dc:	528007a1 	mov	w1, #0x3d                  	// #61
  4007e0:	94000168 	bl	400d80 <strchr>
  4007e4:	b50005e0 	cbnz	x0, 4008a0 <unsetenv+0xe0>
  4007e8:	f90013f5 	str	x21, [sp, #32]
  4007ec:	f0000013 	adrp	x19, 403000 <g_env_count>
  4007f0:	91000275 	add	x21, x19, #0x0
  4007f4:	52800022 	mov	w2, #0x1                   	// #1
  4007f8:	910042a0 	add	x0, x21, #0x10
  4007fc:	d503201f 	nop
  400800:	085ffc01 	ldaxrb	w1, [x0]
  400804:	08037c02 	stxrb	w3, w2, [x0]
  400808:	35ffffc3 	cbnz	w3, 400800 <unsetenv+0x40>
  40080c:	3707ffa1 	tbnz	w1, #0, 400800 <unsetenv+0x40>
  400810:	aa1403e0 	mov	x0, x20
  400814:	97fffe57 	bl	400170 <find_index>
  400818:	2a0003e1 	mov	w1, w0
  40081c:	36f80120 	tbz	w0, #31, 400840 <unsetenv+0x80>
  400820:	91000273 	add	x19, x19, #0x0
  400824:	91004273 	add	x19, x19, #0x10
  400828:	089ffe7f 	stlrb	wzr, [x19]
  40082c:	a94153f3 	ldp	x19, x20, [sp, #16]
  400830:	52800000 	mov	w0, #0x0                   	// #0
  400834:	f94013f5 	ldr	x21, [sp, #32]
  400838:	a8c47bfd 	ldp	x29, x30, [sp], #64
  40083c:	d65f03c0 	ret
  400840:	93407c14 	sxtw	x20, w0
  400844:	b9003fe1 	str	w1, [sp, #60]
  400848:	f94006a0 	ldr	x0, [x21, #8]
  40084c:	91000694 	add	x20, x20, #0x1
  400850:	f8615800 	ldr	x0, [x0, w1, uxtw #3]
  400854:	9400007b 	bl	400a40 <free>
  400858:	f9400263 	ldr	x3, [x19]
  40085c:	f94006a4 	ldr	x4, [x21, #8]
  400860:	eb03029f 	cmp	x20, x3
  400864:	b9403fe1 	ldr	w1, [sp, #60]
  400868:	54000122 	b.cs	40088c <unsetenv+0xcc>  // b.hs, b.nlast
  40086c:	91002080 	add	x0, x4, #0x8
  400870:	8b030c82 	add	x2, x4, x3, lsl #3
  400874:	8b214c00 	add	x0, x0, w1, uxtw #3
  400878:	f9400001 	ldr	x1, [x0]
  40087c:	91002000 	add	x0, x0, #0x8
  400880:	f81f0001 	stur	x1, [x0, #-16]
  400884:	eb02001f 	cmp	x0, x2
  400888:	54ffff81 	b.ne	400878 <unsetenv+0xb8>  // b.any
  40088c:	d1000463 	sub	x3, x3, #0x1
  400890:	f9000263 	str	x3, [x19]
  400894:	b4fffc64 	cbz	x4, 400820 <unsetenv+0x60>
  400898:	f823789f 	str	xzr, [x4, x3, lsl #3]
  40089c:	17ffffe1 	b	400820 <unsetenv+0x60>
  4008a0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4008a4:	940000bb 	bl	400b90 <__errno_location@GLIBC_2.2.5>
  4008a8:	528002c1 	mov	w1, #0x16                  	// #22
  4008ac:	b9000001 	str	w1, [x0]
  4008b0:	12800000 	mov	w0, #0xffffffff            	// #-1
  4008b4:	17ffffe1 	b	400838 <unsetenv+0x78>
  4008b8:	d503201f 	nop
  4008bc:	d503201f 	nop

00000000004008c0 <clearenv>:
  4008c0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4008c4:	52800022 	mov	w2, #0x1                   	// #1
  4008c8:	910003fd 	mov	x29, sp
  4008cc:	a9025bf5 	stp	x21, x22, [sp, #32]
  4008d0:	f0000016 	adrp	x22, 403000 <g_env_count>
  4008d4:	910002c0 	add	x0, x22, #0x0
  4008d8:	91004000 	add	x0, x0, #0x10
  4008dc:	a90153f3 	stp	x19, x20, [sp, #16]
  4008e0:	085ffc01 	ldaxrb	w1, [x0]
  4008e4:	08037c02 	stxrb	w3, w2, [x0]
  4008e8:	35ffffc3 	cbnz	w3, 4008e0 <clearenv+0x20>
  4008ec:	3707ffa1 	tbnz	w1, #0, 4008e0 <clearenv+0x20>
  4008f0:	f94002c0 	ldr	x0, [x22]
  4008f4:	b40001a0 	cbz	x0, 400928 <clearenv+0x68>
  4008f8:	910002d5 	add	x21, x22, #0x0
  4008fc:	d2800014 	mov	x20, #0x0                   	// #0
  400900:	d2800013 	mov	x19, #0x0                   	// #0
  400904:	d503201f 	nop
  400908:	f94006a0 	ldr	x0, [x21, #8]
  40090c:	91000673 	add	x19, x19, #0x1
  400910:	f8746800 	ldr	x0, [x0, x20]
  400914:	91002294 	add	x20, x20, #0x8
  400918:	9400004a 	bl	400a40 <free>
  40091c:	f94002a0 	ldr	x0, [x21]
  400920:	eb13001f 	cmp	x0, x19
  400924:	54ffff28 	b.hi	400908 <clearenv+0x48>  // b.pmore
  400928:	910002d3 	add	x19, x22, #0x0
  40092c:	f9400660 	ldr	x0, [x19, #8]
  400930:	94000044 	bl	400a40 <free>
  400934:	f90002df 	str	xzr, [x22]
  400938:	d0000000 	adrp	x0, 402000 <memmove+0xbf0>
  40093c:	f9400c00 	ldr	x0, [x0, #24]
  400940:	f900067f 	str	xzr, [x19, #8]
  400944:	f9000e7f 	str	xzr, [x19, #24]
  400948:	f900001f 	str	xzr, [x0]
  40094c:	91004273 	add	x19, x19, #0x10
  400950:	089ffe7f 	stlrb	wzr, [x19]
  400954:	52800000 	mov	w0, #0x0                   	// #0
  400958:	a94153f3 	ldp	x19, x20, [sp, #16]
  40095c:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400960:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400964:	d65f03c0 	ret
	...

0000000000400970 <malloc>:
  400970:	b4000640 	cbz	x0, 400a38 <malloc+0xc8>
  400974:	91003c00 	add	x0, x0, #0xf
  400978:	f0000006 	adrp	x6, 403000 <g_env_count>
  40097c:	9100c0c4 	add	x4, x6, #0x30
  400980:	927c6c02 	and	x2, x0, #0xfffffff0
  400984:	f100405f 	cmp	x2, #0x10
  400988:	d2800200 	mov	x0, #0x10                  	// #16
  40098c:	9a802042 	csel	x2, x2, x0, cs	// cs = hs, nlast
  400990:	91002080 	add	x0, x4, #0x8
  400994:	52800023 	mov	w3, #0x1                   	// #1
  400998:	085ffc01 	ldaxrb	w1, [x0]
  40099c:	08057c03 	stxrb	w5, w3, [x0]
  4009a0:	35ffffc5 	cbnz	w5, 400998 <malloc+0x28>
  4009a4:	3707ffa1 	tbnz	w1, #0, 400998 <malloc+0x28>
  4009a8:	f94018c1 	ldr	x1, [x6, #48]
  4009ac:	b5000081 	cbnz	x1, 4009bc <malloc+0x4c>
  4009b0:	1400000c 	b	4009e0 <malloc+0x70>
  4009b4:	aa0003e4 	mov	x4, x0
  4009b8:	b4000141 	cbz	x1, 4009e0 <malloc+0x70>
  4009bc:	aa0103e0 	mov	x0, x1
  4009c0:	a97f8423 	ldp	x3, x1, [x1, #-8]
  4009c4:	eb02007f 	cmp	x3, x2
  4009c8:	54ffff63 	b.cc	4009b4 <malloc+0x44>  // b.lo, b.ul, b.last
  4009cc:	9100c0c6 	add	x6, x6, #0x30
  4009d0:	f9000081 	str	x1, [x4]
  4009d4:	910020c6 	add	x6, x6, #0x8
  4009d8:	089ffcdf 	stlrb	wzr, [x6]
  4009dc:	d65f03c0 	ret
  4009e0:	d2801ac8 	mov	x8, #0xd6                  	// #214
  4009e4:	d2800000 	mov	x0, #0x0                   	// #0
  4009e8:	d4000001 	svc	#0x0
  4009ec:	aa0003e1 	mov	x1, x0
  4009f0:	d29fffe0 	mov	x0, #0xffff                	// #65535
  4009f4:	eb00003f 	cmp	x1, x0
  4009f8:	540001ad 	b.le	400a2c <malloc+0xbc>
  4009fc:	91002043 	add	x3, x2, #0x8
  400a00:	8b010063 	add	x3, x3, x1
  400a04:	aa0303e0 	mov	x0, x3
  400a08:	d4000001 	svc	#0x0
  400a0c:	eb00007f 	cmp	x3, x0
  400a10:	540000ec 	b.gt	400a2c <malloc+0xbc>
  400a14:	9100c0c6 	add	x6, x6, #0x30
  400a18:	910020c6 	add	x6, x6, #0x8
  400a1c:	089ffcdf 	stlrb	wzr, [x6]
  400a20:	aa0103e0 	mov	x0, x1
  400a24:	f8008402 	str	x2, [x0], #8
  400a28:	d65f03c0 	ret
  400a2c:	9100c0c0 	add	x0, x6, #0x30
  400a30:	91002000 	add	x0, x0, #0x8
  400a34:	089ffc1f 	stlrb	wzr, [x0]
  400a38:	d2800000 	mov	x0, #0x0                   	// #0
  400a3c:	d65f03c0 	ret

0000000000400a40 <free>:
  400a40:	d29fffe1 	mov	x1, #0xffff                	// #65535
  400a44:	eb01001f 	cmp	x0, x1
  400a48:	54000048 	b.hi	400a50 <free+0x10>  // b.pmore
  400a4c:	d65f03c0 	ret
  400a50:	f0000005 	adrp	x5, 403000 <g_env_count>
  400a54:	9100c0a1 	add	x1, x5, #0x30
  400a58:	91002021 	add	x1, x1, #0x8
  400a5c:	52800023 	mov	w3, #0x1                   	// #1
  400a60:	085ffc22 	ldaxrb	w2, [x1]
  400a64:	08047c23 	stxrb	w4, w3, [x1]
  400a68:	35ffffc4 	cbnz	w4, 400a60 <free+0x20>
  400a6c:	3707ffa2 	tbnz	w2, #0, 400a60 <free+0x20>
  400a70:	f94018a2 	ldr	x2, [x5, #48]
  400a74:	f9000002 	str	x2, [x0]
  400a78:	f90018a0 	str	x0, [x5, #48]
  400a7c:	089ffc3f 	stlrb	wzr, [x1]
  400a80:	d65f03c0 	ret
  400a84:	d503201f 	nop
  400a88:	d503201f 	nop
  400a8c:	d503201f 	nop

0000000000400a90 <calloc>:
  400a90:	b4000060 	cbz	x0, 400a9c <calloc+0xc>
  400a94:	9bc17c02 	umulh	x2, x0, x1
  400a98:	b5000222 	cbnz	x2, 400adc <calloc+0x4c>
  400a9c:	9b017c02 	mul	x2, x0, x1
  400aa0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400aa4:	910003fd 	mov	x29, sp
  400aa8:	aa0203e0 	mov	x0, x2
  400aac:	f9000be2 	str	x2, [sp, #16]
  400ab0:	97ffffb0 	bl	400970 <malloc>
  400ab4:	aa0003e3 	mov	x3, x0
  400ab8:	b40000c0 	cbz	x0, 400ad0 <calloc+0x40>
  400abc:	f9400be2 	ldr	x2, [sp, #16]
  400ac0:	52800001 	mov	w1, #0x0                   	// #0
  400ac4:	f9000fe0 	str	x0, [sp, #24]
  400ac8:	94000232 	bl	401390 <memset>
  400acc:	f9400fe3 	ldr	x3, [sp, #24]
  400ad0:	aa0303e0 	mov	x0, x3
  400ad4:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400ad8:	d65f03c0 	ret
  400adc:	d2800003 	mov	x3, #0x0                   	// #0
  400ae0:	aa0303e0 	mov	x0, x3
  400ae4:	d65f03c0 	ret
  400ae8:	d503201f 	nop
  400aec:	d503201f 	nop

0000000000400af0 <realloc>:
  400af0:	b4000380 	cbz	x0, 400b60 <realloc+0x70>
  400af4:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400af8:	910003fd 	mov	x29, sp
  400afc:	b4000361 	cbz	x1, 400b68 <realloc+0x78>
  400b00:	f85f8002 	ldur	x2, [x0, #-8]
  400b04:	aa0003e3 	mov	x3, x0
  400b08:	aa0003e4 	mov	x4, x0
  400b0c:	eb02003f 	cmp	x1, x2
  400b10:	54000088 	b.hi	400b20 <realloc+0x30>  // b.pmore
  400b14:	aa0403e0 	mov	x0, x4
  400b18:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400b1c:	d65f03c0 	ret
  400b20:	aa0103e0 	mov	x0, x1
  400b24:	a9018fe2 	stp	x2, x3, [sp, #24]
  400b28:	97ffff92 	bl	400970 <malloc>
  400b2c:	aa0003e4 	mov	x4, x0
  400b30:	b4ffff20 	cbz	x0, 400b14 <realloc+0x24>
  400b34:	a9418fe2 	ldp	x2, x3, [sp, #24]
  400b38:	f9000fe3 	str	x3, [sp, #24]
  400b3c:	f90017e0 	str	x0, [sp, #40]
  400b40:	aa0303e1 	mov	x1, x3
  400b44:	940001ff 	bl	401340 <memcpy>
  400b48:	f9400fe0 	ldr	x0, [sp, #24]
  400b4c:	97ffffbd 	bl	400a40 <free>
  400b50:	f94017e4 	ldr	x4, [sp, #40]
  400b54:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400b58:	aa0403e0 	mov	x0, x4
  400b5c:	d65f03c0 	ret
  400b60:	aa0103e0 	mov	x0, x1
  400b64:	17ffff83 	b	400970 <malloc>
  400b68:	97ffffb6 	bl	400a40 <free>
  400b6c:	d2800004 	mov	x4, #0x0                   	// #0
  400b70:	17ffffe9 	b	400b14 <realloc+0x24>
  400b74:	d503201f 	nop
  400b78:	d503201f 	nop
  400b7c:	d503201f 	nop

0000000000400b80 <heap_stats>:
  400b80:	d65f03c0 	ret
	...

0000000000400b90 <__errno_location@GLIBC_2.2.5>:
  400b90:	f0000000 	adrp	x0, 403000 <g_env_count>
  400b94:	9100f000 	add	x0, x0, #0x3c
  400b98:	d65f03c0 	ret
  400b9c:	00000000 	udf	#0

0000000000400ba0 <strlen>:
  400ba0:	aa0003e2 	mov	x2, x0
  400ba4:	b4000120 	cbz	x0, 400bc8 <strlen+0x28>
  400ba8:	39400000 	ldrb	w0, [x0]
  400bac:	340000e0 	cbz	w0, 400bc8 <strlen+0x28>
  400bb0:	d2800000 	mov	x0, #0x0                   	// #0
  400bb4:	d503201f 	nop
  400bb8:	91000400 	add	x0, x0, #0x1
  400bbc:	38606841 	ldrb	w1, [x2, x0]
  400bc0:	35ffffc1 	cbnz	w1, 400bb8 <strlen+0x18>
  400bc4:	d65f03c0 	ret
  400bc8:	d2800000 	mov	x0, #0x0                   	// #0
  400bcc:	d65f03c0 	ret

0000000000400bd0 <strncpy>:
  400bd0:	f100001f 	cmp	x0, #0x0
  400bd4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400bd8:	54000220 	b.eq	400c1c <strncpy+0x4c>  // b.none
  400bdc:	d2800003 	mov	x3, #0x0                   	// #0
  400be0:	b50000c2 	cbnz	x2, 400bf8 <strncpy+0x28>
  400be4:	1400000e 	b	400c1c <strncpy+0x4c>
  400be8:	38236804 	strb	w4, [x0, x3]
  400bec:	91000463 	add	x3, x3, #0x1
  400bf0:	eb03005f 	cmp	x2, x3
  400bf4:	54000140 	b.eq	400c1c <strncpy+0x4c>  // b.none
  400bf8:	38636824 	ldrb	w4, [x1, x3]
  400bfc:	35ffff64 	cbnz	w4, 400be8 <strncpy+0x18>
  400c00:	eb03005f 	cmp	x2, x3
  400c04:	540000c9 	b.ls	400c1c <strncpy+0x4c>  // b.plast
  400c08:	8b030003 	add	x3, x0, x3
  400c0c:	8b020002 	add	x2, x0, x2
  400c10:	3800147f 	strb	wzr, [x3], #1
  400c14:	eb02007f 	cmp	x3, x2
  400c18:	54ffffc1 	b.ne	400c10 <strncpy+0x40>  // b.any
  400c1c:	d65f03c0 	ret

0000000000400c20 <strcpy>:
  400c20:	f100001f 	cmp	x0, #0x0
  400c24:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c28:	54000140 	b.eq	400c50 <strcpy+0x30>  // b.none
  400c2c:	39400023 	ldrb	w3, [x1]
  400c30:	34000123 	cbz	w3, 400c54 <strcpy+0x34>
  400c34:	d2800002 	mov	x2, #0x0                   	// #0
  400c38:	38226803 	strb	w3, [x0, x2]
  400c3c:	91000442 	add	x2, x2, #0x1
  400c40:	38626823 	ldrb	w3, [x1, x2]
  400c44:	35ffffa3 	cbnz	w3, 400c38 <strcpy+0x18>
  400c48:	8b020002 	add	x2, x0, x2
  400c4c:	3900005f 	strb	wzr, [x2]
  400c50:	d65f03c0 	ret
  400c54:	aa0003e2 	mov	x2, x0
  400c58:	3900005f 	strb	wzr, [x2]
  400c5c:	17fffffd 	b	400c50 <strcpy+0x30>

0000000000400c60 <strcmp>:
  400c60:	f100001f 	cmp	x0, #0x0
  400c64:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c68:	540001a0 	b.eq	400c9c <strcmp+0x3c>  // b.none
  400c6c:	39400002 	ldrb	w2, [x0]
  400c70:	350000a2 	cbnz	w2, 400c84 <strcmp+0x24>
  400c74:	1400000f 	b	400cb0 <strcmp+0x50>
  400c78:	38401c02 	ldrb	w2, [x0, #1]!
  400c7c:	34000142 	cbz	w2, 400ca4 <strcmp+0x44>
  400c80:	91000421 	add	x1, x1, #0x1
  400c84:	39400023 	ldrb	w3, [x1]
  400c88:	7100007f 	cmp	w3, #0x0
  400c8c:	7a421060 	ccmp	w3, w2, #0x0, ne	// ne = any
  400c90:	54ffff40 	b.eq	400c78 <strcmp+0x18>  // b.none
  400c94:	4b030040 	sub	w0, w2, w3
  400c98:	d65f03c0 	ret
  400c9c:	52800000 	mov	w0, #0x0                   	// #0
  400ca0:	d65f03c0 	ret
  400ca4:	39400423 	ldrb	w3, [x1, #1]
  400ca8:	4b030040 	sub	w0, w2, w3
  400cac:	17fffffb 	b	400c98 <strcmp+0x38>
  400cb0:	39400023 	ldrb	w3, [x1]
  400cb4:	4b030040 	sub	w0, w2, w3
  400cb8:	17fffff8 	b	400c98 <strcmp+0x38>
  400cbc:	d503201f 	nop

0000000000400cc0 <strncmp>:
  400cc0:	f100003f 	cmp	x1, #0x0
  400cc4:	d2800003 	mov	x3, #0x0                   	// #0
  400cc8:	fa401844 	ccmp	x2, #0x0, #0x4, ne	// ne = any
  400ccc:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
  400cd0:	54000081 	b.ne	400ce0 <strncmp+0x20>  // b.any
  400cd4:	52800004 	mov	w4, #0x0                   	// #0
  400cd8:	2a0403e0 	mov	w0, w4
  400cdc:	d65f03c0 	ret
  400ce0:	38636804 	ldrb	w4, [x0, x3]
  400ce4:	34000104 	cbz	w4, 400d04 <strncmp+0x44>
  400ce8:	38636825 	ldrb	w5, [x1, x3]
  400cec:	340000c5 	cbz	w5, 400d04 <strncmp+0x44>
  400cf0:	6b05009f 	cmp	w4, w5
  400cf4:	54000181 	b.ne	400d24 <strncmp+0x64>  // b.any
  400cf8:	91000463 	add	x3, x3, #0x1
  400cfc:	eb03005f 	cmp	x2, x3
  400d00:	54ffff08 	b.hi	400ce0 <strncmp+0x20>  // b.pmore
  400d04:	52800004 	mov	w4, #0x0                   	// #0
  400d08:	eb02007f 	cmp	x3, x2
  400d0c:	54fffe60 	b.eq	400cd8 <strncmp+0x18>  // b.none
  400d10:	38636804 	ldrb	w4, [x0, x3]
  400d14:	38636820 	ldrb	w0, [x1, x3]
  400d18:	4b000084 	sub	w4, w4, w0
  400d1c:	2a0403e0 	mov	w0, w4
  400d20:	d65f03c0 	ret
  400d24:	4b050084 	sub	w4, w4, w5
  400d28:	2a0403e0 	mov	w0, w4
  400d2c:	d65f03c0 	ret

0000000000400d30 <strcat>:
  400d30:	f100001f 	cmp	x0, #0x0
  400d34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d38:	54000041 	b.ne	400d40 <strcat+0x10>  // b.any
  400d3c:	d65f03c0 	ret
  400d40:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400d44:	910003fd 	mov	x29, sp
  400d48:	a90107e0 	stp	x0, x1, [sp, #16]
  400d4c:	97ffff95 	bl	400ba0 <strlen>
  400d50:	a94107e3 	ldp	x3, x1, [sp, #16]
  400d54:	39400022 	ldrb	w2, [x1]
  400d58:	8b000060 	add	x0, x3, x0
  400d5c:	34000082 	cbz	w2, 400d6c <strcat+0x3c>
  400d60:	38001402 	strb	w2, [x0], #1
  400d64:	38401c22 	ldrb	w2, [x1, #1]!
  400d68:	35ffffc2 	cbnz	w2, 400d60 <strcat+0x30>
  400d6c:	3900001f 	strb	wzr, [x0]
  400d70:	aa0303e0 	mov	x0, x3
  400d74:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400d78:	d65f03c0 	ret
  400d7c:	d503201f 	nop

0000000000400d80 <strchr>:
  400d80:	b4000120 	cbz	x0, 400da4 <strchr+0x24>
  400d84:	39400002 	ldrb	w2, [x0]
  400d88:	12001c21 	and	w1, w1, #0xff
  400d8c:	35000082 	cbnz	w2, 400d9c <strchr+0x1c>
  400d90:	14000006 	b	400da8 <strchr+0x28>
  400d94:	38401c02 	ldrb	w2, [x0, #1]!
  400d98:	34000082 	cbz	w2, 400da8 <strchr+0x28>
  400d9c:	6b01005f 	cmp	w2, w1
  400da0:	54ffffa1 	b.ne	400d94 <strchr+0x14>  // b.any
  400da4:	d65f03c0 	ret
  400da8:	7100003f 	cmp	w1, #0x0
  400dac:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
  400db0:	d65f03c0 	ret
  400db4:	d503201f 	nop
  400db8:	d503201f 	nop
  400dbc:	d503201f 	nop

0000000000400dc0 <strdup>:
  400dc0:	b4000300 	cbz	x0, 400e20 <strdup+0x60>
  400dc4:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400dc8:	910003fd 	mov	x29, sp
  400dcc:	f9000fe0 	str	x0, [sp, #24]
  400dd0:	97ffff74 	bl	400ba0 <strlen>
  400dd4:	91000403 	add	x3, x0, #0x1
  400dd8:	f9000be3 	str	x3, [sp, #16]
  400ddc:	aa0303e0 	mov	x0, x3
  400de0:	97fffee4 	bl	400970 <malloc>
  400de4:	b4000180 	cbz	x0, 400e14 <strdup+0x54>
  400de8:	a94113e3 	ldp	x3, x4, [sp, #16]
  400dec:	d2800001 	mov	x1, #0x0                   	// #0
  400df0:	b40000e3 	cbz	x3, 400e0c <strdup+0x4c>
  400df4:	d503201f 	nop
  400df8:	38616882 	ldrb	w2, [x4, x1]
  400dfc:	38216802 	strb	w2, [x0, x1]
  400e00:	91000421 	add	x1, x1, #0x1
  400e04:	eb01007f 	cmp	x3, x1
  400e08:	54ffff81 	b.ne	400df8 <strdup+0x38>  // b.any
  400e0c:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400e10:	d65f03c0 	ret
  400e14:	d2800000 	mov	x0, #0x0                   	// #0
  400e18:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400e1c:	d65f03c0 	ret
  400e20:	d2800000 	mov	x0, #0x0                   	// #0
  400e24:	d65f03c0 	ret
  400e28:	d503201f 	nop
  400e2c:	d503201f 	nop

0000000000400e30 <strstr>:
  400e30:	f100001f 	cmp	x0, #0x0
  400e34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400e38:	54000480 	b.eq	400ec8 <strstr+0x98>  // b.none
  400e3c:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400e40:	910003fd 	mov	x29, sp
  400e44:	a90153f3 	stp	x19, x20, [sp, #16]
  400e48:	aa0003f3 	mov	x19, x0
  400e4c:	39400022 	ldrb	w2, [x1]
  400e50:	35000082 	cbnz	w2, 400e60 <strstr+0x30>
  400e54:	a94153f3 	ldp	x19, x20, [sp, #16]
  400e58:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400e5c:	d65f03c0 	ret
  400e60:	aa0103f4 	mov	x20, x1
  400e64:	aa0103e0 	mov	x0, x1
  400e68:	f90013f5 	str	x21, [sp, #32]
  400e6c:	97ffff4d 	bl	400ba0 <strlen>
  400e70:	39400262 	ldrb	w2, [x19]
  400e74:	aa0003f5 	mov	x21, x0
  400e78:	35000082 	cbnz	w2, 400e88 <strstr+0x58>
  400e7c:	1400000e 	b	400eb4 <strstr+0x84>
  400e80:	38401e62 	ldrb	w2, [x19, #1]!
  400e84:	34000182 	cbz	w2, 400eb4 <strstr+0x84>
  400e88:	39400280 	ldrb	w0, [x20]
  400e8c:	6b02001f 	cmp	w0, w2
  400e90:	54ffff81 	b.ne	400e80 <strstr+0x50>  // b.any
  400e94:	aa1503e2 	mov	x2, x21
  400e98:	aa1403e1 	mov	x1, x20
  400e9c:	aa1303e0 	mov	x0, x19
  400ea0:	97ffff88 	bl	400cc0 <strncmp>
  400ea4:	35fffee0 	cbnz	w0, 400e80 <strstr+0x50>
  400ea8:	f94013f5 	ldr	x21, [sp, #32]
  400eac:	aa1303e0 	mov	x0, x19
  400eb0:	17ffffe9 	b	400e54 <strstr+0x24>
  400eb4:	f94013f5 	ldr	x21, [sp, #32]
  400eb8:	d2800000 	mov	x0, #0x0                   	// #0
  400ebc:	a94153f3 	ldp	x19, x20, [sp, #16]
  400ec0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400ec4:	d65f03c0 	ret
  400ec8:	d2800000 	mov	x0, #0x0                   	// #0
  400ecc:	d65f03c0 	ret

0000000000400ed0 <strtol>:
  400ed0:	91100006 	add	x6, x0, #0x400
  400ed4:	d29fffe5 	mov	x5, #0xffff                	// #65535
  400ed8:	eb05001f 	cmp	x0, x5
  400edc:	540000a8 	b.hi	400ef0 <strtol+0x20>  // b.pmore
  400ee0:	14000011 	b	400f24 <strtol+0x54>
  400ee4:	eb0300df 	cmp	x6, x3
  400ee8:	54000260 	b.eq	400f34 <strtol+0x64>  // b.none
  400eec:	aa0303e0 	mov	x0, x3
  400ef0:	39400004 	ldrb	w4, [x0]
  400ef4:	51002483 	sub	w3, w4, #0x9
  400ef8:	7100809f 	cmp	w4, #0x20
  400efc:	12001c63 	and	w3, w3, #0xff
  400f00:	7a441860 	ccmp	w3, #0x4, #0x0, ne	// ne = any
  400f04:	540001c8 	b.hi	400f3c <strtol+0x6c>  // b.pmore
  400f08:	91000403 	add	x3, x0, #0x1
  400f0c:	eb05007f 	cmp	x3, x5
  400f10:	54fffea8 	b.hi	400ee4 <strtol+0x14>  // b.pmore
  400f14:	b4000041 	cbz	x1, 400f1c <strtol+0x4c>
  400f18:	f9000023 	str	x3, [x1]
  400f1c:	d2800000 	mov	x0, #0x0                   	// #0
  400f20:	d65f03c0 	ret
  400f24:	b4ffffc1 	cbz	x1, 400f1c <strtol+0x4c>
  400f28:	f9000020 	str	x0, [x1]
  400f2c:	d2800000 	mov	x0, #0x0                   	// #0
  400f30:	17fffffc 	b	400f20 <strtol+0x50>
  400f34:	39400404 	ldrb	w4, [x0, #1]
  400f38:	aa0603e0 	mov	x0, x6
  400f3c:	7100ac9f 	cmp	w4, #0x2b
  400f40:	54000560 	b.eq	400fec <strtol+0x11c>  // b.none
  400f44:	7100b49f 	cmp	w4, #0x2d
  400f48:	540009e0 	b.eq	401084 <strtol+0x1b4>  // b.none
  400f4c:	350006e2 	cbnz	w2, 401028 <strtol+0x158>
  400f50:	7100c09f 	cmp	w4, #0x30
  400f54:	540005e1 	b.ne	401010 <strtol+0x140>  // b.any
  400f58:	39400404 	ldrb	w4, [x0, #1]
  400f5c:	121a7882 	and	w2, w4, #0xffffffdf
  400f60:	7101605f 	cmp	w2, #0x58
  400f64:	540019a0 	b.eq	401298 <strtol+0x3c8>  // b.none
  400f68:	91000400 	add	x0, x0, #0x1
  400f6c:	528000ea 	mov	w10, #0x7                   	// #7
  400f70:	92fe0008 	mov	x8, #0xfffffffffffffff     	// #1152921504606846975
  400f74:	52800102 	mov	w2, #0x8                   	// #8
  400f78:	d280002b 	mov	x11, #0x1                   	// #1
  400f7c:	d503201f 	nop
  400f80:	34fffd24 	cbz	w4, 400f24 <strtol+0x54>
  400f84:	93407c49 	sxtw	x9, w2
  400f88:	52800007 	mov	w7, #0x0                   	// #0
  400f8c:	d2800005 	mov	x5, #0x0                   	// #0
  400f90:	14000008 	b	400fb0 <strtol+0xe0>
  400f94:	7a4a0064 	ccmp	w3, w10, #0x4, eq	// eq = none
  400f98:	1a9fd7e4 	cset	w4, gt
  400f9c:	2a0400e7 	orr	w7, w7, w4
  400fa0:	38401c04 	ldrb	w4, [x0, #1]!
  400fa4:	93407c63 	sxtw	x3, w3
  400fa8:	9b050d25 	madd	x5, x9, x5, x3
  400fac:	340005a4 	cbz	w4, 401060 <strtol+0x190>
  400fb0:	5100c083 	sub	w3, w4, #0x30
  400fb4:	12001c66 	and	w6, w3, #0xff
  400fb8:	710024df 	cmp	w6, #0x9
  400fbc:	540000c9 	b.ls	400fd4 <strtol+0x104>  // b.plast
  400fc0:	51018483 	sub	w3, w4, #0x61
  400fc4:	12001c63 	and	w3, w3, #0xff
  400fc8:	7100647f 	cmp	w3, #0x19
  400fcc:	540003e8 	b.hi	401048 <strtol+0x178>  // b.pmore
  400fd0:	51015c83 	sub	w3, w4, #0x57
  400fd4:	6b03005f 	cmp	w2, w3
  400fd8:	5400044d 	b.le	401060 <strtol+0x190>
  400fdc:	eb05011f 	cmp	x8, x5
  400fe0:	54fffda2 	b.cs	400f94 <strtol+0xc4>  // b.hs, b.nlast
  400fe4:	52800027 	mov	w7, #0x1                   	// #1
  400fe8:	17ffffee 	b	400fa0 <strtol+0xd0>
  400fec:	91000403 	add	x3, x0, #0x1
  400ff0:	d29fffe4 	mov	x4, #0xffff                	// #65535
  400ff4:	eb04007f 	cmp	x3, x4
  400ff8:	54fff8e9 	b.ls	400f14 <strtol+0x44>  // b.plast
  400ffc:	35000682 	cbnz	w2, 4010cc <strtol+0x1fc>
  401000:	39400404 	ldrb	w4, [x0, #1]
  401004:	7100c09f 	cmp	w4, #0x30
  401008:	54000aa0 	b.eq	40115c <strtol+0x28c>  // b.none
  40100c:	aa0303e0 	mov	x0, x3
  401010:	b202e7e8 	mov	x8, #0xcccccccccccccccc    	// #-3689348814741910324
  401014:	528000ea 	mov	w10, #0x7                   	// #7
  401018:	f2e19988 	movk	x8, #0xccc, lsl #48
  40101c:	52800142 	mov	w2, #0xa                   	// #10
  401020:	d280002b 	mov	x11, #0x1                   	// #1
  401024:	17ffffd7 	b	400f80 <strtol+0xb0>
  401028:	7100405f 	cmp	w2, #0x10
  40102c:	540006c0 	b.eq	401104 <strtol+0x234>  // b.none
  401030:	93407c4a 	sxtw	x10, w2
  401034:	92f00003 	mov	x3, #0x7fffffffffffffff    	// #9223372036854775807
  401038:	d280002b 	mov	x11, #0x1                   	// #1
  40103c:	9aca0868 	udiv	x8, x3, x10
  401040:	1b0a8d0a 	msub	w10, w8, w10, w3
  401044:	17ffffcf 	b	400f80 <strtol+0xb0>
  401048:	51010483 	sub	w3, w4, #0x41
  40104c:	12001c63 	and	w3, w3, #0xff
  401050:	7100647f 	cmp	w3, #0x19
  401054:	54000068 	b.hi	401060 <strtol+0x190>  // b.pmore
  401058:	5100dc83 	sub	w3, w4, #0x37
  40105c:	17ffffde 	b	400fd4 <strtol+0x104>
  401060:	b4000041 	cbz	x1, 401068 <strtol+0x198>
  401064:	f9000020 	str	x0, [x1]
  401068:	35000067 	cbnz	w7, 401074 <strtol+0x1a4>
  40106c:	9b0b7ca0 	mul	x0, x5, x11
  401070:	d65f03c0 	ret
  401074:	7100057f 	cmp	w11, #0x1
  401078:	da9f13e0 	csetm	x0, eq	// eq = none
  40107c:	d2410000 	eor	x0, x0, #0x8000000000000000
  401080:	d65f03c0 	ret
  401084:	91000405 	add	x5, x0, #0x1
  401088:	d29fffe3 	mov	x3, #0xffff                	// #65535
  40108c:	eb0300bf 	cmp	x5, x3
  401090:	54000329 	b.ls	4010f4 <strtol+0x224>  // b.plast
  401094:	34000442 	cbz	w2, 40111c <strtol+0x24c>
  401098:	7100405f 	cmp	w2, #0x10
  40109c:	54000880 	b.eq	4011ac <strtol+0x2dc>  // b.none
  4010a0:	93407c43 	sxtw	x3, w2
  4010a4:	92f00004 	mov	x4, #0x7fffffffffffffff    	// #9223372036854775807
  4010a8:	9ac30888 	udiv	x8, x4, x3
  4010ac:	9b039103 	msub	x3, x8, x3, x4
  4010b0:	1100046a 	add	w10, w3, #0x1
  4010b4:	6b0a005f 	cmp	w2, w10
  4010b8:	5400046d 	b.le	401144 <strtol+0x274>
  4010bc:	39400404 	ldrb	w4, [x0, #1]
  4010c0:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4010c4:	aa0503e0 	mov	x0, x5
  4010c8:	17ffffae 	b	400f80 <strtol+0xb0>
  4010cc:	7100405f 	cmp	w2, #0x10
  4010d0:	540005e0 	b.eq	40118c <strtol+0x2bc>  // b.none
  4010d4:	93407c4a 	sxtw	x10, w2
  4010d8:	92f00004 	mov	x4, #0x7fffffffffffffff    	// #9223372036854775807
  4010dc:	d280002b 	mov	x11, #0x1                   	// #1
  4010e0:	9aca0888 	udiv	x8, x4, x10
  4010e4:	1b0a910a 	msub	w10, w8, w10, w4
  4010e8:	39400404 	ldrb	w4, [x0, #1]
  4010ec:	aa0303e0 	mov	x0, x3
  4010f0:	17ffffa4 	b	400f80 <strtol+0xb0>
  4010f4:	b4fff141 	cbz	x1, 400f1c <strtol+0x4c>
  4010f8:	d2800000 	mov	x0, #0x0                   	// #0
  4010fc:	f9000025 	str	x5, [x1]
  401100:	17ffff88 	b	400f20 <strtol+0x50>
  401104:	7100c09f 	cmp	w4, #0x30
  401108:	54000620 	b.eq	4011cc <strtol+0x2fc>  // b.none
  40110c:	528001ea 	mov	w10, #0xf                   	// #15
  401110:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401114:	d280002b 	mov	x11, #0x1                   	// #1
  401118:	17ffff9a 	b	400f80 <strtol+0xb0>
  40111c:	39400404 	ldrb	w4, [x0, #1]
  401120:	7100c09f 	cmp	w4, #0x30
  401124:	54000660 	b.eq	4011f0 <strtol+0x320>  // b.none
  401128:	b202e7e8 	mov	x8, #0xcccccccccccccccc    	// #-3689348814741910324
  40112c:	aa0503e0 	mov	x0, x5
  401130:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401134:	52800142 	mov	w2, #0xa                   	// #10
  401138:	5280010a 	mov	w10, #0x8                   	// #8
  40113c:	f2e19988 	movk	x8, #0xccc, lsl #48
  401140:	17ffff90 	b	400f80 <strtol+0xb0>
  401144:	39400404 	ldrb	w4, [x0, #1]
  401148:	91000508 	add	x8, x8, #0x1
  40114c:	4b02014a 	sub	w10, w10, w2
  401150:	aa0503e0 	mov	x0, x5
  401154:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401158:	17ffff8a 	b	400f80 <strtol+0xb0>
  40115c:	39400804 	ldrb	w4, [x0, #2]
  401160:	121a7882 	and	w2, w4, #0xffffffdf
  401164:	12001c42 	and	w2, w2, #0xff
  401168:	7101605f 	cmp	w2, #0x58
  40116c:	54000641 	b.ne	401234 <strtol+0x364>  // b.any
  401170:	39400c04 	ldrb	w4, [x0, #3]
  401174:	528001ea 	mov	w10, #0xf                   	// #15
  401178:	91000c00 	add	x0, x0, #0x3
  40117c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401180:	52800202 	mov	w2, #0x10                  	// #16
  401184:	d280002b 	mov	x11, #0x1                   	// #1
  401188:	17ffff7e 	b	400f80 <strtol+0xb0>
  40118c:	39400404 	ldrb	w4, [x0, #1]
  401190:	7100c09f 	cmp	w4, #0x30
  401194:	540005c0 	b.eq	40124c <strtol+0x37c>  // b.none
  401198:	aa0303e0 	mov	x0, x3
  40119c:	528001ea 	mov	w10, #0xf                   	// #15
  4011a0:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4011a4:	d280002b 	mov	x11, #0x1                   	// #1
  4011a8:	17ffff76 	b	400f80 <strtol+0xb0>
  4011ac:	39400404 	ldrb	w4, [x0, #1]
  4011b0:	7100c09f 	cmp	w4, #0x30
  4011b4:	54000800 	b.eq	4012b4 <strtol+0x3e4>  // b.none
  4011b8:	aa0503e0 	mov	x0, x5
  4011bc:	5280000a 	mov	w10, #0x0                   	// #0
  4011c0:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4011c4:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4011c8:	17ffff6e 	b	400f80 <strtol+0xb0>
  4011cc:	39400403 	ldrb	w3, [x0, #1]
  4011d0:	121a7863 	and	w3, w3, #0xffffffdf
  4011d4:	12001c63 	and	w3, w3, #0xff
  4011d8:	7101607f 	cmp	w3, #0x58
  4011dc:	540004c0 	b.eq	401274 <strtol+0x3a4>  // b.none
  4011e0:	d280002b 	mov	x11, #0x1                   	// #1
  4011e4:	528001ea 	mov	w10, #0xf                   	// #15
  4011e8:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4011ec:	17ffff66 	b	400f84 <strtol+0xb4>
  4011f0:	39400804 	ldrb	w4, [x0, #2]
  4011f4:	121a7882 	and	w2, w4, #0xffffffdf
  4011f8:	7101605f 	cmp	w2, #0x58
  4011fc:	540000e0 	b.eq	401218 <strtol+0x348>  // b.none
  401200:	91000800 	add	x0, x0, #0x2
  401204:	5280000a 	mov	w10, #0x0                   	// #0
  401208:	d2e20008 	mov	x8, #0x1000000000000000    	// #1152921504606846976
  40120c:	52800102 	mov	w2, #0x8                   	// #8
  401210:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401214:	17ffff5b 	b	400f80 <strtol+0xb0>
  401218:	39400c04 	ldrb	w4, [x0, #3]
  40121c:	5280000a 	mov	w10, #0x0                   	// #0
  401220:	91000c00 	add	x0, x0, #0x3
  401224:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  401228:	52800202 	mov	w2, #0x10                  	// #16
  40122c:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401230:	17ffff54 	b	400f80 <strtol+0xb0>
  401234:	91000800 	add	x0, x0, #0x2
  401238:	528000ea 	mov	w10, #0x7                   	// #7
  40123c:	92fe0008 	mov	x8, #0xfffffffffffffff     	// #1152921504606846975
  401240:	52800102 	mov	w2, #0x8                   	// #8
  401244:	d280002b 	mov	x11, #0x1                   	// #1
  401248:	17ffff4e 	b	400f80 <strtol+0xb0>
  40124c:	39400805 	ldrb	w5, [x0, #2]
  401250:	121a78a5 	and	w5, w5, #0xffffffdf
  401254:	12001ca5 	and	w5, w5, #0xff
  401258:	710160bf 	cmp	w5, #0x58
  40125c:	54000120 	b.eq	401280 <strtol+0x3b0>  // b.none
  401260:	aa0303e0 	mov	x0, x3
  401264:	d280002b 	mov	x11, #0x1                   	// #1
  401268:	528001ea 	mov	w10, #0xf                   	// #15
  40126c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401270:	17ffff45 	b	400f84 <strtol+0xb4>
  401274:	39400804 	ldrb	w4, [x0, #2]
  401278:	91000800 	add	x0, x0, #0x2
  40127c:	17ffffa4 	b	40110c <strtol+0x23c>
  401280:	39400c04 	ldrb	w4, [x0, #3]
  401284:	528001ea 	mov	w10, #0xf                   	// #15
  401288:	91000c00 	add	x0, x0, #0x3
  40128c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401290:	d280002b 	mov	x11, #0x1                   	// #1
  401294:	17ffff3b 	b	400f80 <strtol+0xb0>
  401298:	39400804 	ldrb	w4, [x0, #2]
  40129c:	528001ea 	mov	w10, #0xf                   	// #15
  4012a0:	91000800 	add	x0, x0, #0x2
  4012a4:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4012a8:	52800202 	mov	w2, #0x10                  	// #16
  4012ac:	d280002b 	mov	x11, #0x1                   	// #1
  4012b0:	17ffff34 	b	400f80 <strtol+0xb0>
  4012b4:	39400803 	ldrb	w3, [x0, #2]
  4012b8:	121a7863 	and	w3, w3, #0xffffffdf
  4012bc:	12001c63 	and	w3, w3, #0xff
  4012c0:	7101607f 	cmp	w3, #0x58
  4012c4:	540000e1 	b.ne	4012e0 <strtol+0x410>  // b.any
  4012c8:	39400c04 	ldrb	w4, [x0, #3]
  4012cc:	5280000a 	mov	w10, #0x0                   	// #0
  4012d0:	91000c00 	add	x0, x0, #0x3
  4012d4:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4012d8:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4012dc:	17ffff29 	b	400f80 <strtol+0xb0>
  4012e0:	aa0503e0 	mov	x0, x5
  4012e4:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4012e8:	5280000a 	mov	w10, #0x0                   	// #0
  4012ec:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4012f0:	17ffff25 	b	400f84 <strtol+0xb4>
  4012f4:	d503201f 	nop
  4012f8:	d503201f 	nop
  4012fc:	d503201f 	nop

0000000000401300 <__isoc23_strtol>:
  401300:	17fffef4 	b	400ed0 <strtol>
  401304:	d503201f 	nop
  401308:	d503201f 	nop
  40130c:	d503201f 	nop

0000000000401310 <atoi>:
  401310:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  401314:	52800142 	mov	w2, #0xa                   	// #10
  401318:	d2800001 	mov	x1, #0x0                   	// #0
  40131c:	910003fd 	mov	x29, sp
  401320:	97fffeec 	bl	400ed0 <strtol>
  401324:	a8c17bfd 	ldp	x29, x30, [sp], #16
  401328:	d65f03c0 	ret
  40132c:	d503201f 	nop

0000000000401330 <atol>:
  401330:	52800142 	mov	w2, #0xa                   	// #10
  401334:	d2800001 	mov	x1, #0x0                   	// #0
  401338:	17fffee6 	b	400ed0 <strtol>
  40133c:	d503201f 	nop

0000000000401340 <memcpy>:
  401340:	f100005f 	cmp	x2, #0x0
  401344:	d29fffe3 	mov	x3, #0xffff                	// #65535
  401348:	fa431020 	ccmp	x1, x3, #0x0, ne	// ne = any
  40134c:	fa438000 	ccmp	x0, x3, #0x0, hi	// hi = pmore
  401350:	54000048 	b.hi	401358 <memcpy+0x18>  // b.pmore
  401354:	d65f03c0 	ret
  401358:	d2800003 	mov	x3, #0x0                   	// #0
  40135c:	d503201f 	nop
  401360:	38636824 	ldrb	w4, [x1, x3]
  401364:	38236804 	strb	w4, [x0, x3]
  401368:	91000463 	add	x3, x3, #0x1
  40136c:	eb03005f 	cmp	x2, x3
  401370:	54ffff88 	b.hi	401360 <memcpy+0x20>  // b.pmore
  401374:	d65f03c0 	ret
  401378:	d503201f 	nop
  40137c:	d503201f 	nop

0000000000401380 <__memcpy_chk>:
  401380:	17fffff0 	b	401340 <memcpy>
  401384:	d503201f 	nop
  401388:	d503201f 	nop
  40138c:	d503201f 	nop

0000000000401390 <memset>:
  401390:	aa0003e3 	mov	x3, x0
  401394:	d29fffe4 	mov	x4, #0xffff                	// #65535
  401398:	eb04001f 	cmp	x0, x4
  40139c:	540000c9 	b.ls	4013b4 <memset+0x24>  // b.plast
  4013a0:	b40000a2 	cbz	x2, 4013b4 <memset+0x24>
  4013a4:	8b020002 	add	x2, x0, x2
  4013a8:	38001461 	strb	w1, [x3], #1
  4013ac:	eb02007f 	cmp	x3, x2
  4013b0:	54ffffc1 	b.ne	4013a8 <memset+0x18>  // b.any
  4013b4:	d65f03c0 	ret
  4013b8:	d503201f 	nop
  4013bc:	d503201f 	nop

00000000004013c0 <memcmp>:
  4013c0:	f100001f 	cmp	x0, #0x0
  4013c4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4013c8:	540001a0 	b.eq	4013fc <memcmp+0x3c>  // b.none
  4013cc:	b4000182 	cbz	x2, 4013fc <memcmp+0x3c>
  4013d0:	d2800003 	mov	x3, #0x0                   	// #0
  4013d4:	14000004 	b	4013e4 <memcmp+0x24>
  4013d8:	91000463 	add	x3, x3, #0x1
  4013dc:	eb03005f 	cmp	x2, x3
  4013e0:	540000e0 	b.eq	4013fc <memcmp+0x3c>  // b.none
  4013e4:	38636804 	ldrb	w4, [x0, x3]
  4013e8:	38636825 	ldrb	w5, [x1, x3]
  4013ec:	6b05009f 	cmp	w4, w5
  4013f0:	54ffff40 	b.eq	4013d8 <memcmp+0x18>  // b.none
  4013f4:	4b050080 	sub	w0, w4, w5
  4013f8:	d65f03c0 	ret
  4013fc:	52800000 	mov	w0, #0x0                   	// #0
  401400:	d65f03c0 	ret
  401404:	d503201f 	nop
  401408:	d503201f 	nop
  40140c:	d503201f 	nop

0000000000401410 <memmove>:
  401410:	f100001f 	cmp	x0, #0x0
  401414:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401418:	540001e0 	b.eq	401454 <memmove+0x44>  // b.none
  40141c:	d29fffe3 	mov	x3, #0xffff                	// #65535
  401420:	eb03001f 	cmp	x0, x3
  401424:	fa438020 	ccmp	x1, x3, #0x0, hi	// hi = pmore
  401428:	54000169 	b.ls	401454 <memmove+0x44>  // b.plast
  40142c:	eb01001f 	cmp	x0, x1
  401430:	54000142 	b.cs	401458 <memmove+0x48>  // b.hs, b.nlast
  401434:	b4000102 	cbz	x2, 401454 <memmove+0x44>
  401438:	d2800003 	mov	x3, #0x0                   	// #0
  40143c:	d503201f 	nop
  401440:	38636824 	ldrb	w4, [x1, x3]
  401444:	38236804 	strb	w4, [x0, x3]
  401448:	91000463 	add	x3, x3, #0x1
  40144c:	eb03005f 	cmp	x2, x3
  401450:	54ffff81 	b.ne	401440 <memmove+0x30>  // b.any
  401454:	d65f03c0 	ret
  401458:	b4ffffe2 	cbz	x2, 401454 <memmove+0x44>
  40145c:	d1000442 	sub	x2, x2, #0x1
  401460:	38626823 	ldrb	w3, [x1, x2]
  401464:	38226803 	strb	w3, [x0, x2]
  401468:	17fffffc 	b	401458 <memmove+0x48>
