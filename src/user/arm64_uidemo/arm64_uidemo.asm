
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
  400024:	94000137 	bl	400500 <__libc_init_environ>
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
  400060:	90000000 	adrp	x0, 400000 <_start>
  400064:	d2800048 	mov	x8, #0x2                   	// #2
  400068:	d2800002 	mov	x2, #0x0                   	// #0
  40006c:	aa0803e1 	mov	x1, x8
  400070:	f940b000 	ldr	x0, [x0, #352]
  400074:	d4000001 	svc	#0x0
  400078:	aa0003e4 	mov	x4, x0
  40007c:	b6f80080 	tbz	x0, #63, 40008c <main+0x2c>
  400080:	d2800788 	mov	x8, #0x3c                  	// #60
  400084:	d2800020 	mov	x0, #0x1                   	// #1
  400088:	d4000001 	svc	#0x0
  40008c:	93407c84 	sxtw	x4, w4
  400090:	d2800128 	mov	x8, #0x9                   	// #9
  400094:	d2800000 	mov	x0, #0x0                   	// #0
  400098:	d2a00601 	mov	x1, #0x300000              	// #3145728
  40009c:	d2800042 	mov	x2, #0x2                   	// #2
  4000a0:	d2800023 	mov	x3, #0x1                   	// #1
  4000a4:	d2800005 	mov	x5, #0x0                   	// #0
  4000a8:	d4000001 	svc	#0x0
  4000ac:	aa0003e3 	mov	x3, x0
  4000b0:	b140041f 	cmn	x0, #0x1, lsl #12
  4000b4:	540000e9 	b.ls	4000d0 <main+0x70>  // b.plast
  4000b8:	d2800068 	mov	x8, #0x3                   	// #3
  4000bc:	aa0403e0 	mov	x0, x4
  4000c0:	d4000001 	svc	#0x0
  4000c4:	d2800788 	mov	x8, #0x3c                  	// #60
  4000c8:	aa0203e0 	mov	x0, x2
  4000cc:	d4000001 	svc	#0x0
  4000d0:	5282eb26 	mov	w6, #0x1759                	// #5977
  4000d4:	52800001 	mov	w1, #0x0                   	// #0
  4000d8:	12800007 	mov	w7, #0xffffffff            	// #-1
  4000dc:	72ba36e6 	movk	w6, #0xd1b7, lsl #16
  4000e0:	5284e205 	mov	w5, #0x2710                	// #10000
  4000e4:	14000005 	b	4000f8 <main+0x98>
  4000e8:	11000421 	add	w1, w1, #0x1
  4000ec:	91001063 	add	x3, x3, #0x4
  4000f0:	7143003f 	cmp	w1, #0xc0, lsl #12
  4000f4:	540001c0 	b.eq	40012c <main+0xcc>  // b.none
  4000f8:	9ba67c22 	umull	x2, w1, w6
  4000fc:	b9000067 	str	w7, [x3]
  400100:	d36dfc42 	lsr	x2, x2, #45
  400104:	1b058442 	msub	w2, w2, w5, w1
  400108:	7100005f 	cmp	w2, #0x0
  40010c:	7a400824 	ccmp	w1, #0x0, #0x4, eq	// eq = none
  400110:	54fffec0 	b.eq	4000e8 <main+0x88>  // b.none
  400114:	d2800308 	mov	x8, #0x18                  	// #24
  400118:	d4000001 	svc	#0x0
  40011c:	11000421 	add	w1, w1, #0x1
  400120:	91001063 	add	x3, x3, #0x4
  400124:	7143003f 	cmp	w1, #0xc0, lsl #12
  400128:	54fffe81 	b.ne	4000f8 <main+0x98>  // b.any
  40012c:	d2800208 	mov	x8, #0x10                  	// #16
  400130:	aa0403e0 	mov	x0, x4
  400134:	d288c061 	mov	x1, #0x4603                	// #17923
  400138:	d2800002 	mov	x2, #0x0                   	// #0
  40013c:	d4000001 	svc	#0x0
  400140:	d2800068 	mov	x8, #0x3                   	// #3
  400144:	aa0403e0 	mov	x0, x4
  400148:	d4000001 	svc	#0x0
  40014c:	d2800788 	mov	x8, #0x3c                  	// #60
  400150:	d2800000 	mov	x0, #0x0                   	// #0
  400154:	d4000001 	svc	#0x0
  400158:	52800000 	mov	w0, #0x0                   	// #0
  40015c:	d65f03c0 	ret
  400160:	00402000 	.word	0x00402000
	...

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
  400208:	b40015c0 	cbz	x0, 4004c0 <set_pair+0x2c0>
  40020c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400210:	aa0003f5 	mov	x21, x0
  400214:	a90363f7 	stp	x23, x24, [sp, #48]
  400218:	aa0103f7 	mov	x23, x1
  40021c:	39400001 	ldrb	w1, [x0]
  400220:	340015a1 	cbz	w1, 4004d4 <set_pair+0x2d4>
  400224:	aa0303f6 	mov	x22, x3
  400228:	528007a1 	mov	w1, #0x3d                  	// #61
  40022c:	a9046bf9 	stp	x25, x26, [sp, #64]
  400230:	2a0203f9 	mov	w25, w2
  400234:	94000293 	bl	400c80 <strchr>
  400238:	b50013e0 	cbnz	x0, 4004b4 <set_pair+0x2b4>
  40023c:	f10002ff 	cmp	x23, #0x0
  400240:	d0000000 	adrp	x0, 402000 <memmove+0xcf0>
  400244:	91002000 	add	x0, x0, #0x8
  400248:	a90153f3 	stp	x19, x20, [sp, #16]
  40024c:	9a970017 	csel	x23, x0, x23, eq	// eq = none
  400250:	aa1503e0 	mov	x0, x21
  400254:	94000213 	bl	400aa0 <strlen>
  400258:	aa1603f4 	mov	x20, x22
  40025c:	aa0003f3 	mov	x19, x0
  400260:	aa1703e0 	mov	x0, x23
  400264:	9400020f 	bl	400aa0 <strlen>
  400268:	aa0003f8 	mov	x24, x0
  40026c:	b4000496 	cbz	x22, 4002fc <set_pair+0xfc>
  400270:	f0000013 	adrp	x19, 403000 <g_env_count>
  400274:	91000277 	add	x23, x19, #0x0
  400278:	910042e9 	add	x9, x23, #0x10
  40027c:	52800022 	mov	w2, #0x1                   	// #1
  400280:	085ffd21 	ldaxrb	w1, [x9]
  400284:	08037d22 	stxrb	w3, w2, [x9]
  400288:	35ffffc3 	cbnz	w3, 400280 <set_pair+0x80>
  40028c:	3707ffa1 	tbnz	w1, #0, 400280 <set_pair+0x80>
  400290:	aa1503e0 	mov	x0, x21
  400294:	97ffffb7 	bl	400170 <find_index>
  400298:	2a2003e2 	mvn	w2, w0
  40029c:	52000321 	eor	w1, w25, #0x1
  4002a0:	6a427c3f 	tst	w1, w2, lsr #31
  4002a4:	54000741 	b.ne	40038c <set_pair+0x18c>  // b.any
  4002a8:	37f80580 	tbnz	w0, #31, 400358 <set_pair+0x158>
  4002ac:	f94006e2 	ldr	x2, [x23, #8]
  4002b0:	d37d7c15 	ubfiz	x21, x0, #3, #32
  4002b4:	8b150041 	add	x1, x2, x21
  4002b8:	f8605840 	ldr	x0, [x2, w0, uxtw #3]
  4002bc:	eb14001f 	cmp	x0, x20
  4002c0:	54000080 	b.eq	4002d0 <set_pair+0xd0>  // b.none
  4002c4:	9400019f 	bl	400940 <free>
  4002c8:	f94006e1 	ldr	x1, [x23, #8]
  4002cc:	8b150021 	add	x1, x1, x21
  4002d0:	f9000034 	str	x20, [x1]
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
  400308:	54000c43 	b.cc	400490 <set_pair+0x290>  // b.lo, b.ul, b.last
  40030c:	8b180260 	add	x0, x19, x24
  400310:	aa0003fa 	mov	x26, x0
  400314:	91000800 	add	x0, x0, #0x2
  400318:	94000156 	bl	400870 <malloc>
  40031c:	aa0003f4 	mov	x20, x0
  400320:	b4000b80 	cbz	x0, 400490 <set_pair+0x290>
  400324:	aa1303e2 	mov	x2, x19
  400328:	aa1503e1 	mov	x1, x21
  40032c:	940003c5 	bl	401240 <memcpy>
  400330:	528007a0 	mov	w0, #0x3d                  	// #61
  400334:	38336a80 	strb	w0, [x20, x19]
  400338:	91000660 	add	x0, x19, #0x1
  40033c:	aa1803e2 	mov	x2, x24
  400340:	aa1703e1 	mov	x1, x23
  400344:	8b000280 	add	x0, x20, x0
  400348:	940003be 	bl	401240 <memcpy>
  40034c:	8b1a0280 	add	x0, x20, x26
  400350:	3900041f 	strb	wzr, [x0, #1]
  400354:	17ffffc7 	b	400270 <set_pair+0x70>
  400358:	f9400262 	ldr	x2, [x19]
  40035c:	f9400ef8 	ldr	x24, [x23, #24]
  400360:	91000840 	add	x0, x2, #0x2
  400364:	eb18001f 	cmp	x0, x24
  400368:	540001c8 	b.hi	4003a0 <set_pair+0x1a0>  // b.pmore
  40036c:	f94006f5 	ldr	x21, [x23, #8]
  400370:	b40007f5 	cbz	x21, 40046c <set_pair+0x26c>
  400374:	91000440 	add	x0, x2, #0x1
  400378:	f8227ab4 	str	x20, [x21, x2, lsl #3]
  40037c:	8b020ea2 	add	x2, x21, x2, lsl #3
  400380:	f9000260 	str	x0, [x19]
  400384:	f900045f 	str	xzr, [x2, #8]
  400388:	17ffffd3 	b	4002d4 <set_pair+0xd4>
  40038c:	089ffd3f 	stlrb	wzr, [x9]
  400390:	b5fffa96 	cbnz	x22, 4002e0 <set_pair+0xe0>
  400394:	aa1403e0 	mov	x0, x20
  400398:	9400016a 	bl	400940 <free>
  40039c:	17ffffd1 	b	4002e0 <set_pair+0xe0>
  4003a0:	b4000698 	cbz	x24, 400470 <set_pair+0x270>
  4003a4:	d503201f 	nop
  4003a8:	b7f806d8 	tbnz	x24, #63, 400480 <set_pair+0x280>
  4003ac:	8b180318 	add	x24, x24, x24
  4003b0:	eb18001f 	cmp	x0, x24
  4003b4:	54ffffa8 	b.hi	4003a8 <set_pair+0x1a8>  // b.pmore
  4003b8:	d37df317 	lsl	x23, x24, #3
  4003bc:	aa1703e0 	mov	x0, x23
  4003c0:	9400012c 	bl	400870 <malloc>
  4003c4:	aa0003f5 	mov	x21, x0
  4003c8:	b40005c0 	cbz	x0, 400480 <set_pair+0x280>
  4003cc:	f9400263 	ldr	x3, [x19]
  4003d0:	91000260 	add	x0, x19, #0x0
  4003d4:	f9400400 	ldr	x0, [x0, #8]
  4003d8:	b4000843 	cbz	x3, 4004e0 <set_pair+0x2e0>
  4003dc:	d2800002 	mov	x2, #0x0                   	// #0
  4003e0:	b4000340 	cbz	x0, 400448 <set_pair+0x248>
  4003e4:	d503201f 	nop
  4003e8:	f8627804 	ldr	x4, [x0, x2, lsl #3]
  4003ec:	f8227aa4 	str	x4, [x21, x2, lsl #3]
  4003f0:	91000442 	add	x2, x2, #0x1
  4003f4:	eb03005f 	cmp	x2, x3
  4003f8:	54ffff81 	b.ne	4003e8 <set_pair+0x1e8>  // b.any
  4003fc:	8b030ea2 	add	x2, x21, x3, lsl #3
  400400:	91000463 	add	x3, x3, #0x1
  400404:	f900005f 	str	xzr, [x2]
  400408:	8b1502e4 	add	x4, x23, x21
  40040c:	8b030ea2 	add	x2, x21, x3, lsl #3
  400410:	eb03031f 	cmp	x24, x3
  400414:	54000089 	b.ls	400424 <set_pair+0x224>  // b.plast
  400418:	f800845f 	str	xzr, [x2], #8
  40041c:	eb04005f 	cmp	x2, x4
  400420:	54ffffc1 	b.ne	400418 <set_pair+0x218>  // b.any
  400424:	94000147 	bl	400940 <free>
  400428:	d0000002 	adrp	x2, 402000 <memmove+0xcf0>
  40042c:	f9400c42 	ldr	x2, [x2, #24]
  400430:	91000260 	add	x0, x19, #0x0
  400434:	f9000055 	str	x21, [x2]
  400438:	f9400262 	ldr	x2, [x19]
  40043c:	f9000415 	str	x21, [x0, #8]
  400440:	f9000c18 	str	x24, [x0, #24]
  400444:	17ffffcc 	b	400374 <set_pair+0x174>
  400448:	91000444 	add	x4, x2, #0x1
  40044c:	f8227abf 	str	xzr, [x21, x2, lsl #3]
  400450:	eb04007f 	cmp	x3, x4
  400454:	54fffd40 	b.eq	4003fc <set_pair+0x1fc>  // b.none
  400458:	91000842 	add	x2, x2, #0x2
  40045c:	f8247abf 	str	xzr, [x21, x4, lsl #3]
  400460:	eb03005f 	cmp	x2, x3
  400464:	54ffff21 	b.ne	400448 <set_pair+0x248>  // b.any
  400468:	17ffffe5 	b	4003fc <set_pair+0x1fc>
  40046c:	b5fffa78 	cbnz	x24, 4003b8 <set_pair+0x1b8>
  400470:	d2800118 	mov	x24, #0x8                   	// #8
  400474:	f100201f 	cmp	x0, #0x8
  400478:	54fff988 	b.hi	4003a8 <set_pair+0x1a8>  // b.pmore
  40047c:	17ffffcf 	b	4003b8 <set_pair+0x1b8>
  400480:	91000260 	add	x0, x19, #0x0
  400484:	91004000 	add	x0, x0, #0x10
  400488:	089ffc1f 	stlrb	wzr, [x0]
  40048c:	b4000316 	cbz	x22, 4004ec <set_pair+0x2ec>
  400490:	94000180 	bl	400a90 <__errno_location@GLIBC_2.2.5>
  400494:	52800181 	mov	w1, #0xc                   	// #12
  400498:	b9000001 	str	w1, [x0]
  40049c:	12800000 	mov	w0, #0xffffffff            	// #-1
  4004a0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4004a4:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4004a8:	a94363f7 	ldp	x23, x24, [sp, #48]
  4004ac:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4004b0:	17ffff91 	b	4002f4 <set_pair+0xf4>
  4004b4:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4004b8:	a94363f7 	ldp	x23, x24, [sp, #48]
  4004bc:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4004c0:	94000174 	bl	400a90 <__errno_location@GLIBC_2.2.5>
  4004c4:	528002c1 	mov	w1, #0x16                  	// #22
  4004c8:	b9000001 	str	w1, [x0]
  4004cc:	12800000 	mov	w0, #0xffffffff            	// #-1
  4004d0:	17ffff89 	b	4002f4 <set_pair+0xf4>
  4004d4:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4004d8:	a94363f7 	ldp	x23, x24, [sp, #48]
  4004dc:	17fffff9 	b	4004c0 <set_pair+0x2c0>
  4004e0:	aa1503e2 	mov	x2, x21
  4004e4:	d2800023 	mov	x3, #0x1                   	// #1
  4004e8:	17ffffc7 	b	400404 <set_pair+0x204>
  4004ec:	aa1403e0 	mov	x0, x20
  4004f0:	94000114 	bl	400940 <free>
  4004f4:	17ffffe7 	b	400490 <set_pair+0x290>
  4004f8:	d503201f 	nop
  4004fc:	d503201f 	nop

0000000000400500 <__libc_init_environ>:
  400500:	f0000003 	adrp	x3, 403000 <g_env_count>
  400504:	b4000200 	cbz	x0, 400544 <__libc_init_environ+0x44>
  400508:	f9400001 	ldr	x1, [x0]
  40050c:	b40001c1 	cbz	x1, 400544 <__libc_init_environ+0x44>
  400510:	91000061 	add	x1, x3, #0x0
  400514:	f9000420 	str	x0, [x1, #8]
  400518:	d0000001 	adrp	x1, 402000 <memmove+0xcf0>
  40051c:	f9400c21 	ldr	x1, [x1, #24]
  400520:	f9000020 	str	x0, [x1]
  400524:	d2800001 	mov	x1, #0x0                   	// #0
  400528:	91000421 	add	x1, x1, #0x1
  40052c:	f8617802 	ldr	x2, [x0, x1, lsl #3]
  400530:	b5ffffc2 	cbnz	x2, 400528 <__libc_init_environ+0x28>
  400534:	91000060 	add	x0, x3, #0x0
  400538:	f9000061 	str	x1, [x3]
  40053c:	f9000c01 	str	x1, [x0, #24]
  400540:	d65f03c0 	ret
  400544:	91000060 	add	x0, x3, #0x0
  400548:	d2800001 	mov	x1, #0x0                   	// #0
  40054c:	f9000061 	str	x1, [x3]
  400550:	f900041f 	str	xzr, [x0, #8]
  400554:	d0000000 	adrp	x0, 402000 <memmove+0xcf0>
  400558:	f9400c00 	ldr	x0, [x0, #24]
  40055c:	f900001f 	str	xzr, [x0]
  400560:	91000060 	add	x0, x3, #0x0
  400564:	f9000c01 	str	x1, [x0, #24]
  400568:	d65f03c0 	ret
  40056c:	d503201f 	nop

0000000000400570 <getenv>:
  400570:	b4000440 	cbz	x0, 4005f8 <getenv+0x88>
  400574:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400578:	52800023 	mov	w3, #0x1                   	// #1
  40057c:	910003fd 	mov	x29, sp
  400580:	f9000bf3 	str	x19, [sp, #16]
  400584:	f0000013 	adrp	x19, 403000 <g_env_count>
  400588:	91000269 	add	x9, x19, #0x0
  40058c:	91004121 	add	x1, x9, #0x10
  400590:	085ffc22 	ldaxrb	w2, [x1]
  400594:	08047c23 	stxrb	w4, w3, [x1]
  400598:	35ffffc4 	cbnz	w4, 400590 <getenv+0x20>
  40059c:	3707ffa2 	tbnz	w2, #0, 400590 <getenv+0x20>
  4005a0:	97fffef4 	bl	400170 <find_index>
  4005a4:	37f801c0 	tbnz	w0, #31, 4005dc <getenv+0x6c>
  4005a8:	f9400521 	ldr	x1, [x9, #8]
  4005ac:	f8605820 	ldr	x0, [x1, w0, uxtw #3]
  4005b0:	b4000160 	cbz	x0, 4005dc <getenv+0x6c>
  4005b4:	528007a1 	mov	w1, #0x3d                  	// #61
  4005b8:	940001b2 	bl	400c80 <strchr>
  4005bc:	b4000100 	cbz	x0, 4005dc <getenv+0x6c>
  4005c0:	91000400 	add	x0, x0, #0x1
  4005c4:	91000273 	add	x19, x19, #0x0
  4005c8:	91004273 	add	x19, x19, #0x10
  4005cc:	089ffe7f 	stlrb	wzr, [x19]
  4005d0:	f9400bf3 	ldr	x19, [sp, #16]
  4005d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
  4005d8:	d65f03c0 	ret
  4005dc:	d2800000 	mov	x0, #0x0                   	// #0
  4005e0:	91000273 	add	x19, x19, #0x0
  4005e4:	91004273 	add	x19, x19, #0x10
  4005e8:	089ffe7f 	stlrb	wzr, [x19]
  4005ec:	f9400bf3 	ldr	x19, [sp, #16]
  4005f0:	a8c27bfd 	ldp	x29, x30, [sp], #32
  4005f4:	d65f03c0 	ret
  4005f8:	d65f03c0 	ret
  4005fc:	d503201f 	nop

0000000000400600 <secure_getenv>:
  400600:	17ffffdc 	b	400570 <getenv>
  400604:	d503201f 	nop
  400608:	d503201f 	nop
  40060c:	d503201f 	nop

0000000000400610 <__secure_getenv>:
  400610:	17fffffc 	b	400600 <secure_getenv>
  400614:	d503201f 	nop
  400618:	d503201f 	nop
  40061c:	d503201f 	nop

0000000000400620 <setenv>:
  400620:	7100005f 	cmp	w2, #0x0
  400624:	d2800003 	mov	x3, #0x0                   	// #0
  400628:	1a9f07e2 	cset	w2, ne	// ne = any
  40062c:	17fffef5 	b	400200 <set_pair>

0000000000400630 <putenv>:
  400630:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400634:	910003fd 	mov	x29, sp
  400638:	b4000380 	cbz	x0, 4006a8 <putenv+0x78>
  40063c:	528007a1 	mov	w1, #0x3d                  	// #61
  400640:	a90153f3 	stp	x19, x20, [sp, #16]
  400644:	aa0003f4 	mov	x20, x0
  400648:	9400018e 	bl	400c80 <strchr>
  40064c:	f100001f 	cmp	x0, #0x0
  400650:	aa0003f3 	mov	x19, x0
  400654:	fa401284 	ccmp	x20, x0, #0x4, ne	// ne = any
  400658:	540001c0 	b.eq	400690 <putenv+0x60>  // b.none
  40065c:	aa0003e1 	mov	x1, x0
  400660:	f90013f5 	str	x21, [sp, #32]
  400664:	aa1403e3 	mov	x3, x20
  400668:	aa1403e0 	mov	x0, x20
  40066c:	39400275 	ldrb	w21, [x19]
  400670:	52800022 	mov	w2, #0x1                   	// #1
  400674:	3800143f 	strb	wzr, [x1], #1
  400678:	97fffee2 	bl	400200 <set_pair>
  40067c:	39000275 	strb	w21, [x19]
  400680:	a94153f3 	ldp	x19, x20, [sp, #16]
  400684:	f94013f5 	ldr	x21, [sp, #32]
  400688:	a8c37bfd 	ldp	x29, x30, [sp], #48
  40068c:	d65f03c0 	ret
  400690:	94000100 	bl	400a90 <__errno_location@GLIBC_2.2.5>
  400694:	528002c1 	mov	w1, #0x16                  	// #22
  400698:	b9000001 	str	w1, [x0]
  40069c:	12800000 	mov	w0, #0xffffffff            	// #-1
  4006a0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4006a4:	17fffff9 	b	400688 <putenv+0x58>
  4006a8:	940000fa 	bl	400a90 <__errno_location@GLIBC_2.2.5>
  4006ac:	528002c1 	mov	w1, #0x16                  	// #22
  4006b0:	b9000001 	str	w1, [x0]
  4006b4:	12800000 	mov	w0, #0xffffffff            	// #-1
  4006b8:	17fffff4 	b	400688 <putenv+0x58>
  4006bc:	d503201f 	nop

00000000004006c0 <unsetenv>:
  4006c0:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
  4006c4:	910003fd 	mov	x29, sp
  4006c8:	b40006e0 	cbz	x0, 4007a4 <unsetenv+0xe4>
  4006cc:	a90153f3 	stp	x19, x20, [sp, #16]
  4006d0:	aa0003f4 	mov	x20, x0
  4006d4:	39400001 	ldrb	w1, [x0]
  4006d8:	34000641 	cbz	w1, 4007a0 <unsetenv+0xe0>
  4006dc:	528007a1 	mov	w1, #0x3d                  	// #61
  4006e0:	94000168 	bl	400c80 <strchr>
  4006e4:	b50005e0 	cbnz	x0, 4007a0 <unsetenv+0xe0>
  4006e8:	f90013f5 	str	x21, [sp, #32]
  4006ec:	f0000013 	adrp	x19, 403000 <g_env_count>
  4006f0:	91000275 	add	x21, x19, #0x0
  4006f4:	52800022 	mov	w2, #0x1                   	// #1
  4006f8:	910042a0 	add	x0, x21, #0x10
  4006fc:	d503201f 	nop
  400700:	085ffc01 	ldaxrb	w1, [x0]
  400704:	08037c02 	stxrb	w3, w2, [x0]
  400708:	35ffffc3 	cbnz	w3, 400700 <unsetenv+0x40>
  40070c:	3707ffa1 	tbnz	w1, #0, 400700 <unsetenv+0x40>
  400710:	aa1403e0 	mov	x0, x20
  400714:	97fffe97 	bl	400170 <find_index>
  400718:	2a0003e1 	mov	w1, w0
  40071c:	36f80120 	tbz	w0, #31, 400740 <unsetenv+0x80>
  400720:	91000273 	add	x19, x19, #0x0
  400724:	91004273 	add	x19, x19, #0x10
  400728:	089ffe7f 	stlrb	wzr, [x19]
  40072c:	a94153f3 	ldp	x19, x20, [sp, #16]
  400730:	52800000 	mov	w0, #0x0                   	// #0
  400734:	f94013f5 	ldr	x21, [sp, #32]
  400738:	a8c47bfd 	ldp	x29, x30, [sp], #64
  40073c:	d65f03c0 	ret
  400740:	93407c14 	sxtw	x20, w0
  400744:	b9003fe1 	str	w1, [sp, #60]
  400748:	f94006a0 	ldr	x0, [x21, #8]
  40074c:	91000694 	add	x20, x20, #0x1
  400750:	f8615800 	ldr	x0, [x0, w1, uxtw #3]
  400754:	9400007b 	bl	400940 <free>
  400758:	f9400263 	ldr	x3, [x19]
  40075c:	f94006a4 	ldr	x4, [x21, #8]
  400760:	eb03029f 	cmp	x20, x3
  400764:	b9403fe1 	ldr	w1, [sp, #60]
  400768:	54000122 	b.cs	40078c <unsetenv+0xcc>  // b.hs, b.nlast
  40076c:	91002080 	add	x0, x4, #0x8
  400770:	8b030c82 	add	x2, x4, x3, lsl #3
  400774:	8b214c00 	add	x0, x0, w1, uxtw #3
  400778:	f9400001 	ldr	x1, [x0]
  40077c:	91002000 	add	x0, x0, #0x8
  400780:	f81f0001 	stur	x1, [x0, #-16]
  400784:	eb02001f 	cmp	x0, x2
  400788:	54ffff81 	b.ne	400778 <unsetenv+0xb8>  // b.any
  40078c:	d1000463 	sub	x3, x3, #0x1
  400790:	f9000263 	str	x3, [x19]
  400794:	b4fffc64 	cbz	x4, 400720 <unsetenv+0x60>
  400798:	f823789f 	str	xzr, [x4, x3, lsl #3]
  40079c:	17ffffe1 	b	400720 <unsetenv+0x60>
  4007a0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4007a4:	940000bb 	bl	400a90 <__errno_location@GLIBC_2.2.5>
  4007a8:	528002c1 	mov	w1, #0x16                  	// #22
  4007ac:	b9000001 	str	w1, [x0]
  4007b0:	12800000 	mov	w0, #0xffffffff            	// #-1
  4007b4:	17ffffe1 	b	400738 <unsetenv+0x78>
  4007b8:	d503201f 	nop
  4007bc:	d503201f 	nop

00000000004007c0 <clearenv>:
  4007c0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4007c4:	52800022 	mov	w2, #0x1                   	// #1
  4007c8:	910003fd 	mov	x29, sp
  4007cc:	a9025bf5 	stp	x21, x22, [sp, #32]
  4007d0:	f0000016 	adrp	x22, 403000 <g_env_count>
  4007d4:	910002c0 	add	x0, x22, #0x0
  4007d8:	91004000 	add	x0, x0, #0x10
  4007dc:	a90153f3 	stp	x19, x20, [sp, #16]
  4007e0:	085ffc01 	ldaxrb	w1, [x0]
  4007e4:	08037c02 	stxrb	w3, w2, [x0]
  4007e8:	35ffffc3 	cbnz	w3, 4007e0 <clearenv+0x20>
  4007ec:	3707ffa1 	tbnz	w1, #0, 4007e0 <clearenv+0x20>
  4007f0:	f94002c0 	ldr	x0, [x22]
  4007f4:	b40001a0 	cbz	x0, 400828 <clearenv+0x68>
  4007f8:	910002d5 	add	x21, x22, #0x0
  4007fc:	d2800014 	mov	x20, #0x0                   	// #0
  400800:	d2800013 	mov	x19, #0x0                   	// #0
  400804:	d503201f 	nop
  400808:	f94006a0 	ldr	x0, [x21, #8]
  40080c:	91000673 	add	x19, x19, #0x1
  400810:	f8746800 	ldr	x0, [x0, x20]
  400814:	91002294 	add	x20, x20, #0x8
  400818:	9400004a 	bl	400940 <free>
  40081c:	f94002a0 	ldr	x0, [x21]
  400820:	eb13001f 	cmp	x0, x19
  400824:	54ffff28 	b.hi	400808 <clearenv+0x48>  // b.pmore
  400828:	910002d3 	add	x19, x22, #0x0
  40082c:	f9400660 	ldr	x0, [x19, #8]
  400830:	94000044 	bl	400940 <free>
  400834:	f90002df 	str	xzr, [x22]
  400838:	d0000000 	adrp	x0, 402000 <memmove+0xcf0>
  40083c:	f9400c00 	ldr	x0, [x0, #24]
  400840:	f900067f 	str	xzr, [x19, #8]
  400844:	f9000e7f 	str	xzr, [x19, #24]
  400848:	f900001f 	str	xzr, [x0]
  40084c:	91004273 	add	x19, x19, #0x10
  400850:	089ffe7f 	stlrb	wzr, [x19]
  400854:	52800000 	mov	w0, #0x0                   	// #0
  400858:	a94153f3 	ldp	x19, x20, [sp, #16]
  40085c:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400860:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400864:	d65f03c0 	ret
	...

0000000000400870 <malloc>:
  400870:	b4000640 	cbz	x0, 400938 <malloc+0xc8>
  400874:	91003c00 	add	x0, x0, #0xf
  400878:	f0000006 	adrp	x6, 403000 <g_env_count>
  40087c:	9100a0c4 	add	x4, x6, #0x28
  400880:	927c6c02 	and	x2, x0, #0xfffffff0
  400884:	f100405f 	cmp	x2, #0x10
  400888:	d2800200 	mov	x0, #0x10                  	// #16
  40088c:	9a802042 	csel	x2, x2, x0, cs	// cs = hs, nlast
  400890:	91002080 	add	x0, x4, #0x8
  400894:	52800023 	mov	w3, #0x1                   	// #1
  400898:	085ffc01 	ldaxrb	w1, [x0]
  40089c:	08057c03 	stxrb	w5, w3, [x0]
  4008a0:	35ffffc5 	cbnz	w5, 400898 <malloc+0x28>
  4008a4:	3707ffa1 	tbnz	w1, #0, 400898 <malloc+0x28>
  4008a8:	f94014c1 	ldr	x1, [x6, #40]
  4008ac:	b5000081 	cbnz	x1, 4008bc <malloc+0x4c>
  4008b0:	1400000c 	b	4008e0 <malloc+0x70>
  4008b4:	aa0003e4 	mov	x4, x0
  4008b8:	b4000141 	cbz	x1, 4008e0 <malloc+0x70>
  4008bc:	aa0103e0 	mov	x0, x1
  4008c0:	a97f8423 	ldp	x3, x1, [x1, #-8]
  4008c4:	eb02007f 	cmp	x3, x2
  4008c8:	54ffff63 	b.cc	4008b4 <malloc+0x44>  // b.lo, b.ul, b.last
  4008cc:	9100a0c6 	add	x6, x6, #0x28
  4008d0:	f9000081 	str	x1, [x4]
  4008d4:	910020c6 	add	x6, x6, #0x8
  4008d8:	089ffcdf 	stlrb	wzr, [x6]
  4008dc:	d65f03c0 	ret
  4008e0:	d2801ac8 	mov	x8, #0xd6                  	// #214
  4008e4:	d2800000 	mov	x0, #0x0                   	// #0
  4008e8:	d4000001 	svc	#0x0
  4008ec:	aa0003e1 	mov	x1, x0
  4008f0:	d29fffe0 	mov	x0, #0xffff                	// #65535
  4008f4:	eb00003f 	cmp	x1, x0
  4008f8:	540001ad 	b.le	40092c <malloc+0xbc>
  4008fc:	91002043 	add	x3, x2, #0x8
  400900:	8b010063 	add	x3, x3, x1
  400904:	aa0303e0 	mov	x0, x3
  400908:	d4000001 	svc	#0x0
  40090c:	eb00007f 	cmp	x3, x0
  400910:	540000ec 	b.gt	40092c <malloc+0xbc>
  400914:	9100a0c6 	add	x6, x6, #0x28
  400918:	910020c6 	add	x6, x6, #0x8
  40091c:	089ffcdf 	stlrb	wzr, [x6]
  400920:	aa0103e0 	mov	x0, x1
  400924:	f8008402 	str	x2, [x0], #8
  400928:	d65f03c0 	ret
  40092c:	9100a0c0 	add	x0, x6, #0x28
  400930:	91002000 	add	x0, x0, #0x8
  400934:	089ffc1f 	stlrb	wzr, [x0]
  400938:	d2800000 	mov	x0, #0x0                   	// #0
  40093c:	d65f03c0 	ret

0000000000400940 <free>:
  400940:	d29fffe1 	mov	x1, #0xffff                	// #65535
  400944:	eb01001f 	cmp	x0, x1
  400948:	54000048 	b.hi	400950 <free+0x10>  // b.pmore
  40094c:	d65f03c0 	ret
  400950:	f0000005 	adrp	x5, 403000 <g_env_count>
  400954:	9100a0a1 	add	x1, x5, #0x28
  400958:	91002021 	add	x1, x1, #0x8
  40095c:	52800023 	mov	w3, #0x1                   	// #1
  400960:	085ffc22 	ldaxrb	w2, [x1]
  400964:	08047c23 	stxrb	w4, w3, [x1]
  400968:	35ffffc4 	cbnz	w4, 400960 <free+0x20>
  40096c:	3707ffa2 	tbnz	w2, #0, 400960 <free+0x20>
  400970:	f94014a2 	ldr	x2, [x5, #40]
  400974:	f9000002 	str	x2, [x0]
  400978:	f90014a0 	str	x0, [x5, #40]
  40097c:	089ffc3f 	stlrb	wzr, [x1]
  400980:	d65f03c0 	ret
  400984:	d503201f 	nop
  400988:	d503201f 	nop
  40098c:	d503201f 	nop

0000000000400990 <calloc>:
  400990:	b4000060 	cbz	x0, 40099c <calloc+0xc>
  400994:	9bc17c02 	umulh	x2, x0, x1
  400998:	b5000222 	cbnz	x2, 4009dc <calloc+0x4c>
  40099c:	9b017c02 	mul	x2, x0, x1
  4009a0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  4009a4:	910003fd 	mov	x29, sp
  4009a8:	aa0203e0 	mov	x0, x2
  4009ac:	f9000be2 	str	x2, [sp, #16]
  4009b0:	97ffffb0 	bl	400870 <malloc>
  4009b4:	aa0003e3 	mov	x3, x0
  4009b8:	b40000c0 	cbz	x0, 4009d0 <calloc+0x40>
  4009bc:	f9400be2 	ldr	x2, [sp, #16]
  4009c0:	52800001 	mov	w1, #0x0                   	// #0
  4009c4:	f9000fe0 	str	x0, [sp, #24]
  4009c8:	94000232 	bl	401290 <memset>
  4009cc:	f9400fe3 	ldr	x3, [sp, #24]
  4009d0:	aa0303e0 	mov	x0, x3
  4009d4:	a8c27bfd 	ldp	x29, x30, [sp], #32
  4009d8:	d65f03c0 	ret
  4009dc:	d2800003 	mov	x3, #0x0                   	// #0
  4009e0:	aa0303e0 	mov	x0, x3
  4009e4:	d65f03c0 	ret
  4009e8:	d503201f 	nop
  4009ec:	d503201f 	nop

00000000004009f0 <realloc>:
  4009f0:	b4000380 	cbz	x0, 400a60 <realloc+0x70>
  4009f4:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4009f8:	910003fd 	mov	x29, sp
  4009fc:	b4000361 	cbz	x1, 400a68 <realloc+0x78>
  400a00:	f85f8002 	ldur	x2, [x0, #-8]
  400a04:	aa0003e3 	mov	x3, x0
  400a08:	aa0003e4 	mov	x4, x0
  400a0c:	eb02003f 	cmp	x1, x2
  400a10:	54000088 	b.hi	400a20 <realloc+0x30>  // b.pmore
  400a14:	aa0403e0 	mov	x0, x4
  400a18:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400a1c:	d65f03c0 	ret
  400a20:	aa0103e0 	mov	x0, x1
  400a24:	a9018fe2 	stp	x2, x3, [sp, #24]
  400a28:	97ffff92 	bl	400870 <malloc>
  400a2c:	aa0003e4 	mov	x4, x0
  400a30:	b4ffff20 	cbz	x0, 400a14 <realloc+0x24>
  400a34:	a9418fe2 	ldp	x2, x3, [sp, #24]
  400a38:	f9000fe3 	str	x3, [sp, #24]
  400a3c:	f90017e0 	str	x0, [sp, #40]
  400a40:	aa0303e1 	mov	x1, x3
  400a44:	940001ff 	bl	401240 <memcpy>
  400a48:	f9400fe0 	ldr	x0, [sp, #24]
  400a4c:	97ffffbd 	bl	400940 <free>
  400a50:	f94017e4 	ldr	x4, [sp, #40]
  400a54:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400a58:	aa0403e0 	mov	x0, x4
  400a5c:	d65f03c0 	ret
  400a60:	aa0103e0 	mov	x0, x1
  400a64:	17ffff83 	b	400870 <malloc>
  400a68:	97ffffb6 	bl	400940 <free>
  400a6c:	d2800004 	mov	x4, #0x0                   	// #0
  400a70:	17ffffe9 	b	400a14 <realloc+0x24>
  400a74:	d503201f 	nop
  400a78:	d503201f 	nop
  400a7c:	d503201f 	nop

0000000000400a80 <heap_stats>:
  400a80:	d65f03c0 	ret
	...

0000000000400a90 <__errno_location@GLIBC_2.2.5>:
  400a90:	f0000000 	adrp	x0, 403000 <g_env_count>
  400a94:	9100d000 	add	x0, x0, #0x34
  400a98:	d65f03c0 	ret
  400a9c:	00000000 	udf	#0

0000000000400aa0 <strlen>:
  400aa0:	aa0003e2 	mov	x2, x0
  400aa4:	b4000120 	cbz	x0, 400ac8 <strlen+0x28>
  400aa8:	39400000 	ldrb	w0, [x0]
  400aac:	340000e0 	cbz	w0, 400ac8 <strlen+0x28>
  400ab0:	d2800000 	mov	x0, #0x0                   	// #0
  400ab4:	d503201f 	nop
  400ab8:	91000400 	add	x0, x0, #0x1
  400abc:	38606841 	ldrb	w1, [x2, x0]
  400ac0:	35ffffc1 	cbnz	w1, 400ab8 <strlen+0x18>
  400ac4:	d65f03c0 	ret
  400ac8:	d2800000 	mov	x0, #0x0                   	// #0
  400acc:	d65f03c0 	ret

0000000000400ad0 <strncpy>:
  400ad0:	f100001f 	cmp	x0, #0x0
  400ad4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400ad8:	54000220 	b.eq	400b1c <strncpy+0x4c>  // b.none
  400adc:	d2800003 	mov	x3, #0x0                   	// #0
  400ae0:	b50000c2 	cbnz	x2, 400af8 <strncpy+0x28>
  400ae4:	1400000e 	b	400b1c <strncpy+0x4c>
  400ae8:	38236804 	strb	w4, [x0, x3]
  400aec:	91000463 	add	x3, x3, #0x1
  400af0:	eb03005f 	cmp	x2, x3
  400af4:	54000140 	b.eq	400b1c <strncpy+0x4c>  // b.none
  400af8:	38636824 	ldrb	w4, [x1, x3]
  400afc:	35ffff64 	cbnz	w4, 400ae8 <strncpy+0x18>
  400b00:	eb03005f 	cmp	x2, x3
  400b04:	540000c9 	b.ls	400b1c <strncpy+0x4c>  // b.plast
  400b08:	8b030003 	add	x3, x0, x3
  400b0c:	8b020002 	add	x2, x0, x2
  400b10:	3800147f 	strb	wzr, [x3], #1
  400b14:	eb02007f 	cmp	x3, x2
  400b18:	54ffffc1 	b.ne	400b10 <strncpy+0x40>  // b.any
  400b1c:	d65f03c0 	ret

0000000000400b20 <strcpy>:
  400b20:	f100001f 	cmp	x0, #0x0
  400b24:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400b28:	54000140 	b.eq	400b50 <strcpy+0x30>  // b.none
  400b2c:	39400023 	ldrb	w3, [x1]
  400b30:	34000123 	cbz	w3, 400b54 <strcpy+0x34>
  400b34:	d2800002 	mov	x2, #0x0                   	// #0
  400b38:	38226803 	strb	w3, [x0, x2]
  400b3c:	91000442 	add	x2, x2, #0x1
  400b40:	38626823 	ldrb	w3, [x1, x2]
  400b44:	35ffffa3 	cbnz	w3, 400b38 <strcpy+0x18>
  400b48:	8b020002 	add	x2, x0, x2
  400b4c:	3900005f 	strb	wzr, [x2]
  400b50:	d65f03c0 	ret
  400b54:	aa0003e2 	mov	x2, x0
  400b58:	3900005f 	strb	wzr, [x2]
  400b5c:	17fffffd 	b	400b50 <strcpy+0x30>

0000000000400b60 <strcmp>:
  400b60:	f100001f 	cmp	x0, #0x0
  400b64:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400b68:	540001a0 	b.eq	400b9c <strcmp+0x3c>  // b.none
  400b6c:	39400002 	ldrb	w2, [x0]
  400b70:	350000a2 	cbnz	w2, 400b84 <strcmp+0x24>
  400b74:	1400000f 	b	400bb0 <strcmp+0x50>
  400b78:	38401c02 	ldrb	w2, [x0, #1]!
  400b7c:	34000142 	cbz	w2, 400ba4 <strcmp+0x44>
  400b80:	91000421 	add	x1, x1, #0x1
  400b84:	39400023 	ldrb	w3, [x1]
  400b88:	7100007f 	cmp	w3, #0x0
  400b8c:	7a421060 	ccmp	w3, w2, #0x0, ne	// ne = any
  400b90:	54ffff40 	b.eq	400b78 <strcmp+0x18>  // b.none
  400b94:	4b030040 	sub	w0, w2, w3
  400b98:	d65f03c0 	ret
  400b9c:	52800000 	mov	w0, #0x0                   	// #0
  400ba0:	d65f03c0 	ret
  400ba4:	39400423 	ldrb	w3, [x1, #1]
  400ba8:	4b030040 	sub	w0, w2, w3
  400bac:	17fffffb 	b	400b98 <strcmp+0x38>
  400bb0:	39400023 	ldrb	w3, [x1]
  400bb4:	4b030040 	sub	w0, w2, w3
  400bb8:	17fffff8 	b	400b98 <strcmp+0x38>
  400bbc:	d503201f 	nop

0000000000400bc0 <strncmp>:
  400bc0:	f100003f 	cmp	x1, #0x0
  400bc4:	d2800003 	mov	x3, #0x0                   	// #0
  400bc8:	fa401844 	ccmp	x2, #0x0, #0x4, ne	// ne = any
  400bcc:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
  400bd0:	54000081 	b.ne	400be0 <strncmp+0x20>  // b.any
  400bd4:	52800004 	mov	w4, #0x0                   	// #0
  400bd8:	2a0403e0 	mov	w0, w4
  400bdc:	d65f03c0 	ret
  400be0:	38636804 	ldrb	w4, [x0, x3]
  400be4:	34000104 	cbz	w4, 400c04 <strncmp+0x44>
  400be8:	38636825 	ldrb	w5, [x1, x3]
  400bec:	340000c5 	cbz	w5, 400c04 <strncmp+0x44>
  400bf0:	6b05009f 	cmp	w4, w5
  400bf4:	54000181 	b.ne	400c24 <strncmp+0x64>  // b.any
  400bf8:	91000463 	add	x3, x3, #0x1
  400bfc:	eb03005f 	cmp	x2, x3
  400c00:	54ffff08 	b.hi	400be0 <strncmp+0x20>  // b.pmore
  400c04:	52800004 	mov	w4, #0x0                   	// #0
  400c08:	eb02007f 	cmp	x3, x2
  400c0c:	54fffe60 	b.eq	400bd8 <strncmp+0x18>  // b.none
  400c10:	38636804 	ldrb	w4, [x0, x3]
  400c14:	38636820 	ldrb	w0, [x1, x3]
  400c18:	4b000084 	sub	w4, w4, w0
  400c1c:	2a0403e0 	mov	w0, w4
  400c20:	d65f03c0 	ret
  400c24:	4b050084 	sub	w4, w4, w5
  400c28:	2a0403e0 	mov	w0, w4
  400c2c:	d65f03c0 	ret

0000000000400c30 <strcat>:
  400c30:	f100001f 	cmp	x0, #0x0
  400c34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c38:	54000041 	b.ne	400c40 <strcat+0x10>  // b.any
  400c3c:	d65f03c0 	ret
  400c40:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400c44:	910003fd 	mov	x29, sp
  400c48:	a90107e0 	stp	x0, x1, [sp, #16]
  400c4c:	97ffff95 	bl	400aa0 <strlen>
  400c50:	a94107e3 	ldp	x3, x1, [sp, #16]
  400c54:	39400022 	ldrb	w2, [x1]
  400c58:	8b000060 	add	x0, x3, x0
  400c5c:	34000082 	cbz	w2, 400c6c <strcat+0x3c>
  400c60:	38001402 	strb	w2, [x0], #1
  400c64:	38401c22 	ldrb	w2, [x1, #1]!
  400c68:	35ffffc2 	cbnz	w2, 400c60 <strcat+0x30>
  400c6c:	3900001f 	strb	wzr, [x0]
  400c70:	aa0303e0 	mov	x0, x3
  400c74:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400c78:	d65f03c0 	ret
  400c7c:	d503201f 	nop

0000000000400c80 <strchr>:
  400c80:	b4000120 	cbz	x0, 400ca4 <strchr+0x24>
  400c84:	39400002 	ldrb	w2, [x0]
  400c88:	12001c21 	and	w1, w1, #0xff
  400c8c:	35000082 	cbnz	w2, 400c9c <strchr+0x1c>
  400c90:	14000006 	b	400ca8 <strchr+0x28>
  400c94:	38401c02 	ldrb	w2, [x0, #1]!
  400c98:	34000082 	cbz	w2, 400ca8 <strchr+0x28>
  400c9c:	6b01005f 	cmp	w2, w1
  400ca0:	54ffffa1 	b.ne	400c94 <strchr+0x14>  // b.any
  400ca4:	d65f03c0 	ret
  400ca8:	7100003f 	cmp	w1, #0x0
  400cac:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
  400cb0:	d65f03c0 	ret
  400cb4:	d503201f 	nop
  400cb8:	d503201f 	nop
  400cbc:	d503201f 	nop

0000000000400cc0 <strdup>:
  400cc0:	b4000300 	cbz	x0, 400d20 <strdup+0x60>
  400cc4:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400cc8:	910003fd 	mov	x29, sp
  400ccc:	f9000fe0 	str	x0, [sp, #24]
  400cd0:	97ffff74 	bl	400aa0 <strlen>
  400cd4:	91000403 	add	x3, x0, #0x1
  400cd8:	f9000be3 	str	x3, [sp, #16]
  400cdc:	aa0303e0 	mov	x0, x3
  400ce0:	97fffee4 	bl	400870 <malloc>
  400ce4:	b4000180 	cbz	x0, 400d14 <strdup+0x54>
  400ce8:	a94113e3 	ldp	x3, x4, [sp, #16]
  400cec:	d2800001 	mov	x1, #0x0                   	// #0
  400cf0:	b40000e3 	cbz	x3, 400d0c <strdup+0x4c>
  400cf4:	d503201f 	nop
  400cf8:	38616882 	ldrb	w2, [x4, x1]
  400cfc:	38216802 	strb	w2, [x0, x1]
  400d00:	91000421 	add	x1, x1, #0x1
  400d04:	eb01007f 	cmp	x3, x1
  400d08:	54ffff81 	b.ne	400cf8 <strdup+0x38>  // b.any
  400d0c:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400d10:	d65f03c0 	ret
  400d14:	d2800000 	mov	x0, #0x0                   	// #0
  400d18:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400d1c:	d65f03c0 	ret
  400d20:	d2800000 	mov	x0, #0x0                   	// #0
  400d24:	d65f03c0 	ret
  400d28:	d503201f 	nop
  400d2c:	d503201f 	nop

0000000000400d30 <strstr>:
  400d30:	f100001f 	cmp	x0, #0x0
  400d34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d38:	54000480 	b.eq	400dc8 <strstr+0x98>  // b.none
  400d3c:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400d40:	910003fd 	mov	x29, sp
  400d44:	a90153f3 	stp	x19, x20, [sp, #16]
  400d48:	aa0003f3 	mov	x19, x0
  400d4c:	39400022 	ldrb	w2, [x1]
  400d50:	35000082 	cbnz	w2, 400d60 <strstr+0x30>
  400d54:	a94153f3 	ldp	x19, x20, [sp, #16]
  400d58:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400d5c:	d65f03c0 	ret
  400d60:	aa0103f4 	mov	x20, x1
  400d64:	aa0103e0 	mov	x0, x1
  400d68:	f90013f5 	str	x21, [sp, #32]
  400d6c:	97ffff4d 	bl	400aa0 <strlen>
  400d70:	39400262 	ldrb	w2, [x19]
  400d74:	aa0003f5 	mov	x21, x0
  400d78:	35000082 	cbnz	w2, 400d88 <strstr+0x58>
  400d7c:	1400000e 	b	400db4 <strstr+0x84>
  400d80:	38401e62 	ldrb	w2, [x19, #1]!
  400d84:	34000182 	cbz	w2, 400db4 <strstr+0x84>
  400d88:	39400280 	ldrb	w0, [x20]
  400d8c:	6b02001f 	cmp	w0, w2
  400d90:	54ffff81 	b.ne	400d80 <strstr+0x50>  // b.any
  400d94:	aa1503e2 	mov	x2, x21
  400d98:	aa1403e1 	mov	x1, x20
  400d9c:	aa1303e0 	mov	x0, x19
  400da0:	97ffff88 	bl	400bc0 <strncmp>
  400da4:	35fffee0 	cbnz	w0, 400d80 <strstr+0x50>
  400da8:	f94013f5 	ldr	x21, [sp, #32]
  400dac:	aa1303e0 	mov	x0, x19
  400db0:	17ffffe9 	b	400d54 <strstr+0x24>
  400db4:	f94013f5 	ldr	x21, [sp, #32]
  400db8:	d2800000 	mov	x0, #0x0                   	// #0
  400dbc:	a94153f3 	ldp	x19, x20, [sp, #16]
  400dc0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400dc4:	d65f03c0 	ret
  400dc8:	d2800000 	mov	x0, #0x0                   	// #0
  400dcc:	d65f03c0 	ret

0000000000400dd0 <strtol>:
  400dd0:	91100006 	add	x6, x0, #0x400
  400dd4:	d29fffe5 	mov	x5, #0xffff                	// #65535
  400dd8:	eb05001f 	cmp	x0, x5
  400ddc:	540000a8 	b.hi	400df0 <strtol+0x20>  // b.pmore
  400de0:	14000011 	b	400e24 <strtol+0x54>
  400de4:	eb0300df 	cmp	x6, x3
  400de8:	54000260 	b.eq	400e34 <strtol+0x64>  // b.none
  400dec:	aa0303e0 	mov	x0, x3
  400df0:	39400004 	ldrb	w4, [x0]
  400df4:	51002483 	sub	w3, w4, #0x9
  400df8:	7100809f 	cmp	w4, #0x20
  400dfc:	12001c63 	and	w3, w3, #0xff
  400e00:	7a441860 	ccmp	w3, #0x4, #0x0, ne	// ne = any
  400e04:	540001c8 	b.hi	400e3c <strtol+0x6c>  // b.pmore
  400e08:	91000403 	add	x3, x0, #0x1
  400e0c:	eb05007f 	cmp	x3, x5
  400e10:	54fffea8 	b.hi	400de4 <strtol+0x14>  // b.pmore
  400e14:	b4000041 	cbz	x1, 400e1c <strtol+0x4c>
  400e18:	f9000023 	str	x3, [x1]
  400e1c:	d2800000 	mov	x0, #0x0                   	// #0
  400e20:	d65f03c0 	ret
  400e24:	b4ffffc1 	cbz	x1, 400e1c <strtol+0x4c>
  400e28:	f9000020 	str	x0, [x1]
  400e2c:	d2800000 	mov	x0, #0x0                   	// #0
  400e30:	17fffffc 	b	400e20 <strtol+0x50>
  400e34:	39400404 	ldrb	w4, [x0, #1]
  400e38:	aa0603e0 	mov	x0, x6
  400e3c:	7100ac9f 	cmp	w4, #0x2b
  400e40:	54000560 	b.eq	400eec <strtol+0x11c>  // b.none
  400e44:	7100b49f 	cmp	w4, #0x2d
  400e48:	540009e0 	b.eq	400f84 <strtol+0x1b4>  // b.none
  400e4c:	350006e2 	cbnz	w2, 400f28 <strtol+0x158>
  400e50:	7100c09f 	cmp	w4, #0x30
  400e54:	540005e1 	b.ne	400f10 <strtol+0x140>  // b.any
  400e58:	39400404 	ldrb	w4, [x0, #1]
  400e5c:	121a7882 	and	w2, w4, #0xffffffdf
  400e60:	7101605f 	cmp	w2, #0x58
  400e64:	540019a0 	b.eq	401198 <strtol+0x3c8>  // b.none
  400e68:	91000400 	add	x0, x0, #0x1
  400e6c:	528000ea 	mov	w10, #0x7                   	// #7
  400e70:	92fe0008 	mov	x8, #0xfffffffffffffff     	// #1152921504606846975
  400e74:	52800102 	mov	w2, #0x8                   	// #8
  400e78:	d280002b 	mov	x11, #0x1                   	// #1
  400e7c:	d503201f 	nop
  400e80:	34fffd24 	cbz	w4, 400e24 <strtol+0x54>
  400e84:	93407c49 	sxtw	x9, w2
  400e88:	52800007 	mov	w7, #0x0                   	// #0
  400e8c:	d2800005 	mov	x5, #0x0                   	// #0
  400e90:	14000008 	b	400eb0 <strtol+0xe0>
  400e94:	7a4a0064 	ccmp	w3, w10, #0x4, eq	// eq = none
  400e98:	1a9fd7e4 	cset	w4, gt
  400e9c:	2a0400e7 	orr	w7, w7, w4
  400ea0:	38401c04 	ldrb	w4, [x0, #1]!
  400ea4:	93407c63 	sxtw	x3, w3
  400ea8:	9b050d25 	madd	x5, x9, x5, x3
  400eac:	340005a4 	cbz	w4, 400f60 <strtol+0x190>
  400eb0:	5100c083 	sub	w3, w4, #0x30
  400eb4:	12001c66 	and	w6, w3, #0xff
  400eb8:	710024df 	cmp	w6, #0x9
  400ebc:	540000c9 	b.ls	400ed4 <strtol+0x104>  // b.plast
  400ec0:	51018483 	sub	w3, w4, #0x61
  400ec4:	12001c63 	and	w3, w3, #0xff
  400ec8:	7100647f 	cmp	w3, #0x19
  400ecc:	540003e8 	b.hi	400f48 <strtol+0x178>  // b.pmore
  400ed0:	51015c83 	sub	w3, w4, #0x57
  400ed4:	6b03005f 	cmp	w2, w3
  400ed8:	5400044d 	b.le	400f60 <strtol+0x190>
  400edc:	eb05011f 	cmp	x8, x5
  400ee0:	54fffda2 	b.cs	400e94 <strtol+0xc4>  // b.hs, b.nlast
  400ee4:	52800027 	mov	w7, #0x1                   	// #1
  400ee8:	17ffffee 	b	400ea0 <strtol+0xd0>
  400eec:	91000403 	add	x3, x0, #0x1
  400ef0:	d29fffe4 	mov	x4, #0xffff                	// #65535
  400ef4:	eb04007f 	cmp	x3, x4
  400ef8:	54fff8e9 	b.ls	400e14 <strtol+0x44>  // b.plast
  400efc:	35000682 	cbnz	w2, 400fcc <strtol+0x1fc>
  400f00:	39400404 	ldrb	w4, [x0, #1]
  400f04:	7100c09f 	cmp	w4, #0x30
  400f08:	54000aa0 	b.eq	40105c <strtol+0x28c>  // b.none
  400f0c:	aa0303e0 	mov	x0, x3
  400f10:	b202e7e8 	mov	x8, #0xcccccccccccccccc    	// #-3689348814741910324
  400f14:	528000ea 	mov	w10, #0x7                   	// #7
  400f18:	f2e19988 	movk	x8, #0xccc, lsl #48
  400f1c:	52800142 	mov	w2, #0xa                   	// #10
  400f20:	d280002b 	mov	x11, #0x1                   	// #1
  400f24:	17ffffd7 	b	400e80 <strtol+0xb0>
  400f28:	7100405f 	cmp	w2, #0x10
  400f2c:	540006c0 	b.eq	401004 <strtol+0x234>  // b.none
  400f30:	93407c4a 	sxtw	x10, w2
  400f34:	92f00003 	mov	x3, #0x7fffffffffffffff    	// #9223372036854775807
  400f38:	d280002b 	mov	x11, #0x1                   	// #1
  400f3c:	9aca0868 	udiv	x8, x3, x10
  400f40:	1b0a8d0a 	msub	w10, w8, w10, w3
  400f44:	17ffffcf 	b	400e80 <strtol+0xb0>
  400f48:	51010483 	sub	w3, w4, #0x41
  400f4c:	12001c63 	and	w3, w3, #0xff
  400f50:	7100647f 	cmp	w3, #0x19
  400f54:	54000068 	b.hi	400f60 <strtol+0x190>  // b.pmore
  400f58:	5100dc83 	sub	w3, w4, #0x37
  400f5c:	17ffffde 	b	400ed4 <strtol+0x104>
  400f60:	b4000041 	cbz	x1, 400f68 <strtol+0x198>
  400f64:	f9000020 	str	x0, [x1]
  400f68:	35000067 	cbnz	w7, 400f74 <strtol+0x1a4>
  400f6c:	9b0b7ca0 	mul	x0, x5, x11
  400f70:	d65f03c0 	ret
  400f74:	7100057f 	cmp	w11, #0x1
  400f78:	da9f13e0 	csetm	x0, eq	// eq = none
  400f7c:	d2410000 	eor	x0, x0, #0x8000000000000000
  400f80:	d65f03c0 	ret
  400f84:	91000405 	add	x5, x0, #0x1
  400f88:	d29fffe3 	mov	x3, #0xffff                	// #65535
  400f8c:	eb0300bf 	cmp	x5, x3
  400f90:	54000329 	b.ls	400ff4 <strtol+0x224>  // b.plast
  400f94:	34000442 	cbz	w2, 40101c <strtol+0x24c>
  400f98:	7100405f 	cmp	w2, #0x10
  400f9c:	54000880 	b.eq	4010ac <strtol+0x2dc>  // b.none
  400fa0:	93407c43 	sxtw	x3, w2
  400fa4:	92f00004 	mov	x4, #0x7fffffffffffffff    	// #9223372036854775807
  400fa8:	9ac30888 	udiv	x8, x4, x3
  400fac:	9b039103 	msub	x3, x8, x3, x4
  400fb0:	1100046a 	add	w10, w3, #0x1
  400fb4:	6b0a005f 	cmp	w2, w10
  400fb8:	5400046d 	b.le	401044 <strtol+0x274>
  400fbc:	39400404 	ldrb	w4, [x0, #1]
  400fc0:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  400fc4:	aa0503e0 	mov	x0, x5
  400fc8:	17ffffae 	b	400e80 <strtol+0xb0>
  400fcc:	7100405f 	cmp	w2, #0x10
  400fd0:	540005e0 	b.eq	40108c <strtol+0x2bc>  // b.none
  400fd4:	93407c4a 	sxtw	x10, w2
  400fd8:	92f00004 	mov	x4, #0x7fffffffffffffff    	// #9223372036854775807
  400fdc:	d280002b 	mov	x11, #0x1                   	// #1
  400fe0:	9aca0888 	udiv	x8, x4, x10
  400fe4:	1b0a910a 	msub	w10, w8, w10, w4
  400fe8:	39400404 	ldrb	w4, [x0, #1]
  400fec:	aa0303e0 	mov	x0, x3
  400ff0:	17ffffa4 	b	400e80 <strtol+0xb0>
  400ff4:	b4fff141 	cbz	x1, 400e1c <strtol+0x4c>
  400ff8:	d2800000 	mov	x0, #0x0                   	// #0
  400ffc:	f9000025 	str	x5, [x1]
  401000:	17ffff88 	b	400e20 <strtol+0x50>
  401004:	7100c09f 	cmp	w4, #0x30
  401008:	54000620 	b.eq	4010cc <strtol+0x2fc>  // b.none
  40100c:	528001ea 	mov	w10, #0xf                   	// #15
  401010:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401014:	d280002b 	mov	x11, #0x1                   	// #1
  401018:	17ffff9a 	b	400e80 <strtol+0xb0>
  40101c:	39400404 	ldrb	w4, [x0, #1]
  401020:	7100c09f 	cmp	w4, #0x30
  401024:	54000660 	b.eq	4010f0 <strtol+0x320>  // b.none
  401028:	b202e7e8 	mov	x8, #0xcccccccccccccccc    	// #-3689348814741910324
  40102c:	aa0503e0 	mov	x0, x5
  401030:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401034:	52800142 	mov	w2, #0xa                   	// #10
  401038:	5280010a 	mov	w10, #0x8                   	// #8
  40103c:	f2e19988 	movk	x8, #0xccc, lsl #48
  401040:	17ffff90 	b	400e80 <strtol+0xb0>
  401044:	39400404 	ldrb	w4, [x0, #1]
  401048:	91000508 	add	x8, x8, #0x1
  40104c:	4b02014a 	sub	w10, w10, w2
  401050:	aa0503e0 	mov	x0, x5
  401054:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401058:	17ffff8a 	b	400e80 <strtol+0xb0>
  40105c:	39400804 	ldrb	w4, [x0, #2]
  401060:	121a7882 	and	w2, w4, #0xffffffdf
  401064:	12001c42 	and	w2, w2, #0xff
  401068:	7101605f 	cmp	w2, #0x58
  40106c:	54000641 	b.ne	401134 <strtol+0x364>  // b.any
  401070:	39400c04 	ldrb	w4, [x0, #3]
  401074:	528001ea 	mov	w10, #0xf                   	// #15
  401078:	91000c00 	add	x0, x0, #0x3
  40107c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401080:	52800202 	mov	w2, #0x10                  	// #16
  401084:	d280002b 	mov	x11, #0x1                   	// #1
  401088:	17ffff7e 	b	400e80 <strtol+0xb0>
  40108c:	39400404 	ldrb	w4, [x0, #1]
  401090:	7100c09f 	cmp	w4, #0x30
  401094:	540005c0 	b.eq	40114c <strtol+0x37c>  // b.none
  401098:	aa0303e0 	mov	x0, x3
  40109c:	528001ea 	mov	w10, #0xf                   	// #15
  4010a0:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4010a4:	d280002b 	mov	x11, #0x1                   	// #1
  4010a8:	17ffff76 	b	400e80 <strtol+0xb0>
  4010ac:	39400404 	ldrb	w4, [x0, #1]
  4010b0:	7100c09f 	cmp	w4, #0x30
  4010b4:	54000800 	b.eq	4011b4 <strtol+0x3e4>  // b.none
  4010b8:	aa0503e0 	mov	x0, x5
  4010bc:	5280000a 	mov	w10, #0x0                   	// #0
  4010c0:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4010c4:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4010c8:	17ffff6e 	b	400e80 <strtol+0xb0>
  4010cc:	39400403 	ldrb	w3, [x0, #1]
  4010d0:	121a7863 	and	w3, w3, #0xffffffdf
  4010d4:	12001c63 	and	w3, w3, #0xff
  4010d8:	7101607f 	cmp	w3, #0x58
  4010dc:	540004c0 	b.eq	401174 <strtol+0x3a4>  // b.none
  4010e0:	d280002b 	mov	x11, #0x1                   	// #1
  4010e4:	528001ea 	mov	w10, #0xf                   	// #15
  4010e8:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4010ec:	17ffff66 	b	400e84 <strtol+0xb4>
  4010f0:	39400804 	ldrb	w4, [x0, #2]
  4010f4:	121a7882 	and	w2, w4, #0xffffffdf
  4010f8:	7101605f 	cmp	w2, #0x58
  4010fc:	540000e0 	b.eq	401118 <strtol+0x348>  // b.none
  401100:	91000800 	add	x0, x0, #0x2
  401104:	5280000a 	mov	w10, #0x0                   	// #0
  401108:	d2e20008 	mov	x8, #0x1000000000000000    	// #1152921504606846976
  40110c:	52800102 	mov	w2, #0x8                   	// #8
  401110:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401114:	17ffff5b 	b	400e80 <strtol+0xb0>
  401118:	39400c04 	ldrb	w4, [x0, #3]
  40111c:	5280000a 	mov	w10, #0x0                   	// #0
  401120:	91000c00 	add	x0, x0, #0x3
  401124:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  401128:	52800202 	mov	w2, #0x10                  	// #16
  40112c:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401130:	17ffff54 	b	400e80 <strtol+0xb0>
  401134:	91000800 	add	x0, x0, #0x2
  401138:	528000ea 	mov	w10, #0x7                   	// #7
  40113c:	92fe0008 	mov	x8, #0xfffffffffffffff     	// #1152921504606846975
  401140:	52800102 	mov	w2, #0x8                   	// #8
  401144:	d280002b 	mov	x11, #0x1                   	// #1
  401148:	17ffff4e 	b	400e80 <strtol+0xb0>
  40114c:	39400805 	ldrb	w5, [x0, #2]
  401150:	121a78a5 	and	w5, w5, #0xffffffdf
  401154:	12001ca5 	and	w5, w5, #0xff
  401158:	710160bf 	cmp	w5, #0x58
  40115c:	54000120 	b.eq	401180 <strtol+0x3b0>  // b.none
  401160:	aa0303e0 	mov	x0, x3
  401164:	d280002b 	mov	x11, #0x1                   	// #1
  401168:	528001ea 	mov	w10, #0xf                   	// #15
  40116c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401170:	17ffff45 	b	400e84 <strtol+0xb4>
  401174:	39400804 	ldrb	w4, [x0, #2]
  401178:	91000800 	add	x0, x0, #0x2
  40117c:	17ffffa4 	b	40100c <strtol+0x23c>
  401180:	39400c04 	ldrb	w4, [x0, #3]
  401184:	528001ea 	mov	w10, #0xf                   	// #15
  401188:	91000c00 	add	x0, x0, #0x3
  40118c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401190:	d280002b 	mov	x11, #0x1                   	// #1
  401194:	17ffff3b 	b	400e80 <strtol+0xb0>
  401198:	39400804 	ldrb	w4, [x0, #2]
  40119c:	528001ea 	mov	w10, #0xf                   	// #15
  4011a0:	91000800 	add	x0, x0, #0x2
  4011a4:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4011a8:	52800202 	mov	w2, #0x10                  	// #16
  4011ac:	d280002b 	mov	x11, #0x1                   	// #1
  4011b0:	17ffff34 	b	400e80 <strtol+0xb0>
  4011b4:	39400803 	ldrb	w3, [x0, #2]
  4011b8:	121a7863 	and	w3, w3, #0xffffffdf
  4011bc:	12001c63 	and	w3, w3, #0xff
  4011c0:	7101607f 	cmp	w3, #0x58
  4011c4:	540000e1 	b.ne	4011e0 <strtol+0x410>  // b.any
  4011c8:	39400c04 	ldrb	w4, [x0, #3]
  4011cc:	5280000a 	mov	w10, #0x0                   	// #0
  4011d0:	91000c00 	add	x0, x0, #0x3
  4011d4:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4011d8:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4011dc:	17ffff29 	b	400e80 <strtol+0xb0>
  4011e0:	aa0503e0 	mov	x0, x5
  4011e4:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4011e8:	5280000a 	mov	w10, #0x0                   	// #0
  4011ec:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4011f0:	17ffff25 	b	400e84 <strtol+0xb4>
  4011f4:	d503201f 	nop
  4011f8:	d503201f 	nop
  4011fc:	d503201f 	nop

0000000000401200 <__isoc23_strtol>:
  401200:	17fffef4 	b	400dd0 <strtol>
  401204:	d503201f 	nop
  401208:	d503201f 	nop
  40120c:	d503201f 	nop

0000000000401210 <atoi>:
  401210:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  401214:	52800142 	mov	w2, #0xa                   	// #10
  401218:	d2800001 	mov	x1, #0x0                   	// #0
  40121c:	910003fd 	mov	x29, sp
  401220:	97fffeec 	bl	400dd0 <strtol>
  401224:	a8c17bfd 	ldp	x29, x30, [sp], #16
  401228:	d65f03c0 	ret
  40122c:	d503201f 	nop

0000000000401230 <atol>:
  401230:	52800142 	mov	w2, #0xa                   	// #10
  401234:	d2800001 	mov	x1, #0x0                   	// #0
  401238:	17fffee6 	b	400dd0 <strtol>
  40123c:	d503201f 	nop

0000000000401240 <memcpy>:
  401240:	f100005f 	cmp	x2, #0x0
  401244:	d29fffe3 	mov	x3, #0xffff                	// #65535
  401248:	fa431020 	ccmp	x1, x3, #0x0, ne	// ne = any
  40124c:	fa438000 	ccmp	x0, x3, #0x0, hi	// hi = pmore
  401250:	54000048 	b.hi	401258 <memcpy+0x18>  // b.pmore
  401254:	d65f03c0 	ret
  401258:	d2800003 	mov	x3, #0x0                   	// #0
  40125c:	d503201f 	nop
  401260:	38636824 	ldrb	w4, [x1, x3]
  401264:	38236804 	strb	w4, [x0, x3]
  401268:	91000463 	add	x3, x3, #0x1
  40126c:	eb03005f 	cmp	x2, x3
  401270:	54ffff88 	b.hi	401260 <memcpy+0x20>  // b.pmore
  401274:	d65f03c0 	ret
  401278:	d503201f 	nop
  40127c:	d503201f 	nop

0000000000401280 <__memcpy_chk>:
  401280:	17fffff0 	b	401240 <memcpy>
  401284:	d503201f 	nop
  401288:	d503201f 	nop
  40128c:	d503201f 	nop

0000000000401290 <memset>:
  401290:	aa0003e3 	mov	x3, x0
  401294:	d29fffe4 	mov	x4, #0xffff                	// #65535
  401298:	eb04001f 	cmp	x0, x4
  40129c:	540000c9 	b.ls	4012b4 <memset+0x24>  // b.plast
  4012a0:	b40000a2 	cbz	x2, 4012b4 <memset+0x24>
  4012a4:	8b020002 	add	x2, x0, x2
  4012a8:	38001461 	strb	w1, [x3], #1
  4012ac:	eb02007f 	cmp	x3, x2
  4012b0:	54ffffc1 	b.ne	4012a8 <memset+0x18>  // b.any
  4012b4:	d65f03c0 	ret
  4012b8:	d503201f 	nop
  4012bc:	d503201f 	nop

00000000004012c0 <memcmp>:
  4012c0:	f100001f 	cmp	x0, #0x0
  4012c4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4012c8:	540001a0 	b.eq	4012fc <memcmp+0x3c>  // b.none
  4012cc:	b4000182 	cbz	x2, 4012fc <memcmp+0x3c>
  4012d0:	d2800003 	mov	x3, #0x0                   	// #0
  4012d4:	14000004 	b	4012e4 <memcmp+0x24>
  4012d8:	91000463 	add	x3, x3, #0x1
  4012dc:	eb03005f 	cmp	x2, x3
  4012e0:	540000e0 	b.eq	4012fc <memcmp+0x3c>  // b.none
  4012e4:	38636804 	ldrb	w4, [x0, x3]
  4012e8:	38636825 	ldrb	w5, [x1, x3]
  4012ec:	6b05009f 	cmp	w4, w5
  4012f0:	54ffff40 	b.eq	4012d8 <memcmp+0x18>  // b.none
  4012f4:	4b050080 	sub	w0, w4, w5
  4012f8:	d65f03c0 	ret
  4012fc:	52800000 	mov	w0, #0x0                   	// #0
  401300:	d65f03c0 	ret
  401304:	d503201f 	nop
  401308:	d503201f 	nop
  40130c:	d503201f 	nop

0000000000401310 <memmove>:
  401310:	f100001f 	cmp	x0, #0x0
  401314:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401318:	540001e0 	b.eq	401354 <memmove+0x44>  // b.none
  40131c:	d29fffe3 	mov	x3, #0xffff                	// #65535
  401320:	eb03001f 	cmp	x0, x3
  401324:	fa438020 	ccmp	x1, x3, #0x0, hi	// hi = pmore
  401328:	54000169 	b.ls	401354 <memmove+0x44>  // b.plast
  40132c:	eb01001f 	cmp	x0, x1
  401330:	54000142 	b.cs	401358 <memmove+0x48>  // b.hs, b.nlast
  401334:	b4000102 	cbz	x2, 401354 <memmove+0x44>
  401338:	d2800003 	mov	x3, #0x0                   	// #0
  40133c:	d503201f 	nop
  401340:	38636824 	ldrb	w4, [x1, x3]
  401344:	38236804 	strb	w4, [x0, x3]
  401348:	91000463 	add	x3, x3, #0x1
  40134c:	eb03005f 	cmp	x2, x3
  401350:	54ffff81 	b.ne	401340 <memmove+0x30>  // b.any
  401354:	d65f03c0 	ret
  401358:	b4ffffe2 	cbz	x2, 401354 <memmove+0x44>
  40135c:	d1000442 	sub	x2, x2, #0x1
  401360:	38626823 	ldrb	w3, [x1, x2]
  401364:	38226803 	strb	w3, [x0, x2]
  401368:	17fffffc 	b	401358 <memmove+0x48>
