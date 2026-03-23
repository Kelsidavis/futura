
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
  400044:	d4001001 	svc	#0x80
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
  400234:	940002c7 	bl	400d50 <strchr>
  400238:	b50013e0 	cbnz	x0, 4004b4 <set_pair+0x2b4>
  40023c:	f10002ff 	cmp	x23, #0x0
  400240:	d0000000 	adrp	x0, 402000 <memmove+0xc50>
  400244:	91002000 	add	x0, x0, #0x8
  400248:	a90153f3 	stp	x19, x20, [sp, #16]
  40024c:	9a970017 	csel	x23, x0, x23, eq	// eq = none
  400250:	aa1503e0 	mov	x0, x21
  400254:	94000247 	bl	400b70 <strlen>
  400258:	aa1603f4 	mov	x20, x22
  40025c:	aa0003f3 	mov	x19, x0
  400260:	aa1703e0 	mov	x0, x23
  400264:	94000243 	bl	400b70 <strlen>
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
  4002c4:	940001cb 	bl	4009f0 <free>
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
  400318:	94000182 	bl	400920 <malloc>
  40031c:	aa0003f4 	mov	x20, x0
  400320:	b4000b80 	cbz	x0, 400490 <set_pair+0x290>
  400324:	aa1303e2 	mov	x2, x19
  400328:	aa1503e1 	mov	x1, x21
  40032c:	940003ed 	bl	4012e0 <memcpy>
  400330:	528007a0 	mov	w0, #0x3d                  	// #61
  400334:	38336a80 	strb	w0, [x20, x19]
  400338:	91000660 	add	x0, x19, #0x1
  40033c:	aa1803e2 	mov	x2, x24
  400340:	aa1703e1 	mov	x1, x23
  400344:	8b000280 	add	x0, x20, x0
  400348:	940003e6 	bl	4012e0 <memcpy>
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
  400398:	94000196 	bl	4009f0 <free>
  40039c:	17ffffd1 	b	4002e0 <set_pair+0xe0>
  4003a0:	b4000698 	cbz	x24, 400470 <set_pair+0x270>
  4003a4:	d503201f 	nop
  4003a8:	b7f806d8 	tbnz	x24, #63, 400480 <set_pair+0x280>
  4003ac:	8b180318 	add	x24, x24, x24
  4003b0:	eb18001f 	cmp	x0, x24
  4003b4:	54ffffa8 	b.hi	4003a8 <set_pair+0x1a8>  // b.pmore
  4003b8:	d37df317 	lsl	x23, x24, #3
  4003bc:	aa1703e0 	mov	x0, x23
  4003c0:	94000158 	bl	400920 <malloc>
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
  400424:	94000173 	bl	4009f0 <free>
  400428:	d0000002 	adrp	x2, 402000 <memmove+0xc50>
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
  400490:	940001ac 	bl	400b40 <__errno_location@GLIBC_2.2.5>
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
  4004c0:	940001a0 	bl	400b40 <__errno_location@GLIBC_2.2.5>
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
  4004f0:	94000140 	bl	4009f0 <free>
  4004f4:	17ffffe7 	b	400490 <set_pair+0x290>
  4004f8:	d503201f 	nop
  4004fc:	d503201f 	nop

0000000000400500 <__libc_init_environ>:
  400500:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
  400504:	910003fd 	mov	x29, sp
  400508:	a9025bf5 	stp	x21, x22, [sp, #32]
  40050c:	a90363f7 	stp	x23, x24, [sp, #48]
  400510:	b4000720 	cbz	x0, 4005f4 <__libc_init_environ+0xf4>
  400514:	f9400002 	ldr	x2, [x0]
  400518:	d2800001 	mov	x1, #0x0                   	// #0
  40051c:	b40006c2 	cbz	x2, 4005f4 <__libc_init_environ+0xf4>
  400520:	a90153f3 	stp	x19, x20, [sp, #16]
  400524:	a9046bf9 	stp	x25, x26, [sp, #64]
  400528:	aa0103f7 	mov	x23, x1
  40052c:	91000421 	add	x1, x1, #0x1
  400530:	f8617802 	ldr	x2, [x0, x1, lsl #3]
  400534:	b5ffffa2 	cbnz	x2, 400528 <__libc_init_environ+0x28>
  400538:	91000af7 	add	x23, x23, #0x2
  40053c:	f0000018 	adrp	x24, 403000 <g_env_count>
  400540:	91000319 	add	x25, x24, #0x0
  400544:	aa0003f3 	mov	x19, x0
  400548:	d37df2fa 	lsl	x26, x23, #3
  40054c:	aa1a03e0 	mov	x0, x26
  400550:	940000f4 	bl	400920 <malloc>
  400554:	f9000720 	str	x0, [x25, #8]
  400558:	b40005c0 	cbz	x0, 400610 <__libc_init_environ+0x110>
  40055c:	d100235a 	sub	x26, x26, #0x8
  400560:	d2800016 	mov	x22, #0x0                   	// #0
  400564:	8b1a027a 	add	x26, x19, x26
  400568:	f9002bfb 	str	x27, [sp, #80]
  40056c:	d503201f 	nop
  400570:	f9400260 	ldr	x0, [x19]
  400574:	9400017f 	bl	400b70 <strlen>
  400578:	91000415 	add	x21, x0, #0x1
  40057c:	aa1503e0 	mov	x0, x21
  400580:	940000e8 	bl	400920 <malloc>
  400584:	aa0003f4 	mov	x20, x0
  400588:	b4000100 	cbz	x0, 4005a8 <__libc_init_environ+0xa8>
  40058c:	f9400261 	ldr	x1, [x19]
  400590:	aa1503e2 	mov	x2, x21
  400594:	d37df2db 	lsl	x27, x22, #3
  400598:	910006d6 	add	x22, x22, #0x1
  40059c:	94000351 	bl	4012e0 <memcpy>
  4005a0:	f9400720 	ldr	x0, [x25, #8]
  4005a4:	f83b6814 	str	x20, [x0, x27]
  4005a8:	91002273 	add	x19, x19, #0x8
  4005ac:	eb13035f 	cmp	x26, x19
  4005b0:	54fffe01 	b.ne	400570 <__libc_init_environ+0x70>  // b.any
  4005b4:	91000300 	add	x0, x24, #0x0
  4005b8:	f9402bfb 	ldr	x27, [sp, #80]
  4005bc:	f9400400 	ldr	x0, [x0, #8]
  4005c0:	f836781f 	str	xzr, [x0, x22, lsl #3]
  4005c4:	a94153f3 	ldp	x19, x20, [sp, #16]
  4005c8:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4005cc:	f9000316 	str	x22, [x24]
  4005d0:	d0000001 	adrp	x1, 402000 <memmove+0xc50>
  4005d4:	f9400c21 	ldr	x1, [x1, #24]
  4005d8:	f9000020 	str	x0, [x1]
  4005dc:	91000300 	add	x0, x24, #0x0
  4005e0:	f9000c17 	str	x23, [x0, #24]
  4005e4:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4005e8:	a94363f7 	ldp	x23, x24, [sp, #48]
  4005ec:	a8c67bfd 	ldp	x29, x30, [sp], #96
  4005f0:	d65f03c0 	ret
  4005f4:	f0000018 	adrp	x24, 403000 <g_env_count>
  4005f8:	91000300 	add	x0, x24, #0x0
  4005fc:	f900041f 	str	xzr, [x0, #8]
  400600:	d2800000 	mov	x0, #0x0                   	// #0
  400604:	d2800016 	mov	x22, #0x0                   	// #0
  400608:	d2800017 	mov	x23, #0x0                   	// #0
  40060c:	17fffff0 	b	4005cc <__libc_init_environ+0xcc>
  400610:	a94153f3 	ldp	x19, x20, [sp, #16]
  400614:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400618:	17fffffa 	b	400600 <__libc_init_environ+0x100>
  40061c:	d503201f 	nop

0000000000400620 <getenv>:
  400620:	b4000440 	cbz	x0, 4006a8 <getenv+0x88>
  400624:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400628:	52800023 	mov	w3, #0x1                   	// #1
  40062c:	910003fd 	mov	x29, sp
  400630:	f9000bf3 	str	x19, [sp, #16]
  400634:	f0000013 	adrp	x19, 403000 <g_env_count>
  400638:	91000269 	add	x9, x19, #0x0
  40063c:	91004121 	add	x1, x9, #0x10
  400640:	085ffc22 	ldaxrb	w2, [x1]
  400644:	08047c23 	stxrb	w4, w3, [x1]
  400648:	35ffffc4 	cbnz	w4, 400640 <getenv+0x20>
  40064c:	3707ffa2 	tbnz	w2, #0, 400640 <getenv+0x20>
  400650:	97fffec8 	bl	400170 <find_index>
  400654:	37f801c0 	tbnz	w0, #31, 40068c <getenv+0x6c>
  400658:	f9400521 	ldr	x1, [x9, #8]
  40065c:	f8605820 	ldr	x0, [x1, w0, uxtw #3]
  400660:	b4000160 	cbz	x0, 40068c <getenv+0x6c>
  400664:	528007a1 	mov	w1, #0x3d                  	// #61
  400668:	940001ba 	bl	400d50 <strchr>
  40066c:	b4000100 	cbz	x0, 40068c <getenv+0x6c>
  400670:	91000400 	add	x0, x0, #0x1
  400674:	91000273 	add	x19, x19, #0x0
  400678:	91004273 	add	x19, x19, #0x10
  40067c:	089ffe7f 	stlrb	wzr, [x19]
  400680:	f9400bf3 	ldr	x19, [sp, #16]
  400684:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400688:	d65f03c0 	ret
  40068c:	d2800000 	mov	x0, #0x0                   	// #0
  400690:	91000273 	add	x19, x19, #0x0
  400694:	91004273 	add	x19, x19, #0x10
  400698:	089ffe7f 	stlrb	wzr, [x19]
  40069c:	f9400bf3 	ldr	x19, [sp, #16]
  4006a0:	a8c27bfd 	ldp	x29, x30, [sp], #32
  4006a4:	d65f03c0 	ret
  4006a8:	d65f03c0 	ret
  4006ac:	d503201f 	nop

00000000004006b0 <secure_getenv>:
  4006b0:	17ffffdc 	b	400620 <getenv>
  4006b4:	d503201f 	nop
  4006b8:	d503201f 	nop
  4006bc:	d503201f 	nop

00000000004006c0 <__secure_getenv>:
  4006c0:	17fffffc 	b	4006b0 <secure_getenv>
  4006c4:	d503201f 	nop
  4006c8:	d503201f 	nop
  4006cc:	d503201f 	nop

00000000004006d0 <setenv>:
  4006d0:	7100005f 	cmp	w2, #0x0
  4006d4:	d2800003 	mov	x3, #0x0                   	// #0
  4006d8:	1a9f07e2 	cset	w2, ne	// ne = any
  4006dc:	17fffec9 	b	400200 <set_pair>

00000000004006e0 <putenv>:
  4006e0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4006e4:	910003fd 	mov	x29, sp
  4006e8:	b4000380 	cbz	x0, 400758 <putenv+0x78>
  4006ec:	528007a1 	mov	w1, #0x3d                  	// #61
  4006f0:	a90153f3 	stp	x19, x20, [sp, #16]
  4006f4:	aa0003f4 	mov	x20, x0
  4006f8:	94000196 	bl	400d50 <strchr>
  4006fc:	f100001f 	cmp	x0, #0x0
  400700:	aa0003f3 	mov	x19, x0
  400704:	fa401284 	ccmp	x20, x0, #0x4, ne	// ne = any
  400708:	540001c0 	b.eq	400740 <putenv+0x60>  // b.none
  40070c:	aa0003e1 	mov	x1, x0
  400710:	f90013f5 	str	x21, [sp, #32]
  400714:	aa1403e3 	mov	x3, x20
  400718:	aa1403e0 	mov	x0, x20
  40071c:	39400275 	ldrb	w21, [x19]
  400720:	52800022 	mov	w2, #0x1                   	// #1
  400724:	3800143f 	strb	wzr, [x1], #1
  400728:	97fffeb6 	bl	400200 <set_pair>
  40072c:	39000275 	strb	w21, [x19]
  400730:	a94153f3 	ldp	x19, x20, [sp, #16]
  400734:	f94013f5 	ldr	x21, [sp, #32]
  400738:	a8c37bfd 	ldp	x29, x30, [sp], #48
  40073c:	d65f03c0 	ret
  400740:	94000100 	bl	400b40 <__errno_location@GLIBC_2.2.5>
  400744:	528002c1 	mov	w1, #0x16                  	// #22
  400748:	b9000001 	str	w1, [x0]
  40074c:	12800000 	mov	w0, #0xffffffff            	// #-1
  400750:	a94153f3 	ldp	x19, x20, [sp, #16]
  400754:	17fffff9 	b	400738 <putenv+0x58>
  400758:	940000fa 	bl	400b40 <__errno_location@GLIBC_2.2.5>
  40075c:	528002c1 	mov	w1, #0x16                  	// #22
  400760:	b9000001 	str	w1, [x0]
  400764:	12800000 	mov	w0, #0xffffffff            	// #-1
  400768:	17fffff4 	b	400738 <putenv+0x58>
  40076c:	d503201f 	nop

0000000000400770 <unsetenv>:
  400770:	a9bc7bfd 	stp	x29, x30, [sp, #-64]!
  400774:	910003fd 	mov	x29, sp
  400778:	b40006e0 	cbz	x0, 400854 <unsetenv+0xe4>
  40077c:	a90153f3 	stp	x19, x20, [sp, #16]
  400780:	aa0003f4 	mov	x20, x0
  400784:	39400001 	ldrb	w1, [x0]
  400788:	34000641 	cbz	w1, 400850 <unsetenv+0xe0>
  40078c:	528007a1 	mov	w1, #0x3d                  	// #61
  400790:	94000170 	bl	400d50 <strchr>
  400794:	b50005e0 	cbnz	x0, 400850 <unsetenv+0xe0>
  400798:	f90013f5 	str	x21, [sp, #32]
  40079c:	f0000013 	adrp	x19, 403000 <g_env_count>
  4007a0:	91000275 	add	x21, x19, #0x0
  4007a4:	52800022 	mov	w2, #0x1                   	// #1
  4007a8:	910042a0 	add	x0, x21, #0x10
  4007ac:	d503201f 	nop
  4007b0:	085ffc01 	ldaxrb	w1, [x0]
  4007b4:	08037c02 	stxrb	w3, w2, [x0]
  4007b8:	35ffffc3 	cbnz	w3, 4007b0 <unsetenv+0x40>
  4007bc:	3707ffa1 	tbnz	w1, #0, 4007b0 <unsetenv+0x40>
  4007c0:	aa1403e0 	mov	x0, x20
  4007c4:	97fffe6b 	bl	400170 <find_index>
  4007c8:	2a0003e1 	mov	w1, w0
  4007cc:	36f80120 	tbz	w0, #31, 4007f0 <unsetenv+0x80>
  4007d0:	91000273 	add	x19, x19, #0x0
  4007d4:	91004273 	add	x19, x19, #0x10
  4007d8:	089ffe7f 	stlrb	wzr, [x19]
  4007dc:	a94153f3 	ldp	x19, x20, [sp, #16]
  4007e0:	52800000 	mov	w0, #0x0                   	// #0
  4007e4:	f94013f5 	ldr	x21, [sp, #32]
  4007e8:	a8c47bfd 	ldp	x29, x30, [sp], #64
  4007ec:	d65f03c0 	ret
  4007f0:	93407c14 	sxtw	x20, w0
  4007f4:	b9003fe1 	str	w1, [sp, #60]
  4007f8:	f94006a0 	ldr	x0, [x21, #8]
  4007fc:	91000694 	add	x20, x20, #0x1
  400800:	f8615800 	ldr	x0, [x0, w1, uxtw #3]
  400804:	9400007b 	bl	4009f0 <free>
  400808:	f9400263 	ldr	x3, [x19]
  40080c:	f94006a4 	ldr	x4, [x21, #8]
  400810:	eb03029f 	cmp	x20, x3
  400814:	b9403fe1 	ldr	w1, [sp, #60]
  400818:	54000122 	b.cs	40083c <unsetenv+0xcc>  // b.hs, b.nlast
  40081c:	91002080 	add	x0, x4, #0x8
  400820:	8b030c82 	add	x2, x4, x3, lsl #3
  400824:	8b214c00 	add	x0, x0, w1, uxtw #3
  400828:	f9400001 	ldr	x1, [x0]
  40082c:	91002000 	add	x0, x0, #0x8
  400830:	f81f0001 	stur	x1, [x0, #-16]
  400834:	eb02001f 	cmp	x0, x2
  400838:	54ffff81 	b.ne	400828 <unsetenv+0xb8>  // b.any
  40083c:	d1000463 	sub	x3, x3, #0x1
  400840:	f9000263 	str	x3, [x19]
  400844:	b4fffc64 	cbz	x4, 4007d0 <unsetenv+0x60>
  400848:	f823789f 	str	xzr, [x4, x3, lsl #3]
  40084c:	17ffffe1 	b	4007d0 <unsetenv+0x60>
  400850:	a94153f3 	ldp	x19, x20, [sp, #16]
  400854:	940000bb 	bl	400b40 <__errno_location@GLIBC_2.2.5>
  400858:	528002c1 	mov	w1, #0x16                  	// #22
  40085c:	b9000001 	str	w1, [x0]
  400860:	12800000 	mov	w0, #0xffffffff            	// #-1
  400864:	17ffffe1 	b	4007e8 <unsetenv+0x78>
  400868:	d503201f 	nop
  40086c:	d503201f 	nop

0000000000400870 <clearenv>:
  400870:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400874:	52800022 	mov	w2, #0x1                   	// #1
  400878:	910003fd 	mov	x29, sp
  40087c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400880:	f0000016 	adrp	x22, 403000 <g_env_count>
  400884:	910002c0 	add	x0, x22, #0x0
  400888:	91004000 	add	x0, x0, #0x10
  40088c:	a90153f3 	stp	x19, x20, [sp, #16]
  400890:	085ffc01 	ldaxrb	w1, [x0]
  400894:	08037c02 	stxrb	w3, w2, [x0]
  400898:	35ffffc3 	cbnz	w3, 400890 <clearenv+0x20>
  40089c:	3707ffa1 	tbnz	w1, #0, 400890 <clearenv+0x20>
  4008a0:	f94002c0 	ldr	x0, [x22]
  4008a4:	b40001a0 	cbz	x0, 4008d8 <clearenv+0x68>
  4008a8:	910002d5 	add	x21, x22, #0x0
  4008ac:	d2800014 	mov	x20, #0x0                   	// #0
  4008b0:	d2800013 	mov	x19, #0x0                   	// #0
  4008b4:	d503201f 	nop
  4008b8:	f94006a0 	ldr	x0, [x21, #8]
  4008bc:	91000673 	add	x19, x19, #0x1
  4008c0:	f8746800 	ldr	x0, [x0, x20]
  4008c4:	91002294 	add	x20, x20, #0x8
  4008c8:	9400004a 	bl	4009f0 <free>
  4008cc:	f94002a0 	ldr	x0, [x21]
  4008d0:	eb13001f 	cmp	x0, x19
  4008d4:	54ffff28 	b.hi	4008b8 <clearenv+0x48>  // b.pmore
  4008d8:	910002d3 	add	x19, x22, #0x0
  4008dc:	f9400660 	ldr	x0, [x19, #8]
  4008e0:	94000044 	bl	4009f0 <free>
  4008e4:	f90002df 	str	xzr, [x22]
  4008e8:	d0000000 	adrp	x0, 402000 <memmove+0xc50>
  4008ec:	f9400c00 	ldr	x0, [x0, #24]
  4008f0:	f900067f 	str	xzr, [x19, #8]
  4008f4:	f9000e7f 	str	xzr, [x19, #24]
  4008f8:	f900001f 	str	xzr, [x0]
  4008fc:	91004273 	add	x19, x19, #0x10
  400900:	089ffe7f 	stlrb	wzr, [x19]
  400904:	52800000 	mov	w0, #0x0                   	// #0
  400908:	a94153f3 	ldp	x19, x20, [sp, #16]
  40090c:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400910:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400914:	d65f03c0 	ret
	...

0000000000400920 <malloc>:
  400920:	b4000640 	cbz	x0, 4009e8 <malloc+0xc8>
  400924:	91003c00 	add	x0, x0, #0xf
  400928:	f0000006 	adrp	x6, 403000 <g_env_count>
  40092c:	9100a0c4 	add	x4, x6, #0x28
  400930:	927c6c02 	and	x2, x0, #0xfffffff0
  400934:	f100405f 	cmp	x2, #0x10
  400938:	d2800200 	mov	x0, #0x10                  	// #16
  40093c:	9a802042 	csel	x2, x2, x0, cs	// cs = hs, nlast
  400940:	91002080 	add	x0, x4, #0x8
  400944:	52800023 	mov	w3, #0x1                   	// #1
  400948:	085ffc01 	ldaxrb	w1, [x0]
  40094c:	08057c03 	stxrb	w5, w3, [x0]
  400950:	35ffffc5 	cbnz	w5, 400948 <malloc+0x28>
  400954:	3707ffa1 	tbnz	w1, #0, 400948 <malloc+0x28>
  400958:	f94014c1 	ldr	x1, [x6, #40]
  40095c:	b5000081 	cbnz	x1, 40096c <malloc+0x4c>
  400960:	1400000c 	b	400990 <malloc+0x70>
  400964:	aa0003e4 	mov	x4, x0
  400968:	b4000141 	cbz	x1, 400990 <malloc+0x70>
  40096c:	aa0103e0 	mov	x0, x1
  400970:	a97f8423 	ldp	x3, x1, [x1, #-8]
  400974:	eb02007f 	cmp	x3, x2
  400978:	54ffff63 	b.cc	400964 <malloc+0x44>  // b.lo, b.ul, b.last
  40097c:	9100a0c6 	add	x6, x6, #0x28
  400980:	f9000081 	str	x1, [x4]
  400984:	910020c6 	add	x6, x6, #0x8
  400988:	089ffcdf 	stlrb	wzr, [x6]
  40098c:	d65f03c0 	ret
  400990:	d2800188 	mov	x8, #0xc                   	// #12
  400994:	d2800000 	mov	x0, #0x0                   	// #0
  400998:	d4000001 	svc	#0x0
  40099c:	aa0003e1 	mov	x1, x0
  4009a0:	d29fffe0 	mov	x0, #0xffff                	// #65535
  4009a4:	eb00003f 	cmp	x1, x0
  4009a8:	540001ad 	b.le	4009dc <malloc+0xbc>
  4009ac:	91002043 	add	x3, x2, #0x8
  4009b0:	8b010063 	add	x3, x3, x1
  4009b4:	aa0303e0 	mov	x0, x3
  4009b8:	d4000001 	svc	#0x0
  4009bc:	eb00007f 	cmp	x3, x0
  4009c0:	540000ec 	b.gt	4009dc <malloc+0xbc>
  4009c4:	9100a0c6 	add	x6, x6, #0x28
  4009c8:	910020c6 	add	x6, x6, #0x8
  4009cc:	089ffcdf 	stlrb	wzr, [x6]
  4009d0:	aa0103e0 	mov	x0, x1
  4009d4:	f8008402 	str	x2, [x0], #8
  4009d8:	d65f03c0 	ret
  4009dc:	9100a0c0 	add	x0, x6, #0x28
  4009e0:	91002000 	add	x0, x0, #0x8
  4009e4:	089ffc1f 	stlrb	wzr, [x0]
  4009e8:	d2800000 	mov	x0, #0x0                   	// #0
  4009ec:	d65f03c0 	ret

00000000004009f0 <free>:
  4009f0:	d29fffe1 	mov	x1, #0xffff                	// #65535
  4009f4:	eb01001f 	cmp	x0, x1
  4009f8:	54000048 	b.hi	400a00 <free+0x10>  // b.pmore
  4009fc:	d65f03c0 	ret
  400a00:	f0000005 	adrp	x5, 403000 <g_env_count>
  400a04:	9100a0a1 	add	x1, x5, #0x28
  400a08:	91002021 	add	x1, x1, #0x8
  400a0c:	52800023 	mov	w3, #0x1                   	// #1
  400a10:	085ffc22 	ldaxrb	w2, [x1]
  400a14:	08047c23 	stxrb	w4, w3, [x1]
  400a18:	35ffffc4 	cbnz	w4, 400a10 <free+0x20>
  400a1c:	3707ffa2 	tbnz	w2, #0, 400a10 <free+0x20>
  400a20:	f94014a2 	ldr	x2, [x5, #40]
  400a24:	f9000002 	str	x2, [x0]
  400a28:	f90014a0 	str	x0, [x5, #40]
  400a2c:	089ffc3f 	stlrb	wzr, [x1]
  400a30:	d65f03c0 	ret
  400a34:	d503201f 	nop
  400a38:	d503201f 	nop
  400a3c:	d503201f 	nop

0000000000400a40 <calloc>:
  400a40:	b4000060 	cbz	x0, 400a4c <calloc+0xc>
  400a44:	9bc17c02 	umulh	x2, x0, x1
  400a48:	b5000222 	cbnz	x2, 400a8c <calloc+0x4c>
  400a4c:	9b017c02 	mul	x2, x0, x1
  400a50:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400a54:	910003fd 	mov	x29, sp
  400a58:	aa0203e0 	mov	x0, x2
  400a5c:	f9000be2 	str	x2, [sp, #16]
  400a60:	97ffffb0 	bl	400920 <malloc>
  400a64:	aa0003e3 	mov	x3, x0
  400a68:	b40000c0 	cbz	x0, 400a80 <calloc+0x40>
  400a6c:	f9400be2 	ldr	x2, [sp, #16]
  400a70:	52800001 	mov	w1, #0x0                   	// #0
  400a74:	f9000fe0 	str	x0, [sp, #24]
  400a78:	9400022e 	bl	401330 <memset>
  400a7c:	f9400fe3 	ldr	x3, [sp, #24]
  400a80:	aa0303e0 	mov	x0, x3
  400a84:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400a88:	d65f03c0 	ret
  400a8c:	d2800003 	mov	x3, #0x0                   	// #0
  400a90:	aa0303e0 	mov	x0, x3
  400a94:	d65f03c0 	ret
  400a98:	d503201f 	nop
  400a9c:	d503201f 	nop

0000000000400aa0 <realloc>:
  400aa0:	b4000380 	cbz	x0, 400b10 <realloc+0x70>
  400aa4:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400aa8:	910003fd 	mov	x29, sp
  400aac:	b4000361 	cbz	x1, 400b18 <realloc+0x78>
  400ab0:	f85f8002 	ldur	x2, [x0, #-8]
  400ab4:	aa0003e3 	mov	x3, x0
  400ab8:	aa0003e4 	mov	x4, x0
  400abc:	eb02003f 	cmp	x1, x2
  400ac0:	54000088 	b.hi	400ad0 <realloc+0x30>  // b.pmore
  400ac4:	aa0403e0 	mov	x0, x4
  400ac8:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400acc:	d65f03c0 	ret
  400ad0:	aa0103e0 	mov	x0, x1
  400ad4:	a9018fe2 	stp	x2, x3, [sp, #24]
  400ad8:	97ffff92 	bl	400920 <malloc>
  400adc:	aa0003e4 	mov	x4, x0
  400ae0:	b4ffff20 	cbz	x0, 400ac4 <realloc+0x24>
  400ae4:	a9418fe2 	ldp	x2, x3, [sp, #24]
  400ae8:	f9000fe3 	str	x3, [sp, #24]
  400aec:	f90017e0 	str	x0, [sp, #40]
  400af0:	aa0303e1 	mov	x1, x3
  400af4:	940001fb 	bl	4012e0 <memcpy>
  400af8:	f9400fe0 	ldr	x0, [sp, #24]
  400afc:	97ffffbd 	bl	4009f0 <free>
  400b00:	f94017e4 	ldr	x4, [sp, #40]
  400b04:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400b08:	aa0403e0 	mov	x0, x4
  400b0c:	d65f03c0 	ret
  400b10:	aa0103e0 	mov	x0, x1
  400b14:	17ffff83 	b	400920 <malloc>
  400b18:	97ffffb6 	bl	4009f0 <free>
  400b1c:	d2800004 	mov	x4, #0x0                   	// #0
  400b20:	17ffffe9 	b	400ac4 <realloc+0x24>
  400b24:	d503201f 	nop
  400b28:	d503201f 	nop
  400b2c:	d503201f 	nop

0000000000400b30 <heap_stats>:
  400b30:	d65f03c0 	ret
	...

0000000000400b40 <__errno_location@GLIBC_2.2.5>:
  400b40:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  400b44:	910003fd 	mov	x29, sp
  400b48:	d2a00000 	movz	x0, #0x0, lsl #16
  400b4c:	f2800200 	movk	x0, #0x10
  400b50:	d503201f 	nop
  400b54:	d503201f 	nop
  400b58:	d53bd041 	mrs	x1, tpidr_el0
  400b5c:	8b000020 	add	x0, x1, x0
  400b60:	a8c17bfd 	ldp	x29, x30, [sp], #16
  400b64:	d65f03c0 	ret
	...

0000000000400b70 <strlen>:
  400b70:	aa0003e2 	mov	x2, x0
  400b74:	b4000120 	cbz	x0, 400b98 <strlen+0x28>
  400b78:	39400000 	ldrb	w0, [x0]
  400b7c:	340000e0 	cbz	w0, 400b98 <strlen+0x28>
  400b80:	d2800000 	mov	x0, #0x0                   	// #0
  400b84:	d503201f 	nop
  400b88:	91000400 	add	x0, x0, #0x1
  400b8c:	38606841 	ldrb	w1, [x2, x0]
  400b90:	35ffffc1 	cbnz	w1, 400b88 <strlen+0x18>
  400b94:	d65f03c0 	ret
  400b98:	d2800000 	mov	x0, #0x0                   	// #0
  400b9c:	d65f03c0 	ret

0000000000400ba0 <strncpy>:
  400ba0:	f100001f 	cmp	x0, #0x0
  400ba4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400ba8:	54000220 	b.eq	400bec <strncpy+0x4c>  // b.none
  400bac:	d2800003 	mov	x3, #0x0                   	// #0
  400bb0:	b50000c2 	cbnz	x2, 400bc8 <strncpy+0x28>
  400bb4:	1400000e 	b	400bec <strncpy+0x4c>
  400bb8:	38236804 	strb	w4, [x0, x3]
  400bbc:	91000463 	add	x3, x3, #0x1
  400bc0:	eb03005f 	cmp	x2, x3
  400bc4:	54000140 	b.eq	400bec <strncpy+0x4c>  // b.none
  400bc8:	38636824 	ldrb	w4, [x1, x3]
  400bcc:	35ffff64 	cbnz	w4, 400bb8 <strncpy+0x18>
  400bd0:	eb03005f 	cmp	x2, x3
  400bd4:	540000c9 	b.ls	400bec <strncpy+0x4c>  // b.plast
  400bd8:	8b030003 	add	x3, x0, x3
  400bdc:	8b020002 	add	x2, x0, x2
  400be0:	3800147f 	strb	wzr, [x3], #1
  400be4:	eb02007f 	cmp	x3, x2
  400be8:	54ffffc1 	b.ne	400be0 <strncpy+0x40>  // b.any
  400bec:	d65f03c0 	ret

0000000000400bf0 <strcpy>:
  400bf0:	f100001f 	cmp	x0, #0x0
  400bf4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400bf8:	54000140 	b.eq	400c20 <strcpy+0x30>  // b.none
  400bfc:	39400023 	ldrb	w3, [x1]
  400c00:	34000123 	cbz	w3, 400c24 <strcpy+0x34>
  400c04:	d2800002 	mov	x2, #0x0                   	// #0
  400c08:	38226803 	strb	w3, [x0, x2]
  400c0c:	91000442 	add	x2, x2, #0x1
  400c10:	38626823 	ldrb	w3, [x1, x2]
  400c14:	35ffffa3 	cbnz	w3, 400c08 <strcpy+0x18>
  400c18:	8b020002 	add	x2, x0, x2
  400c1c:	3900005f 	strb	wzr, [x2]
  400c20:	d65f03c0 	ret
  400c24:	aa0003e2 	mov	x2, x0
  400c28:	3900005f 	strb	wzr, [x2]
  400c2c:	17fffffd 	b	400c20 <strcpy+0x30>

0000000000400c30 <strcmp>:
  400c30:	f100001f 	cmp	x0, #0x0
  400c34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c38:	540001a0 	b.eq	400c6c <strcmp+0x3c>  // b.none
  400c3c:	39400002 	ldrb	w2, [x0]
  400c40:	350000a2 	cbnz	w2, 400c54 <strcmp+0x24>
  400c44:	1400000f 	b	400c80 <strcmp+0x50>
  400c48:	38401c02 	ldrb	w2, [x0, #1]!
  400c4c:	34000142 	cbz	w2, 400c74 <strcmp+0x44>
  400c50:	91000421 	add	x1, x1, #0x1
  400c54:	39400023 	ldrb	w3, [x1]
  400c58:	7100007f 	cmp	w3, #0x0
  400c5c:	7a421060 	ccmp	w3, w2, #0x0, ne	// ne = any
  400c60:	54ffff40 	b.eq	400c48 <strcmp+0x18>  // b.none
  400c64:	4b030040 	sub	w0, w2, w3
  400c68:	d65f03c0 	ret
  400c6c:	52800000 	mov	w0, #0x0                   	// #0
  400c70:	d65f03c0 	ret
  400c74:	39400423 	ldrb	w3, [x1, #1]
  400c78:	4b030040 	sub	w0, w2, w3
  400c7c:	17fffffb 	b	400c68 <strcmp+0x38>
  400c80:	39400023 	ldrb	w3, [x1]
  400c84:	4b030040 	sub	w0, w2, w3
  400c88:	17fffff8 	b	400c68 <strcmp+0x38>
  400c8c:	d503201f 	nop

0000000000400c90 <strncmp>:
  400c90:	f100003f 	cmp	x1, #0x0
  400c94:	d2800003 	mov	x3, #0x0                   	// #0
  400c98:	fa401844 	ccmp	x2, #0x0, #0x4, ne	// ne = any
  400c9c:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
  400ca0:	54000081 	b.ne	400cb0 <strncmp+0x20>  // b.any
  400ca4:	52800004 	mov	w4, #0x0                   	// #0
  400ca8:	2a0403e0 	mov	w0, w4
  400cac:	d65f03c0 	ret
  400cb0:	38636804 	ldrb	w4, [x0, x3]
  400cb4:	34000104 	cbz	w4, 400cd4 <strncmp+0x44>
  400cb8:	38636825 	ldrb	w5, [x1, x3]
  400cbc:	340000c5 	cbz	w5, 400cd4 <strncmp+0x44>
  400cc0:	6b05009f 	cmp	w4, w5
  400cc4:	54000181 	b.ne	400cf4 <strncmp+0x64>  // b.any
  400cc8:	91000463 	add	x3, x3, #0x1
  400ccc:	eb03005f 	cmp	x2, x3
  400cd0:	54ffff08 	b.hi	400cb0 <strncmp+0x20>  // b.pmore
  400cd4:	52800004 	mov	w4, #0x0                   	// #0
  400cd8:	eb02007f 	cmp	x3, x2
  400cdc:	54fffe60 	b.eq	400ca8 <strncmp+0x18>  // b.none
  400ce0:	38636804 	ldrb	w4, [x0, x3]
  400ce4:	38636820 	ldrb	w0, [x1, x3]
  400ce8:	4b000084 	sub	w4, w4, w0
  400cec:	2a0403e0 	mov	w0, w4
  400cf0:	d65f03c0 	ret
  400cf4:	4b050084 	sub	w4, w4, w5
  400cf8:	2a0403e0 	mov	w0, w4
  400cfc:	d65f03c0 	ret

0000000000400d00 <strcat>:
  400d00:	f100001f 	cmp	x0, #0x0
  400d04:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d08:	54000041 	b.ne	400d10 <strcat+0x10>  // b.any
  400d0c:	d65f03c0 	ret
  400d10:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400d14:	910003fd 	mov	x29, sp
  400d18:	a90107e0 	stp	x0, x1, [sp, #16]
  400d1c:	97ffff95 	bl	400b70 <strlen>
  400d20:	a94107e3 	ldp	x3, x1, [sp, #16]
  400d24:	39400022 	ldrb	w2, [x1]
  400d28:	8b000060 	add	x0, x3, x0
  400d2c:	34000082 	cbz	w2, 400d3c <strcat+0x3c>
  400d30:	38001402 	strb	w2, [x0], #1
  400d34:	38401c22 	ldrb	w2, [x1, #1]!
  400d38:	35ffffc2 	cbnz	w2, 400d30 <strcat+0x30>
  400d3c:	3900001f 	strb	wzr, [x0]
  400d40:	aa0303e0 	mov	x0, x3
  400d44:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400d48:	d65f03c0 	ret
  400d4c:	d503201f 	nop

0000000000400d50 <strchr>:
  400d50:	b4000120 	cbz	x0, 400d74 <strchr+0x24>
  400d54:	39400002 	ldrb	w2, [x0]
  400d58:	12001c21 	and	w1, w1, #0xff
  400d5c:	35000082 	cbnz	w2, 400d6c <strchr+0x1c>
  400d60:	14000006 	b	400d78 <strchr+0x28>
  400d64:	38401c02 	ldrb	w2, [x0, #1]!
  400d68:	34000082 	cbz	w2, 400d78 <strchr+0x28>
  400d6c:	6b01005f 	cmp	w2, w1
  400d70:	54ffffa1 	b.ne	400d64 <strchr+0x14>  // b.any
  400d74:	d65f03c0 	ret
  400d78:	7100003f 	cmp	w1, #0x0
  400d7c:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
  400d80:	d65f03c0 	ret
  400d84:	d503201f 	nop
  400d88:	d503201f 	nop
  400d8c:	d503201f 	nop

0000000000400d90 <strdup>:
  400d90:	b4000300 	cbz	x0, 400df0 <strdup+0x60>
  400d94:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400d98:	910003fd 	mov	x29, sp
  400d9c:	f9000fe0 	str	x0, [sp, #24]
  400da0:	97ffff74 	bl	400b70 <strlen>
  400da4:	91000403 	add	x3, x0, #0x1
  400da8:	f9000be3 	str	x3, [sp, #16]
  400dac:	aa0303e0 	mov	x0, x3
  400db0:	97fffedc 	bl	400920 <malloc>
  400db4:	b4000180 	cbz	x0, 400de4 <strdup+0x54>
  400db8:	a94113e3 	ldp	x3, x4, [sp, #16]
  400dbc:	d2800001 	mov	x1, #0x0                   	// #0
  400dc0:	b40000e3 	cbz	x3, 400ddc <strdup+0x4c>
  400dc4:	d503201f 	nop
  400dc8:	38616882 	ldrb	w2, [x4, x1]
  400dcc:	38216802 	strb	w2, [x0, x1]
  400dd0:	91000421 	add	x1, x1, #0x1
  400dd4:	eb01007f 	cmp	x3, x1
  400dd8:	54ffff81 	b.ne	400dc8 <strdup+0x38>  // b.any
  400ddc:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400de0:	d65f03c0 	ret
  400de4:	d2800000 	mov	x0, #0x0                   	// #0
  400de8:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400dec:	d65f03c0 	ret
  400df0:	d2800000 	mov	x0, #0x0                   	// #0
  400df4:	d65f03c0 	ret
  400df8:	d503201f 	nop
  400dfc:	d503201f 	nop

0000000000400e00 <strstr>:
  400e00:	f100001f 	cmp	x0, #0x0
  400e04:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400e08:	54000480 	b.eq	400e98 <strstr+0x98>  // b.none
  400e0c:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400e10:	910003fd 	mov	x29, sp
  400e14:	a90153f3 	stp	x19, x20, [sp, #16]
  400e18:	aa0003f3 	mov	x19, x0
  400e1c:	39400022 	ldrb	w2, [x1]
  400e20:	35000082 	cbnz	w2, 400e30 <strstr+0x30>
  400e24:	a94153f3 	ldp	x19, x20, [sp, #16]
  400e28:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400e2c:	d65f03c0 	ret
  400e30:	aa0103f4 	mov	x20, x1
  400e34:	aa0103e0 	mov	x0, x1
  400e38:	f90013f5 	str	x21, [sp, #32]
  400e3c:	97ffff4d 	bl	400b70 <strlen>
  400e40:	39400262 	ldrb	w2, [x19]
  400e44:	aa0003f5 	mov	x21, x0
  400e48:	35000082 	cbnz	w2, 400e58 <strstr+0x58>
  400e4c:	1400000e 	b	400e84 <strstr+0x84>
  400e50:	38401e62 	ldrb	w2, [x19, #1]!
  400e54:	34000182 	cbz	w2, 400e84 <strstr+0x84>
  400e58:	39400280 	ldrb	w0, [x20]
  400e5c:	6b02001f 	cmp	w0, w2
  400e60:	54ffff81 	b.ne	400e50 <strstr+0x50>  // b.any
  400e64:	aa1503e2 	mov	x2, x21
  400e68:	aa1403e1 	mov	x1, x20
  400e6c:	aa1303e0 	mov	x0, x19
  400e70:	97ffff88 	bl	400c90 <strncmp>
  400e74:	35fffee0 	cbnz	w0, 400e50 <strstr+0x50>
  400e78:	f94013f5 	ldr	x21, [sp, #32]
  400e7c:	aa1303e0 	mov	x0, x19
  400e80:	17ffffe9 	b	400e24 <strstr+0x24>
  400e84:	f94013f5 	ldr	x21, [sp, #32]
  400e88:	d2800000 	mov	x0, #0x0                   	// #0
  400e8c:	a94153f3 	ldp	x19, x20, [sp, #16]
  400e90:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400e94:	d65f03c0 	ret
  400e98:	d2800000 	mov	x0, #0x0                   	// #0
  400e9c:	d65f03c0 	ret

0000000000400ea0 <strtol>:
  400ea0:	91100006 	add	x6, x0, #0x400
  400ea4:	d29fffe5 	mov	x5, #0xffff                	// #65535
  400ea8:	eb05001f 	cmp	x0, x5
  400eac:	540000a8 	b.hi	400ec0 <strtol+0x20>  // b.pmore
  400eb0:	14000011 	b	400ef4 <strtol+0x54>
  400eb4:	eb0300df 	cmp	x6, x3
  400eb8:	54000260 	b.eq	400f04 <strtol+0x64>  // b.none
  400ebc:	aa0303e0 	mov	x0, x3
  400ec0:	39400004 	ldrb	w4, [x0]
  400ec4:	51002483 	sub	w3, w4, #0x9
  400ec8:	7100809f 	cmp	w4, #0x20
  400ecc:	12001c63 	and	w3, w3, #0xff
  400ed0:	7a441860 	ccmp	w3, #0x4, #0x0, ne	// ne = any
  400ed4:	540001c8 	b.hi	400f0c <strtol+0x6c>  // b.pmore
  400ed8:	91000403 	add	x3, x0, #0x1
  400edc:	eb05007f 	cmp	x3, x5
  400ee0:	54fffea8 	b.hi	400eb4 <strtol+0x14>  // b.pmore
  400ee4:	b4000041 	cbz	x1, 400eec <strtol+0x4c>
  400ee8:	f9000023 	str	x3, [x1]
  400eec:	d2800000 	mov	x0, #0x0                   	// #0
  400ef0:	d65f03c0 	ret
  400ef4:	b4ffffc1 	cbz	x1, 400eec <strtol+0x4c>
  400ef8:	f9000020 	str	x0, [x1]
  400efc:	d2800000 	mov	x0, #0x0                   	// #0
  400f00:	17fffffc 	b	400ef0 <strtol+0x50>
  400f04:	39400404 	ldrb	w4, [x0, #1]
  400f08:	aa0603e0 	mov	x0, x6
  400f0c:	7100ac9f 	cmp	w4, #0x2b
  400f10:	54000560 	b.eq	400fbc <strtol+0x11c>  // b.none
  400f14:	7100b49f 	cmp	w4, #0x2d
  400f18:	540009e0 	b.eq	401054 <strtol+0x1b4>  // b.none
  400f1c:	350006e2 	cbnz	w2, 400ff8 <strtol+0x158>
  400f20:	7100c09f 	cmp	w4, #0x30
  400f24:	540005e1 	b.ne	400fe0 <strtol+0x140>  // b.any
  400f28:	39400404 	ldrb	w4, [x0, #1]
  400f2c:	121a7882 	and	w2, w4, #0xffffffdf
  400f30:	7101605f 	cmp	w2, #0x58
  400f34:	540019a0 	b.eq	401268 <strtol+0x3c8>  // b.none
  400f38:	91000400 	add	x0, x0, #0x1
  400f3c:	528000ea 	mov	w10, #0x7                   	// #7
  400f40:	92fe0008 	mov	x8, #0xfffffffffffffff     	// #1152921504606846975
  400f44:	52800102 	mov	w2, #0x8                   	// #8
  400f48:	d280002b 	mov	x11, #0x1                   	// #1
  400f4c:	d503201f 	nop
  400f50:	34fffd24 	cbz	w4, 400ef4 <strtol+0x54>
  400f54:	93407c49 	sxtw	x9, w2
  400f58:	52800007 	mov	w7, #0x0                   	// #0
  400f5c:	d2800005 	mov	x5, #0x0                   	// #0
  400f60:	14000008 	b	400f80 <strtol+0xe0>
  400f64:	7a4a0064 	ccmp	w3, w10, #0x4, eq	// eq = none
  400f68:	1a9fd7e4 	cset	w4, gt
  400f6c:	2a0400e7 	orr	w7, w7, w4
  400f70:	38401c04 	ldrb	w4, [x0, #1]!
  400f74:	93407c63 	sxtw	x3, w3
  400f78:	9b050d25 	madd	x5, x9, x5, x3
  400f7c:	340005a4 	cbz	w4, 401030 <strtol+0x190>
  400f80:	5100c083 	sub	w3, w4, #0x30
  400f84:	12001c66 	and	w6, w3, #0xff
  400f88:	710024df 	cmp	w6, #0x9
  400f8c:	540000c9 	b.ls	400fa4 <strtol+0x104>  // b.plast
  400f90:	51018483 	sub	w3, w4, #0x61
  400f94:	12001c63 	and	w3, w3, #0xff
  400f98:	7100647f 	cmp	w3, #0x19
  400f9c:	540003e8 	b.hi	401018 <strtol+0x178>  // b.pmore
  400fa0:	51015c83 	sub	w3, w4, #0x57
  400fa4:	6b03005f 	cmp	w2, w3
  400fa8:	5400044d 	b.le	401030 <strtol+0x190>
  400fac:	eb05011f 	cmp	x8, x5
  400fb0:	54fffda2 	b.cs	400f64 <strtol+0xc4>  // b.hs, b.nlast
  400fb4:	52800027 	mov	w7, #0x1                   	// #1
  400fb8:	17ffffee 	b	400f70 <strtol+0xd0>
  400fbc:	91000403 	add	x3, x0, #0x1
  400fc0:	d29fffe4 	mov	x4, #0xffff                	// #65535
  400fc4:	eb04007f 	cmp	x3, x4
  400fc8:	54fff8e9 	b.ls	400ee4 <strtol+0x44>  // b.plast
  400fcc:	35000682 	cbnz	w2, 40109c <strtol+0x1fc>
  400fd0:	39400404 	ldrb	w4, [x0, #1]
  400fd4:	7100c09f 	cmp	w4, #0x30
  400fd8:	54000aa0 	b.eq	40112c <strtol+0x28c>  // b.none
  400fdc:	aa0303e0 	mov	x0, x3
  400fe0:	b202e7e8 	mov	x8, #0xcccccccccccccccc    	// #-3689348814741910324
  400fe4:	528000ea 	mov	w10, #0x7                   	// #7
  400fe8:	f2e19988 	movk	x8, #0xccc, lsl #48
  400fec:	52800142 	mov	w2, #0xa                   	// #10
  400ff0:	d280002b 	mov	x11, #0x1                   	// #1
  400ff4:	17ffffd7 	b	400f50 <strtol+0xb0>
  400ff8:	7100405f 	cmp	w2, #0x10
  400ffc:	540006c0 	b.eq	4010d4 <strtol+0x234>  // b.none
  401000:	93407c4a 	sxtw	x10, w2
  401004:	92f00003 	mov	x3, #0x7fffffffffffffff    	// #9223372036854775807
  401008:	d280002b 	mov	x11, #0x1                   	// #1
  40100c:	9aca0868 	udiv	x8, x3, x10
  401010:	1b0a8d0a 	msub	w10, w8, w10, w3
  401014:	17ffffcf 	b	400f50 <strtol+0xb0>
  401018:	51010483 	sub	w3, w4, #0x41
  40101c:	12001c63 	and	w3, w3, #0xff
  401020:	7100647f 	cmp	w3, #0x19
  401024:	54000068 	b.hi	401030 <strtol+0x190>  // b.pmore
  401028:	5100dc83 	sub	w3, w4, #0x37
  40102c:	17ffffde 	b	400fa4 <strtol+0x104>
  401030:	b4000041 	cbz	x1, 401038 <strtol+0x198>
  401034:	f9000020 	str	x0, [x1]
  401038:	35000067 	cbnz	w7, 401044 <strtol+0x1a4>
  40103c:	9b0b7ca0 	mul	x0, x5, x11
  401040:	d65f03c0 	ret
  401044:	7100057f 	cmp	w11, #0x1
  401048:	da9f13e0 	csetm	x0, eq	// eq = none
  40104c:	d2410000 	eor	x0, x0, #0x8000000000000000
  401050:	d65f03c0 	ret
  401054:	91000405 	add	x5, x0, #0x1
  401058:	d29fffe3 	mov	x3, #0xffff                	// #65535
  40105c:	eb0300bf 	cmp	x5, x3
  401060:	54000329 	b.ls	4010c4 <strtol+0x224>  // b.plast
  401064:	34000442 	cbz	w2, 4010ec <strtol+0x24c>
  401068:	7100405f 	cmp	w2, #0x10
  40106c:	54000880 	b.eq	40117c <strtol+0x2dc>  // b.none
  401070:	93407c43 	sxtw	x3, w2
  401074:	92f00004 	mov	x4, #0x7fffffffffffffff    	// #9223372036854775807
  401078:	9ac30888 	udiv	x8, x4, x3
  40107c:	9b039103 	msub	x3, x8, x3, x4
  401080:	1100046a 	add	w10, w3, #0x1
  401084:	6b0a005f 	cmp	w2, w10
  401088:	5400046d 	b.le	401114 <strtol+0x274>
  40108c:	39400404 	ldrb	w4, [x0, #1]
  401090:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401094:	aa0503e0 	mov	x0, x5
  401098:	17ffffae 	b	400f50 <strtol+0xb0>
  40109c:	7100405f 	cmp	w2, #0x10
  4010a0:	540005e0 	b.eq	40115c <strtol+0x2bc>  // b.none
  4010a4:	93407c4a 	sxtw	x10, w2
  4010a8:	92f00004 	mov	x4, #0x7fffffffffffffff    	// #9223372036854775807
  4010ac:	d280002b 	mov	x11, #0x1                   	// #1
  4010b0:	9aca0888 	udiv	x8, x4, x10
  4010b4:	1b0a910a 	msub	w10, w8, w10, w4
  4010b8:	39400404 	ldrb	w4, [x0, #1]
  4010bc:	aa0303e0 	mov	x0, x3
  4010c0:	17ffffa4 	b	400f50 <strtol+0xb0>
  4010c4:	b4fff141 	cbz	x1, 400eec <strtol+0x4c>
  4010c8:	d2800000 	mov	x0, #0x0                   	// #0
  4010cc:	f9000025 	str	x5, [x1]
  4010d0:	17ffff88 	b	400ef0 <strtol+0x50>
  4010d4:	7100c09f 	cmp	w4, #0x30
  4010d8:	54000620 	b.eq	40119c <strtol+0x2fc>  // b.none
  4010dc:	528001ea 	mov	w10, #0xf                   	// #15
  4010e0:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4010e4:	d280002b 	mov	x11, #0x1                   	// #1
  4010e8:	17ffff9a 	b	400f50 <strtol+0xb0>
  4010ec:	39400404 	ldrb	w4, [x0, #1]
  4010f0:	7100c09f 	cmp	w4, #0x30
  4010f4:	54000660 	b.eq	4011c0 <strtol+0x320>  // b.none
  4010f8:	b202e7e8 	mov	x8, #0xcccccccccccccccc    	// #-3689348814741910324
  4010fc:	aa0503e0 	mov	x0, x5
  401100:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401104:	52800142 	mov	w2, #0xa                   	// #10
  401108:	5280010a 	mov	w10, #0x8                   	// #8
  40110c:	f2e19988 	movk	x8, #0xccc, lsl #48
  401110:	17ffff90 	b	400f50 <strtol+0xb0>
  401114:	39400404 	ldrb	w4, [x0, #1]
  401118:	91000508 	add	x8, x8, #0x1
  40111c:	4b02014a 	sub	w10, w10, w2
  401120:	aa0503e0 	mov	x0, x5
  401124:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401128:	17ffff8a 	b	400f50 <strtol+0xb0>
  40112c:	39400804 	ldrb	w4, [x0, #2]
  401130:	121a7882 	and	w2, w4, #0xffffffdf
  401134:	12001c42 	and	w2, w2, #0xff
  401138:	7101605f 	cmp	w2, #0x58
  40113c:	54000641 	b.ne	401204 <strtol+0x364>  // b.any
  401140:	39400c04 	ldrb	w4, [x0, #3]
  401144:	528001ea 	mov	w10, #0xf                   	// #15
  401148:	91000c00 	add	x0, x0, #0x3
  40114c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401150:	52800202 	mov	w2, #0x10                  	// #16
  401154:	d280002b 	mov	x11, #0x1                   	// #1
  401158:	17ffff7e 	b	400f50 <strtol+0xb0>
  40115c:	39400404 	ldrb	w4, [x0, #1]
  401160:	7100c09f 	cmp	w4, #0x30
  401164:	540005c0 	b.eq	40121c <strtol+0x37c>  // b.none
  401168:	aa0303e0 	mov	x0, x3
  40116c:	528001ea 	mov	w10, #0xf                   	// #15
  401170:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401174:	d280002b 	mov	x11, #0x1                   	// #1
  401178:	17ffff76 	b	400f50 <strtol+0xb0>
  40117c:	39400404 	ldrb	w4, [x0, #1]
  401180:	7100c09f 	cmp	w4, #0x30
  401184:	54000800 	b.eq	401284 <strtol+0x3e4>  // b.none
  401188:	aa0503e0 	mov	x0, x5
  40118c:	5280000a 	mov	w10, #0x0                   	// #0
  401190:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  401194:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401198:	17ffff6e 	b	400f50 <strtol+0xb0>
  40119c:	39400403 	ldrb	w3, [x0, #1]
  4011a0:	121a7863 	and	w3, w3, #0xffffffdf
  4011a4:	12001c63 	and	w3, w3, #0xff
  4011a8:	7101607f 	cmp	w3, #0x58
  4011ac:	540004c0 	b.eq	401244 <strtol+0x3a4>  // b.none
  4011b0:	d280002b 	mov	x11, #0x1                   	// #1
  4011b4:	528001ea 	mov	w10, #0xf                   	// #15
  4011b8:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  4011bc:	17ffff66 	b	400f54 <strtol+0xb4>
  4011c0:	39400804 	ldrb	w4, [x0, #2]
  4011c4:	121a7882 	and	w2, w4, #0xffffffdf
  4011c8:	7101605f 	cmp	w2, #0x58
  4011cc:	540000e0 	b.eq	4011e8 <strtol+0x348>  // b.none
  4011d0:	91000800 	add	x0, x0, #0x2
  4011d4:	5280000a 	mov	w10, #0x0                   	// #0
  4011d8:	d2e20008 	mov	x8, #0x1000000000000000    	// #1152921504606846976
  4011dc:	52800102 	mov	w2, #0x8                   	// #8
  4011e0:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4011e4:	17ffff5b 	b	400f50 <strtol+0xb0>
  4011e8:	39400c04 	ldrb	w4, [x0, #3]
  4011ec:	5280000a 	mov	w10, #0x0                   	// #0
  4011f0:	91000c00 	add	x0, x0, #0x3
  4011f4:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4011f8:	52800202 	mov	w2, #0x10                  	// #16
  4011fc:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  401200:	17ffff54 	b	400f50 <strtol+0xb0>
  401204:	91000800 	add	x0, x0, #0x2
  401208:	528000ea 	mov	w10, #0x7                   	// #7
  40120c:	92fe0008 	mov	x8, #0xfffffffffffffff     	// #1152921504606846975
  401210:	52800102 	mov	w2, #0x8                   	// #8
  401214:	d280002b 	mov	x11, #0x1                   	// #1
  401218:	17ffff4e 	b	400f50 <strtol+0xb0>
  40121c:	39400805 	ldrb	w5, [x0, #2]
  401220:	121a78a5 	and	w5, w5, #0xffffffdf
  401224:	12001ca5 	and	w5, w5, #0xff
  401228:	710160bf 	cmp	w5, #0x58
  40122c:	54000120 	b.eq	401250 <strtol+0x3b0>  // b.none
  401230:	aa0303e0 	mov	x0, x3
  401234:	d280002b 	mov	x11, #0x1                   	// #1
  401238:	528001ea 	mov	w10, #0xf                   	// #15
  40123c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401240:	17ffff45 	b	400f54 <strtol+0xb4>
  401244:	39400804 	ldrb	w4, [x0, #2]
  401248:	91000800 	add	x0, x0, #0x2
  40124c:	17ffffa4 	b	4010dc <strtol+0x23c>
  401250:	39400c04 	ldrb	w4, [x0, #3]
  401254:	528001ea 	mov	w10, #0xf                   	// #15
  401258:	91000c00 	add	x0, x0, #0x3
  40125c:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401260:	d280002b 	mov	x11, #0x1                   	// #1
  401264:	17ffff3b 	b	400f50 <strtol+0xb0>
  401268:	39400804 	ldrb	w4, [x0, #2]
  40126c:	528001ea 	mov	w10, #0xf                   	// #15
  401270:	91000800 	add	x0, x0, #0x2
  401274:	92ff0008 	mov	x8, #0x7ffffffffffffff     	// #576460752303423487
  401278:	52800202 	mov	w2, #0x10                  	// #16
  40127c:	d280002b 	mov	x11, #0x1                   	// #1
  401280:	17ffff34 	b	400f50 <strtol+0xb0>
  401284:	39400803 	ldrb	w3, [x0, #2]
  401288:	121a7863 	and	w3, w3, #0xffffffdf
  40128c:	12001c63 	and	w3, w3, #0xff
  401290:	7101607f 	cmp	w3, #0x58
  401294:	540000e1 	b.ne	4012b0 <strtol+0x410>  // b.any
  401298:	39400c04 	ldrb	w4, [x0, #3]
  40129c:	5280000a 	mov	w10, #0x0                   	// #0
  4012a0:	91000c00 	add	x0, x0, #0x3
  4012a4:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4012a8:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4012ac:	17ffff29 	b	400f50 <strtol+0xb0>
  4012b0:	aa0503e0 	mov	x0, x5
  4012b4:	9280000b 	mov	x11, #0xffffffffffffffff    	// #-1
  4012b8:	5280000a 	mov	w10, #0x0                   	// #0
  4012bc:	d2e10008 	mov	x8, #0x800000000000000     	// #576460752303423488
  4012c0:	17ffff25 	b	400f54 <strtol+0xb4>
  4012c4:	d503201f 	nop
  4012c8:	d503201f 	nop
  4012cc:	d503201f 	nop

00000000004012d0 <__isoc23_strtol>:
  4012d0:	17fffef4 	b	400ea0 <strtol>
  4012d4:	d503201f 	nop
  4012d8:	d503201f 	nop
  4012dc:	d503201f 	nop

00000000004012e0 <memcpy>:
  4012e0:	f100001f 	cmp	x0, #0x0
  4012e4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4012e8:	540001a0 	b.eq	40131c <memcpy+0x3c>  // b.none
  4012ec:	d29fffe3 	mov	x3, #0xffff                	// #65535
  4012f0:	eb03001f 	cmp	x0, x3
  4012f4:	fa438020 	ccmp	x1, x3, #0x0, hi	// hi = pmore
  4012f8:	54000129 	b.ls	40131c <memcpy+0x3c>  // b.plast
  4012fc:	b4000102 	cbz	x2, 40131c <memcpy+0x3c>
  401300:	d2800003 	mov	x3, #0x0                   	// #0
  401304:	d503201f 	nop
  401308:	38636824 	ldrb	w4, [x1, x3]
  40130c:	38236804 	strb	w4, [x0, x3]
  401310:	91000463 	add	x3, x3, #0x1
  401314:	eb03005f 	cmp	x2, x3
  401318:	54ffff81 	b.ne	401308 <memcpy+0x28>  // b.any
  40131c:	d65f03c0 	ret

0000000000401320 <__memcpy_chk>:
  401320:	17fffff0 	b	4012e0 <memcpy>
  401324:	d503201f 	nop
  401328:	d503201f 	nop
  40132c:	d503201f 	nop

0000000000401330 <memset>:
  401330:	aa0003e3 	mov	x3, x0
  401334:	d29fffe4 	mov	x4, #0xffff                	// #65535
  401338:	eb04001f 	cmp	x0, x4
  40133c:	540000c9 	b.ls	401354 <memset+0x24>  // b.plast
  401340:	b40000a2 	cbz	x2, 401354 <memset+0x24>
  401344:	8b020002 	add	x2, x0, x2
  401348:	38001461 	strb	w1, [x3], #1
  40134c:	eb02007f 	cmp	x3, x2
  401350:	54ffffc1 	b.ne	401348 <memset+0x18>  // b.any
  401354:	d65f03c0 	ret
  401358:	d503201f 	nop
  40135c:	d503201f 	nop

0000000000401360 <memcmp>:
  401360:	f100001f 	cmp	x0, #0x0
  401364:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401368:	540001a0 	b.eq	40139c <memcmp+0x3c>  // b.none
  40136c:	b4000182 	cbz	x2, 40139c <memcmp+0x3c>
  401370:	d2800003 	mov	x3, #0x0                   	// #0
  401374:	14000004 	b	401384 <memcmp+0x24>
  401378:	91000463 	add	x3, x3, #0x1
  40137c:	eb03005f 	cmp	x2, x3
  401380:	540000e0 	b.eq	40139c <memcmp+0x3c>  // b.none
  401384:	38636804 	ldrb	w4, [x0, x3]
  401388:	38636825 	ldrb	w5, [x1, x3]
  40138c:	6b05009f 	cmp	w4, w5
  401390:	54ffff40 	b.eq	401378 <memcmp+0x18>  // b.none
  401394:	4b050080 	sub	w0, w4, w5
  401398:	d65f03c0 	ret
  40139c:	52800000 	mov	w0, #0x0                   	// #0
  4013a0:	d65f03c0 	ret
  4013a4:	d503201f 	nop
  4013a8:	d503201f 	nop
  4013ac:	d503201f 	nop

00000000004013b0 <memmove>:
  4013b0:	f100001f 	cmp	x0, #0x0
  4013b4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4013b8:	540001e0 	b.eq	4013f4 <memmove+0x44>  // b.none
  4013bc:	d29fffe3 	mov	x3, #0xffff                	// #65535
  4013c0:	eb03001f 	cmp	x0, x3
  4013c4:	fa438020 	ccmp	x1, x3, #0x0, hi	// hi = pmore
  4013c8:	54000169 	b.ls	4013f4 <memmove+0x44>  // b.plast
  4013cc:	eb01001f 	cmp	x0, x1
  4013d0:	54000142 	b.cs	4013f8 <memmove+0x48>  // b.hs, b.nlast
  4013d4:	b4000102 	cbz	x2, 4013f4 <memmove+0x44>
  4013d8:	d2800003 	mov	x3, #0x0                   	// #0
  4013dc:	d503201f 	nop
  4013e0:	38636824 	ldrb	w4, [x1, x3]
  4013e4:	38236804 	strb	w4, [x0, x3]
  4013e8:	91000463 	add	x3, x3, #0x1
  4013ec:	eb03005f 	cmp	x2, x3
  4013f0:	54ffff81 	b.ne	4013e0 <memmove+0x30>  // b.any
  4013f4:	d65f03c0 	ret
  4013f8:	b4ffffe2 	cbz	x2, 4013f4 <memmove+0x44>
  4013fc:	d1000442 	sub	x2, x2, #0x1
  401400:	38626823 	ldrb	w3, [x1, x2]
  401404:	38226803 	strb	w3, [x0, x2]
  401408:	17fffffc 	b	4013f8 <memmove+0x48>
