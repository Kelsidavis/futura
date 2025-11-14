
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
  400024:	9400012b 	bl	4004d0 <__libc_init_environ>
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
  400160:	004011c8 	.word	0x004011c8
	...

0000000000400170 <find_index>:
  400170:	b0000001 	adrp	x1, 401000 <strtol+0xe0>
  400174:	9108a022 	add	x2, x1, #0x228
  400178:	f9411426 	ldr	x6, [x1, #552]
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
  400208:	b4001320 	cbz	x0, 40046c <set_pair+0x26c>
  40020c:	a90153f3 	stp	x19, x20, [sp, #16]
  400210:	aa0103f4 	mov	x20, x1
  400214:	a9025bf5 	stp	x21, x22, [sp, #32]
  400218:	aa0003f5 	mov	x21, x0
  40021c:	39400001 	ldrb	w1, [x0]
  400220:	34001301 	cbz	w1, 400480 <set_pair+0x280>
  400224:	528007a1 	mov	w1, #0x3d                  	// #61
  400228:	a90363f7 	stp	x23, x24, [sp, #48]
  40022c:	2a0203f8 	mov	w24, w2
  400230:	aa0303f7 	mov	x23, x3
  400234:	940002e7 	bl	400dd0 <strchr>
  400238:	b5001140 	cbnz	x0, 400460 <set_pair+0x260>
  40023c:	f100029f 	cmp	x20, #0x0
  400240:	b0000013 	adrp	x19, 401000 <strtol+0xe0>
  400244:	91074273 	add	x19, x19, #0x1d0
  400248:	aa1503e0 	mov	x0, x21
  40024c:	9a940273 	csel	x19, x19, x20, eq	// eq = none
  400250:	a9046bf9 	stp	x25, x26, [sp, #64]
  400254:	94000267 	bl	400bf0 <strlen>
  400258:	aa1703f6 	mov	x22, x23
  40025c:	aa0003f4 	mov	x20, x0
  400260:	aa1303e0 	mov	x0, x19
  400264:	94000263 	bl	400bf0 <strlen>
  400268:	aa0003f9 	mov	x25, x0
  40026c:	b4000497 	cbz	x23, 4002fc <set_pair+0xfc>
  400270:	b0000014 	adrp	x20, 401000 <strtol+0xe0>
  400274:	9108a299 	add	x25, x20, #0x228
  400278:	91004333 	add	x19, x25, #0x10
  40027c:	d503201f 	nop
  400280:	aa1303e1 	mov	x1, x19
  400284:	52800020 	mov	w0, #0x1                   	// #1
  400288:	940003c6 	bl	4011a0 <__aarch64_swp1_acq>
  40028c:	3707ffa0 	tbnz	w0, #0, 400280 <set_pair+0x80>
  400290:	aa1503e0 	mov	x0, x21
  400294:	97ffffb7 	bl	400170 <find_index>
  400298:	2a2003e1 	mvn	w1, w0
  40029c:	52000318 	eor	w24, w24, #0x1
  4002a0:	6a417f1f 	tst	w24, w1, lsr #31
  4002a4:	540006a1 	b.ne	400378 <set_pair+0x178>  // b.any
  4002a8:	37f804e0 	tbnz	w0, #31, 400344 <set_pair+0x144>
  4002ac:	f9400722 	ldr	x2, [x25, #8]
  4002b0:	d37d7c13 	ubfiz	x19, x0, #3, #32
  4002b4:	8b130041 	add	x1, x2, x19
  4002b8:	f8605840 	ldr	x0, [x2, w0, uxtw #3]
  4002bc:	eb16001f 	cmp	x0, x22
  4002c0:	54000080 	b.eq	4002d0 <set_pair+0xd0>  // b.none
  4002c4:	9400020b 	bl	400af0 <free>
  4002c8:	f9400721 	ldr	x1, [x25, #8]
  4002cc:	8b130021 	add	x1, x1, x19
  4002d0:	f9000036 	str	x22, [x1]
  4002d4:	9108a294 	add	x20, x20, #0x228
  4002d8:	91004294 	add	x20, x20, #0x10
  4002dc:	089ffe9f 	stlrb	wzr, [x20]
  4002e0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4002e4:	52800000 	mov	w0, #0x0                   	// #0
  4002e8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4002ec:	a94363f7 	ldp	x23, x24, [sp, #48]
  4002f0:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4002f4:	a8c57bfd 	ldp	x29, x30, [sp], #80
  4002f8:	d65f03c0 	ret
  4002fc:	8b00029a 	add	x26, x20, x0
  400300:	91000b40 	add	x0, x26, #0x2
  400304:	940001ab 	bl	4009b0 <malloc>
  400308:	aa0003f6 	mov	x22, x0
  40030c:	b4000d00 	cbz	x0, 4004ac <set_pair+0x2ac>
  400310:	aa1403e2 	mov	x2, x20
  400314:	aa1503e1 	mov	x1, x21
  400318:	8b1a02da 	add	x26, x22, x26
  40031c:	94000361 	bl	4010a0 <memcpy>
  400320:	528007a0 	mov	w0, #0x3d                  	// #61
  400324:	38346ac0 	strb	w0, [x22, x20]
  400328:	91000680 	add	x0, x20, #0x1
  40032c:	aa1903e2 	mov	x2, x25
  400330:	aa1303e1 	mov	x1, x19
  400334:	8b0002c0 	add	x0, x22, x0
  400338:	9400035a 	bl	4010a0 <memcpy>
  40033c:	3900075f 	strb	wzr, [x26, #1]
  400340:	17ffffcc 	b	400270 <set_pair+0x70>
  400344:	f9411681 	ldr	x1, [x20, #552]
  400348:	f9400f33 	ldr	x19, [x25, #24]
  40034c:	91000820 	add	x0, x1, #0x2
  400350:	eb13001f 	cmp	x0, x19
  400354:	540001c8 	b.hi	40038c <set_pair+0x18c>  // b.pmore
  400358:	f9400735 	ldr	x21, [x25, #8]
  40035c:	b4000795 	cbz	x21, 40044c <set_pair+0x24c>
  400360:	91000420 	add	x0, x1, #0x1
  400364:	f8217ab6 	str	x22, [x21, x1, lsl #3]
  400368:	8b010ea1 	add	x1, x21, x1, lsl #3
  40036c:	f9011680 	str	x0, [x20, #552]
  400370:	f900043f 	str	xzr, [x1, #8]
  400374:	17ffffd8 	b	4002d4 <set_pair+0xd4>
  400378:	089ffe7f 	stlrb	wzr, [x19]
  40037c:	b5fffb37 	cbnz	x23, 4002e0 <set_pair+0xe0>
  400380:	aa1603e0 	mov	x0, x22
  400384:	940001db 	bl	400af0 <free>
  400388:	17ffffd6 	b	4002e0 <set_pair+0xe0>
  40038c:	b4000633 	cbz	x19, 400450 <set_pair+0x250>
  400390:	8b130273 	add	x19, x19, x19
  400394:	eb13001f 	cmp	x0, x19
  400398:	54ffffc8 	b.hi	400390 <set_pair+0x190>  // b.pmore
  40039c:	d37df278 	lsl	x24, x19, #3
  4003a0:	aa1803e0 	mov	x0, x24
  4003a4:	94000183 	bl	4009b0 <malloc>
  4003a8:	aa0003f5 	mov	x21, x0
  4003ac:	9108a280 	add	x0, x20, #0x228
  4003b0:	b4000755 	cbz	x21, 400498 <set_pair+0x298>
  4003b4:	f9411682 	ldr	x2, [x20, #552]
  4003b8:	f9400400 	ldr	x0, [x0, #8]
  4003bc:	b4000682 	cbz	x2, 40048c <set_pair+0x28c>
  4003c0:	d2800001 	mov	x1, #0x0                   	// #0
  4003c4:	b4000320 	cbz	x0, 400428 <set_pair+0x228>
  4003c8:	f8617803 	ldr	x3, [x0, x1, lsl #3]
  4003cc:	f8217aa3 	str	x3, [x21, x1, lsl #3]
  4003d0:	91000421 	add	x1, x1, #0x1
  4003d4:	eb01005f 	cmp	x2, x1
  4003d8:	54ffff81 	b.ne	4003c8 <set_pair+0x1c8>  // b.any
  4003dc:	8b020ea1 	add	x1, x21, x2, lsl #3
  4003e0:	91000442 	add	x2, x2, #0x1
  4003e4:	f900003f 	str	xzr, [x1]
  4003e8:	8b150303 	add	x3, x24, x21
  4003ec:	8b020ea1 	add	x1, x21, x2, lsl #3
  4003f0:	eb02027f 	cmp	x19, x2
  4003f4:	54000089 	b.ls	400404 <set_pair+0x204>  // b.plast
  4003f8:	f800843f 	str	xzr, [x1], #8
  4003fc:	eb03003f 	cmp	x1, x3
  400400:	54ffffc1 	b.ne	4003f8 <set_pair+0x1f8>  // b.any
  400404:	940001bb 	bl	400af0 <free>
  400408:	b0000001 	adrp	x1, 401000 <strtol+0xe0>
  40040c:	f9410421 	ldr	x1, [x1, #520]
  400410:	9108a280 	add	x0, x20, #0x228
  400414:	f9000035 	str	x21, [x1]
  400418:	f9411681 	ldr	x1, [x20, #552]
  40041c:	f9000415 	str	x21, [x0, #8]
  400420:	f9000c13 	str	x19, [x0, #24]
  400424:	17ffffcf 	b	400360 <set_pair+0x160>
  400428:	91000423 	add	x3, x1, #0x1
  40042c:	f8217abf 	str	xzr, [x21, x1, lsl #3]
  400430:	eb03005f 	cmp	x2, x3
  400434:	54fffd40 	b.eq	4003dc <set_pair+0x1dc>  // b.none
  400438:	91000821 	add	x1, x1, #0x2
  40043c:	f8237abf 	str	xzr, [x21, x3, lsl #3]
  400440:	eb01005f 	cmp	x2, x1
  400444:	54ffff21 	b.ne	400428 <set_pair+0x228>  // b.any
  400448:	17ffffe5 	b	4003dc <set_pair+0x1dc>
  40044c:	b5fffa93 	cbnz	x19, 40039c <set_pair+0x19c>
  400450:	d2800113 	mov	x19, #0x8                   	// #8
  400454:	f100201f 	cmp	x0, #0x8
  400458:	54fff9c8 	b.hi	400390 <set_pair+0x190>  // b.pmore
  40045c:	17ffffd0 	b	40039c <set_pair+0x19c>
  400460:	a94153f3 	ldp	x19, x20, [sp, #16]
  400464:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400468:	a94363f7 	ldp	x23, x24, [sp, #48]
  40046c:	940001dd 	bl	400be0 <__errno_location@GLIBC_2.2.5>
  400470:	528002c1 	mov	w1, #0x16                  	// #22
  400474:	b9000001 	str	w1, [x0]
  400478:	12800000 	mov	w0, #0xffffffff            	// #-1
  40047c:	17ffff9e 	b	4002f4 <set_pair+0xf4>
  400480:	a94153f3 	ldp	x19, x20, [sp, #16]
  400484:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400488:	17fffff9 	b	40046c <set_pair+0x26c>
  40048c:	aa1503e1 	mov	x1, x21
  400490:	d2800022 	mov	x2, #0x1                   	// #1
  400494:	17ffffd4 	b	4003e4 <set_pair+0x1e4>
  400498:	91004000 	add	x0, x0, #0x10
  40049c:	089ffc1f 	stlrb	wzr, [x0]
  4004a0:	b5000077 	cbnz	x23, 4004ac <set_pair+0x2ac>
  4004a4:	aa1603e0 	mov	x0, x22
  4004a8:	94000192 	bl	400af0 <free>
  4004ac:	940001cd 	bl	400be0 <__errno_location@GLIBC_2.2.5>
  4004b0:	52800181 	mov	w1, #0xc                   	// #12
  4004b4:	b9000001 	str	w1, [x0]
  4004b8:	12800000 	mov	w0, #0xffffffff            	// #-1
  4004bc:	a94153f3 	ldp	x19, x20, [sp, #16]
  4004c0:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4004c4:	a94363f7 	ldp	x23, x24, [sp, #48]
  4004c8:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4004cc:	17ffff8a 	b	4002f4 <set_pair+0xf4>

00000000004004d0 <__libc_init_environ>:
  4004d0:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
  4004d4:	910003fd 	mov	x29, sp
  4004d8:	a90363f7 	stp	x23, x24, [sp, #48]
  4004dc:	a90573fb 	stp	x27, x28, [sp, #80]
  4004e0:	b40007e0 	cbz	x0, 4005dc <__libc_init_environ+0x10c>
  4004e4:	f9400001 	ldr	x1, [x0]
  4004e8:	b40007a1 	cbz	x1, 4005dc <__libc_init_environ+0x10c>
  4004ec:	d1002003 	sub	x3, x0, #0x8
  4004f0:	d2800101 	mov	x1, #0x8                   	// #8
  4004f4:	d280001c 	mov	x28, #0x0                   	// #0
  4004f8:	a9025bf5 	stp	x21, x22, [sp, #32]
  4004fc:	a9046bf9 	stp	x25, x26, [sp, #64]
  400500:	aa0103f7 	mov	x23, x1
  400504:	91002021 	add	x1, x1, #0x8
  400508:	aa1c03f8 	mov	x24, x28
  40050c:	9100079c 	add	x28, x28, #0x1
  400510:	f8616862 	ldr	x2, [x3, x1]
  400514:	b5ffff62 	cbnz	x2, 400500 <__libc_init_environ+0x30>
  400518:	91000b18 	add	x24, x24, #0x2
  40051c:	b000001b 	adrp	x27, 401000 <strtol+0xe0>
  400520:	9108a37a 	add	x26, x27, #0x228
  400524:	aa0003f6 	mov	x22, x0
  400528:	d37df319 	lsl	x25, x24, #3
  40052c:	aa1903e0 	mov	x0, x25
  400530:	94000120 	bl	4009b0 <malloc>
  400534:	f9000740 	str	x0, [x26, #8]
  400538:	b4000600 	cbz	x0, 4005f8 <__libc_init_environ+0x128>
  40053c:	d1002339 	sub	x25, x25, #0x8
  400540:	a90153f3 	stp	x19, x20, [sp, #16]
  400544:	d2800013 	mov	x19, #0x0                   	// #0
  400548:	14000009 	b	40056c <__libc_init_environ+0x9c>
  40054c:	f8736ac1 	ldr	x1, [x22, x19]
  400550:	aa1503e2 	mov	x2, x21
  400554:	940002d3 	bl	4010a0 <memcpy>
  400558:	f9400740 	ldr	x0, [x26, #8]
  40055c:	f8336814 	str	x20, [x0, x19]
  400560:	91002273 	add	x19, x19, #0x8
  400564:	eb19027f 	cmp	x19, x25
  400568:	540001a0 	b.eq	40059c <__libc_init_environ+0xcc>  // b.none
  40056c:	f8736ac0 	ldr	x0, [x22, x19]
  400570:	940001a0 	bl	400bf0 <strlen>
  400574:	91000415 	add	x21, x0, #0x1
  400578:	aa1503e0 	mov	x0, x21
  40057c:	9400010d 	bl	4009b0 <malloc>
  400580:	aa0003f4 	mov	x20, x0
  400584:	b5fffe40 	cbnz	x0, 40054c <__libc_init_environ+0x7c>
  400588:	f9400740 	ldr	x0, [x26, #8]
  40058c:	f833681f 	str	xzr, [x0, x19]
  400590:	91002273 	add	x19, x19, #0x8
  400594:	eb19027f 	cmp	x19, x25
  400598:	54fffea1 	b.ne	40056c <__libc_init_environ+0x9c>  // b.any
  40059c:	9108a360 	add	x0, x27, #0x228
  4005a0:	f9400400 	ldr	x0, [x0, #8]
  4005a4:	f837681f 	str	xzr, [x0, x23]
  4005a8:	a94153f3 	ldp	x19, x20, [sp, #16]
  4005ac:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4005b0:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4005b4:	f901177c 	str	x28, [x27, #552]
  4005b8:	b0000001 	adrp	x1, 401000 <strtol+0xe0>
  4005bc:	f9410421 	ldr	x1, [x1, #520]
  4005c0:	f9000020 	str	x0, [x1]
  4005c4:	9108a360 	add	x0, x27, #0x228
  4005c8:	f9000c18 	str	x24, [x0, #24]
  4005cc:	a94363f7 	ldp	x23, x24, [sp, #48]
  4005d0:	a94573fb 	ldp	x27, x28, [sp, #80]
  4005d4:	a8c67bfd 	ldp	x29, x30, [sp], #96
  4005d8:	d65f03c0 	ret
  4005dc:	b000001b 	adrp	x27, 401000 <strtol+0xe0>
  4005e0:	9108a360 	add	x0, x27, #0x228
  4005e4:	f900041f 	str	xzr, [x0, #8]
  4005e8:	d2800000 	mov	x0, #0x0                   	// #0
  4005ec:	d280001c 	mov	x28, #0x0                   	// #0
  4005f0:	d2800018 	mov	x24, #0x0                   	// #0
  4005f4:	17fffff0 	b	4005b4 <__libc_init_environ+0xe4>
  4005f8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4005fc:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400600:	17fffffa 	b	4005e8 <__libc_init_environ+0x118>
  400604:	d503201f 	nop
  400608:	d503201f 	nop
  40060c:	d503201f 	nop

0000000000400610 <getenv>:
  400610:	b40004a0 	cbz	x0, 4006a4 <getenv+0x94>
  400614:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400618:	910003fd 	mov	x29, sp
  40061c:	a90153f3 	stp	x19, x20, [sp, #16]
  400620:	a9025bf5 	stp	x21, x22, [sp, #32]
  400624:	b0000014 	adrp	x20, 401000 <strtol+0xe0>
  400628:	9108a295 	add	x21, x20, #0x228
  40062c:	aa0003f6 	mov	x22, x0
  400630:	910042a1 	add	x1, x21, #0x10
  400634:	52800020 	mov	w0, #0x1                   	// #1
  400638:	940002da 	bl	4011a0 <__aarch64_swp1_acq>
  40063c:	3707ffa0 	tbnz	w0, #0, 400630 <getenv+0x20>
  400640:	aa1603e0 	mov	x0, x22
  400644:	97fffecb 	bl	400170 <find_index>
  400648:	37f801e0 	tbnz	w0, #31, 400684 <getenv+0x74>
  40064c:	f94006a1 	ldr	x1, [x21, #8]
  400650:	f8605820 	ldr	x0, [x1, w0, uxtw #3]
  400654:	b4000180 	cbz	x0, 400684 <getenv+0x74>
  400658:	528007a1 	mov	w1, #0x3d                  	// #61
  40065c:	940001dd 	bl	400dd0 <strchr>
  400660:	b4000120 	cbz	x0, 400684 <getenv+0x74>
  400664:	91000400 	add	x0, x0, #0x1
  400668:	9108a294 	add	x20, x20, #0x228
  40066c:	91004294 	add	x20, x20, #0x10
  400670:	089ffe9f 	stlrb	wzr, [x20]
  400674:	a94153f3 	ldp	x19, x20, [sp, #16]
  400678:	a9425bf5 	ldp	x21, x22, [sp, #32]
  40067c:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400680:	d65f03c0 	ret
  400684:	d2800000 	mov	x0, #0x0                   	// #0
  400688:	9108a294 	add	x20, x20, #0x228
  40068c:	91004294 	add	x20, x20, #0x10
  400690:	089ffe9f 	stlrb	wzr, [x20]
  400694:	a94153f3 	ldp	x19, x20, [sp, #16]
  400698:	a9425bf5 	ldp	x21, x22, [sp, #32]
  40069c:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4006a0:	d65f03c0 	ret
  4006a4:	d65f03c0 	ret
  4006a8:	d503201f 	nop
  4006ac:	d503201f 	nop

00000000004006b0 <secure_getenv>:
  4006b0:	17ffffd8 	b	400610 <getenv>
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
  4006f8:	940001b6 	bl	400dd0 <strchr>
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
  400740:	94000128 	bl	400be0 <__errno_location@GLIBC_2.2.5>
  400744:	528002c1 	mov	w1, #0x16                  	// #22
  400748:	b9000001 	str	w1, [x0]
  40074c:	12800000 	mov	w0, #0xffffffff            	// #-1
  400750:	a94153f3 	ldp	x19, x20, [sp, #16]
  400754:	17fffff9 	b	400738 <putenv+0x58>
  400758:	94000122 	bl	400be0 <__errno_location@GLIBC_2.2.5>
  40075c:	528002c1 	mov	w1, #0x16                  	// #22
  400760:	b9000001 	str	w1, [x0]
  400764:	12800000 	mov	w0, #0xffffffff            	// #-1
  400768:	17fffff4 	b	400738 <putenv+0x58>
  40076c:	d503201f 	nop

0000000000400770 <unsetenv>:
  400770:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400774:	910003fd 	mov	x29, sp
  400778:	b4000660 	cbz	x0, 400844 <unsetenv+0xd4>
  40077c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400780:	aa0003f5 	mov	x21, x0
  400784:	39400001 	ldrb	w1, [x0]
  400788:	340005c1 	cbz	w1, 400840 <unsetenv+0xd0>
  40078c:	528007a1 	mov	w1, #0x3d                  	// #61
  400790:	94000190 	bl	400dd0 <strchr>
  400794:	b5000560 	cbnz	x0, 400840 <unsetenv+0xd0>
  400798:	a90153f3 	stp	x19, x20, [sp, #16]
  40079c:	b0000014 	adrp	x20, 401000 <strtol+0xe0>
  4007a0:	9108a296 	add	x22, x20, #0x228
  4007a4:	d503201f 	nop
  4007a8:	910042c1 	add	x1, x22, #0x10
  4007ac:	52800020 	mov	w0, #0x1                   	// #1
  4007b0:	9400027c 	bl	4011a0 <__aarch64_swp1_acq>
  4007b4:	3707ffa0 	tbnz	w0, #0, 4007a8 <unsetenv+0x38>
  4007b8:	aa1503e0 	mov	x0, x21
  4007bc:	97fffe6d 	bl	400170 <find_index>
  4007c0:	2a0003f5 	mov	w21, w0
  4007c4:	36f80120 	tbz	w0, #31, 4007e8 <unsetenv+0x78>
  4007c8:	9108a294 	add	x20, x20, #0x228
  4007cc:	91004294 	add	x20, x20, #0x10
  4007d0:	089ffe9f 	stlrb	wzr, [x20]
  4007d4:	a94153f3 	ldp	x19, x20, [sp, #16]
  4007d8:	52800000 	mov	w0, #0x0                   	// #0
  4007dc:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4007e0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4007e4:	d65f03c0 	ret
  4007e8:	93407c13 	sxtw	x19, w0
  4007ec:	f94006c0 	ldr	x0, [x22, #8]
  4007f0:	91000673 	add	x19, x19, #0x1
  4007f4:	f8755800 	ldr	x0, [x0, w21, uxtw #3]
  4007f8:	940000be 	bl	400af0 <free>
  4007fc:	f9411683 	ldr	x3, [x20, #552]
  400800:	f94006c4 	ldr	x4, [x22, #8]
  400804:	eb03027f 	cmp	x19, x3
  400808:	54000122 	b.cs	40082c <unsetenv+0xbc>  // b.hs, b.nlast
  40080c:	91002080 	add	x0, x4, #0x8
  400810:	8b030c82 	add	x2, x4, x3, lsl #3
  400814:	8b354c00 	add	x0, x0, w21, uxtw #3
  400818:	f9400001 	ldr	x1, [x0]
  40081c:	91002000 	add	x0, x0, #0x8
  400820:	f81f0001 	stur	x1, [x0, #-16]
  400824:	eb02001f 	cmp	x0, x2
  400828:	54ffff81 	b.ne	400818 <unsetenv+0xa8>  // b.any
  40082c:	d1000463 	sub	x3, x3, #0x1
  400830:	f9011683 	str	x3, [x20, #552]
  400834:	b4fffca4 	cbz	x4, 4007c8 <unsetenv+0x58>
  400838:	f823789f 	str	xzr, [x4, x3, lsl #3]
  40083c:	17ffffe3 	b	4007c8 <unsetenv+0x58>
  400840:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400844:	940000e7 	bl	400be0 <__errno_location@GLIBC_2.2.5>
  400848:	528002c1 	mov	w1, #0x16                  	// #22
  40084c:	b9000001 	str	w1, [x0]
  400850:	12800000 	mov	w0, #0xffffffff            	// #-1
  400854:	17ffffe3 	b	4007e0 <unsetenv+0x70>
  400858:	d503201f 	nop
  40085c:	d503201f 	nop

0000000000400860 <clearenv>:
  400860:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400864:	910003fd 	mov	x29, sp
  400868:	a90153f3 	stp	x19, x20, [sp, #16]
  40086c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400870:	b0000016 	adrp	x22, 401000 <strtol+0xe0>
  400874:	9108a2d3 	add	x19, x22, #0x228
  400878:	91004273 	add	x19, x19, #0x10
  40087c:	d503201f 	nop
  400880:	aa1303e1 	mov	x1, x19
  400884:	52800020 	mov	w0, #0x1                   	// #1
  400888:	94000246 	bl	4011a0 <__aarch64_swp1_acq>
  40088c:	3707ffa0 	tbnz	w0, #0, 400880 <clearenv+0x20>
  400890:	f94116c0 	ldr	x0, [x22, #552]
  400894:	b40001a0 	cbz	x0, 4008c8 <clearenv+0x68>
  400898:	9108a2d5 	add	x21, x22, #0x228
  40089c:	d2800014 	mov	x20, #0x0                   	// #0
  4008a0:	d2800013 	mov	x19, #0x0                   	// #0
  4008a4:	d503201f 	nop
  4008a8:	f94006a0 	ldr	x0, [x21, #8]
  4008ac:	91000673 	add	x19, x19, #0x1
  4008b0:	f8746800 	ldr	x0, [x0, x20]
  4008b4:	91002294 	add	x20, x20, #0x8
  4008b8:	9400008e 	bl	400af0 <free>
  4008bc:	f94002a0 	ldr	x0, [x21]
  4008c0:	eb13001f 	cmp	x0, x19
  4008c4:	54ffff28 	b.hi	4008a8 <clearenv+0x48>  // b.pmore
  4008c8:	9108a2d3 	add	x19, x22, #0x228
  4008cc:	f9400660 	ldr	x0, [x19, #8]
  4008d0:	94000088 	bl	400af0 <free>
  4008d4:	f90116df 	str	xzr, [x22, #552]
  4008d8:	b0000000 	adrp	x0, 401000 <strtol+0xe0>
  4008dc:	f9410400 	ldr	x0, [x0, #520]
  4008e0:	f900067f 	str	xzr, [x19, #8]
  4008e4:	f9000e7f 	str	xzr, [x19, #24]
  4008e8:	f900001f 	str	xzr, [x0]
  4008ec:	91004273 	add	x19, x19, #0x10
  4008f0:	089ffe7f 	stlrb	wzr, [x19]
  4008f4:	52800000 	mov	w0, #0x0                   	// #0
  4008f8:	a94153f3 	ldp	x19, x20, [sp, #16]
  4008fc:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400900:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400904:	d65f03c0 	ret
	...

0000000000400910 <insert_free_block>:
  400910:	52800021 	mov	w1, #0x1                   	// #1
  400914:	39002001 	strb	w1, [x0, #8]
  400918:	b0000001 	adrp	x1, 401000 <strtol+0xe0>
  40091c:	f9412822 	ldr	x2, [x1, #592]
  400920:	f100005f 	cmp	x2, #0x0
  400924:	fa401042 	ccmp	x2, x0, #0x2, ne	// ne = any
  400928:	540002a9 	b.ls	40097c <insert_free_block+0x6c>  // b.plast
  40092c:	f9012820 	str	x0, [x1, #592]
  400930:	f9000802 	str	x2, [x0, #16]
  400934:	14000006 	b	40094c <insert_free_block+0x3c>
  400938:	f9400043 	ldr	x3, [x2]
  40093c:	8b030041 	add	x1, x2, x3
  400940:	91006021 	add	x1, x1, #0x18
  400944:	eb01001f 	cmp	x0, x1
  400948:	540000a0 	b.eq	40095c <insert_free_block+0x4c>  // b.none
  40094c:	aa0003e2 	mov	x2, x0
  400950:	f9400800 	ldr	x0, [x0, #16]
  400954:	b5ffff20 	cbnz	x0, 400938 <insert_free_block+0x28>
  400958:	d65f03c0 	ret
  40095c:	f9400001 	ldr	x1, [x0]
  400960:	91006063 	add	x3, x3, #0x18
  400964:	f9400800 	ldr	x0, [x0, #16]
  400968:	8b010063 	add	x3, x3, x1
  40096c:	f9000043 	str	x3, [x2]
  400970:	f9000840 	str	x0, [x2, #16]
  400974:	aa0203e0 	mov	x0, x2
  400978:	17fffff5 	b	40094c <insert_free_block+0x3c>
  40097c:	aa0203e1 	mov	x1, x2
  400980:	14000003 	b	40098c <insert_free_block+0x7c>
  400984:	eb00003f 	cmp	x1, x0
  400988:	54000082 	b.cs	400998 <insert_free_block+0x88>  // b.hs, b.nlast
  40098c:	aa0103e3 	mov	x3, x1
  400990:	f9400821 	ldr	x1, [x1, #16]
  400994:	b5ffff81 	cbnz	x1, 400984 <insert_free_block+0x74>
  400998:	f9000801 	str	x1, [x0, #16]
  40099c:	f9000860 	str	x0, [x3, #16]
  4009a0:	aa0203e0 	mov	x0, x2
  4009a4:	17ffffea 	b	40094c <insert_free_block+0x3c>
  4009a8:	d503201f 	nop
  4009ac:	d503201f 	nop

00000000004009b0 <malloc>:
  4009b0:	b4000640 	cbz	x0, 400a78 <malloc+0xc8>
  4009b4:	91003c00 	add	x0, x0, #0xf
  4009b8:	927c6c02 	and	x2, x0, #0xfffffff0
  4009bc:	b0000005 	adrp	x5, 401000 <strtol+0xe0>
  4009c0:	f94128a0 	ldr	x0, [x5, #592]
  4009c4:	b4000180 	cbz	x0, 4009f4 <malloc+0x44>
  4009c8:	d2800003 	mov	x3, #0x0                   	// #0
  4009cc:	14000002 	b	4009d4 <malloc+0x24>
  4009d0:	aa0103e0 	mov	x0, x1
  4009d4:	39402001 	ldrb	w1, [x0, #8]
  4009d8:	36000081 	tbz	w1, #0, 4009e8 <malloc+0x38>
  4009dc:	f9400001 	ldr	x1, [x0]
  4009e0:	eb01005f 	cmp	x2, x1
  4009e4:	540004e9 	b.ls	400a80 <malloc+0xd0>  // b.plast
  4009e8:	f9400801 	ldr	x1, [x0, #16]
  4009ec:	aa0003e3 	mov	x3, x0
  4009f0:	b5ffff01 	cbnz	x1, 4009d0 <malloc+0x20>
  4009f4:	d2800188 	mov	x8, #0xc                   	// #12
  4009f8:	d2800000 	mov	x0, #0x0                   	// #0
  4009fc:	d4000001 	svc	#0x0
  400a00:	aa0003e4 	mov	x4, x0
  400a04:	b7f803a0 	tbnz	x0, #63, 400a78 <malloc+0xc8>
  400a08:	91009c41 	add	x1, x2, #0x27
  400a0c:	927c6c21 	and	x1, x1, #0xfffffff0
  400a10:	8b000023 	add	x3, x1, x0
  400a14:	aa0303e0 	mov	x0, x3
  400a18:	d4000001 	svc	#0x0
  400a1c:	eb00007f 	cmp	x3, x0
  400a20:	540002cc 	b.gt	400a78 <malloc+0xc8>
  400a24:	d1006021 	sub	x1, x1, #0x18
  400a28:	f9000081 	str	x1, [x4]
  400a2c:	cb020021 	sub	x1, x1, x2
  400a30:	3900209f 	strb	wzr, [x4, #8]
  400a34:	f900089f 	str	xzr, [x4, #16]
  400a38:	f100603f 	cmp	x1, #0x18
  400a3c:	54000569 	b.ls	400ae8 <malloc+0x138>  // b.plast
  400a40:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  400a44:	91006043 	add	x3, x2, #0x18
  400a48:	8b030080 	add	x0, x4, x3
  400a4c:	910003fd 	mov	x29, sp
  400a50:	d1006021 	sub	x1, x1, #0x18
  400a54:	f8236881 	str	x1, [x4, x3]
  400a58:	f900081f 	str	xzr, [x0, #16]
  400a5c:	f9000082 	str	x2, [x4]
  400a60:	f9000880 	str	x0, [x4, #16]
  400a64:	97ffffab 	bl	400910 <insert_free_block>
  400a68:	a8c17bfd 	ldp	x29, x30, [sp], #16
  400a6c:	91006080 	add	x0, x4, #0x18
  400a70:	f900089f 	str	xzr, [x4, #16]
  400a74:	d65f03c0 	ret
  400a78:	d2800000 	mov	x0, #0x0                   	// #0
  400a7c:	d65f03c0 	ret
  400a80:	cb020021 	sub	x1, x1, x2
  400a84:	f9400807 	ldr	x7, [x0, #16]
  400a88:	f100603f 	cmp	x1, #0x18
  400a8c:	540002a9 	b.ls	400ae0 <malloc+0x130>  // b.plast
  400a90:	91006046 	add	x6, x2, #0x18
  400a94:	d1006021 	sub	x1, x1, #0x18
  400a98:	8b060004 	add	x4, x0, x6
  400a9c:	f8266801 	str	x1, [x0, x6]
  400aa0:	52800021 	mov	w1, #0x1                   	// #1
  400aa4:	39002081 	strb	w1, [x4, #8]
  400aa8:	f9000887 	str	x7, [x4, #16]
  400aac:	f9000002 	str	x2, [x0]
  400ab0:	f9000804 	str	x4, [x0, #16]
  400ab4:	b40000c3 	cbz	x3, 400acc <malloc+0x11c>
  400ab8:	f9000864 	str	x4, [x3, #16]
  400abc:	91006000 	add	x0, x0, #0x18
  400ac0:	381f001f 	sturb	wzr, [x0, #-16]
  400ac4:	f81f801f 	stur	xzr, [x0, #-8]
  400ac8:	d65f03c0 	ret
  400acc:	91006000 	add	x0, x0, #0x18
  400ad0:	f90128a4 	str	x4, [x5, #592]
  400ad4:	381f001f 	sturb	wzr, [x0, #-16]
  400ad8:	f81f801f 	stur	xzr, [x0, #-8]
  400adc:	d65f03c0 	ret
  400ae0:	aa0703e4 	mov	x4, x7
  400ae4:	17fffff4 	b	400ab4 <malloc+0x104>
  400ae8:	91006080 	add	x0, x4, #0x18
  400aec:	d65f03c0 	ret

0000000000400af0 <free>:
  400af0:	b4000060 	cbz	x0, 400afc <free+0xc>
  400af4:	d1006000 	sub	x0, x0, #0x18
  400af8:	17ffff86 	b	400910 <insert_free_block>
  400afc:	d65f03c0 	ret

0000000000400b00 <calloc>:
  400b00:	9b017c02 	mul	x2, x0, x1
  400b04:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400b08:	910003fd 	mov	x29, sp
  400b0c:	aa0203e0 	mov	x0, x2
  400b10:	f9000be2 	str	x2, [sp, #16]
  400b14:	97ffffa7 	bl	4009b0 <malloc>
  400b18:	aa0003e3 	mov	x3, x0
  400b1c:	b40000c0 	cbz	x0, 400b34 <calloc+0x34>
  400b20:	f9400be2 	ldr	x2, [sp, #16]
  400b24:	52800001 	mov	w1, #0x0                   	// #0
  400b28:	f9000fe0 	str	x0, [sp, #24]
  400b2c:	9400016d 	bl	4010e0 <memset>
  400b30:	f9400fe3 	ldr	x3, [sp, #24]
  400b34:	aa0303e0 	mov	x0, x3
  400b38:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400b3c:	d65f03c0 	ret

0000000000400b40 <realloc>:
  400b40:	b40003e0 	cbz	x0, 400bbc <realloc+0x7c>
  400b44:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400b48:	910003fd 	mov	x29, sp
  400b4c:	b40003c1 	cbz	x1, 400bc4 <realloc+0x84>
  400b50:	aa0003e3 	mov	x3, x0
  400b54:	aa0003e4 	mov	x4, x0
  400b58:	f85e8000 	ldur	x0, [x0, #-24]
  400b5c:	eb01001f 	cmp	x0, x1
  400b60:	54000083 	b.cc	400b70 <realloc+0x30>  // b.lo, b.ul, b.last
  400b64:	aa0403e0 	mov	x0, x4
  400b68:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400b6c:	d65f03c0 	ret
  400b70:	aa0103e0 	mov	x0, x1
  400b74:	a9018fe1 	stp	x1, x3, [sp, #24]
  400b78:	97ffff8e 	bl	4009b0 <malloc>
  400b7c:	aa0003e4 	mov	x4, x0
  400b80:	b4ffff20 	cbz	x0, 400b64 <realloc+0x24>
  400b84:	a9418fe1 	ldp	x1, x3, [sp, #24]
  400b88:	f9000fe3 	str	x3, [sp, #24]
  400b8c:	f90017e0 	str	x0, [sp, #40]
  400b90:	f85e8062 	ldur	x2, [x3, #-24]
  400b94:	eb01005f 	cmp	x2, x1
  400b98:	9a819042 	csel	x2, x2, x1, ls	// ls = plast
  400b9c:	aa0303e1 	mov	x1, x3
  400ba0:	94000140 	bl	4010a0 <memcpy>
  400ba4:	f9400fe0 	ldr	x0, [sp, #24]
  400ba8:	97ffffd2 	bl	400af0 <free>
  400bac:	f94017e4 	ldr	x4, [sp, #40]
  400bb0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400bb4:	aa0403e0 	mov	x0, x4
  400bb8:	d65f03c0 	ret
  400bbc:	aa0103e0 	mov	x0, x1
  400bc0:	17ffff7c 	b	4009b0 <malloc>
  400bc4:	97ffffcb 	bl	400af0 <free>
  400bc8:	d2800004 	mov	x4, #0x0                   	// #0
  400bcc:	17ffffe6 	b	400b64 <realloc+0x24>

0000000000400bd0 <heap_stats>:
  400bd0:	d65f03c0 	ret
	...

0000000000400be0 <__errno_location@GLIBC_2.2.5>:
  400be0:	b0000000 	adrp	x0, 401000 <strtol+0xe0>
  400be4:	91096000 	add	x0, x0, #0x258
  400be8:	d65f03c0 	ret
  400bec:	00000000 	udf	#0

0000000000400bf0 <strlen>:
  400bf0:	aa0003e2 	mov	x2, x0
  400bf4:	b4000120 	cbz	x0, 400c18 <strlen+0x28>
  400bf8:	39400000 	ldrb	w0, [x0]
  400bfc:	340000e0 	cbz	w0, 400c18 <strlen+0x28>
  400c00:	d2800000 	mov	x0, #0x0                   	// #0
  400c04:	d503201f 	nop
  400c08:	91000400 	add	x0, x0, #0x1
  400c0c:	38606841 	ldrb	w1, [x2, x0]
  400c10:	35ffffc1 	cbnz	w1, 400c08 <strlen+0x18>
  400c14:	d65f03c0 	ret
  400c18:	d2800000 	mov	x0, #0x0                   	// #0
  400c1c:	d65f03c0 	ret

0000000000400c20 <strncpy>:
  400c20:	f100001f 	cmp	x0, #0x0
  400c24:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c28:	54000220 	b.eq	400c6c <strncpy+0x4c>  // b.none
  400c2c:	d2800003 	mov	x3, #0x0                   	// #0
  400c30:	b50000c2 	cbnz	x2, 400c48 <strncpy+0x28>
  400c34:	1400000e 	b	400c6c <strncpy+0x4c>
  400c38:	38236804 	strb	w4, [x0, x3]
  400c3c:	91000463 	add	x3, x3, #0x1
  400c40:	eb03005f 	cmp	x2, x3
  400c44:	54000140 	b.eq	400c6c <strncpy+0x4c>  // b.none
  400c48:	38636824 	ldrb	w4, [x1, x3]
  400c4c:	35ffff64 	cbnz	w4, 400c38 <strncpy+0x18>
  400c50:	eb03005f 	cmp	x2, x3
  400c54:	540000c9 	b.ls	400c6c <strncpy+0x4c>  // b.plast
  400c58:	8b030003 	add	x3, x0, x3
  400c5c:	8b020002 	add	x2, x0, x2
  400c60:	3800147f 	strb	wzr, [x3], #1
  400c64:	eb02007f 	cmp	x3, x2
  400c68:	54ffffc1 	b.ne	400c60 <strncpy+0x40>  // b.any
  400c6c:	d65f03c0 	ret

0000000000400c70 <strcpy>:
  400c70:	f100001f 	cmp	x0, #0x0
  400c74:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c78:	54000140 	b.eq	400ca0 <strcpy+0x30>  // b.none
  400c7c:	39400023 	ldrb	w3, [x1]
  400c80:	34000123 	cbz	w3, 400ca4 <strcpy+0x34>
  400c84:	d2800002 	mov	x2, #0x0                   	// #0
  400c88:	38226803 	strb	w3, [x0, x2]
  400c8c:	91000442 	add	x2, x2, #0x1
  400c90:	38626823 	ldrb	w3, [x1, x2]
  400c94:	35ffffa3 	cbnz	w3, 400c88 <strcpy+0x18>
  400c98:	8b020002 	add	x2, x0, x2
  400c9c:	3900005f 	strb	wzr, [x2]
  400ca0:	d65f03c0 	ret
  400ca4:	aa0003e2 	mov	x2, x0
  400ca8:	3900005f 	strb	wzr, [x2]
  400cac:	17fffffd 	b	400ca0 <strcpy+0x30>

0000000000400cb0 <strcmp>:
  400cb0:	f100001f 	cmp	x0, #0x0
  400cb4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400cb8:	540001a0 	b.eq	400cec <strcmp+0x3c>  // b.none
  400cbc:	39400002 	ldrb	w2, [x0]
  400cc0:	350000a2 	cbnz	w2, 400cd4 <strcmp+0x24>
  400cc4:	1400000f 	b	400d00 <strcmp+0x50>
  400cc8:	38401c02 	ldrb	w2, [x0, #1]!
  400ccc:	34000142 	cbz	w2, 400cf4 <strcmp+0x44>
  400cd0:	91000421 	add	x1, x1, #0x1
  400cd4:	39400023 	ldrb	w3, [x1]
  400cd8:	7100007f 	cmp	w3, #0x0
  400cdc:	7a421060 	ccmp	w3, w2, #0x0, ne	// ne = any
  400ce0:	54ffff40 	b.eq	400cc8 <strcmp+0x18>  // b.none
  400ce4:	4b030040 	sub	w0, w2, w3
  400ce8:	d65f03c0 	ret
  400cec:	52800000 	mov	w0, #0x0                   	// #0
  400cf0:	d65f03c0 	ret
  400cf4:	39400423 	ldrb	w3, [x1, #1]
  400cf8:	4b030040 	sub	w0, w2, w3
  400cfc:	17fffffb 	b	400ce8 <strcmp+0x38>
  400d00:	39400023 	ldrb	w3, [x1]
  400d04:	4b030040 	sub	w0, w2, w3
  400d08:	17fffff8 	b	400ce8 <strcmp+0x38>
  400d0c:	d503201f 	nop

0000000000400d10 <strncmp>:
  400d10:	f100003f 	cmp	x1, #0x0
  400d14:	d2800003 	mov	x3, #0x0                   	// #0
  400d18:	fa401844 	ccmp	x2, #0x0, #0x4, ne	// ne = any
  400d1c:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
  400d20:	54000081 	b.ne	400d30 <strncmp+0x20>  // b.any
  400d24:	52800004 	mov	w4, #0x0                   	// #0
  400d28:	2a0403e0 	mov	w0, w4
  400d2c:	d65f03c0 	ret
  400d30:	38636804 	ldrb	w4, [x0, x3]
  400d34:	34000104 	cbz	w4, 400d54 <strncmp+0x44>
  400d38:	38636825 	ldrb	w5, [x1, x3]
  400d3c:	340000c5 	cbz	w5, 400d54 <strncmp+0x44>
  400d40:	6b05009f 	cmp	w4, w5
  400d44:	54000181 	b.ne	400d74 <strncmp+0x64>  // b.any
  400d48:	91000463 	add	x3, x3, #0x1
  400d4c:	eb03005f 	cmp	x2, x3
  400d50:	54ffff08 	b.hi	400d30 <strncmp+0x20>  // b.pmore
  400d54:	52800004 	mov	w4, #0x0                   	// #0
  400d58:	eb02007f 	cmp	x3, x2
  400d5c:	54fffe60 	b.eq	400d28 <strncmp+0x18>  // b.none
  400d60:	38636804 	ldrb	w4, [x0, x3]
  400d64:	38636820 	ldrb	w0, [x1, x3]
  400d68:	4b000084 	sub	w4, w4, w0
  400d6c:	2a0403e0 	mov	w0, w4
  400d70:	d65f03c0 	ret
  400d74:	4b050084 	sub	w4, w4, w5
  400d78:	2a0403e0 	mov	w0, w4
  400d7c:	d65f03c0 	ret

0000000000400d80 <strcat>:
  400d80:	f100001f 	cmp	x0, #0x0
  400d84:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d88:	54000041 	b.ne	400d90 <strcat+0x10>  // b.any
  400d8c:	d65f03c0 	ret
  400d90:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400d94:	910003fd 	mov	x29, sp
  400d98:	a90107e0 	stp	x0, x1, [sp, #16]
  400d9c:	97ffff95 	bl	400bf0 <strlen>
  400da0:	a94107e3 	ldp	x3, x1, [sp, #16]
  400da4:	39400022 	ldrb	w2, [x1]
  400da8:	8b000060 	add	x0, x3, x0
  400dac:	34000082 	cbz	w2, 400dbc <strcat+0x3c>
  400db0:	38001402 	strb	w2, [x0], #1
  400db4:	38401c22 	ldrb	w2, [x1, #1]!
  400db8:	35ffffc2 	cbnz	w2, 400db0 <strcat+0x30>
  400dbc:	3900001f 	strb	wzr, [x0]
  400dc0:	aa0303e0 	mov	x0, x3
  400dc4:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400dc8:	d65f03c0 	ret
  400dcc:	d503201f 	nop

0000000000400dd0 <strchr>:
  400dd0:	b4000120 	cbz	x0, 400df4 <strchr+0x24>
  400dd4:	39400002 	ldrb	w2, [x0]
  400dd8:	12001c21 	and	w1, w1, #0xff
  400ddc:	35000082 	cbnz	w2, 400dec <strchr+0x1c>
  400de0:	14000006 	b	400df8 <strchr+0x28>
  400de4:	38401c02 	ldrb	w2, [x0, #1]!
  400de8:	34000082 	cbz	w2, 400df8 <strchr+0x28>
  400dec:	6b01005f 	cmp	w2, w1
  400df0:	54ffffa1 	b.ne	400de4 <strchr+0x14>  // b.any
  400df4:	d65f03c0 	ret
  400df8:	7100003f 	cmp	w1, #0x0
  400dfc:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
  400e00:	d65f03c0 	ret
  400e04:	d503201f 	nop
  400e08:	d503201f 	nop
  400e0c:	d503201f 	nop

0000000000400e10 <strdup>:
  400e10:	b4000300 	cbz	x0, 400e70 <strdup+0x60>
  400e14:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400e18:	910003fd 	mov	x29, sp
  400e1c:	f9000fe0 	str	x0, [sp, #24]
  400e20:	97ffff74 	bl	400bf0 <strlen>
  400e24:	91000403 	add	x3, x0, #0x1
  400e28:	f9000be3 	str	x3, [sp, #16]
  400e2c:	aa0303e0 	mov	x0, x3
  400e30:	97fffee0 	bl	4009b0 <malloc>
  400e34:	b4000180 	cbz	x0, 400e64 <strdup+0x54>
  400e38:	a94113e3 	ldp	x3, x4, [sp, #16]
  400e3c:	d2800001 	mov	x1, #0x0                   	// #0
  400e40:	b40000e3 	cbz	x3, 400e5c <strdup+0x4c>
  400e44:	d503201f 	nop
  400e48:	38616882 	ldrb	w2, [x4, x1]
  400e4c:	38216802 	strb	w2, [x0, x1]
  400e50:	91000421 	add	x1, x1, #0x1
  400e54:	eb01007f 	cmp	x3, x1
  400e58:	54ffff81 	b.ne	400e48 <strdup+0x38>  // b.any
  400e5c:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400e60:	d65f03c0 	ret
  400e64:	d2800000 	mov	x0, #0x0                   	// #0
  400e68:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400e6c:	d65f03c0 	ret
  400e70:	d2800000 	mov	x0, #0x0                   	// #0
  400e74:	d65f03c0 	ret
  400e78:	d503201f 	nop
  400e7c:	d503201f 	nop

0000000000400e80 <strstr>:
  400e80:	f100001f 	cmp	x0, #0x0
  400e84:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400e88:	54000480 	b.eq	400f18 <strstr+0x98>  // b.none
  400e8c:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400e90:	910003fd 	mov	x29, sp
  400e94:	a90153f3 	stp	x19, x20, [sp, #16]
  400e98:	aa0003f3 	mov	x19, x0
  400e9c:	39400022 	ldrb	w2, [x1]
  400ea0:	35000082 	cbnz	w2, 400eb0 <strstr+0x30>
  400ea4:	a94153f3 	ldp	x19, x20, [sp, #16]
  400ea8:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400eac:	d65f03c0 	ret
  400eb0:	aa0103f4 	mov	x20, x1
  400eb4:	aa0103e0 	mov	x0, x1
  400eb8:	f90013f5 	str	x21, [sp, #32]
  400ebc:	97ffff4d 	bl	400bf0 <strlen>
  400ec0:	39400262 	ldrb	w2, [x19]
  400ec4:	aa0003f5 	mov	x21, x0
  400ec8:	35000082 	cbnz	w2, 400ed8 <strstr+0x58>
  400ecc:	1400000e 	b	400f04 <strstr+0x84>
  400ed0:	38401e62 	ldrb	w2, [x19, #1]!
  400ed4:	34000182 	cbz	w2, 400f04 <strstr+0x84>
  400ed8:	39400280 	ldrb	w0, [x20]
  400edc:	6b02001f 	cmp	w0, w2
  400ee0:	54ffff81 	b.ne	400ed0 <strstr+0x50>  // b.any
  400ee4:	aa1503e2 	mov	x2, x21
  400ee8:	aa1403e1 	mov	x1, x20
  400eec:	aa1303e0 	mov	x0, x19
  400ef0:	97ffff88 	bl	400d10 <strncmp>
  400ef4:	35fffee0 	cbnz	w0, 400ed0 <strstr+0x50>
  400ef8:	f94013f5 	ldr	x21, [sp, #32]
  400efc:	aa1303e0 	mov	x0, x19
  400f00:	17ffffe9 	b	400ea4 <strstr+0x24>
  400f04:	f94013f5 	ldr	x21, [sp, #32]
  400f08:	d2800000 	mov	x0, #0x0                   	// #0
  400f0c:	a94153f3 	ldp	x19, x20, [sp, #16]
  400f10:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400f14:	d65f03c0 	ret
  400f18:	d2800000 	mov	x0, #0x0                   	// #0
  400f1c:	d65f03c0 	ret

0000000000400f20 <strtol>:
  400f20:	aa0003e5 	mov	x5, x0
  400f24:	b40009e0 	cbz	x0, 401060 <strtol+0x140>
  400f28:	39400004 	ldrb	w4, [x0]
  400f2c:	51002480 	sub	w0, w4, #0x9
  400f30:	7100809f 	cmp	w4, #0x20
  400f34:	12001c00 	and	w0, w0, #0xff
  400f38:	7a441800 	ccmp	w0, #0x4, #0x0, ne	// ne = any
  400f3c:	540000e8 	b.hi	400f58 <strtol+0x38>  // b.pmore
  400f40:	38401ca4 	ldrb	w4, [x5, #1]!
  400f44:	51002483 	sub	w3, w4, #0x9
  400f48:	7100809f 	cmp	w4, #0x20
  400f4c:	12001c63 	and	w3, w3, #0xff
  400f50:	7a441860 	ccmp	w3, #0x4, #0x0, ne	// ne = any
  400f54:	54ffff69 	b.ls	400f40 <strtol+0x20>  // b.plast
  400f58:	7100ac9f 	cmp	w4, #0x2b
  400f5c:	540006a0 	b.eq	401030 <strtol+0x110>  // b.none
  400f60:	7100b49f 	cmp	w4, #0x2d
  400f64:	d2800028 	mov	x8, #0x1                   	// #1
  400f68:	9a8514a5 	cinc	x5, x5, eq	// eq = none
  400f6c:	da9f1108 	csinv	x8, x8, xzr, ne	// ne = any
  400f70:	394000a3 	ldrb	w3, [x5]
  400f74:	35000462 	cbnz	w2, 401000 <strtol+0xe0>
  400f78:	52800142 	mov	w2, #0xa                   	// #10
  400f7c:	7100c07f 	cmp	w3, #0x30
  400f80:	540005e0 	b.eq	40103c <strtol+0x11c>  // b.none
  400f84:	340007c3 	cbz	w3, 40107c <strtol+0x15c>
  400f88:	93407c47 	sxtw	x7, w2
  400f8c:	d2800004 	mov	x4, #0x0                   	// #0
  400f90:	14000008 	b	400fb0 <strtol+0x90>
  400f94:	51015c60 	sub	w0, w3, #0x57
  400f98:	6b02001f 	cmp	w0, w2
  400f9c:	540002aa 	b.ge	400ff0 <strtol+0xd0>  // b.tcont
  400fa0:	38401ca3 	ldrb	w3, [x5, #1]!
  400fa4:	93407c00 	sxtw	x0, w0
  400fa8:	9b0400e4 	madd	x4, x7, x4, x0
  400fac:	34000223 	cbz	w3, 400ff0 <strtol+0xd0>
  400fb0:	5100c060 	sub	w0, w3, #0x30
  400fb4:	12001c06 	and	w6, w0, #0xff
  400fb8:	710024df 	cmp	w6, #0x9
  400fbc:	54fffee9 	b.ls	400f98 <strtol+0x78>  // b.plast
  400fc0:	51018460 	sub	w0, w3, #0x61
  400fc4:	12001c00 	and	w0, w0, #0xff
  400fc8:	7100641f 	cmp	w0, #0x19
  400fcc:	54fffe49 	b.ls	400f94 <strtol+0x74>  // b.plast
  400fd0:	51010460 	sub	w0, w3, #0x41
  400fd4:	12001c00 	and	w0, w0, #0xff
  400fd8:	7100641f 	cmp	w0, #0x19
  400fdc:	540000a8 	b.hi	400ff0 <strtol+0xd0>  // b.pmore
  400fe0:	5100dc60 	sub	w0, w3, #0x37
  400fe4:	6b02001f 	cmp	w0, w2
  400fe8:	54fffdcb 	b.lt	400fa0 <strtol+0x80>  // b.tstop
  400fec:	d503201f 	nop
  400ff0:	9b047d00 	mul	x0, x8, x4
  400ff4:	b4000041 	cbz	x1, 400ffc <strtol+0xdc>
  400ff8:	f9000025 	str	x5, [x1]
  400ffc:	d65f03c0 	ret
  401000:	7100405f 	cmp	w2, #0x10
  401004:	54fffc01 	b.ne	400f84 <strtol+0x64>  // b.any
  401008:	7100c07f 	cmp	w3, #0x30
  40100c:	54fffbc1 	b.ne	400f84 <strtol+0x64>  // b.any
  401010:	394004a0 	ldrb	w0, [x5, #1]
  401014:	121a7800 	and	w0, w0, #0xffffffdf
  401018:	12001c00 	and	w0, w0, #0xff
  40101c:	7101601f 	cmp	w0, #0x58
  401020:	54fffb41 	b.ne	400f88 <strtol+0x68>  // b.any
  401024:	394008a3 	ldrb	w3, [x5, #2]
  401028:	910008a5 	add	x5, x5, #0x2
  40102c:	17ffffd6 	b	400f84 <strtol+0x64>
  401030:	910004a5 	add	x5, x5, #0x1
  401034:	d2800028 	mov	x8, #0x1                   	// #1
  401038:	17ffffce 	b	400f70 <strtol+0x50>
  40103c:	394004a3 	ldrb	w3, [x5, #1]
  401040:	121a7860 	and	w0, w3, #0xffffffdf
  401044:	12001c00 	and	w0, w0, #0xff
  401048:	7101601f 	cmp	w0, #0x58
  40104c:	54000121 	b.ne	401070 <strtol+0x150>  // b.any
  401050:	394008a3 	ldrb	w3, [x5, #2]
  401054:	52800202 	mov	w2, #0x10                  	// #16
  401058:	910008a5 	add	x5, x5, #0x2
  40105c:	17ffffca 	b	400f84 <strtol+0x64>
  401060:	b4000041 	cbz	x1, 401068 <strtol+0x148>
  401064:	f900003f 	str	xzr, [x1]
  401068:	d2800000 	mov	x0, #0x0                   	// #0
  40106c:	d65f03c0 	ret
  401070:	910004a5 	add	x5, x5, #0x1
  401074:	52800102 	mov	w2, #0x8                   	// #8
  401078:	17ffffc3 	b	400f84 <strtol+0x64>
  40107c:	d2800000 	mov	x0, #0x0                   	// #0
  401080:	17ffffdd 	b	400ff4 <strtol+0xd4>
  401084:	d503201f 	nop
  401088:	d503201f 	nop
  40108c:	d503201f 	nop

0000000000401090 <__isoc23_strtol>:
  401090:	17ffffa4 	b	400f20 <strtol>
  401094:	d503201f 	nop
  401098:	d503201f 	nop
  40109c:	d503201f 	nop

00000000004010a0 <memcpy>:
  4010a0:	f100001f 	cmp	x0, #0x0
  4010a4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4010a8:	54000120 	b.eq	4010cc <memcpy+0x2c>  // b.none
  4010ac:	b4000102 	cbz	x2, 4010cc <memcpy+0x2c>
  4010b0:	d2800003 	mov	x3, #0x0                   	// #0
  4010b4:	d503201f 	nop
  4010b8:	38636824 	ldrb	w4, [x1, x3]
  4010bc:	38236804 	strb	w4, [x0, x3]
  4010c0:	91000463 	add	x3, x3, #0x1
  4010c4:	eb03005f 	cmp	x2, x3
  4010c8:	54ffff81 	b.ne	4010b8 <memcpy+0x18>  // b.any
  4010cc:	d65f03c0 	ret

00000000004010d0 <__memcpy_chk>:
  4010d0:	17fffff4 	b	4010a0 <memcpy>
  4010d4:	d503201f 	nop
  4010d8:	d503201f 	nop
  4010dc:	d503201f 	nop

00000000004010e0 <memset>:
  4010e0:	b40000e0 	cbz	x0, 4010fc <memset+0x1c>
  4010e4:	b40000c2 	cbz	x2, 4010fc <memset+0x1c>
  4010e8:	aa0003e3 	mov	x3, x0
  4010ec:	8b020002 	add	x2, x0, x2
  4010f0:	38001461 	strb	w1, [x3], #1
  4010f4:	eb02007f 	cmp	x3, x2
  4010f8:	54ffffc1 	b.ne	4010f0 <memset+0x10>  // b.any
  4010fc:	d65f03c0 	ret

0000000000401100 <memcmp>:
  401100:	f100001f 	cmp	x0, #0x0
  401104:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401108:	540001a0 	b.eq	40113c <memcmp+0x3c>  // b.none
  40110c:	b4000182 	cbz	x2, 40113c <memcmp+0x3c>
  401110:	d2800003 	mov	x3, #0x0                   	// #0
  401114:	14000004 	b	401124 <memcmp+0x24>
  401118:	91000463 	add	x3, x3, #0x1
  40111c:	eb03005f 	cmp	x2, x3
  401120:	540000e0 	b.eq	40113c <memcmp+0x3c>  // b.none
  401124:	38636804 	ldrb	w4, [x0, x3]
  401128:	38636825 	ldrb	w5, [x1, x3]
  40112c:	6b05009f 	cmp	w4, w5
  401130:	54ffff40 	b.eq	401118 <memcmp+0x18>  // b.none
  401134:	4b050080 	sub	w0, w4, w5
  401138:	d65f03c0 	ret
  40113c:	52800000 	mov	w0, #0x0                   	// #0
  401140:	d65f03c0 	ret
  401144:	d503201f 	nop
  401148:	d503201f 	nop
  40114c:	d503201f 	nop

0000000000401150 <memmove>:
  401150:	f100001f 	cmp	x0, #0x0
  401154:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401158:	54000160 	b.eq	401184 <memmove+0x34>  // b.none
  40115c:	eb01001f 	cmp	x0, x1
  401160:	54000142 	b.cs	401188 <memmove+0x38>  // b.hs, b.nlast
  401164:	b4000102 	cbz	x2, 401184 <memmove+0x34>
  401168:	d2800003 	mov	x3, #0x0                   	// #0
  40116c:	d503201f 	nop
  401170:	38636824 	ldrb	w4, [x1, x3]
  401174:	38236804 	strb	w4, [x0, x3]
  401178:	91000463 	add	x3, x3, #0x1
  40117c:	eb03005f 	cmp	x2, x3
  401180:	54ffff81 	b.ne	401170 <memmove+0x20>  // b.any
  401184:	d65f03c0 	ret
  401188:	b4ffffe2 	cbz	x2, 401184 <memmove+0x34>
  40118c:	d1000442 	sub	x2, x2, #0x1
  401190:	38626823 	ldrb	w3, [x1, x2]
  401194:	38226803 	strb	w3, [x0, x2]
  401198:	17fffffc 	b	401188 <memmove+0x38>
  40119c:	00000000 	udf	#0

00000000004011a0 <__aarch64_swp1_acq>:
  4011a0:	90000010 	adrp	x16, 401000 <strtol+0xe0>
  4011a4:	39497210 	ldrb	w16, [x16, #604]
  4011a8:	34000070 	cbz	w16, 4011b4 <__aarch64_swp1_acq+0x14>
  4011ac:	38a08020 	swpab	w0, w0, [x1]
  4011b0:	d65f03c0 	ret
  4011b4:	2a0003f0 	mov	w16, w0
  4011b8:	085ffc20 	ldaxrb	w0, [x1]
  4011bc:	08117c30 	stxrb	w17, w16, [x1]
  4011c0:	35ffffd1 	cbnz	w17, 4011b8 <__aarch64_swp1_acq+0x18>
  4011c4:	d65f03c0 	ret
