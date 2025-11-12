
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
  400024:	9400011b 	bl	400490 <__libc_init_environ>
  400028:	aa1303e0 	mov	x0, x19
  40002c:	aa1403e1 	mov	x1, x20
  400030:	9400000c 	bl	400060 <main>
  400034:	94000002 	bl	40003c <exit>
  400038:	d4200000 	brk	#0x0

000000000040003c <exit>:
  40003c:	d2800ba8 	mov	x8, #0x5d                  	// #93
  400040:	d4001001 	svc	#0x80
  400044:	d4200000 	brk	#0x0
	...

0000000000400060 <main>:
  400060:	90000000 	adrp	x0, 400000 <_start>
  400064:	d2800048 	mov	x8, #0x2                   	// #2
  400068:	d2800002 	mov	x2, #0x0                   	// #0
  40006c:	aa0803e1 	mov	x1, x8
  400070:	f9409000 	ldr	x0, [x0, #288]
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
  4000ac:	aa0003e1 	mov	x1, x0
  4000b0:	b140041f 	cmn	x0, #0x1, lsl #12
  4000b4:	540000e9 	b.ls	4000d0 <main+0x70>  // b.plast
  4000b8:	d2800068 	mov	x8, #0x3                   	// #3
  4000bc:	aa0403e0 	mov	x0, x4
  4000c0:	d4000001 	svc	#0x0
  4000c4:	d2800788 	mov	x8, #0x3c                  	// #60
  4000c8:	aa0203e0 	mov	x0, x2
  4000cc:	d4000001 	svc	#0x0
  4000d0:	6f00041f 	mvni	v31.4s, #0x0
  4000d4:	914c0020 	add	x0, x1, #0x300, lsl #12
  4000d8:	d503201f 	nop
  4000dc:	d503201f 	nop
  4000e0:	3c81043f 	str	q31, [x1], #16
  4000e4:	eb01001f 	cmp	x0, x1
  4000e8:	54ffffc1 	b.ne	4000e0 <main+0x80>  // b.any
  4000ec:	d2800208 	mov	x8, #0x10                  	// #16
  4000f0:	aa0403e0 	mov	x0, x4
  4000f4:	d288c061 	mov	x1, #0x4603                	// #17923
  4000f8:	d2800002 	mov	x2, #0x0                   	// #0
  4000fc:	d4000001 	svc	#0x0
  400100:	d2800068 	mov	x8, #0x3                   	// #3
  400104:	aa0403e0 	mov	x0, x4
  400108:	d4000001 	svc	#0x0
  40010c:	d2800788 	mov	x8, #0x3c                  	// #60
  400110:	d2800000 	mov	x0, #0x0                   	// #0
  400114:	d4000001 	svc	#0x0
  400118:	52800000 	mov	w0, #0x0                   	// #0
  40011c:	d65f03c0 	ret
  400120:	00401188 	.word	0x00401188
	...

0000000000400130 <find_index>:
  400130:	b0000001 	adrp	x1, 401000 <strtol+0x120>
  400134:	9107a022 	add	x2, x1, #0x1e8
  400138:	f940f426 	ldr	x6, [x1, #488]
  40013c:	b4000346 	cbz	x6, 4001a4 <find_index+0x74>
  400140:	f9400448 	ldr	x8, [x2, #8]
  400144:	f100001f 	cmp	x0, #0x0
  400148:	1a9f17e7 	cset	w7, eq	// eq = none
  40014c:	d2800005 	mov	x5, #0x0                   	// #0
  400150:	f8657904 	ldr	x4, [x8, x5, lsl #3]
  400154:	f100009f 	cmp	x4, #0x0
  400158:	7a4018e0 	ccmp	w7, #0x0, #0x0, ne	// ne = any
  40015c:	540001e1 	b.ne	400198 <find_index+0x68>  // b.any
  400160:	39400082 	ldrb	w2, [x4]
  400164:	d2800001 	mov	x1, #0x0                   	// #0
  400168:	350000e2 	cbnz	w2, 400184 <find_index+0x54>
  40016c:	1400000b 	b	400198 <find_index+0x68>
  400170:	6b02007f 	cmp	w3, w2
  400174:	54000121 	b.ne	400198 <find_index+0x68>  // b.any
  400178:	91000421 	add	x1, x1, #0x1
  40017c:	38616882 	ldrb	w2, [x4, x1]
  400180:	340000c2 	cbz	w2, 400198 <find_index+0x68>
  400184:	38616803 	ldrb	w3, [x0, x1]
  400188:	35ffff43 	cbnz	w3, 400170 <find_index+0x40>
  40018c:	7100f45f 	cmp	w2, #0x3d
  400190:	540000e0 	b.eq	4001ac <find_index+0x7c>  // b.none
  400194:	d503201f 	nop
  400198:	910004a5 	add	x5, x5, #0x1
  40019c:	eb0600bf 	cmp	x5, x6
  4001a0:	54fffd81 	b.ne	400150 <find_index+0x20>  // b.any
  4001a4:	12800000 	mov	w0, #0xffffffff            	// #-1
  4001a8:	d65f03c0 	ret
  4001ac:	2a0503e0 	mov	w0, w5
  4001b0:	d65f03c0 	ret
  4001b4:	d503201f 	nop
  4001b8:	d503201f 	nop
  4001bc:	d503201f 	nop

00000000004001c0 <set_pair>:
  4001c0:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
  4001c4:	910003fd 	mov	x29, sp
  4001c8:	b4001320 	cbz	x0, 40042c <set_pair+0x26c>
  4001cc:	a90153f3 	stp	x19, x20, [sp, #16]
  4001d0:	aa0103f4 	mov	x20, x1
  4001d4:	a9025bf5 	stp	x21, x22, [sp, #32]
  4001d8:	aa0003f5 	mov	x21, x0
  4001dc:	39400001 	ldrb	w1, [x0]
  4001e0:	34001301 	cbz	w1, 400440 <set_pair+0x280>
  4001e4:	528007a1 	mov	w1, #0x3d                  	// #61
  4001e8:	a90363f7 	stp	x23, x24, [sp, #48]
  4001ec:	2a0203f8 	mov	w24, w2
  4001f0:	aa0303f7 	mov	x23, x3
  4001f4:	940002e7 	bl	400d90 <strchr>
  4001f8:	b5001140 	cbnz	x0, 400420 <set_pair+0x260>
  4001fc:	f100029f 	cmp	x20, #0x0
  400200:	b0000013 	adrp	x19, 401000 <strtol+0x120>
  400204:	91064273 	add	x19, x19, #0x190
  400208:	aa1503e0 	mov	x0, x21
  40020c:	9a940273 	csel	x19, x19, x20, eq	// eq = none
  400210:	a9046bf9 	stp	x25, x26, [sp, #64]
  400214:	94000267 	bl	400bb0 <strlen>
  400218:	aa1703f6 	mov	x22, x23
  40021c:	aa0003f4 	mov	x20, x0
  400220:	aa1303e0 	mov	x0, x19
  400224:	94000263 	bl	400bb0 <strlen>
  400228:	aa0003f9 	mov	x25, x0
  40022c:	b4000497 	cbz	x23, 4002bc <set_pair+0xfc>
  400230:	b0000014 	adrp	x20, 401000 <strtol+0x120>
  400234:	9107a299 	add	x25, x20, #0x1e8
  400238:	91004333 	add	x19, x25, #0x10
  40023c:	d503201f 	nop
  400240:	aa1303e1 	mov	x1, x19
  400244:	52800020 	mov	w0, #0x1                   	// #1
  400248:	940003c6 	bl	401160 <__aarch64_swp1_acq>
  40024c:	3707ffa0 	tbnz	w0, #0, 400240 <set_pair+0x80>
  400250:	aa1503e0 	mov	x0, x21
  400254:	97ffffb7 	bl	400130 <find_index>
  400258:	2a2003e1 	mvn	w1, w0
  40025c:	52000318 	eor	w24, w24, #0x1
  400260:	6a417f1f 	tst	w24, w1, lsr #31
  400264:	540006a1 	b.ne	400338 <set_pair+0x178>  // b.any
  400268:	37f804e0 	tbnz	w0, #31, 400304 <set_pair+0x144>
  40026c:	f9400722 	ldr	x2, [x25, #8]
  400270:	d37d7c13 	ubfiz	x19, x0, #3, #32
  400274:	8b130041 	add	x1, x2, x19
  400278:	f8605840 	ldr	x0, [x2, w0, uxtw #3]
  40027c:	eb16001f 	cmp	x0, x22
  400280:	54000080 	b.eq	400290 <set_pair+0xd0>  // b.none
  400284:	9400020b 	bl	400ab0 <free>
  400288:	f9400721 	ldr	x1, [x25, #8]
  40028c:	8b130021 	add	x1, x1, x19
  400290:	f9000036 	str	x22, [x1]
  400294:	9107a294 	add	x20, x20, #0x1e8
  400298:	91004294 	add	x20, x20, #0x10
  40029c:	089ffe9f 	stlrb	wzr, [x20]
  4002a0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4002a4:	52800000 	mov	w0, #0x0                   	// #0
  4002a8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4002ac:	a94363f7 	ldp	x23, x24, [sp, #48]
  4002b0:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4002b4:	a8c57bfd 	ldp	x29, x30, [sp], #80
  4002b8:	d65f03c0 	ret
  4002bc:	8b00029a 	add	x26, x20, x0
  4002c0:	91000b40 	add	x0, x26, #0x2
  4002c4:	940001ab 	bl	400970 <malloc>
  4002c8:	aa0003f6 	mov	x22, x0
  4002cc:	b4000d00 	cbz	x0, 40046c <set_pair+0x2ac>
  4002d0:	aa1403e2 	mov	x2, x20
  4002d4:	aa1503e1 	mov	x1, x21
  4002d8:	8b1a02da 	add	x26, x22, x26
  4002dc:	94000361 	bl	401060 <memcpy>
  4002e0:	528007a0 	mov	w0, #0x3d                  	// #61
  4002e4:	38346ac0 	strb	w0, [x22, x20]
  4002e8:	91000680 	add	x0, x20, #0x1
  4002ec:	aa1903e2 	mov	x2, x25
  4002f0:	aa1303e1 	mov	x1, x19
  4002f4:	8b0002c0 	add	x0, x22, x0
  4002f8:	9400035a 	bl	401060 <memcpy>
  4002fc:	3900075f 	strb	wzr, [x26, #1]
  400300:	17ffffcc 	b	400230 <set_pair+0x70>
  400304:	f940f681 	ldr	x1, [x20, #488]
  400308:	f9400f33 	ldr	x19, [x25, #24]
  40030c:	91000820 	add	x0, x1, #0x2
  400310:	eb13001f 	cmp	x0, x19
  400314:	540001c8 	b.hi	40034c <set_pair+0x18c>  // b.pmore
  400318:	f9400735 	ldr	x21, [x25, #8]
  40031c:	b4000795 	cbz	x21, 40040c <set_pair+0x24c>
  400320:	91000420 	add	x0, x1, #0x1
  400324:	f8217ab6 	str	x22, [x21, x1, lsl #3]
  400328:	8b010ea1 	add	x1, x21, x1, lsl #3
  40032c:	f900f680 	str	x0, [x20, #488]
  400330:	f900043f 	str	xzr, [x1, #8]
  400334:	17ffffd8 	b	400294 <set_pair+0xd4>
  400338:	089ffe7f 	stlrb	wzr, [x19]
  40033c:	b5fffb37 	cbnz	x23, 4002a0 <set_pair+0xe0>
  400340:	aa1603e0 	mov	x0, x22
  400344:	940001db 	bl	400ab0 <free>
  400348:	17ffffd6 	b	4002a0 <set_pair+0xe0>
  40034c:	b4000633 	cbz	x19, 400410 <set_pair+0x250>
  400350:	8b130273 	add	x19, x19, x19
  400354:	eb13001f 	cmp	x0, x19
  400358:	54ffffc8 	b.hi	400350 <set_pair+0x190>  // b.pmore
  40035c:	d37df278 	lsl	x24, x19, #3
  400360:	aa1803e0 	mov	x0, x24
  400364:	94000183 	bl	400970 <malloc>
  400368:	aa0003f5 	mov	x21, x0
  40036c:	9107a280 	add	x0, x20, #0x1e8
  400370:	b4000755 	cbz	x21, 400458 <set_pair+0x298>
  400374:	f940f682 	ldr	x2, [x20, #488]
  400378:	f9400400 	ldr	x0, [x0, #8]
  40037c:	b4000682 	cbz	x2, 40044c <set_pair+0x28c>
  400380:	d2800001 	mov	x1, #0x0                   	// #0
  400384:	b4000320 	cbz	x0, 4003e8 <set_pair+0x228>
  400388:	f8617803 	ldr	x3, [x0, x1, lsl #3]
  40038c:	f8217aa3 	str	x3, [x21, x1, lsl #3]
  400390:	91000421 	add	x1, x1, #0x1
  400394:	eb01005f 	cmp	x2, x1
  400398:	54ffff81 	b.ne	400388 <set_pair+0x1c8>  // b.any
  40039c:	8b020ea1 	add	x1, x21, x2, lsl #3
  4003a0:	91000442 	add	x2, x2, #0x1
  4003a4:	f900003f 	str	xzr, [x1]
  4003a8:	8b150303 	add	x3, x24, x21
  4003ac:	8b020ea1 	add	x1, x21, x2, lsl #3
  4003b0:	eb02027f 	cmp	x19, x2
  4003b4:	54000089 	b.ls	4003c4 <set_pair+0x204>  // b.plast
  4003b8:	f800843f 	str	xzr, [x1], #8
  4003bc:	eb03003f 	cmp	x1, x3
  4003c0:	54ffffc1 	b.ne	4003b8 <set_pair+0x1f8>  // b.any
  4003c4:	940001bb 	bl	400ab0 <free>
  4003c8:	b0000001 	adrp	x1, 401000 <strtol+0x120>
  4003cc:	f940e421 	ldr	x1, [x1, #456]
  4003d0:	9107a280 	add	x0, x20, #0x1e8
  4003d4:	f9000035 	str	x21, [x1]
  4003d8:	f940f681 	ldr	x1, [x20, #488]
  4003dc:	f9000415 	str	x21, [x0, #8]
  4003e0:	f9000c13 	str	x19, [x0, #24]
  4003e4:	17ffffcf 	b	400320 <set_pair+0x160>
  4003e8:	91000423 	add	x3, x1, #0x1
  4003ec:	f8217abf 	str	xzr, [x21, x1, lsl #3]
  4003f0:	eb03005f 	cmp	x2, x3
  4003f4:	54fffd40 	b.eq	40039c <set_pair+0x1dc>  // b.none
  4003f8:	91000821 	add	x1, x1, #0x2
  4003fc:	f8237abf 	str	xzr, [x21, x3, lsl #3]
  400400:	eb01005f 	cmp	x2, x1
  400404:	54ffff21 	b.ne	4003e8 <set_pair+0x228>  // b.any
  400408:	17ffffe5 	b	40039c <set_pair+0x1dc>
  40040c:	b5fffa93 	cbnz	x19, 40035c <set_pair+0x19c>
  400410:	d2800113 	mov	x19, #0x8                   	// #8
  400414:	f100201f 	cmp	x0, #0x8
  400418:	54fff9c8 	b.hi	400350 <set_pair+0x190>  // b.pmore
  40041c:	17ffffd0 	b	40035c <set_pair+0x19c>
  400420:	a94153f3 	ldp	x19, x20, [sp, #16]
  400424:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400428:	a94363f7 	ldp	x23, x24, [sp, #48]
  40042c:	940001dd 	bl	400ba0 <__errno_location@GLIBC_2.2.5>
  400430:	528002c1 	mov	w1, #0x16                  	// #22
  400434:	b9000001 	str	w1, [x0]
  400438:	12800000 	mov	w0, #0xffffffff            	// #-1
  40043c:	17ffff9e 	b	4002b4 <set_pair+0xf4>
  400440:	a94153f3 	ldp	x19, x20, [sp, #16]
  400444:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400448:	17fffff9 	b	40042c <set_pair+0x26c>
  40044c:	aa1503e1 	mov	x1, x21
  400450:	d2800022 	mov	x2, #0x1                   	// #1
  400454:	17ffffd4 	b	4003a4 <set_pair+0x1e4>
  400458:	91004000 	add	x0, x0, #0x10
  40045c:	089ffc1f 	stlrb	wzr, [x0]
  400460:	b5000077 	cbnz	x23, 40046c <set_pair+0x2ac>
  400464:	aa1603e0 	mov	x0, x22
  400468:	94000192 	bl	400ab0 <free>
  40046c:	940001cd 	bl	400ba0 <__errno_location@GLIBC_2.2.5>
  400470:	52800181 	mov	w1, #0xc                   	// #12
  400474:	b9000001 	str	w1, [x0]
  400478:	12800000 	mov	w0, #0xffffffff            	// #-1
  40047c:	a94153f3 	ldp	x19, x20, [sp, #16]
  400480:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400484:	a94363f7 	ldp	x23, x24, [sp, #48]
  400488:	a9446bf9 	ldp	x25, x26, [sp, #64]
  40048c:	17ffff8a 	b	4002b4 <set_pair+0xf4>

0000000000400490 <__libc_init_environ>:
  400490:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
  400494:	910003fd 	mov	x29, sp
  400498:	a90363f7 	stp	x23, x24, [sp, #48]
  40049c:	a90573fb 	stp	x27, x28, [sp, #80]
  4004a0:	b40007e0 	cbz	x0, 40059c <__libc_init_environ+0x10c>
  4004a4:	f9400001 	ldr	x1, [x0]
  4004a8:	b40007a1 	cbz	x1, 40059c <__libc_init_environ+0x10c>
  4004ac:	d1002003 	sub	x3, x0, #0x8
  4004b0:	d2800101 	mov	x1, #0x8                   	// #8
  4004b4:	d280001c 	mov	x28, #0x0                   	// #0
  4004b8:	a9025bf5 	stp	x21, x22, [sp, #32]
  4004bc:	a9046bf9 	stp	x25, x26, [sp, #64]
  4004c0:	aa0103f7 	mov	x23, x1
  4004c4:	91002021 	add	x1, x1, #0x8
  4004c8:	aa1c03f8 	mov	x24, x28
  4004cc:	9100079c 	add	x28, x28, #0x1
  4004d0:	f8616862 	ldr	x2, [x3, x1]
  4004d4:	b5ffff62 	cbnz	x2, 4004c0 <__libc_init_environ+0x30>
  4004d8:	91000b18 	add	x24, x24, #0x2
  4004dc:	b000001b 	adrp	x27, 401000 <strtol+0x120>
  4004e0:	9107a37a 	add	x26, x27, #0x1e8
  4004e4:	aa0003f6 	mov	x22, x0
  4004e8:	d37df319 	lsl	x25, x24, #3
  4004ec:	aa1903e0 	mov	x0, x25
  4004f0:	94000120 	bl	400970 <malloc>
  4004f4:	f9000740 	str	x0, [x26, #8]
  4004f8:	b4000600 	cbz	x0, 4005b8 <__libc_init_environ+0x128>
  4004fc:	d1002339 	sub	x25, x25, #0x8
  400500:	a90153f3 	stp	x19, x20, [sp, #16]
  400504:	d2800013 	mov	x19, #0x0                   	// #0
  400508:	14000009 	b	40052c <__libc_init_environ+0x9c>
  40050c:	f8736ac1 	ldr	x1, [x22, x19]
  400510:	aa1503e2 	mov	x2, x21
  400514:	940002d3 	bl	401060 <memcpy>
  400518:	f9400740 	ldr	x0, [x26, #8]
  40051c:	f8336814 	str	x20, [x0, x19]
  400520:	91002273 	add	x19, x19, #0x8
  400524:	eb19027f 	cmp	x19, x25
  400528:	540001a0 	b.eq	40055c <__libc_init_environ+0xcc>  // b.none
  40052c:	f8736ac0 	ldr	x0, [x22, x19]
  400530:	940001a0 	bl	400bb0 <strlen>
  400534:	91000415 	add	x21, x0, #0x1
  400538:	aa1503e0 	mov	x0, x21
  40053c:	9400010d 	bl	400970 <malloc>
  400540:	aa0003f4 	mov	x20, x0
  400544:	b5fffe40 	cbnz	x0, 40050c <__libc_init_environ+0x7c>
  400548:	f9400740 	ldr	x0, [x26, #8]
  40054c:	f833681f 	str	xzr, [x0, x19]
  400550:	91002273 	add	x19, x19, #0x8
  400554:	eb19027f 	cmp	x19, x25
  400558:	54fffea1 	b.ne	40052c <__libc_init_environ+0x9c>  // b.any
  40055c:	9107a360 	add	x0, x27, #0x1e8
  400560:	f9400400 	ldr	x0, [x0, #8]
  400564:	f837681f 	str	xzr, [x0, x23]
  400568:	a94153f3 	ldp	x19, x20, [sp, #16]
  40056c:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400570:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400574:	f900f77c 	str	x28, [x27, #488]
  400578:	b0000001 	adrp	x1, 401000 <strtol+0x120>
  40057c:	f940e421 	ldr	x1, [x1, #456]
  400580:	f9000020 	str	x0, [x1]
  400584:	9107a360 	add	x0, x27, #0x1e8
  400588:	f9000c18 	str	x24, [x0, #24]
  40058c:	a94363f7 	ldp	x23, x24, [sp, #48]
  400590:	a94573fb 	ldp	x27, x28, [sp, #80]
  400594:	a8c67bfd 	ldp	x29, x30, [sp], #96
  400598:	d65f03c0 	ret
  40059c:	b000001b 	adrp	x27, 401000 <strtol+0x120>
  4005a0:	9107a360 	add	x0, x27, #0x1e8
  4005a4:	f900041f 	str	xzr, [x0, #8]
  4005a8:	d2800000 	mov	x0, #0x0                   	// #0
  4005ac:	d280001c 	mov	x28, #0x0                   	// #0
  4005b0:	d2800018 	mov	x24, #0x0                   	// #0
  4005b4:	17fffff0 	b	400574 <__libc_init_environ+0xe4>
  4005b8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4005bc:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4005c0:	17fffffa 	b	4005a8 <__libc_init_environ+0x118>
  4005c4:	d503201f 	nop
  4005c8:	d503201f 	nop
  4005cc:	d503201f 	nop

00000000004005d0 <getenv>:
  4005d0:	b40004a0 	cbz	x0, 400664 <getenv+0x94>
  4005d4:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4005d8:	910003fd 	mov	x29, sp
  4005dc:	a90153f3 	stp	x19, x20, [sp, #16]
  4005e0:	a9025bf5 	stp	x21, x22, [sp, #32]
  4005e4:	b0000014 	adrp	x20, 401000 <strtol+0x120>
  4005e8:	9107a295 	add	x21, x20, #0x1e8
  4005ec:	aa0003f6 	mov	x22, x0
  4005f0:	910042a1 	add	x1, x21, #0x10
  4005f4:	52800020 	mov	w0, #0x1                   	// #1
  4005f8:	940002da 	bl	401160 <__aarch64_swp1_acq>
  4005fc:	3707ffa0 	tbnz	w0, #0, 4005f0 <getenv+0x20>
  400600:	aa1603e0 	mov	x0, x22
  400604:	97fffecb 	bl	400130 <find_index>
  400608:	37f801e0 	tbnz	w0, #31, 400644 <getenv+0x74>
  40060c:	f94006a1 	ldr	x1, [x21, #8]
  400610:	f8605820 	ldr	x0, [x1, w0, uxtw #3]
  400614:	b4000180 	cbz	x0, 400644 <getenv+0x74>
  400618:	528007a1 	mov	w1, #0x3d                  	// #61
  40061c:	940001dd 	bl	400d90 <strchr>
  400620:	b4000120 	cbz	x0, 400644 <getenv+0x74>
  400624:	91000400 	add	x0, x0, #0x1
  400628:	9107a294 	add	x20, x20, #0x1e8
  40062c:	91004294 	add	x20, x20, #0x10
  400630:	089ffe9f 	stlrb	wzr, [x20]
  400634:	a94153f3 	ldp	x19, x20, [sp, #16]
  400638:	a9425bf5 	ldp	x21, x22, [sp, #32]
  40063c:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400640:	d65f03c0 	ret
  400644:	d2800000 	mov	x0, #0x0                   	// #0
  400648:	9107a294 	add	x20, x20, #0x1e8
  40064c:	91004294 	add	x20, x20, #0x10
  400650:	089ffe9f 	stlrb	wzr, [x20]
  400654:	a94153f3 	ldp	x19, x20, [sp, #16]
  400658:	a9425bf5 	ldp	x21, x22, [sp, #32]
  40065c:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400660:	d65f03c0 	ret
  400664:	d65f03c0 	ret
  400668:	d503201f 	nop
  40066c:	d503201f 	nop

0000000000400670 <secure_getenv>:
  400670:	17ffffd8 	b	4005d0 <getenv>
  400674:	d503201f 	nop
  400678:	d503201f 	nop
  40067c:	d503201f 	nop

0000000000400680 <__secure_getenv>:
  400680:	17fffffc 	b	400670 <secure_getenv>
  400684:	d503201f 	nop
  400688:	d503201f 	nop
  40068c:	d503201f 	nop

0000000000400690 <setenv>:
  400690:	7100005f 	cmp	w2, #0x0
  400694:	d2800003 	mov	x3, #0x0                   	// #0
  400698:	1a9f07e2 	cset	w2, ne	// ne = any
  40069c:	17fffec9 	b	4001c0 <set_pair>

00000000004006a0 <putenv>:
  4006a0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4006a4:	910003fd 	mov	x29, sp
  4006a8:	b4000380 	cbz	x0, 400718 <putenv+0x78>
  4006ac:	528007a1 	mov	w1, #0x3d                  	// #61
  4006b0:	a90153f3 	stp	x19, x20, [sp, #16]
  4006b4:	aa0003f4 	mov	x20, x0
  4006b8:	940001b6 	bl	400d90 <strchr>
  4006bc:	f100001f 	cmp	x0, #0x0
  4006c0:	aa0003f3 	mov	x19, x0
  4006c4:	fa401284 	ccmp	x20, x0, #0x4, ne	// ne = any
  4006c8:	540001c0 	b.eq	400700 <putenv+0x60>  // b.none
  4006cc:	aa0003e1 	mov	x1, x0
  4006d0:	f90013f5 	str	x21, [sp, #32]
  4006d4:	aa1403e3 	mov	x3, x20
  4006d8:	aa1403e0 	mov	x0, x20
  4006dc:	39400275 	ldrb	w21, [x19]
  4006e0:	52800022 	mov	w2, #0x1                   	// #1
  4006e4:	3800143f 	strb	wzr, [x1], #1
  4006e8:	97fffeb6 	bl	4001c0 <set_pair>
  4006ec:	39000275 	strb	w21, [x19]
  4006f0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4006f4:	f94013f5 	ldr	x21, [sp, #32]
  4006f8:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4006fc:	d65f03c0 	ret
  400700:	94000128 	bl	400ba0 <__errno_location@GLIBC_2.2.5>
  400704:	528002c1 	mov	w1, #0x16                  	// #22
  400708:	b9000001 	str	w1, [x0]
  40070c:	12800000 	mov	w0, #0xffffffff            	// #-1
  400710:	a94153f3 	ldp	x19, x20, [sp, #16]
  400714:	17fffff9 	b	4006f8 <putenv+0x58>
  400718:	94000122 	bl	400ba0 <__errno_location@GLIBC_2.2.5>
  40071c:	528002c1 	mov	w1, #0x16                  	// #22
  400720:	b9000001 	str	w1, [x0]
  400724:	12800000 	mov	w0, #0xffffffff            	// #-1
  400728:	17fffff4 	b	4006f8 <putenv+0x58>
  40072c:	d503201f 	nop

0000000000400730 <unsetenv>:
  400730:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400734:	910003fd 	mov	x29, sp
  400738:	b4000660 	cbz	x0, 400804 <unsetenv+0xd4>
  40073c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400740:	aa0003f5 	mov	x21, x0
  400744:	39400001 	ldrb	w1, [x0]
  400748:	340005c1 	cbz	w1, 400800 <unsetenv+0xd0>
  40074c:	528007a1 	mov	w1, #0x3d                  	// #61
  400750:	94000190 	bl	400d90 <strchr>
  400754:	b5000560 	cbnz	x0, 400800 <unsetenv+0xd0>
  400758:	a90153f3 	stp	x19, x20, [sp, #16]
  40075c:	b0000014 	adrp	x20, 401000 <strtol+0x120>
  400760:	9107a296 	add	x22, x20, #0x1e8
  400764:	d503201f 	nop
  400768:	910042c1 	add	x1, x22, #0x10
  40076c:	52800020 	mov	w0, #0x1                   	// #1
  400770:	9400027c 	bl	401160 <__aarch64_swp1_acq>
  400774:	3707ffa0 	tbnz	w0, #0, 400768 <unsetenv+0x38>
  400778:	aa1503e0 	mov	x0, x21
  40077c:	97fffe6d 	bl	400130 <find_index>
  400780:	2a0003f5 	mov	w21, w0
  400784:	36f80120 	tbz	w0, #31, 4007a8 <unsetenv+0x78>
  400788:	9107a294 	add	x20, x20, #0x1e8
  40078c:	91004294 	add	x20, x20, #0x10
  400790:	089ffe9f 	stlrb	wzr, [x20]
  400794:	a94153f3 	ldp	x19, x20, [sp, #16]
  400798:	52800000 	mov	w0, #0x0                   	// #0
  40079c:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4007a0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4007a4:	d65f03c0 	ret
  4007a8:	93407c13 	sxtw	x19, w0
  4007ac:	f94006c0 	ldr	x0, [x22, #8]
  4007b0:	91000673 	add	x19, x19, #0x1
  4007b4:	f8755800 	ldr	x0, [x0, w21, uxtw #3]
  4007b8:	940000be 	bl	400ab0 <free>
  4007bc:	f940f683 	ldr	x3, [x20, #488]
  4007c0:	f94006c4 	ldr	x4, [x22, #8]
  4007c4:	eb03027f 	cmp	x19, x3
  4007c8:	54000122 	b.cs	4007ec <unsetenv+0xbc>  // b.hs, b.nlast
  4007cc:	91002080 	add	x0, x4, #0x8
  4007d0:	8b030c82 	add	x2, x4, x3, lsl #3
  4007d4:	8b354c00 	add	x0, x0, w21, uxtw #3
  4007d8:	f9400001 	ldr	x1, [x0]
  4007dc:	91002000 	add	x0, x0, #0x8
  4007e0:	f81f0001 	stur	x1, [x0, #-16]
  4007e4:	eb02001f 	cmp	x0, x2
  4007e8:	54ffff81 	b.ne	4007d8 <unsetenv+0xa8>  // b.any
  4007ec:	d1000463 	sub	x3, x3, #0x1
  4007f0:	f900f683 	str	x3, [x20, #488]
  4007f4:	b4fffca4 	cbz	x4, 400788 <unsetenv+0x58>
  4007f8:	f823789f 	str	xzr, [x4, x3, lsl #3]
  4007fc:	17ffffe3 	b	400788 <unsetenv+0x58>
  400800:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400804:	940000e7 	bl	400ba0 <__errno_location@GLIBC_2.2.5>
  400808:	528002c1 	mov	w1, #0x16                  	// #22
  40080c:	b9000001 	str	w1, [x0]
  400810:	12800000 	mov	w0, #0xffffffff            	// #-1
  400814:	17ffffe3 	b	4007a0 <unsetenv+0x70>
  400818:	d503201f 	nop
  40081c:	d503201f 	nop

0000000000400820 <clearenv>:
  400820:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400824:	910003fd 	mov	x29, sp
  400828:	a90153f3 	stp	x19, x20, [sp, #16]
  40082c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400830:	b0000016 	adrp	x22, 401000 <strtol+0x120>
  400834:	9107a2d3 	add	x19, x22, #0x1e8
  400838:	91004273 	add	x19, x19, #0x10
  40083c:	d503201f 	nop
  400840:	aa1303e1 	mov	x1, x19
  400844:	52800020 	mov	w0, #0x1                   	// #1
  400848:	94000246 	bl	401160 <__aarch64_swp1_acq>
  40084c:	3707ffa0 	tbnz	w0, #0, 400840 <clearenv+0x20>
  400850:	f940f6c0 	ldr	x0, [x22, #488]
  400854:	b40001a0 	cbz	x0, 400888 <clearenv+0x68>
  400858:	9107a2d5 	add	x21, x22, #0x1e8
  40085c:	d2800014 	mov	x20, #0x0                   	// #0
  400860:	d2800013 	mov	x19, #0x0                   	// #0
  400864:	d503201f 	nop
  400868:	f94006a0 	ldr	x0, [x21, #8]
  40086c:	91000673 	add	x19, x19, #0x1
  400870:	f8746800 	ldr	x0, [x0, x20]
  400874:	91002294 	add	x20, x20, #0x8
  400878:	9400008e 	bl	400ab0 <free>
  40087c:	f94002a0 	ldr	x0, [x21]
  400880:	eb13001f 	cmp	x0, x19
  400884:	54ffff28 	b.hi	400868 <clearenv+0x48>  // b.pmore
  400888:	9107a2d3 	add	x19, x22, #0x1e8
  40088c:	f9400660 	ldr	x0, [x19, #8]
  400890:	94000088 	bl	400ab0 <free>
  400894:	f900f6df 	str	xzr, [x22, #488]
  400898:	b0000000 	adrp	x0, 401000 <strtol+0x120>
  40089c:	f940e400 	ldr	x0, [x0, #456]
  4008a0:	f900067f 	str	xzr, [x19, #8]
  4008a4:	f9000e7f 	str	xzr, [x19, #24]
  4008a8:	f900001f 	str	xzr, [x0]
  4008ac:	91004273 	add	x19, x19, #0x10
  4008b0:	089ffe7f 	stlrb	wzr, [x19]
  4008b4:	52800000 	mov	w0, #0x0                   	// #0
  4008b8:	a94153f3 	ldp	x19, x20, [sp, #16]
  4008bc:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4008c0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4008c4:	d65f03c0 	ret
	...

00000000004008d0 <insert_free_block>:
  4008d0:	52800021 	mov	w1, #0x1                   	// #1
  4008d4:	39002001 	strb	w1, [x0, #8]
  4008d8:	b0000001 	adrp	x1, 401000 <strtol+0x120>
  4008dc:	f9410822 	ldr	x2, [x1, #528]
  4008e0:	f100005f 	cmp	x2, #0x0
  4008e4:	fa401042 	ccmp	x2, x0, #0x2, ne	// ne = any
  4008e8:	540002a9 	b.ls	40093c <insert_free_block+0x6c>  // b.plast
  4008ec:	f9010820 	str	x0, [x1, #528]
  4008f0:	f9000802 	str	x2, [x0, #16]
  4008f4:	14000006 	b	40090c <insert_free_block+0x3c>
  4008f8:	f9400043 	ldr	x3, [x2]
  4008fc:	8b030041 	add	x1, x2, x3
  400900:	91006021 	add	x1, x1, #0x18
  400904:	eb01001f 	cmp	x0, x1
  400908:	540000a0 	b.eq	40091c <insert_free_block+0x4c>  // b.none
  40090c:	aa0003e2 	mov	x2, x0
  400910:	f9400800 	ldr	x0, [x0, #16]
  400914:	b5ffff20 	cbnz	x0, 4008f8 <insert_free_block+0x28>
  400918:	d65f03c0 	ret
  40091c:	f9400001 	ldr	x1, [x0]
  400920:	91006063 	add	x3, x3, #0x18
  400924:	f9400800 	ldr	x0, [x0, #16]
  400928:	8b010063 	add	x3, x3, x1
  40092c:	f9000043 	str	x3, [x2]
  400930:	f9000840 	str	x0, [x2, #16]
  400934:	aa0203e0 	mov	x0, x2
  400938:	17fffff5 	b	40090c <insert_free_block+0x3c>
  40093c:	aa0203e1 	mov	x1, x2
  400940:	14000003 	b	40094c <insert_free_block+0x7c>
  400944:	eb00003f 	cmp	x1, x0
  400948:	54000082 	b.cs	400958 <insert_free_block+0x88>  // b.hs, b.nlast
  40094c:	aa0103e3 	mov	x3, x1
  400950:	f9400821 	ldr	x1, [x1, #16]
  400954:	b5ffff81 	cbnz	x1, 400944 <insert_free_block+0x74>
  400958:	f9000801 	str	x1, [x0, #16]
  40095c:	f9000860 	str	x0, [x3, #16]
  400960:	aa0203e0 	mov	x0, x2
  400964:	17ffffea 	b	40090c <insert_free_block+0x3c>
  400968:	d503201f 	nop
  40096c:	d503201f 	nop

0000000000400970 <malloc>:
  400970:	b4000640 	cbz	x0, 400a38 <malloc+0xc8>
  400974:	91003c00 	add	x0, x0, #0xf
  400978:	927c6c02 	and	x2, x0, #0xfffffff0
  40097c:	b0000005 	adrp	x5, 401000 <strtol+0x120>
  400980:	f94108a0 	ldr	x0, [x5, #528]
  400984:	b4000180 	cbz	x0, 4009b4 <malloc+0x44>
  400988:	d2800003 	mov	x3, #0x0                   	// #0
  40098c:	14000002 	b	400994 <malloc+0x24>
  400990:	aa0103e0 	mov	x0, x1
  400994:	39402001 	ldrb	w1, [x0, #8]
  400998:	36000081 	tbz	w1, #0, 4009a8 <malloc+0x38>
  40099c:	f9400001 	ldr	x1, [x0]
  4009a0:	eb01005f 	cmp	x2, x1
  4009a4:	540004e9 	b.ls	400a40 <malloc+0xd0>  // b.plast
  4009a8:	f9400801 	ldr	x1, [x0, #16]
  4009ac:	aa0003e3 	mov	x3, x0
  4009b0:	b5ffff01 	cbnz	x1, 400990 <malloc+0x20>
  4009b4:	d2800188 	mov	x8, #0xc                   	// #12
  4009b8:	d2800000 	mov	x0, #0x0                   	// #0
  4009bc:	d4000001 	svc	#0x0
  4009c0:	aa0003e4 	mov	x4, x0
  4009c4:	b7f803a0 	tbnz	x0, #63, 400a38 <malloc+0xc8>
  4009c8:	91009c41 	add	x1, x2, #0x27
  4009cc:	927c6c21 	and	x1, x1, #0xfffffff0
  4009d0:	8b000023 	add	x3, x1, x0
  4009d4:	aa0303e0 	mov	x0, x3
  4009d8:	d4000001 	svc	#0x0
  4009dc:	eb00007f 	cmp	x3, x0
  4009e0:	540002cc 	b.gt	400a38 <malloc+0xc8>
  4009e4:	d1006021 	sub	x1, x1, #0x18
  4009e8:	f9000081 	str	x1, [x4]
  4009ec:	cb020021 	sub	x1, x1, x2
  4009f0:	3900209f 	strb	wzr, [x4, #8]
  4009f4:	f900089f 	str	xzr, [x4, #16]
  4009f8:	f100603f 	cmp	x1, #0x18
  4009fc:	54000569 	b.ls	400aa8 <malloc+0x138>  // b.plast
  400a00:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  400a04:	91006043 	add	x3, x2, #0x18
  400a08:	8b030080 	add	x0, x4, x3
  400a0c:	910003fd 	mov	x29, sp
  400a10:	d1006021 	sub	x1, x1, #0x18
  400a14:	f8236881 	str	x1, [x4, x3]
  400a18:	f900081f 	str	xzr, [x0, #16]
  400a1c:	f9000082 	str	x2, [x4]
  400a20:	f9000880 	str	x0, [x4, #16]
  400a24:	97ffffab 	bl	4008d0 <insert_free_block>
  400a28:	a8c17bfd 	ldp	x29, x30, [sp], #16
  400a2c:	91006080 	add	x0, x4, #0x18
  400a30:	f900089f 	str	xzr, [x4, #16]
  400a34:	d65f03c0 	ret
  400a38:	d2800000 	mov	x0, #0x0                   	// #0
  400a3c:	d65f03c0 	ret
  400a40:	cb020021 	sub	x1, x1, x2
  400a44:	f9400807 	ldr	x7, [x0, #16]
  400a48:	f100603f 	cmp	x1, #0x18
  400a4c:	540002a9 	b.ls	400aa0 <malloc+0x130>  // b.plast
  400a50:	91006046 	add	x6, x2, #0x18
  400a54:	d1006021 	sub	x1, x1, #0x18
  400a58:	8b060004 	add	x4, x0, x6
  400a5c:	f8266801 	str	x1, [x0, x6]
  400a60:	52800021 	mov	w1, #0x1                   	// #1
  400a64:	39002081 	strb	w1, [x4, #8]
  400a68:	f9000887 	str	x7, [x4, #16]
  400a6c:	f9000002 	str	x2, [x0]
  400a70:	f9000804 	str	x4, [x0, #16]
  400a74:	b40000c3 	cbz	x3, 400a8c <malloc+0x11c>
  400a78:	f9000864 	str	x4, [x3, #16]
  400a7c:	91006000 	add	x0, x0, #0x18
  400a80:	381f001f 	sturb	wzr, [x0, #-16]
  400a84:	f81f801f 	stur	xzr, [x0, #-8]
  400a88:	d65f03c0 	ret
  400a8c:	91006000 	add	x0, x0, #0x18
  400a90:	f90108a4 	str	x4, [x5, #528]
  400a94:	381f001f 	sturb	wzr, [x0, #-16]
  400a98:	f81f801f 	stur	xzr, [x0, #-8]
  400a9c:	d65f03c0 	ret
  400aa0:	aa0703e4 	mov	x4, x7
  400aa4:	17fffff4 	b	400a74 <malloc+0x104>
  400aa8:	91006080 	add	x0, x4, #0x18
  400aac:	d65f03c0 	ret

0000000000400ab0 <free>:
  400ab0:	b4000060 	cbz	x0, 400abc <free+0xc>
  400ab4:	d1006000 	sub	x0, x0, #0x18
  400ab8:	17ffff86 	b	4008d0 <insert_free_block>
  400abc:	d65f03c0 	ret

0000000000400ac0 <calloc>:
  400ac0:	9b017c02 	mul	x2, x0, x1
  400ac4:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400ac8:	910003fd 	mov	x29, sp
  400acc:	aa0203e0 	mov	x0, x2
  400ad0:	f9000be2 	str	x2, [sp, #16]
  400ad4:	97ffffa7 	bl	400970 <malloc>
  400ad8:	aa0003e3 	mov	x3, x0
  400adc:	b40000c0 	cbz	x0, 400af4 <calloc+0x34>
  400ae0:	f9400be2 	ldr	x2, [sp, #16]
  400ae4:	52800001 	mov	w1, #0x0                   	// #0
  400ae8:	f9000fe0 	str	x0, [sp, #24]
  400aec:	9400016d 	bl	4010a0 <memset>
  400af0:	f9400fe3 	ldr	x3, [sp, #24]
  400af4:	aa0303e0 	mov	x0, x3
  400af8:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400afc:	d65f03c0 	ret

0000000000400b00 <realloc>:
  400b00:	b40003e0 	cbz	x0, 400b7c <realloc+0x7c>
  400b04:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400b08:	910003fd 	mov	x29, sp
  400b0c:	b40003c1 	cbz	x1, 400b84 <realloc+0x84>
  400b10:	aa0003e3 	mov	x3, x0
  400b14:	aa0003e4 	mov	x4, x0
  400b18:	f85e8000 	ldur	x0, [x0, #-24]
  400b1c:	eb01001f 	cmp	x0, x1
  400b20:	54000083 	b.cc	400b30 <realloc+0x30>  // b.lo, b.ul, b.last
  400b24:	aa0403e0 	mov	x0, x4
  400b28:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400b2c:	d65f03c0 	ret
  400b30:	aa0103e0 	mov	x0, x1
  400b34:	a9018fe1 	stp	x1, x3, [sp, #24]
  400b38:	97ffff8e 	bl	400970 <malloc>
  400b3c:	aa0003e4 	mov	x4, x0
  400b40:	b4ffff20 	cbz	x0, 400b24 <realloc+0x24>
  400b44:	a9418fe1 	ldp	x1, x3, [sp, #24]
  400b48:	f9000fe3 	str	x3, [sp, #24]
  400b4c:	f90017e0 	str	x0, [sp, #40]
  400b50:	f85e8062 	ldur	x2, [x3, #-24]
  400b54:	eb01005f 	cmp	x2, x1
  400b58:	9a819042 	csel	x2, x2, x1, ls	// ls = plast
  400b5c:	aa0303e1 	mov	x1, x3
  400b60:	94000140 	bl	401060 <memcpy>
  400b64:	f9400fe0 	ldr	x0, [sp, #24]
  400b68:	97ffffd2 	bl	400ab0 <free>
  400b6c:	f94017e4 	ldr	x4, [sp, #40]
  400b70:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400b74:	aa0403e0 	mov	x0, x4
  400b78:	d65f03c0 	ret
  400b7c:	aa0103e0 	mov	x0, x1
  400b80:	17ffff7c 	b	400970 <malloc>
  400b84:	97ffffcb 	bl	400ab0 <free>
  400b88:	d2800004 	mov	x4, #0x0                   	// #0
  400b8c:	17ffffe6 	b	400b24 <realloc+0x24>

0000000000400b90 <heap_stats>:
  400b90:	d65f03c0 	ret
	...

0000000000400ba0 <__errno_location@GLIBC_2.2.5>:
  400ba0:	b0000000 	adrp	x0, 401000 <strtol+0x120>
  400ba4:	91086000 	add	x0, x0, #0x218
  400ba8:	d65f03c0 	ret
  400bac:	00000000 	udf	#0

0000000000400bb0 <strlen>:
  400bb0:	aa0003e2 	mov	x2, x0
  400bb4:	b4000120 	cbz	x0, 400bd8 <strlen+0x28>
  400bb8:	39400000 	ldrb	w0, [x0]
  400bbc:	340000e0 	cbz	w0, 400bd8 <strlen+0x28>
  400bc0:	d2800000 	mov	x0, #0x0                   	// #0
  400bc4:	d503201f 	nop
  400bc8:	91000400 	add	x0, x0, #0x1
  400bcc:	38606841 	ldrb	w1, [x2, x0]
  400bd0:	35ffffc1 	cbnz	w1, 400bc8 <strlen+0x18>
  400bd4:	d65f03c0 	ret
  400bd8:	d2800000 	mov	x0, #0x0                   	// #0
  400bdc:	d65f03c0 	ret

0000000000400be0 <strncpy>:
  400be0:	f100001f 	cmp	x0, #0x0
  400be4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400be8:	54000220 	b.eq	400c2c <strncpy+0x4c>  // b.none
  400bec:	d2800003 	mov	x3, #0x0                   	// #0
  400bf0:	b50000c2 	cbnz	x2, 400c08 <strncpy+0x28>
  400bf4:	1400000e 	b	400c2c <strncpy+0x4c>
  400bf8:	38236804 	strb	w4, [x0, x3]
  400bfc:	91000463 	add	x3, x3, #0x1
  400c00:	eb03005f 	cmp	x2, x3
  400c04:	54000140 	b.eq	400c2c <strncpy+0x4c>  // b.none
  400c08:	38636824 	ldrb	w4, [x1, x3]
  400c0c:	35ffff64 	cbnz	w4, 400bf8 <strncpy+0x18>
  400c10:	eb03005f 	cmp	x2, x3
  400c14:	540000c9 	b.ls	400c2c <strncpy+0x4c>  // b.plast
  400c18:	8b030003 	add	x3, x0, x3
  400c1c:	8b020002 	add	x2, x0, x2
  400c20:	3800147f 	strb	wzr, [x3], #1
  400c24:	eb02007f 	cmp	x3, x2
  400c28:	54ffffc1 	b.ne	400c20 <strncpy+0x40>  // b.any
  400c2c:	d65f03c0 	ret

0000000000400c30 <strcpy>:
  400c30:	f100001f 	cmp	x0, #0x0
  400c34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c38:	54000140 	b.eq	400c60 <strcpy+0x30>  // b.none
  400c3c:	39400023 	ldrb	w3, [x1]
  400c40:	34000123 	cbz	w3, 400c64 <strcpy+0x34>
  400c44:	d2800002 	mov	x2, #0x0                   	// #0
  400c48:	38226803 	strb	w3, [x0, x2]
  400c4c:	91000442 	add	x2, x2, #0x1
  400c50:	38626823 	ldrb	w3, [x1, x2]
  400c54:	35ffffa3 	cbnz	w3, 400c48 <strcpy+0x18>
  400c58:	8b020002 	add	x2, x0, x2
  400c5c:	3900005f 	strb	wzr, [x2]
  400c60:	d65f03c0 	ret
  400c64:	aa0003e2 	mov	x2, x0
  400c68:	3900005f 	strb	wzr, [x2]
  400c6c:	17fffffd 	b	400c60 <strcpy+0x30>

0000000000400c70 <strcmp>:
  400c70:	f100001f 	cmp	x0, #0x0
  400c74:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400c78:	540001a0 	b.eq	400cac <strcmp+0x3c>  // b.none
  400c7c:	39400002 	ldrb	w2, [x0]
  400c80:	350000a2 	cbnz	w2, 400c94 <strcmp+0x24>
  400c84:	1400000f 	b	400cc0 <strcmp+0x50>
  400c88:	38401c02 	ldrb	w2, [x0, #1]!
  400c8c:	34000142 	cbz	w2, 400cb4 <strcmp+0x44>
  400c90:	91000421 	add	x1, x1, #0x1
  400c94:	39400023 	ldrb	w3, [x1]
  400c98:	7100007f 	cmp	w3, #0x0
  400c9c:	7a421060 	ccmp	w3, w2, #0x0, ne	// ne = any
  400ca0:	54ffff40 	b.eq	400c88 <strcmp+0x18>  // b.none
  400ca4:	4b030040 	sub	w0, w2, w3
  400ca8:	d65f03c0 	ret
  400cac:	52800000 	mov	w0, #0x0                   	// #0
  400cb0:	d65f03c0 	ret
  400cb4:	39400423 	ldrb	w3, [x1, #1]
  400cb8:	4b030040 	sub	w0, w2, w3
  400cbc:	17fffffb 	b	400ca8 <strcmp+0x38>
  400cc0:	39400023 	ldrb	w3, [x1]
  400cc4:	4b030040 	sub	w0, w2, w3
  400cc8:	17fffff8 	b	400ca8 <strcmp+0x38>
  400ccc:	d503201f 	nop

0000000000400cd0 <strncmp>:
  400cd0:	f100003f 	cmp	x1, #0x0
  400cd4:	d2800003 	mov	x3, #0x0                   	// #0
  400cd8:	fa401844 	ccmp	x2, #0x0, #0x4, ne	// ne = any
  400cdc:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
  400ce0:	54000081 	b.ne	400cf0 <strncmp+0x20>  // b.any
  400ce4:	52800004 	mov	w4, #0x0                   	// #0
  400ce8:	2a0403e0 	mov	w0, w4
  400cec:	d65f03c0 	ret
  400cf0:	38636804 	ldrb	w4, [x0, x3]
  400cf4:	34000104 	cbz	w4, 400d14 <strncmp+0x44>
  400cf8:	38636825 	ldrb	w5, [x1, x3]
  400cfc:	340000c5 	cbz	w5, 400d14 <strncmp+0x44>
  400d00:	6b05009f 	cmp	w4, w5
  400d04:	54000181 	b.ne	400d34 <strncmp+0x64>  // b.any
  400d08:	91000463 	add	x3, x3, #0x1
  400d0c:	eb03005f 	cmp	x2, x3
  400d10:	54ffff08 	b.hi	400cf0 <strncmp+0x20>  // b.pmore
  400d14:	52800004 	mov	w4, #0x0                   	// #0
  400d18:	eb02007f 	cmp	x3, x2
  400d1c:	54fffe60 	b.eq	400ce8 <strncmp+0x18>  // b.none
  400d20:	38636804 	ldrb	w4, [x0, x3]
  400d24:	38636820 	ldrb	w0, [x1, x3]
  400d28:	4b000084 	sub	w4, w4, w0
  400d2c:	2a0403e0 	mov	w0, w4
  400d30:	d65f03c0 	ret
  400d34:	4b050084 	sub	w4, w4, w5
  400d38:	2a0403e0 	mov	w0, w4
  400d3c:	d65f03c0 	ret

0000000000400d40 <strcat>:
  400d40:	f100001f 	cmp	x0, #0x0
  400d44:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d48:	54000041 	b.ne	400d50 <strcat+0x10>  // b.any
  400d4c:	d65f03c0 	ret
  400d50:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400d54:	910003fd 	mov	x29, sp
  400d58:	a90107e0 	stp	x0, x1, [sp, #16]
  400d5c:	97ffff95 	bl	400bb0 <strlen>
  400d60:	a94107e3 	ldp	x3, x1, [sp, #16]
  400d64:	39400022 	ldrb	w2, [x1]
  400d68:	8b000060 	add	x0, x3, x0
  400d6c:	34000082 	cbz	w2, 400d7c <strcat+0x3c>
  400d70:	38001402 	strb	w2, [x0], #1
  400d74:	38401c22 	ldrb	w2, [x1, #1]!
  400d78:	35ffffc2 	cbnz	w2, 400d70 <strcat+0x30>
  400d7c:	3900001f 	strb	wzr, [x0]
  400d80:	aa0303e0 	mov	x0, x3
  400d84:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400d88:	d65f03c0 	ret
  400d8c:	d503201f 	nop

0000000000400d90 <strchr>:
  400d90:	b4000120 	cbz	x0, 400db4 <strchr+0x24>
  400d94:	39400002 	ldrb	w2, [x0]
  400d98:	12001c21 	and	w1, w1, #0xff
  400d9c:	35000082 	cbnz	w2, 400dac <strchr+0x1c>
  400da0:	14000006 	b	400db8 <strchr+0x28>
  400da4:	38401c02 	ldrb	w2, [x0, #1]!
  400da8:	34000082 	cbz	w2, 400db8 <strchr+0x28>
  400dac:	6b01005f 	cmp	w2, w1
  400db0:	54ffffa1 	b.ne	400da4 <strchr+0x14>  // b.any
  400db4:	d65f03c0 	ret
  400db8:	7100003f 	cmp	w1, #0x0
  400dbc:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
  400dc0:	d65f03c0 	ret
  400dc4:	d503201f 	nop
  400dc8:	d503201f 	nop
  400dcc:	d503201f 	nop

0000000000400dd0 <strdup>:
  400dd0:	b4000300 	cbz	x0, 400e30 <strdup+0x60>
  400dd4:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400dd8:	910003fd 	mov	x29, sp
  400ddc:	f9000fe0 	str	x0, [sp, #24]
  400de0:	97ffff74 	bl	400bb0 <strlen>
  400de4:	91000403 	add	x3, x0, #0x1
  400de8:	f9000be3 	str	x3, [sp, #16]
  400dec:	aa0303e0 	mov	x0, x3
  400df0:	97fffee0 	bl	400970 <malloc>
  400df4:	b4000180 	cbz	x0, 400e24 <strdup+0x54>
  400df8:	a94113e3 	ldp	x3, x4, [sp, #16]
  400dfc:	d2800001 	mov	x1, #0x0                   	// #0
  400e00:	b40000e3 	cbz	x3, 400e1c <strdup+0x4c>
  400e04:	d503201f 	nop
  400e08:	38616882 	ldrb	w2, [x4, x1]
  400e0c:	38216802 	strb	w2, [x0, x1]
  400e10:	91000421 	add	x1, x1, #0x1
  400e14:	eb01007f 	cmp	x3, x1
  400e18:	54ffff81 	b.ne	400e08 <strdup+0x38>  // b.any
  400e1c:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400e20:	d65f03c0 	ret
  400e24:	d2800000 	mov	x0, #0x0                   	// #0
  400e28:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400e2c:	d65f03c0 	ret
  400e30:	d2800000 	mov	x0, #0x0                   	// #0
  400e34:	d65f03c0 	ret
  400e38:	d503201f 	nop
  400e3c:	d503201f 	nop

0000000000400e40 <strstr>:
  400e40:	f100001f 	cmp	x0, #0x0
  400e44:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400e48:	54000480 	b.eq	400ed8 <strstr+0x98>  // b.none
  400e4c:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400e50:	910003fd 	mov	x29, sp
  400e54:	a90153f3 	stp	x19, x20, [sp, #16]
  400e58:	aa0003f3 	mov	x19, x0
  400e5c:	39400022 	ldrb	w2, [x1]
  400e60:	35000082 	cbnz	w2, 400e70 <strstr+0x30>
  400e64:	a94153f3 	ldp	x19, x20, [sp, #16]
  400e68:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400e6c:	d65f03c0 	ret
  400e70:	aa0103f4 	mov	x20, x1
  400e74:	aa0103e0 	mov	x0, x1
  400e78:	f90013f5 	str	x21, [sp, #32]
  400e7c:	97ffff4d 	bl	400bb0 <strlen>
  400e80:	39400262 	ldrb	w2, [x19]
  400e84:	aa0003f5 	mov	x21, x0
  400e88:	35000082 	cbnz	w2, 400e98 <strstr+0x58>
  400e8c:	1400000e 	b	400ec4 <strstr+0x84>
  400e90:	38401e62 	ldrb	w2, [x19, #1]!
  400e94:	34000182 	cbz	w2, 400ec4 <strstr+0x84>
  400e98:	39400280 	ldrb	w0, [x20]
  400e9c:	6b02001f 	cmp	w0, w2
  400ea0:	54ffff81 	b.ne	400e90 <strstr+0x50>  // b.any
  400ea4:	aa1503e2 	mov	x2, x21
  400ea8:	aa1403e1 	mov	x1, x20
  400eac:	aa1303e0 	mov	x0, x19
  400eb0:	97ffff88 	bl	400cd0 <strncmp>
  400eb4:	35fffee0 	cbnz	w0, 400e90 <strstr+0x50>
  400eb8:	f94013f5 	ldr	x21, [sp, #32]
  400ebc:	aa1303e0 	mov	x0, x19
  400ec0:	17ffffe9 	b	400e64 <strstr+0x24>
  400ec4:	f94013f5 	ldr	x21, [sp, #32]
  400ec8:	d2800000 	mov	x0, #0x0                   	// #0
  400ecc:	a94153f3 	ldp	x19, x20, [sp, #16]
  400ed0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400ed4:	d65f03c0 	ret
  400ed8:	d2800000 	mov	x0, #0x0                   	// #0
  400edc:	d65f03c0 	ret

0000000000400ee0 <strtol>:
  400ee0:	aa0003e5 	mov	x5, x0
  400ee4:	b40009e0 	cbz	x0, 401020 <strtol+0x140>
  400ee8:	39400004 	ldrb	w4, [x0]
  400eec:	51002480 	sub	w0, w4, #0x9
  400ef0:	7100809f 	cmp	w4, #0x20
  400ef4:	12001c00 	and	w0, w0, #0xff
  400ef8:	7a441800 	ccmp	w0, #0x4, #0x0, ne	// ne = any
  400efc:	540000e8 	b.hi	400f18 <strtol+0x38>  // b.pmore
  400f00:	38401ca4 	ldrb	w4, [x5, #1]!
  400f04:	51002483 	sub	w3, w4, #0x9
  400f08:	7100809f 	cmp	w4, #0x20
  400f0c:	12001c63 	and	w3, w3, #0xff
  400f10:	7a441860 	ccmp	w3, #0x4, #0x0, ne	// ne = any
  400f14:	54ffff69 	b.ls	400f00 <strtol+0x20>  // b.plast
  400f18:	7100ac9f 	cmp	w4, #0x2b
  400f1c:	540006a0 	b.eq	400ff0 <strtol+0x110>  // b.none
  400f20:	7100b49f 	cmp	w4, #0x2d
  400f24:	d2800028 	mov	x8, #0x1                   	// #1
  400f28:	9a8514a5 	cinc	x5, x5, eq	// eq = none
  400f2c:	da9f1108 	csinv	x8, x8, xzr, ne	// ne = any
  400f30:	394000a3 	ldrb	w3, [x5]
  400f34:	35000462 	cbnz	w2, 400fc0 <strtol+0xe0>
  400f38:	52800142 	mov	w2, #0xa                   	// #10
  400f3c:	7100c07f 	cmp	w3, #0x30
  400f40:	540005e0 	b.eq	400ffc <strtol+0x11c>  // b.none
  400f44:	340007c3 	cbz	w3, 40103c <strtol+0x15c>
  400f48:	93407c47 	sxtw	x7, w2
  400f4c:	d2800004 	mov	x4, #0x0                   	// #0
  400f50:	14000008 	b	400f70 <strtol+0x90>
  400f54:	51015c60 	sub	w0, w3, #0x57
  400f58:	6b02001f 	cmp	w0, w2
  400f5c:	540002aa 	b.ge	400fb0 <strtol+0xd0>  // b.tcont
  400f60:	38401ca3 	ldrb	w3, [x5, #1]!
  400f64:	93407c00 	sxtw	x0, w0
  400f68:	9b0400e4 	madd	x4, x7, x4, x0
  400f6c:	34000223 	cbz	w3, 400fb0 <strtol+0xd0>
  400f70:	5100c060 	sub	w0, w3, #0x30
  400f74:	12001c06 	and	w6, w0, #0xff
  400f78:	710024df 	cmp	w6, #0x9
  400f7c:	54fffee9 	b.ls	400f58 <strtol+0x78>  // b.plast
  400f80:	51018460 	sub	w0, w3, #0x61
  400f84:	12001c00 	and	w0, w0, #0xff
  400f88:	7100641f 	cmp	w0, #0x19
  400f8c:	54fffe49 	b.ls	400f54 <strtol+0x74>  // b.plast
  400f90:	51010460 	sub	w0, w3, #0x41
  400f94:	12001c00 	and	w0, w0, #0xff
  400f98:	7100641f 	cmp	w0, #0x19
  400f9c:	540000a8 	b.hi	400fb0 <strtol+0xd0>  // b.pmore
  400fa0:	5100dc60 	sub	w0, w3, #0x37
  400fa4:	6b02001f 	cmp	w0, w2
  400fa8:	54fffdcb 	b.lt	400f60 <strtol+0x80>  // b.tstop
  400fac:	d503201f 	nop
  400fb0:	9b047d00 	mul	x0, x8, x4
  400fb4:	b4000041 	cbz	x1, 400fbc <strtol+0xdc>
  400fb8:	f9000025 	str	x5, [x1]
  400fbc:	d65f03c0 	ret
  400fc0:	7100405f 	cmp	w2, #0x10
  400fc4:	54fffc01 	b.ne	400f44 <strtol+0x64>  // b.any
  400fc8:	7100c07f 	cmp	w3, #0x30
  400fcc:	54fffbc1 	b.ne	400f44 <strtol+0x64>  // b.any
  400fd0:	394004a0 	ldrb	w0, [x5, #1]
  400fd4:	121a7800 	and	w0, w0, #0xffffffdf
  400fd8:	12001c00 	and	w0, w0, #0xff
  400fdc:	7101601f 	cmp	w0, #0x58
  400fe0:	54fffb41 	b.ne	400f48 <strtol+0x68>  // b.any
  400fe4:	394008a3 	ldrb	w3, [x5, #2]
  400fe8:	910008a5 	add	x5, x5, #0x2
  400fec:	17ffffd6 	b	400f44 <strtol+0x64>
  400ff0:	910004a5 	add	x5, x5, #0x1
  400ff4:	d2800028 	mov	x8, #0x1                   	// #1
  400ff8:	17ffffce 	b	400f30 <strtol+0x50>
  400ffc:	394004a3 	ldrb	w3, [x5, #1]
  401000:	121a7860 	and	w0, w3, #0xffffffdf
  401004:	12001c00 	and	w0, w0, #0xff
  401008:	7101601f 	cmp	w0, #0x58
  40100c:	54000121 	b.ne	401030 <strtol+0x150>  // b.any
  401010:	394008a3 	ldrb	w3, [x5, #2]
  401014:	52800202 	mov	w2, #0x10                  	// #16
  401018:	910008a5 	add	x5, x5, #0x2
  40101c:	17ffffca 	b	400f44 <strtol+0x64>
  401020:	b4000041 	cbz	x1, 401028 <strtol+0x148>
  401024:	f900003f 	str	xzr, [x1]
  401028:	d2800000 	mov	x0, #0x0                   	// #0
  40102c:	d65f03c0 	ret
  401030:	910004a5 	add	x5, x5, #0x1
  401034:	52800102 	mov	w2, #0x8                   	// #8
  401038:	17ffffc3 	b	400f44 <strtol+0x64>
  40103c:	d2800000 	mov	x0, #0x0                   	// #0
  401040:	17ffffdd 	b	400fb4 <strtol+0xd4>
  401044:	d503201f 	nop
  401048:	d503201f 	nop
  40104c:	d503201f 	nop

0000000000401050 <__isoc23_strtol>:
  401050:	17ffffa4 	b	400ee0 <strtol>
  401054:	d503201f 	nop
  401058:	d503201f 	nop
  40105c:	d503201f 	nop

0000000000401060 <memcpy>:
  401060:	f100001f 	cmp	x0, #0x0
  401064:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401068:	54000120 	b.eq	40108c <memcpy+0x2c>  // b.none
  40106c:	b4000102 	cbz	x2, 40108c <memcpy+0x2c>
  401070:	d2800003 	mov	x3, #0x0                   	// #0
  401074:	d503201f 	nop
  401078:	38636824 	ldrb	w4, [x1, x3]
  40107c:	38236804 	strb	w4, [x0, x3]
  401080:	91000463 	add	x3, x3, #0x1
  401084:	eb03005f 	cmp	x2, x3
  401088:	54ffff81 	b.ne	401078 <memcpy+0x18>  // b.any
  40108c:	d65f03c0 	ret

0000000000401090 <__memcpy_chk>:
  401090:	17fffff4 	b	401060 <memcpy>
  401094:	d503201f 	nop
  401098:	d503201f 	nop
  40109c:	d503201f 	nop

00000000004010a0 <memset>:
  4010a0:	b40000e0 	cbz	x0, 4010bc <memset+0x1c>
  4010a4:	b40000c2 	cbz	x2, 4010bc <memset+0x1c>
  4010a8:	aa0003e3 	mov	x3, x0
  4010ac:	8b020002 	add	x2, x0, x2
  4010b0:	38001461 	strb	w1, [x3], #1
  4010b4:	eb02007f 	cmp	x3, x2
  4010b8:	54ffffc1 	b.ne	4010b0 <memset+0x10>  // b.any
  4010bc:	d65f03c0 	ret

00000000004010c0 <memcmp>:
  4010c0:	f100001f 	cmp	x0, #0x0
  4010c4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4010c8:	540001a0 	b.eq	4010fc <memcmp+0x3c>  // b.none
  4010cc:	b4000182 	cbz	x2, 4010fc <memcmp+0x3c>
  4010d0:	d2800003 	mov	x3, #0x0                   	// #0
  4010d4:	14000004 	b	4010e4 <memcmp+0x24>
  4010d8:	91000463 	add	x3, x3, #0x1
  4010dc:	eb03005f 	cmp	x2, x3
  4010e0:	540000e0 	b.eq	4010fc <memcmp+0x3c>  // b.none
  4010e4:	38636804 	ldrb	w4, [x0, x3]
  4010e8:	38636825 	ldrb	w5, [x1, x3]
  4010ec:	6b05009f 	cmp	w4, w5
  4010f0:	54ffff40 	b.eq	4010d8 <memcmp+0x18>  // b.none
  4010f4:	4b050080 	sub	w0, w4, w5
  4010f8:	d65f03c0 	ret
  4010fc:	52800000 	mov	w0, #0x0                   	// #0
  401100:	d65f03c0 	ret
  401104:	d503201f 	nop
  401108:	d503201f 	nop
  40110c:	d503201f 	nop

0000000000401110 <memmove>:
  401110:	f100001f 	cmp	x0, #0x0
  401114:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401118:	54000160 	b.eq	401144 <memmove+0x34>  // b.none
  40111c:	eb01001f 	cmp	x0, x1
  401120:	54000142 	b.cs	401148 <memmove+0x38>  // b.hs, b.nlast
  401124:	b4000102 	cbz	x2, 401144 <memmove+0x34>
  401128:	d2800003 	mov	x3, #0x0                   	// #0
  40112c:	d503201f 	nop
  401130:	38636824 	ldrb	w4, [x1, x3]
  401134:	38236804 	strb	w4, [x0, x3]
  401138:	91000463 	add	x3, x3, #0x1
  40113c:	eb03005f 	cmp	x2, x3
  401140:	54ffff81 	b.ne	401130 <memmove+0x20>  // b.any
  401144:	d65f03c0 	ret
  401148:	b4ffffe2 	cbz	x2, 401144 <memmove+0x34>
  40114c:	d1000442 	sub	x2, x2, #0x1
  401150:	38626823 	ldrb	w3, [x1, x2]
  401154:	38226803 	strb	w3, [x0, x2]
  401158:	17fffffc 	b	401148 <memmove+0x38>
  40115c:	00000000 	udf	#0

0000000000401160 <__aarch64_swp1_acq>:
  401160:	90000010 	adrp	x16, 401000 <strtol+0x120>
  401164:	39487210 	ldrb	w16, [x16, #540]
  401168:	34000070 	cbz	w16, 401174 <__aarch64_swp1_acq+0x14>
  40116c:	38a08020 	swpab	w0, w0, [x1]
  401170:	d65f03c0 	ret
  401174:	2a0003f0 	mov	w16, w0
  401178:	085ffc20 	ldaxrb	w0, [x1]
  40117c:	08117c30 	stxrb	w17, w16, [x1]
  401180:	35ffffd1 	cbnz	w17, 401178 <__aarch64_swp1_acq+0x18>
  401184:	d65f03c0 	ret
