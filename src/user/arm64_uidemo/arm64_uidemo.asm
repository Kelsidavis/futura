
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
  400024:	9400016f 	bl	4005e0 <__libc_init_environ>
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
  400068:	d10103ff 	sub	sp, sp, #0x40
  40006c:	aa0803e1 	mov	x1, x8
  400070:	f9412400 	ldr	x0, [x0, #584]
  400074:	d2800002 	mov	x2, #0x0                   	// #0
  400078:	d4000001 	svc	#0x0
  40007c:	aa0003e4 	mov	x4, x0
  400080:	b6f80080 	tbz	x0, #63, 400090 <main+0x30>
  400084:	d2800788 	mov	x8, #0x3c                  	// #60
  400088:	d2800020 	mov	x0, #0x1                   	// #1
  40008c:	d4000001 	svc	#0x0
  400090:	93407c84 	sxtw	x4, w4
  400094:	d2800128 	mov	x8, #0x9                   	// #9
  400098:	d2800000 	mov	x0, #0x0                   	// #0
  40009c:	d2a00601 	mov	x1, #0x300000              	// #3145728
  4000a0:	d2800062 	mov	x2, #0x3                   	// #3
  4000a4:	d2800023 	mov	x3, #0x1                   	// #1
  4000a8:	d2800005 	mov	x5, #0x0                   	// #0
  4000ac:	d4000001 	svc	#0x0
  4000b0:	aa0003e1 	mov	x1, x0
  4000b4:	aa0003e3 	mov	x3, x0
  4000b8:	b140041f 	cmn	x0, #0x1, lsl #12
  4000bc:	540000e9 	b.ls	4000d8 <main+0x78>  // b.plast
  4000c0:	aa0203e8 	mov	x8, x2
  4000c4:	aa0403e0 	mov	x0, x4
  4000c8:	d4000001 	svc	#0x0
  4000cc:	d2800788 	mov	x8, #0x3c                  	// #60
  4000d0:	d2800040 	mov	x0, #0x2                   	// #2
  4000d4:	d4000001 	svc	#0x0
  4000d8:	4f0747ff 	movi	v31.4s, #0xff, lsl #16
  4000dc:	914c0025 	add	x5, x1, #0x300, lsl #12
  4000e0:	aa0103e0 	mov	x0, x1
  4000e4:	3c81041f 	str	q31, [x0], #16
  4000e8:	eb0000bf 	cmp	x5, x0
  4000ec:	54ffffc1 	b.ne	4000e4 <main+0x84>  // b.any
  4000f0:	b9400020 	ldr	w0, [x1]
  4000f4:	717fc01f 	cmp	w0, #0xff0, lsl #12
  4000f8:	54000940 	b.eq	400220 <main+0x1c0>  // b.none
  4000fc:	32083fe1 	mov	w1, #0xff0000ff            	// #-16776961
  400100:	6b01001f 	cmp	w0, w1
  400104:	54000800 	b.eq	400204 <main+0x1a4>  // b.none
  400108:	0e040c04 	dup	v4.2s, w0
  40010c:	90000000 	adrp	x0, 400000 <_start>
  400110:	0f0005e3 	movi	v3.2s, #0xf
  400114:	0f00053f 	movi	v31.2s, #0x9
  400118:	fd412c1e 	ldr	d30, [x0, #600]
  40011c:	90000000 	adrp	x0, 400000 <_start>
  400120:	0f01e61c 	movi	v28.8b, #0x30
  400124:	0f01e6fb 	movi	v27.8b, #0x37
  400128:	fd413001 	ldr	d1, [x0, #608]
  40012c:	90000000 	adrp	x0, 400000 <_start>
  400130:	2ebe449e 	ushl	v30.2s, v4.2s, v30.2s
  400134:	1e2603e2 	fmov	w2, s31
  400138:	fd413400 	ldr	d0, [x0, #616]
  40013c:	90000000 	adrp	x0, 400000 <_start>
  400140:	2ea14481 	ushl	v1.2s, v4.2s, v1.2s
  400144:	fd41381a 	ldr	d26, [x0, #624]
  400148:	52800140 	mov	w0, #0xa                   	// #10
  40014c:	2ea04480 	ushl	v0.2s, v4.2s, v0.2s
  400150:	0e231fde 	and	v30.8b, v30.8b, v3.8b
  400154:	390023e0 	strb	w0, [sp, #8]
  400158:	2eba449a 	ushl	v26.2s, v4.2s, v26.2s
  40015c:	0e231c21 	and	v1.8b, v1.8b, v3.8b
  400160:	0e231c00 	and	v0.8b, v0.8b, v3.8b
  400164:	0e231f5a 	and	v26.8b, v26.8b, v3.8b
  400168:	0e411bc2 	uzp1	v2.4h, v30.4h, v1.4h
  40016c:	2ebe3ffe 	cmhs	v30.2s, v31.2s, v30.2s
  400170:	2ea13fe1 	cmhs	v1.2s, v31.2s, v1.2s
  400174:	0e5a181d 	uzp1	v29.4h, v0.4h, v26.4h
  400178:	2ea03fe0 	cmhs	v0.2s, v31.2s, v0.2s
  40017c:	2eba3ffa 	cmhs	v26.2s, v31.2s, v26.2s
  400180:	0e411bc1 	uzp1	v1.4h, v30.4h, v1.4h
  400184:	0e1d185d 	uzp1	v29.8b, v2.8b, v29.8b
  400188:	0e5a181a 	uzp1	v26.4h, v0.4h, v26.4h
  40018c:	0e3c87bc 	add	v28.8b, v29.8b, v28.8b
  400190:	0e3b87bb 	add	v27.8b, v29.8b, v27.8b
  400194:	0e1a183a 	uzp1	v26.8b, v1.8b, v26.8b
  400198:	2eba1f9b 	bit	v27.8b, v28.8b, v26.8b
  40019c:	fd0003fb 	str	d27, [sp]
  4001a0:	d2800028 	mov	x8, #0x1                   	// #1
  4001a4:	910003e1 	mov	x1, sp
  4001a8:	aa0803e0 	mov	x0, x8
  4001ac:	92400c42 	and	x2, x2, #0xf
  4001b0:	d4000001 	svc	#0x0
  4001b4:	6f00041f 	mvni	v31.4s, #0x0
  4001b8:	d503201f 	nop
  4001bc:	d503201f 	nop
  4001c0:	3c81047f 	str	q31, [x3], #16
  4001c4:	eb0300bf 	cmp	x5, x3
  4001c8:	54ffffc1 	b.ne	4001c0 <main+0x160>  // b.any
  4001cc:	d2800208 	mov	x8, #0x10                  	// #16
  4001d0:	aa0403e0 	mov	x0, x4
  4001d4:	d288c061 	mov	x1, #0x4603                	// #17923
  4001d8:	d2800002 	mov	x2, #0x0                   	// #0
  4001dc:	d4000001 	svc	#0x0
  4001e0:	d2800068 	mov	x8, #0x3                   	// #3
  4001e4:	aa0403e0 	mov	x0, x4
  4001e8:	d4000001 	svc	#0x0
  4001ec:	d2800788 	mov	x8, #0x3c                  	// #60
  4001f0:	d2800000 	mov	x0, #0x0                   	// #0
  4001f4:	d4000001 	svc	#0x0
  4001f8:	52800000 	mov	w0, #0x0                   	// #0
  4001fc:	910103ff 	add	sp, sp, #0x40
  400200:	d65f03c0 	ret
  400204:	90000000 	adrp	x0, 400000 <_start>
  400208:	52800102 	mov	w2, #0x8                   	// #8
  40020c:	fd41281f 	ldr	d31, [x0, #592]
  400210:	52814960 	mov	w0, #0xa4b                 	// #2635
  400214:	790013e0 	strh	w0, [sp, #8]
  400218:	fd0003ff 	str	d31, [sp]
  40021c:	17ffffe1 	b	4001a0 <main+0x140>
  400220:	528caa40 	mov	w0, #0x6552                	// #25938
  400224:	528000e2 	mov	w2, #0x7                   	// #7
  400228:	72a40c80 	movk	w0, #0x2064, lsl #16
  40022c:	b90003e0 	str	w0, [sp]
  400230:	528969e0 	mov	w0, #0x4b4f                	// #19279
  400234:	79000be0 	strh	w0, [sp, #4]
  400238:	52800140 	mov	w0, #0xa                   	// #10
  40023c:	39001be0 	strb	w0, [sp, #6]
  400240:	17ffffd8 	b	4001a0 <main+0x140>
  400244:	d503201f 	nop
  400248:	004012d8 	.word	0x004012d8
  40024c:	00000000 	.word	0x00000000
  400250:	42646552 	.word	0x42646552
  400254:	4f205247 	.word	0x4f205247
  400258:	ffffffe4 	.word	0xffffffe4
  40025c:	ffffffe8 	.word	0xffffffe8
  400260:	ffffffec 	.word	0xffffffec
  400264:	fffffff0 	.word	0xfffffff0
  400268:	fffffff4 	.word	0xfffffff4
  40026c:	fffffff8 	.word	0xfffffff8
  400270:	fffffffc 	.word	0xfffffffc
	...

0000000000400280 <find_index>:
  400280:	b0000001 	adrp	x1, 401000 <strstr+0x70>
  400284:	910ce022 	add	x2, x1, #0x338
  400288:	f9419c26 	ldr	x6, [x1, #824]
  40028c:	b4000346 	cbz	x6, 4002f4 <find_index+0x74>
  400290:	f9400448 	ldr	x8, [x2, #8]
  400294:	f100001f 	cmp	x0, #0x0
  400298:	1a9f17e7 	cset	w7, eq	// eq = none
  40029c:	d2800005 	mov	x5, #0x0                   	// #0
  4002a0:	f8657904 	ldr	x4, [x8, x5, lsl #3]
  4002a4:	f100009f 	cmp	x4, #0x0
  4002a8:	7a4018e0 	ccmp	w7, #0x0, #0x0, ne	// ne = any
  4002ac:	540001e1 	b.ne	4002e8 <find_index+0x68>  // b.any
  4002b0:	39400082 	ldrb	w2, [x4]
  4002b4:	d2800001 	mov	x1, #0x0                   	// #0
  4002b8:	350000e2 	cbnz	w2, 4002d4 <find_index+0x54>
  4002bc:	1400000b 	b	4002e8 <find_index+0x68>
  4002c0:	6b02007f 	cmp	w3, w2
  4002c4:	54000121 	b.ne	4002e8 <find_index+0x68>  // b.any
  4002c8:	91000421 	add	x1, x1, #0x1
  4002cc:	38616882 	ldrb	w2, [x4, x1]
  4002d0:	340000c2 	cbz	w2, 4002e8 <find_index+0x68>
  4002d4:	38616803 	ldrb	w3, [x0, x1]
  4002d8:	35ffff43 	cbnz	w3, 4002c0 <find_index+0x40>
  4002dc:	7100f45f 	cmp	w2, #0x3d
  4002e0:	540000e0 	b.eq	4002fc <find_index+0x7c>  // b.none
  4002e4:	d503201f 	nop
  4002e8:	910004a5 	add	x5, x5, #0x1
  4002ec:	eb0600bf 	cmp	x5, x6
  4002f0:	54fffd81 	b.ne	4002a0 <find_index+0x20>  // b.any
  4002f4:	12800000 	mov	w0, #0xffffffff            	// #-1
  4002f8:	d65f03c0 	ret
  4002fc:	2a0503e0 	mov	w0, w5
  400300:	d65f03c0 	ret
  400304:	d503201f 	nop
  400308:	d503201f 	nop
  40030c:	d503201f 	nop

0000000000400310 <set_pair>:
  400310:	a9bb7bfd 	stp	x29, x30, [sp, #-80]!
  400314:	910003fd 	mov	x29, sp
  400318:	b4001320 	cbz	x0, 40057c <set_pair+0x26c>
  40031c:	a90153f3 	stp	x19, x20, [sp, #16]
  400320:	aa0103f4 	mov	x20, x1
  400324:	a9025bf5 	stp	x21, x22, [sp, #32]
  400328:	aa0003f5 	mov	x21, x0
  40032c:	39400001 	ldrb	w1, [x0]
  400330:	34001301 	cbz	w1, 400590 <set_pair+0x280>
  400334:	528007a1 	mov	w1, #0x3d                  	// #61
  400338:	a90363f7 	stp	x23, x24, [sp, #48]
  40033c:	2a0203f8 	mov	w24, w2
  400340:	aa0303f7 	mov	x23, x3
  400344:	940002e7 	bl	400ee0 <strchr>
  400348:	b5001140 	cbnz	x0, 400570 <set_pair+0x260>
  40034c:	f100029f 	cmp	x20, #0x0
  400350:	b0000013 	adrp	x19, 401000 <strstr+0x70>
  400354:	910b8273 	add	x19, x19, #0x2e0
  400358:	aa1503e0 	mov	x0, x21
  40035c:	9a940273 	csel	x19, x19, x20, eq	// eq = none
  400360:	a9046bf9 	stp	x25, x26, [sp, #64]
  400364:	94000267 	bl	400d00 <strlen>
  400368:	aa1703f6 	mov	x22, x23
  40036c:	aa0003f4 	mov	x20, x0
  400370:	aa1303e0 	mov	x0, x19
  400374:	94000263 	bl	400d00 <strlen>
  400378:	aa0003f9 	mov	x25, x0
  40037c:	b4000497 	cbz	x23, 40040c <set_pair+0xfc>
  400380:	b0000014 	adrp	x20, 401000 <strstr+0x70>
  400384:	910ce299 	add	x25, x20, #0x338
  400388:	91004333 	add	x19, x25, #0x10
  40038c:	d503201f 	nop
  400390:	aa1303e1 	mov	x1, x19
  400394:	52800020 	mov	w0, #0x1                   	// #1
  400398:	940003c6 	bl	4012b0 <__aarch64_swp1_acq>
  40039c:	3707ffa0 	tbnz	w0, #0, 400390 <set_pair+0x80>
  4003a0:	aa1503e0 	mov	x0, x21
  4003a4:	97ffffb7 	bl	400280 <find_index>
  4003a8:	2a2003e1 	mvn	w1, w0
  4003ac:	52000318 	eor	w24, w24, #0x1
  4003b0:	6a417f1f 	tst	w24, w1, lsr #31
  4003b4:	540006a1 	b.ne	400488 <set_pair+0x178>  // b.any
  4003b8:	37f804e0 	tbnz	w0, #31, 400454 <set_pair+0x144>
  4003bc:	f9400722 	ldr	x2, [x25, #8]
  4003c0:	d37d7c13 	ubfiz	x19, x0, #3, #32
  4003c4:	8b130041 	add	x1, x2, x19
  4003c8:	f8605840 	ldr	x0, [x2, w0, uxtw #3]
  4003cc:	eb16001f 	cmp	x0, x22
  4003d0:	54000080 	b.eq	4003e0 <set_pair+0xd0>  // b.none
  4003d4:	9400020b 	bl	400c00 <free>
  4003d8:	f9400721 	ldr	x1, [x25, #8]
  4003dc:	8b130021 	add	x1, x1, x19
  4003e0:	f9000036 	str	x22, [x1]
  4003e4:	910ce294 	add	x20, x20, #0x338
  4003e8:	91004294 	add	x20, x20, #0x10
  4003ec:	089ffe9f 	stlrb	wzr, [x20]
  4003f0:	a94153f3 	ldp	x19, x20, [sp, #16]
  4003f4:	52800000 	mov	w0, #0x0                   	// #0
  4003f8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4003fc:	a94363f7 	ldp	x23, x24, [sp, #48]
  400400:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400404:	a8c57bfd 	ldp	x29, x30, [sp], #80
  400408:	d65f03c0 	ret
  40040c:	8b00029a 	add	x26, x20, x0
  400410:	91000b40 	add	x0, x26, #0x2
  400414:	940001ab 	bl	400ac0 <malloc>
  400418:	aa0003f6 	mov	x22, x0
  40041c:	b4000d00 	cbz	x0, 4005bc <set_pair+0x2ac>
  400420:	aa1403e2 	mov	x2, x20
  400424:	aa1503e1 	mov	x1, x21
  400428:	8b1a02da 	add	x26, x22, x26
  40042c:	94000361 	bl	4011b0 <memcpy>
  400430:	528007a0 	mov	w0, #0x3d                  	// #61
  400434:	38346ac0 	strb	w0, [x22, x20]
  400438:	91000680 	add	x0, x20, #0x1
  40043c:	aa1903e2 	mov	x2, x25
  400440:	aa1303e1 	mov	x1, x19
  400444:	8b0002c0 	add	x0, x22, x0
  400448:	9400035a 	bl	4011b0 <memcpy>
  40044c:	3900075f 	strb	wzr, [x26, #1]
  400450:	17ffffcc 	b	400380 <set_pair+0x70>
  400454:	f9419e81 	ldr	x1, [x20, #824]
  400458:	f9400f33 	ldr	x19, [x25, #24]
  40045c:	91000820 	add	x0, x1, #0x2
  400460:	eb13001f 	cmp	x0, x19
  400464:	540001c8 	b.hi	40049c <set_pair+0x18c>  // b.pmore
  400468:	f9400735 	ldr	x21, [x25, #8]
  40046c:	b4000795 	cbz	x21, 40055c <set_pair+0x24c>
  400470:	91000420 	add	x0, x1, #0x1
  400474:	f8217ab6 	str	x22, [x21, x1, lsl #3]
  400478:	8b010ea1 	add	x1, x21, x1, lsl #3
  40047c:	f9019e80 	str	x0, [x20, #824]
  400480:	f900043f 	str	xzr, [x1, #8]
  400484:	17ffffd8 	b	4003e4 <set_pair+0xd4>
  400488:	089ffe7f 	stlrb	wzr, [x19]
  40048c:	b5fffb37 	cbnz	x23, 4003f0 <set_pair+0xe0>
  400490:	aa1603e0 	mov	x0, x22
  400494:	940001db 	bl	400c00 <free>
  400498:	17ffffd6 	b	4003f0 <set_pair+0xe0>
  40049c:	b4000633 	cbz	x19, 400560 <set_pair+0x250>
  4004a0:	8b130273 	add	x19, x19, x19
  4004a4:	eb13001f 	cmp	x0, x19
  4004a8:	54ffffc8 	b.hi	4004a0 <set_pair+0x190>  // b.pmore
  4004ac:	d37df278 	lsl	x24, x19, #3
  4004b0:	aa1803e0 	mov	x0, x24
  4004b4:	94000183 	bl	400ac0 <malloc>
  4004b8:	aa0003f5 	mov	x21, x0
  4004bc:	910ce280 	add	x0, x20, #0x338
  4004c0:	b4000755 	cbz	x21, 4005a8 <set_pair+0x298>
  4004c4:	f9419e82 	ldr	x2, [x20, #824]
  4004c8:	f9400400 	ldr	x0, [x0, #8]
  4004cc:	b4000682 	cbz	x2, 40059c <set_pair+0x28c>
  4004d0:	d2800001 	mov	x1, #0x0                   	// #0
  4004d4:	b4000320 	cbz	x0, 400538 <set_pair+0x228>
  4004d8:	f8617803 	ldr	x3, [x0, x1, lsl #3]
  4004dc:	f8217aa3 	str	x3, [x21, x1, lsl #3]
  4004e0:	91000421 	add	x1, x1, #0x1
  4004e4:	eb01005f 	cmp	x2, x1
  4004e8:	54ffff81 	b.ne	4004d8 <set_pair+0x1c8>  // b.any
  4004ec:	8b020ea1 	add	x1, x21, x2, lsl #3
  4004f0:	91000442 	add	x2, x2, #0x1
  4004f4:	f900003f 	str	xzr, [x1]
  4004f8:	8b150303 	add	x3, x24, x21
  4004fc:	8b020ea1 	add	x1, x21, x2, lsl #3
  400500:	eb02027f 	cmp	x19, x2
  400504:	54000089 	b.ls	400514 <set_pair+0x204>  // b.plast
  400508:	f800843f 	str	xzr, [x1], #8
  40050c:	eb03003f 	cmp	x1, x3
  400510:	54ffffc1 	b.ne	400508 <set_pair+0x1f8>  // b.any
  400514:	940001bb 	bl	400c00 <free>
  400518:	b0000001 	adrp	x1, 401000 <strstr+0x70>
  40051c:	f9418c21 	ldr	x1, [x1, #792]
  400520:	910ce280 	add	x0, x20, #0x338
  400524:	f9000035 	str	x21, [x1]
  400528:	f9419e81 	ldr	x1, [x20, #824]
  40052c:	f9000415 	str	x21, [x0, #8]
  400530:	f9000c13 	str	x19, [x0, #24]
  400534:	17ffffcf 	b	400470 <set_pair+0x160>
  400538:	91000423 	add	x3, x1, #0x1
  40053c:	f8217abf 	str	xzr, [x21, x1, lsl #3]
  400540:	eb03005f 	cmp	x2, x3
  400544:	54fffd40 	b.eq	4004ec <set_pair+0x1dc>  // b.none
  400548:	91000821 	add	x1, x1, #0x2
  40054c:	f8237abf 	str	xzr, [x21, x3, lsl #3]
  400550:	eb01005f 	cmp	x2, x1
  400554:	54ffff21 	b.ne	400538 <set_pair+0x228>  // b.any
  400558:	17ffffe5 	b	4004ec <set_pair+0x1dc>
  40055c:	b5fffa93 	cbnz	x19, 4004ac <set_pair+0x19c>
  400560:	d2800113 	mov	x19, #0x8                   	// #8
  400564:	f100201f 	cmp	x0, #0x8
  400568:	54fff9c8 	b.hi	4004a0 <set_pair+0x190>  // b.pmore
  40056c:	17ffffd0 	b	4004ac <set_pair+0x19c>
  400570:	a94153f3 	ldp	x19, x20, [sp, #16]
  400574:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400578:	a94363f7 	ldp	x23, x24, [sp, #48]
  40057c:	940001dd 	bl	400cf0 <__errno_location@GLIBC_2.2.5>
  400580:	528002c1 	mov	w1, #0x16                  	// #22
  400584:	b9000001 	str	w1, [x0]
  400588:	12800000 	mov	w0, #0xffffffff            	// #-1
  40058c:	17ffff9e 	b	400404 <set_pair+0xf4>
  400590:	a94153f3 	ldp	x19, x20, [sp, #16]
  400594:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400598:	17fffff9 	b	40057c <set_pair+0x26c>
  40059c:	aa1503e1 	mov	x1, x21
  4005a0:	d2800022 	mov	x2, #0x1                   	// #1
  4005a4:	17ffffd4 	b	4004f4 <set_pair+0x1e4>
  4005a8:	91004000 	add	x0, x0, #0x10
  4005ac:	089ffc1f 	stlrb	wzr, [x0]
  4005b0:	b5000077 	cbnz	x23, 4005bc <set_pair+0x2ac>
  4005b4:	aa1603e0 	mov	x0, x22
  4005b8:	94000192 	bl	400c00 <free>
  4005bc:	940001cd 	bl	400cf0 <__errno_location@GLIBC_2.2.5>
  4005c0:	52800181 	mov	w1, #0xc                   	// #12
  4005c4:	b9000001 	str	w1, [x0]
  4005c8:	12800000 	mov	w0, #0xffffffff            	// #-1
  4005cc:	a94153f3 	ldp	x19, x20, [sp, #16]
  4005d0:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4005d4:	a94363f7 	ldp	x23, x24, [sp, #48]
  4005d8:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4005dc:	17ffff8a 	b	400404 <set_pair+0xf4>

00000000004005e0 <__libc_init_environ>:
  4005e0:	a9ba7bfd 	stp	x29, x30, [sp, #-96]!
  4005e4:	910003fd 	mov	x29, sp
  4005e8:	a90363f7 	stp	x23, x24, [sp, #48]
  4005ec:	a90573fb 	stp	x27, x28, [sp, #80]
  4005f0:	b40007e0 	cbz	x0, 4006ec <__libc_init_environ+0x10c>
  4005f4:	f9400001 	ldr	x1, [x0]
  4005f8:	b40007a1 	cbz	x1, 4006ec <__libc_init_environ+0x10c>
  4005fc:	d1002003 	sub	x3, x0, #0x8
  400600:	d2800101 	mov	x1, #0x8                   	// #8
  400604:	d280001c 	mov	x28, #0x0                   	// #0
  400608:	a9025bf5 	stp	x21, x22, [sp, #32]
  40060c:	a9046bf9 	stp	x25, x26, [sp, #64]
  400610:	aa0103f7 	mov	x23, x1
  400614:	91002021 	add	x1, x1, #0x8
  400618:	aa1c03f8 	mov	x24, x28
  40061c:	9100079c 	add	x28, x28, #0x1
  400620:	f8616862 	ldr	x2, [x3, x1]
  400624:	b5ffff62 	cbnz	x2, 400610 <__libc_init_environ+0x30>
  400628:	91000b18 	add	x24, x24, #0x2
  40062c:	b000001b 	adrp	x27, 401000 <strstr+0x70>
  400630:	910ce37a 	add	x26, x27, #0x338
  400634:	aa0003f6 	mov	x22, x0
  400638:	d37df319 	lsl	x25, x24, #3
  40063c:	aa1903e0 	mov	x0, x25
  400640:	94000120 	bl	400ac0 <malloc>
  400644:	f9000740 	str	x0, [x26, #8]
  400648:	b4000600 	cbz	x0, 400708 <__libc_init_environ+0x128>
  40064c:	d1002339 	sub	x25, x25, #0x8
  400650:	a90153f3 	stp	x19, x20, [sp, #16]
  400654:	d2800013 	mov	x19, #0x0                   	// #0
  400658:	14000009 	b	40067c <__libc_init_environ+0x9c>
  40065c:	f8736ac1 	ldr	x1, [x22, x19]
  400660:	aa1503e2 	mov	x2, x21
  400664:	940002d3 	bl	4011b0 <memcpy>
  400668:	f9400740 	ldr	x0, [x26, #8]
  40066c:	f8336814 	str	x20, [x0, x19]
  400670:	91002273 	add	x19, x19, #0x8
  400674:	eb19027f 	cmp	x19, x25
  400678:	540001a0 	b.eq	4006ac <__libc_init_environ+0xcc>  // b.none
  40067c:	f8736ac0 	ldr	x0, [x22, x19]
  400680:	940001a0 	bl	400d00 <strlen>
  400684:	91000415 	add	x21, x0, #0x1
  400688:	aa1503e0 	mov	x0, x21
  40068c:	9400010d 	bl	400ac0 <malloc>
  400690:	aa0003f4 	mov	x20, x0
  400694:	b5fffe40 	cbnz	x0, 40065c <__libc_init_environ+0x7c>
  400698:	f9400740 	ldr	x0, [x26, #8]
  40069c:	f833681f 	str	xzr, [x0, x19]
  4006a0:	91002273 	add	x19, x19, #0x8
  4006a4:	eb19027f 	cmp	x19, x25
  4006a8:	54fffea1 	b.ne	40067c <__libc_init_environ+0x9c>  // b.any
  4006ac:	910ce360 	add	x0, x27, #0x338
  4006b0:	f9400400 	ldr	x0, [x0, #8]
  4006b4:	f837681f 	str	xzr, [x0, x23]
  4006b8:	a94153f3 	ldp	x19, x20, [sp, #16]
  4006bc:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4006c0:	a9446bf9 	ldp	x25, x26, [sp, #64]
  4006c4:	f9019f7c 	str	x28, [x27, #824]
  4006c8:	b0000001 	adrp	x1, 401000 <strstr+0x70>
  4006cc:	f9418c21 	ldr	x1, [x1, #792]
  4006d0:	f9000020 	str	x0, [x1]
  4006d4:	910ce360 	add	x0, x27, #0x338
  4006d8:	f9000c18 	str	x24, [x0, #24]
  4006dc:	a94363f7 	ldp	x23, x24, [sp, #48]
  4006e0:	a94573fb 	ldp	x27, x28, [sp, #80]
  4006e4:	a8c67bfd 	ldp	x29, x30, [sp], #96
  4006e8:	d65f03c0 	ret
  4006ec:	b000001b 	adrp	x27, 401000 <strstr+0x70>
  4006f0:	910ce360 	add	x0, x27, #0x338
  4006f4:	f900041f 	str	xzr, [x0, #8]
  4006f8:	d2800000 	mov	x0, #0x0                   	// #0
  4006fc:	d280001c 	mov	x28, #0x0                   	// #0
  400700:	d2800018 	mov	x24, #0x0                   	// #0
  400704:	17fffff0 	b	4006c4 <__libc_init_environ+0xe4>
  400708:	a9425bf5 	ldp	x21, x22, [sp, #32]
  40070c:	a9446bf9 	ldp	x25, x26, [sp, #64]
  400710:	17fffffa 	b	4006f8 <__libc_init_environ+0x118>
  400714:	d503201f 	nop
  400718:	d503201f 	nop
  40071c:	d503201f 	nop

0000000000400720 <getenv>:
  400720:	b40004a0 	cbz	x0, 4007b4 <getenv+0x94>
  400724:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400728:	910003fd 	mov	x29, sp
  40072c:	a90153f3 	stp	x19, x20, [sp, #16]
  400730:	a9025bf5 	stp	x21, x22, [sp, #32]
  400734:	b0000014 	adrp	x20, 401000 <strstr+0x70>
  400738:	910ce295 	add	x21, x20, #0x338
  40073c:	aa0003f6 	mov	x22, x0
  400740:	910042a1 	add	x1, x21, #0x10
  400744:	52800020 	mov	w0, #0x1                   	// #1
  400748:	940002da 	bl	4012b0 <__aarch64_swp1_acq>
  40074c:	3707ffa0 	tbnz	w0, #0, 400740 <getenv+0x20>
  400750:	aa1603e0 	mov	x0, x22
  400754:	97fffecb 	bl	400280 <find_index>
  400758:	37f801e0 	tbnz	w0, #31, 400794 <getenv+0x74>
  40075c:	f94006a1 	ldr	x1, [x21, #8]
  400760:	f8605820 	ldr	x0, [x1, w0, uxtw #3]
  400764:	b4000180 	cbz	x0, 400794 <getenv+0x74>
  400768:	528007a1 	mov	w1, #0x3d                  	// #61
  40076c:	940001dd 	bl	400ee0 <strchr>
  400770:	b4000120 	cbz	x0, 400794 <getenv+0x74>
  400774:	91000400 	add	x0, x0, #0x1
  400778:	910ce294 	add	x20, x20, #0x338
  40077c:	91004294 	add	x20, x20, #0x10
  400780:	089ffe9f 	stlrb	wzr, [x20]
  400784:	a94153f3 	ldp	x19, x20, [sp, #16]
  400788:	a9425bf5 	ldp	x21, x22, [sp, #32]
  40078c:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400790:	d65f03c0 	ret
  400794:	d2800000 	mov	x0, #0x0                   	// #0
  400798:	910ce294 	add	x20, x20, #0x338
  40079c:	91004294 	add	x20, x20, #0x10
  4007a0:	089ffe9f 	stlrb	wzr, [x20]
  4007a4:	a94153f3 	ldp	x19, x20, [sp, #16]
  4007a8:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4007ac:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4007b0:	d65f03c0 	ret
  4007b4:	d65f03c0 	ret
  4007b8:	d503201f 	nop
  4007bc:	d503201f 	nop

00000000004007c0 <secure_getenv>:
  4007c0:	17ffffd8 	b	400720 <getenv>
  4007c4:	d503201f 	nop
  4007c8:	d503201f 	nop
  4007cc:	d503201f 	nop

00000000004007d0 <__secure_getenv>:
  4007d0:	17fffffc 	b	4007c0 <secure_getenv>
  4007d4:	d503201f 	nop
  4007d8:	d503201f 	nop
  4007dc:	d503201f 	nop

00000000004007e0 <setenv>:
  4007e0:	7100005f 	cmp	w2, #0x0
  4007e4:	d2800003 	mov	x3, #0x0                   	// #0
  4007e8:	1a9f07e2 	cset	w2, ne	// ne = any
  4007ec:	17fffec9 	b	400310 <set_pair>

00000000004007f0 <putenv>:
  4007f0:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  4007f4:	910003fd 	mov	x29, sp
  4007f8:	b4000380 	cbz	x0, 400868 <putenv+0x78>
  4007fc:	528007a1 	mov	w1, #0x3d                  	// #61
  400800:	a90153f3 	stp	x19, x20, [sp, #16]
  400804:	aa0003f4 	mov	x20, x0
  400808:	940001b6 	bl	400ee0 <strchr>
  40080c:	f100001f 	cmp	x0, #0x0
  400810:	aa0003f3 	mov	x19, x0
  400814:	fa401284 	ccmp	x20, x0, #0x4, ne	// ne = any
  400818:	540001c0 	b.eq	400850 <putenv+0x60>  // b.none
  40081c:	aa0003e1 	mov	x1, x0
  400820:	f90013f5 	str	x21, [sp, #32]
  400824:	aa1403e3 	mov	x3, x20
  400828:	aa1403e0 	mov	x0, x20
  40082c:	39400275 	ldrb	w21, [x19]
  400830:	52800022 	mov	w2, #0x1                   	// #1
  400834:	3800143f 	strb	wzr, [x1], #1
  400838:	97fffeb6 	bl	400310 <set_pair>
  40083c:	39000275 	strb	w21, [x19]
  400840:	a94153f3 	ldp	x19, x20, [sp, #16]
  400844:	f94013f5 	ldr	x21, [sp, #32]
  400848:	a8c37bfd 	ldp	x29, x30, [sp], #48
  40084c:	d65f03c0 	ret
  400850:	94000128 	bl	400cf0 <__errno_location@GLIBC_2.2.5>
  400854:	528002c1 	mov	w1, #0x16                  	// #22
  400858:	b9000001 	str	w1, [x0]
  40085c:	12800000 	mov	w0, #0xffffffff            	// #-1
  400860:	a94153f3 	ldp	x19, x20, [sp, #16]
  400864:	17fffff9 	b	400848 <putenv+0x58>
  400868:	94000122 	bl	400cf0 <__errno_location@GLIBC_2.2.5>
  40086c:	528002c1 	mov	w1, #0x16                  	// #22
  400870:	b9000001 	str	w1, [x0]
  400874:	12800000 	mov	w0, #0xffffffff            	// #-1
  400878:	17fffff4 	b	400848 <putenv+0x58>
  40087c:	d503201f 	nop

0000000000400880 <unsetenv>:
  400880:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400884:	910003fd 	mov	x29, sp
  400888:	b4000660 	cbz	x0, 400954 <unsetenv+0xd4>
  40088c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400890:	aa0003f5 	mov	x21, x0
  400894:	39400001 	ldrb	w1, [x0]
  400898:	340005c1 	cbz	w1, 400950 <unsetenv+0xd0>
  40089c:	528007a1 	mov	w1, #0x3d                  	// #61
  4008a0:	94000190 	bl	400ee0 <strchr>
  4008a4:	b5000560 	cbnz	x0, 400950 <unsetenv+0xd0>
  4008a8:	a90153f3 	stp	x19, x20, [sp, #16]
  4008ac:	b0000014 	adrp	x20, 401000 <strstr+0x70>
  4008b0:	910ce296 	add	x22, x20, #0x338
  4008b4:	d503201f 	nop
  4008b8:	910042c1 	add	x1, x22, #0x10
  4008bc:	52800020 	mov	w0, #0x1                   	// #1
  4008c0:	9400027c 	bl	4012b0 <__aarch64_swp1_acq>
  4008c4:	3707ffa0 	tbnz	w0, #0, 4008b8 <unsetenv+0x38>
  4008c8:	aa1503e0 	mov	x0, x21
  4008cc:	97fffe6d 	bl	400280 <find_index>
  4008d0:	2a0003f5 	mov	w21, w0
  4008d4:	36f80120 	tbz	w0, #31, 4008f8 <unsetenv+0x78>
  4008d8:	910ce294 	add	x20, x20, #0x338
  4008dc:	91004294 	add	x20, x20, #0x10
  4008e0:	089ffe9f 	stlrb	wzr, [x20]
  4008e4:	a94153f3 	ldp	x19, x20, [sp, #16]
  4008e8:	52800000 	mov	w0, #0x0                   	// #0
  4008ec:	a9425bf5 	ldp	x21, x22, [sp, #32]
  4008f0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  4008f4:	d65f03c0 	ret
  4008f8:	93407c13 	sxtw	x19, w0
  4008fc:	f94006c0 	ldr	x0, [x22, #8]
  400900:	91000673 	add	x19, x19, #0x1
  400904:	f8755800 	ldr	x0, [x0, w21, uxtw #3]
  400908:	940000be 	bl	400c00 <free>
  40090c:	f9419e83 	ldr	x3, [x20, #824]
  400910:	f94006c4 	ldr	x4, [x22, #8]
  400914:	eb03027f 	cmp	x19, x3
  400918:	54000122 	b.cs	40093c <unsetenv+0xbc>  // b.hs, b.nlast
  40091c:	91002080 	add	x0, x4, #0x8
  400920:	8b030c82 	add	x2, x4, x3, lsl #3
  400924:	8b354c00 	add	x0, x0, w21, uxtw #3
  400928:	f9400001 	ldr	x1, [x0]
  40092c:	91002000 	add	x0, x0, #0x8
  400930:	f81f0001 	stur	x1, [x0, #-16]
  400934:	eb02001f 	cmp	x0, x2
  400938:	54ffff81 	b.ne	400928 <unsetenv+0xa8>  // b.any
  40093c:	d1000463 	sub	x3, x3, #0x1
  400940:	f9019e83 	str	x3, [x20, #824]
  400944:	b4fffca4 	cbz	x4, 4008d8 <unsetenv+0x58>
  400948:	f823789f 	str	xzr, [x4, x3, lsl #3]
  40094c:	17ffffe3 	b	4008d8 <unsetenv+0x58>
  400950:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400954:	940000e7 	bl	400cf0 <__errno_location@GLIBC_2.2.5>
  400958:	528002c1 	mov	w1, #0x16                  	// #22
  40095c:	b9000001 	str	w1, [x0]
  400960:	12800000 	mov	w0, #0xffffffff            	// #-1
  400964:	17ffffe3 	b	4008f0 <unsetenv+0x70>
  400968:	d503201f 	nop
  40096c:	d503201f 	nop

0000000000400970 <clearenv>:
  400970:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400974:	910003fd 	mov	x29, sp
  400978:	a90153f3 	stp	x19, x20, [sp, #16]
  40097c:	a9025bf5 	stp	x21, x22, [sp, #32]
  400980:	b0000016 	adrp	x22, 401000 <strstr+0x70>
  400984:	910ce2d3 	add	x19, x22, #0x338
  400988:	91004273 	add	x19, x19, #0x10
  40098c:	d503201f 	nop
  400990:	aa1303e1 	mov	x1, x19
  400994:	52800020 	mov	w0, #0x1                   	// #1
  400998:	94000246 	bl	4012b0 <__aarch64_swp1_acq>
  40099c:	3707ffa0 	tbnz	w0, #0, 400990 <clearenv+0x20>
  4009a0:	f9419ec0 	ldr	x0, [x22, #824]
  4009a4:	b40001a0 	cbz	x0, 4009d8 <clearenv+0x68>
  4009a8:	910ce2d5 	add	x21, x22, #0x338
  4009ac:	d2800014 	mov	x20, #0x0                   	// #0
  4009b0:	d2800013 	mov	x19, #0x0                   	// #0
  4009b4:	d503201f 	nop
  4009b8:	f94006a0 	ldr	x0, [x21, #8]
  4009bc:	91000673 	add	x19, x19, #0x1
  4009c0:	f8746800 	ldr	x0, [x0, x20]
  4009c4:	91002294 	add	x20, x20, #0x8
  4009c8:	9400008e 	bl	400c00 <free>
  4009cc:	f94002a0 	ldr	x0, [x21]
  4009d0:	eb13001f 	cmp	x0, x19
  4009d4:	54ffff28 	b.hi	4009b8 <clearenv+0x48>  // b.pmore
  4009d8:	910ce2d3 	add	x19, x22, #0x338
  4009dc:	f9400660 	ldr	x0, [x19, #8]
  4009e0:	94000088 	bl	400c00 <free>
  4009e4:	f9019edf 	str	xzr, [x22, #824]
  4009e8:	b0000000 	adrp	x0, 401000 <strstr+0x70>
  4009ec:	f9418c00 	ldr	x0, [x0, #792]
  4009f0:	f900067f 	str	xzr, [x19, #8]
  4009f4:	f9000e7f 	str	xzr, [x19, #24]
  4009f8:	f900001f 	str	xzr, [x0]
  4009fc:	91004273 	add	x19, x19, #0x10
  400a00:	089ffe7f 	stlrb	wzr, [x19]
  400a04:	52800000 	mov	w0, #0x0                   	// #0
  400a08:	a94153f3 	ldp	x19, x20, [sp, #16]
  400a0c:	a9425bf5 	ldp	x21, x22, [sp, #32]
  400a10:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400a14:	d65f03c0 	ret
	...

0000000000400a20 <insert_free_block>:
  400a20:	52800021 	mov	w1, #0x1                   	// #1
  400a24:	39002001 	strb	w1, [x0, #8]
  400a28:	b0000001 	adrp	x1, 401000 <strstr+0x70>
  400a2c:	f941b022 	ldr	x2, [x1, #864]
  400a30:	f100005f 	cmp	x2, #0x0
  400a34:	fa401042 	ccmp	x2, x0, #0x2, ne	// ne = any
  400a38:	540002a9 	b.ls	400a8c <insert_free_block+0x6c>  // b.plast
  400a3c:	f901b020 	str	x0, [x1, #864]
  400a40:	f9000802 	str	x2, [x0, #16]
  400a44:	14000006 	b	400a5c <insert_free_block+0x3c>
  400a48:	f9400043 	ldr	x3, [x2]
  400a4c:	8b030041 	add	x1, x2, x3
  400a50:	91006021 	add	x1, x1, #0x18
  400a54:	eb01001f 	cmp	x0, x1
  400a58:	540000a0 	b.eq	400a6c <insert_free_block+0x4c>  // b.none
  400a5c:	aa0003e2 	mov	x2, x0
  400a60:	f9400800 	ldr	x0, [x0, #16]
  400a64:	b5ffff20 	cbnz	x0, 400a48 <insert_free_block+0x28>
  400a68:	d65f03c0 	ret
  400a6c:	f9400001 	ldr	x1, [x0]
  400a70:	91006063 	add	x3, x3, #0x18
  400a74:	f9400800 	ldr	x0, [x0, #16]
  400a78:	8b010063 	add	x3, x3, x1
  400a7c:	f9000043 	str	x3, [x2]
  400a80:	f9000840 	str	x0, [x2, #16]
  400a84:	aa0203e0 	mov	x0, x2
  400a88:	17fffff5 	b	400a5c <insert_free_block+0x3c>
  400a8c:	aa0203e1 	mov	x1, x2
  400a90:	14000003 	b	400a9c <insert_free_block+0x7c>
  400a94:	eb00003f 	cmp	x1, x0
  400a98:	54000082 	b.cs	400aa8 <insert_free_block+0x88>  // b.hs, b.nlast
  400a9c:	aa0103e3 	mov	x3, x1
  400aa0:	f9400821 	ldr	x1, [x1, #16]
  400aa4:	b5ffff81 	cbnz	x1, 400a94 <insert_free_block+0x74>
  400aa8:	f9000801 	str	x1, [x0, #16]
  400aac:	f9000860 	str	x0, [x3, #16]
  400ab0:	aa0203e0 	mov	x0, x2
  400ab4:	17ffffea 	b	400a5c <insert_free_block+0x3c>
  400ab8:	d503201f 	nop
  400abc:	d503201f 	nop

0000000000400ac0 <malloc>:
  400ac0:	b4000640 	cbz	x0, 400b88 <malloc+0xc8>
  400ac4:	91003c00 	add	x0, x0, #0xf
  400ac8:	927c6c02 	and	x2, x0, #0xfffffff0
  400acc:	b0000005 	adrp	x5, 401000 <strstr+0x70>
  400ad0:	f941b0a0 	ldr	x0, [x5, #864]
  400ad4:	b4000180 	cbz	x0, 400b04 <malloc+0x44>
  400ad8:	d2800003 	mov	x3, #0x0                   	// #0
  400adc:	14000002 	b	400ae4 <malloc+0x24>
  400ae0:	aa0103e0 	mov	x0, x1
  400ae4:	39402001 	ldrb	w1, [x0, #8]
  400ae8:	36000081 	tbz	w1, #0, 400af8 <malloc+0x38>
  400aec:	f9400001 	ldr	x1, [x0]
  400af0:	eb01005f 	cmp	x2, x1
  400af4:	540004e9 	b.ls	400b90 <malloc+0xd0>  // b.plast
  400af8:	f9400801 	ldr	x1, [x0, #16]
  400afc:	aa0003e3 	mov	x3, x0
  400b00:	b5ffff01 	cbnz	x1, 400ae0 <malloc+0x20>
  400b04:	d2800188 	mov	x8, #0xc                   	// #12
  400b08:	d2800000 	mov	x0, #0x0                   	// #0
  400b0c:	d4000001 	svc	#0x0
  400b10:	aa0003e4 	mov	x4, x0
  400b14:	b7f803a0 	tbnz	x0, #63, 400b88 <malloc+0xc8>
  400b18:	91009c41 	add	x1, x2, #0x27
  400b1c:	927c6c21 	and	x1, x1, #0xfffffff0
  400b20:	8b000023 	add	x3, x1, x0
  400b24:	aa0303e0 	mov	x0, x3
  400b28:	d4000001 	svc	#0x0
  400b2c:	eb00007f 	cmp	x3, x0
  400b30:	540002cc 	b.gt	400b88 <malloc+0xc8>
  400b34:	d1006021 	sub	x1, x1, #0x18
  400b38:	f9000081 	str	x1, [x4]
  400b3c:	cb020021 	sub	x1, x1, x2
  400b40:	3900209f 	strb	wzr, [x4, #8]
  400b44:	f900089f 	str	xzr, [x4, #16]
  400b48:	f100603f 	cmp	x1, #0x18
  400b4c:	54000569 	b.ls	400bf8 <malloc+0x138>  // b.plast
  400b50:	a9bf7bfd 	stp	x29, x30, [sp, #-16]!
  400b54:	91006043 	add	x3, x2, #0x18
  400b58:	8b030080 	add	x0, x4, x3
  400b5c:	910003fd 	mov	x29, sp
  400b60:	d1006021 	sub	x1, x1, #0x18
  400b64:	f8236881 	str	x1, [x4, x3]
  400b68:	f900081f 	str	xzr, [x0, #16]
  400b6c:	f9000082 	str	x2, [x4]
  400b70:	f9000880 	str	x0, [x4, #16]
  400b74:	97ffffab 	bl	400a20 <insert_free_block>
  400b78:	a8c17bfd 	ldp	x29, x30, [sp], #16
  400b7c:	91006080 	add	x0, x4, #0x18
  400b80:	f900089f 	str	xzr, [x4, #16]
  400b84:	d65f03c0 	ret
  400b88:	d2800000 	mov	x0, #0x0                   	// #0
  400b8c:	d65f03c0 	ret
  400b90:	cb020021 	sub	x1, x1, x2
  400b94:	f9400807 	ldr	x7, [x0, #16]
  400b98:	f100603f 	cmp	x1, #0x18
  400b9c:	540002a9 	b.ls	400bf0 <malloc+0x130>  // b.plast
  400ba0:	91006046 	add	x6, x2, #0x18
  400ba4:	d1006021 	sub	x1, x1, #0x18
  400ba8:	8b060004 	add	x4, x0, x6
  400bac:	f8266801 	str	x1, [x0, x6]
  400bb0:	52800021 	mov	w1, #0x1                   	// #1
  400bb4:	39002081 	strb	w1, [x4, #8]
  400bb8:	f9000887 	str	x7, [x4, #16]
  400bbc:	f9000002 	str	x2, [x0]
  400bc0:	f9000804 	str	x4, [x0, #16]
  400bc4:	b40000c3 	cbz	x3, 400bdc <malloc+0x11c>
  400bc8:	f9000864 	str	x4, [x3, #16]
  400bcc:	91006000 	add	x0, x0, #0x18
  400bd0:	381f001f 	sturb	wzr, [x0, #-16]
  400bd4:	f81f801f 	stur	xzr, [x0, #-8]
  400bd8:	d65f03c0 	ret
  400bdc:	91006000 	add	x0, x0, #0x18
  400be0:	f901b0a4 	str	x4, [x5, #864]
  400be4:	381f001f 	sturb	wzr, [x0, #-16]
  400be8:	f81f801f 	stur	xzr, [x0, #-8]
  400bec:	d65f03c0 	ret
  400bf0:	aa0703e4 	mov	x4, x7
  400bf4:	17fffff4 	b	400bc4 <malloc+0x104>
  400bf8:	91006080 	add	x0, x4, #0x18
  400bfc:	d65f03c0 	ret

0000000000400c00 <free>:
  400c00:	b4000060 	cbz	x0, 400c0c <free+0xc>
  400c04:	d1006000 	sub	x0, x0, #0x18
  400c08:	17ffff86 	b	400a20 <insert_free_block>
  400c0c:	d65f03c0 	ret

0000000000400c10 <calloc>:
  400c10:	9b017c02 	mul	x2, x0, x1
  400c14:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400c18:	910003fd 	mov	x29, sp
  400c1c:	aa0203e0 	mov	x0, x2
  400c20:	f9000be2 	str	x2, [sp, #16]
  400c24:	97ffffa7 	bl	400ac0 <malloc>
  400c28:	aa0003e3 	mov	x3, x0
  400c2c:	b40000c0 	cbz	x0, 400c44 <calloc+0x34>
  400c30:	f9400be2 	ldr	x2, [sp, #16]
  400c34:	52800001 	mov	w1, #0x0                   	// #0
  400c38:	f9000fe0 	str	x0, [sp, #24]
  400c3c:	9400016d 	bl	4011f0 <memset>
  400c40:	f9400fe3 	ldr	x3, [sp, #24]
  400c44:	aa0303e0 	mov	x0, x3
  400c48:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400c4c:	d65f03c0 	ret

0000000000400c50 <realloc>:
  400c50:	b40003e0 	cbz	x0, 400ccc <realloc+0x7c>
  400c54:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400c58:	910003fd 	mov	x29, sp
  400c5c:	b40003c1 	cbz	x1, 400cd4 <realloc+0x84>
  400c60:	aa0003e3 	mov	x3, x0
  400c64:	aa0003e4 	mov	x4, x0
  400c68:	f85e8000 	ldur	x0, [x0, #-24]
  400c6c:	eb01001f 	cmp	x0, x1
  400c70:	54000083 	b.cc	400c80 <realloc+0x30>  // b.lo, b.ul, b.last
  400c74:	aa0403e0 	mov	x0, x4
  400c78:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400c7c:	d65f03c0 	ret
  400c80:	aa0103e0 	mov	x0, x1
  400c84:	a9018fe1 	stp	x1, x3, [sp, #24]
  400c88:	97ffff8e 	bl	400ac0 <malloc>
  400c8c:	aa0003e4 	mov	x4, x0
  400c90:	b4ffff20 	cbz	x0, 400c74 <realloc+0x24>
  400c94:	a9418fe1 	ldp	x1, x3, [sp, #24]
  400c98:	f9000fe3 	str	x3, [sp, #24]
  400c9c:	f90017e0 	str	x0, [sp, #40]
  400ca0:	f85e8062 	ldur	x2, [x3, #-24]
  400ca4:	eb01005f 	cmp	x2, x1
  400ca8:	9a819042 	csel	x2, x2, x1, ls	// ls = plast
  400cac:	aa0303e1 	mov	x1, x3
  400cb0:	94000140 	bl	4011b0 <memcpy>
  400cb4:	f9400fe0 	ldr	x0, [sp, #24]
  400cb8:	97ffffd2 	bl	400c00 <free>
  400cbc:	f94017e4 	ldr	x4, [sp, #40]
  400cc0:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400cc4:	aa0403e0 	mov	x0, x4
  400cc8:	d65f03c0 	ret
  400ccc:	aa0103e0 	mov	x0, x1
  400cd0:	17ffff7c 	b	400ac0 <malloc>
  400cd4:	97ffffcb 	bl	400c00 <free>
  400cd8:	d2800004 	mov	x4, #0x0                   	// #0
  400cdc:	17ffffe6 	b	400c74 <realloc+0x24>

0000000000400ce0 <heap_stats>:
  400ce0:	d65f03c0 	ret
	...

0000000000400cf0 <__errno_location@GLIBC_2.2.5>:
  400cf0:	b0000000 	adrp	x0, 401000 <strstr+0x70>
  400cf4:	910da000 	add	x0, x0, #0x368
  400cf8:	d65f03c0 	ret
  400cfc:	00000000 	udf	#0

0000000000400d00 <strlen>:
  400d00:	aa0003e2 	mov	x2, x0
  400d04:	b4000120 	cbz	x0, 400d28 <strlen+0x28>
  400d08:	39400000 	ldrb	w0, [x0]
  400d0c:	340000e0 	cbz	w0, 400d28 <strlen+0x28>
  400d10:	d2800000 	mov	x0, #0x0                   	// #0
  400d14:	d503201f 	nop
  400d18:	91000400 	add	x0, x0, #0x1
  400d1c:	38606841 	ldrb	w1, [x2, x0]
  400d20:	35ffffc1 	cbnz	w1, 400d18 <strlen+0x18>
  400d24:	d65f03c0 	ret
  400d28:	d2800000 	mov	x0, #0x0                   	// #0
  400d2c:	d65f03c0 	ret

0000000000400d30 <strncpy>:
  400d30:	f100001f 	cmp	x0, #0x0
  400d34:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d38:	54000220 	b.eq	400d7c <strncpy+0x4c>  // b.none
  400d3c:	d2800003 	mov	x3, #0x0                   	// #0
  400d40:	b50000c2 	cbnz	x2, 400d58 <strncpy+0x28>
  400d44:	1400000e 	b	400d7c <strncpy+0x4c>
  400d48:	38236804 	strb	w4, [x0, x3]
  400d4c:	91000463 	add	x3, x3, #0x1
  400d50:	eb03005f 	cmp	x2, x3
  400d54:	54000140 	b.eq	400d7c <strncpy+0x4c>  // b.none
  400d58:	38636824 	ldrb	w4, [x1, x3]
  400d5c:	35ffff64 	cbnz	w4, 400d48 <strncpy+0x18>
  400d60:	eb03005f 	cmp	x2, x3
  400d64:	540000c9 	b.ls	400d7c <strncpy+0x4c>  // b.plast
  400d68:	8b030003 	add	x3, x0, x3
  400d6c:	8b020002 	add	x2, x0, x2
  400d70:	3800147f 	strb	wzr, [x3], #1
  400d74:	eb02007f 	cmp	x3, x2
  400d78:	54ffffc1 	b.ne	400d70 <strncpy+0x40>  // b.any
  400d7c:	d65f03c0 	ret

0000000000400d80 <strcpy>:
  400d80:	f100001f 	cmp	x0, #0x0
  400d84:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400d88:	54000140 	b.eq	400db0 <strcpy+0x30>  // b.none
  400d8c:	39400023 	ldrb	w3, [x1]
  400d90:	34000123 	cbz	w3, 400db4 <strcpy+0x34>
  400d94:	d2800002 	mov	x2, #0x0                   	// #0
  400d98:	38226803 	strb	w3, [x0, x2]
  400d9c:	91000442 	add	x2, x2, #0x1
  400da0:	38626823 	ldrb	w3, [x1, x2]
  400da4:	35ffffa3 	cbnz	w3, 400d98 <strcpy+0x18>
  400da8:	8b020002 	add	x2, x0, x2
  400dac:	3900005f 	strb	wzr, [x2]
  400db0:	d65f03c0 	ret
  400db4:	aa0003e2 	mov	x2, x0
  400db8:	3900005f 	strb	wzr, [x2]
  400dbc:	17fffffd 	b	400db0 <strcpy+0x30>

0000000000400dc0 <strcmp>:
  400dc0:	f100001f 	cmp	x0, #0x0
  400dc4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400dc8:	540001a0 	b.eq	400dfc <strcmp+0x3c>  // b.none
  400dcc:	39400002 	ldrb	w2, [x0]
  400dd0:	350000a2 	cbnz	w2, 400de4 <strcmp+0x24>
  400dd4:	1400000f 	b	400e10 <strcmp+0x50>
  400dd8:	38401c02 	ldrb	w2, [x0, #1]!
  400ddc:	34000142 	cbz	w2, 400e04 <strcmp+0x44>
  400de0:	91000421 	add	x1, x1, #0x1
  400de4:	39400023 	ldrb	w3, [x1]
  400de8:	7100007f 	cmp	w3, #0x0
  400dec:	7a421060 	ccmp	w3, w2, #0x0, ne	// ne = any
  400df0:	54ffff40 	b.eq	400dd8 <strcmp+0x18>  // b.none
  400df4:	4b030040 	sub	w0, w2, w3
  400df8:	d65f03c0 	ret
  400dfc:	52800000 	mov	w0, #0x0                   	// #0
  400e00:	d65f03c0 	ret
  400e04:	39400423 	ldrb	w3, [x1, #1]
  400e08:	4b030040 	sub	w0, w2, w3
  400e0c:	17fffffb 	b	400df8 <strcmp+0x38>
  400e10:	39400023 	ldrb	w3, [x1]
  400e14:	4b030040 	sub	w0, w2, w3
  400e18:	17fffff8 	b	400df8 <strcmp+0x38>
  400e1c:	d503201f 	nop

0000000000400e20 <strncmp>:
  400e20:	f100003f 	cmp	x1, #0x0
  400e24:	d2800003 	mov	x3, #0x0                   	// #0
  400e28:	fa401844 	ccmp	x2, #0x0, #0x4, ne	// ne = any
  400e2c:	fa401804 	ccmp	x0, #0x0, #0x4, ne	// ne = any
  400e30:	54000081 	b.ne	400e40 <strncmp+0x20>  // b.any
  400e34:	52800004 	mov	w4, #0x0                   	// #0
  400e38:	2a0403e0 	mov	w0, w4
  400e3c:	d65f03c0 	ret
  400e40:	38636804 	ldrb	w4, [x0, x3]
  400e44:	34000104 	cbz	w4, 400e64 <strncmp+0x44>
  400e48:	38636825 	ldrb	w5, [x1, x3]
  400e4c:	340000c5 	cbz	w5, 400e64 <strncmp+0x44>
  400e50:	6b05009f 	cmp	w4, w5
  400e54:	54000181 	b.ne	400e84 <strncmp+0x64>  // b.any
  400e58:	91000463 	add	x3, x3, #0x1
  400e5c:	eb03005f 	cmp	x2, x3
  400e60:	54ffff08 	b.hi	400e40 <strncmp+0x20>  // b.pmore
  400e64:	52800004 	mov	w4, #0x0                   	// #0
  400e68:	eb02007f 	cmp	x3, x2
  400e6c:	54fffe60 	b.eq	400e38 <strncmp+0x18>  // b.none
  400e70:	38636804 	ldrb	w4, [x0, x3]
  400e74:	38636820 	ldrb	w0, [x1, x3]
  400e78:	4b000084 	sub	w4, w4, w0
  400e7c:	2a0403e0 	mov	w0, w4
  400e80:	d65f03c0 	ret
  400e84:	4b050084 	sub	w4, w4, w5
  400e88:	2a0403e0 	mov	w0, w4
  400e8c:	d65f03c0 	ret

0000000000400e90 <strcat>:
  400e90:	f100001f 	cmp	x0, #0x0
  400e94:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400e98:	54000041 	b.ne	400ea0 <strcat+0x10>  // b.any
  400e9c:	d65f03c0 	ret
  400ea0:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400ea4:	910003fd 	mov	x29, sp
  400ea8:	a90107e0 	stp	x0, x1, [sp, #16]
  400eac:	97ffff95 	bl	400d00 <strlen>
  400eb0:	a94107e3 	ldp	x3, x1, [sp, #16]
  400eb4:	39400022 	ldrb	w2, [x1]
  400eb8:	8b000060 	add	x0, x3, x0
  400ebc:	34000082 	cbz	w2, 400ecc <strcat+0x3c>
  400ec0:	38001402 	strb	w2, [x0], #1
  400ec4:	38401c22 	ldrb	w2, [x1, #1]!
  400ec8:	35ffffc2 	cbnz	w2, 400ec0 <strcat+0x30>
  400ecc:	3900001f 	strb	wzr, [x0]
  400ed0:	aa0303e0 	mov	x0, x3
  400ed4:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400ed8:	d65f03c0 	ret
  400edc:	d503201f 	nop

0000000000400ee0 <strchr>:
  400ee0:	b4000120 	cbz	x0, 400f04 <strchr+0x24>
  400ee4:	39400002 	ldrb	w2, [x0]
  400ee8:	12001c21 	and	w1, w1, #0xff
  400eec:	35000082 	cbnz	w2, 400efc <strchr+0x1c>
  400ef0:	14000006 	b	400f08 <strchr+0x28>
  400ef4:	38401c02 	ldrb	w2, [x0, #1]!
  400ef8:	34000082 	cbz	w2, 400f08 <strchr+0x28>
  400efc:	6b01005f 	cmp	w2, w1
  400f00:	54ffffa1 	b.ne	400ef4 <strchr+0x14>  // b.any
  400f04:	d65f03c0 	ret
  400f08:	7100003f 	cmp	w1, #0x0
  400f0c:	9a9f0000 	csel	x0, x0, xzr, eq	// eq = none
  400f10:	d65f03c0 	ret
  400f14:	d503201f 	nop
  400f18:	d503201f 	nop
  400f1c:	d503201f 	nop

0000000000400f20 <strdup>:
  400f20:	b4000300 	cbz	x0, 400f80 <strdup+0x60>
  400f24:	a9be7bfd 	stp	x29, x30, [sp, #-32]!
  400f28:	910003fd 	mov	x29, sp
  400f2c:	f9000fe0 	str	x0, [sp, #24]
  400f30:	97ffff74 	bl	400d00 <strlen>
  400f34:	91000403 	add	x3, x0, #0x1
  400f38:	f9000be3 	str	x3, [sp, #16]
  400f3c:	aa0303e0 	mov	x0, x3
  400f40:	97fffee0 	bl	400ac0 <malloc>
  400f44:	b4000180 	cbz	x0, 400f74 <strdup+0x54>
  400f48:	a94113e3 	ldp	x3, x4, [sp, #16]
  400f4c:	d2800001 	mov	x1, #0x0                   	// #0
  400f50:	b40000e3 	cbz	x3, 400f6c <strdup+0x4c>
  400f54:	d503201f 	nop
  400f58:	38616882 	ldrb	w2, [x4, x1]
  400f5c:	38216802 	strb	w2, [x0, x1]
  400f60:	91000421 	add	x1, x1, #0x1
  400f64:	eb01007f 	cmp	x3, x1
  400f68:	54ffff81 	b.ne	400f58 <strdup+0x38>  // b.any
  400f6c:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400f70:	d65f03c0 	ret
  400f74:	d2800000 	mov	x0, #0x0                   	// #0
  400f78:	a8c27bfd 	ldp	x29, x30, [sp], #32
  400f7c:	d65f03c0 	ret
  400f80:	d2800000 	mov	x0, #0x0                   	// #0
  400f84:	d65f03c0 	ret
  400f88:	d503201f 	nop
  400f8c:	d503201f 	nop

0000000000400f90 <strstr>:
  400f90:	f100001f 	cmp	x0, #0x0
  400f94:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  400f98:	54000480 	b.eq	401028 <strstr+0x98>  // b.none
  400f9c:	a9bd7bfd 	stp	x29, x30, [sp, #-48]!
  400fa0:	910003fd 	mov	x29, sp
  400fa4:	a90153f3 	stp	x19, x20, [sp, #16]
  400fa8:	aa0003f3 	mov	x19, x0
  400fac:	39400022 	ldrb	w2, [x1]
  400fb0:	35000082 	cbnz	w2, 400fc0 <strstr+0x30>
  400fb4:	a94153f3 	ldp	x19, x20, [sp, #16]
  400fb8:	a8c37bfd 	ldp	x29, x30, [sp], #48
  400fbc:	d65f03c0 	ret
  400fc0:	aa0103f4 	mov	x20, x1
  400fc4:	aa0103e0 	mov	x0, x1
  400fc8:	f90013f5 	str	x21, [sp, #32]
  400fcc:	97ffff4d 	bl	400d00 <strlen>
  400fd0:	39400262 	ldrb	w2, [x19]
  400fd4:	aa0003f5 	mov	x21, x0
  400fd8:	35000082 	cbnz	w2, 400fe8 <strstr+0x58>
  400fdc:	1400000e 	b	401014 <strstr+0x84>
  400fe0:	38401e62 	ldrb	w2, [x19, #1]!
  400fe4:	34000182 	cbz	w2, 401014 <strstr+0x84>
  400fe8:	39400280 	ldrb	w0, [x20]
  400fec:	6b02001f 	cmp	w0, w2
  400ff0:	54ffff81 	b.ne	400fe0 <strstr+0x50>  // b.any
  400ff4:	aa1503e2 	mov	x2, x21
  400ff8:	aa1403e1 	mov	x1, x20
  400ffc:	aa1303e0 	mov	x0, x19
  401000:	97ffff88 	bl	400e20 <strncmp>
  401004:	35fffee0 	cbnz	w0, 400fe0 <strstr+0x50>
  401008:	f94013f5 	ldr	x21, [sp, #32]
  40100c:	aa1303e0 	mov	x0, x19
  401010:	17ffffe9 	b	400fb4 <strstr+0x24>
  401014:	f94013f5 	ldr	x21, [sp, #32]
  401018:	d2800000 	mov	x0, #0x0                   	// #0
  40101c:	a94153f3 	ldp	x19, x20, [sp, #16]
  401020:	a8c37bfd 	ldp	x29, x30, [sp], #48
  401024:	d65f03c0 	ret
  401028:	d2800000 	mov	x0, #0x0                   	// #0
  40102c:	d65f03c0 	ret

0000000000401030 <strtol>:
  401030:	aa0003e5 	mov	x5, x0
  401034:	b40009e0 	cbz	x0, 401170 <strtol+0x140>
  401038:	39400004 	ldrb	w4, [x0]
  40103c:	51002480 	sub	w0, w4, #0x9
  401040:	7100809f 	cmp	w4, #0x20
  401044:	12001c00 	and	w0, w0, #0xff
  401048:	7a441800 	ccmp	w0, #0x4, #0x0, ne	// ne = any
  40104c:	540000e8 	b.hi	401068 <strtol+0x38>  // b.pmore
  401050:	38401ca4 	ldrb	w4, [x5, #1]!
  401054:	51002483 	sub	w3, w4, #0x9
  401058:	7100809f 	cmp	w4, #0x20
  40105c:	12001c63 	and	w3, w3, #0xff
  401060:	7a441860 	ccmp	w3, #0x4, #0x0, ne	// ne = any
  401064:	54ffff69 	b.ls	401050 <strtol+0x20>  // b.plast
  401068:	7100ac9f 	cmp	w4, #0x2b
  40106c:	540006a0 	b.eq	401140 <strtol+0x110>  // b.none
  401070:	7100b49f 	cmp	w4, #0x2d
  401074:	d2800028 	mov	x8, #0x1                   	// #1
  401078:	9a8514a5 	cinc	x5, x5, eq	// eq = none
  40107c:	da9f1108 	csinv	x8, x8, xzr, ne	// ne = any
  401080:	394000a3 	ldrb	w3, [x5]
  401084:	35000462 	cbnz	w2, 401110 <strtol+0xe0>
  401088:	52800142 	mov	w2, #0xa                   	// #10
  40108c:	7100c07f 	cmp	w3, #0x30
  401090:	540005e0 	b.eq	40114c <strtol+0x11c>  // b.none
  401094:	340007c3 	cbz	w3, 40118c <strtol+0x15c>
  401098:	93407c47 	sxtw	x7, w2
  40109c:	d2800004 	mov	x4, #0x0                   	// #0
  4010a0:	14000008 	b	4010c0 <strtol+0x90>
  4010a4:	51015c60 	sub	w0, w3, #0x57
  4010a8:	6b02001f 	cmp	w0, w2
  4010ac:	540002aa 	b.ge	401100 <strtol+0xd0>  // b.tcont
  4010b0:	38401ca3 	ldrb	w3, [x5, #1]!
  4010b4:	93407c00 	sxtw	x0, w0
  4010b8:	9b0400e4 	madd	x4, x7, x4, x0
  4010bc:	34000223 	cbz	w3, 401100 <strtol+0xd0>
  4010c0:	5100c060 	sub	w0, w3, #0x30
  4010c4:	12001c06 	and	w6, w0, #0xff
  4010c8:	710024df 	cmp	w6, #0x9
  4010cc:	54fffee9 	b.ls	4010a8 <strtol+0x78>  // b.plast
  4010d0:	51018460 	sub	w0, w3, #0x61
  4010d4:	12001c00 	and	w0, w0, #0xff
  4010d8:	7100641f 	cmp	w0, #0x19
  4010dc:	54fffe49 	b.ls	4010a4 <strtol+0x74>  // b.plast
  4010e0:	51010460 	sub	w0, w3, #0x41
  4010e4:	12001c00 	and	w0, w0, #0xff
  4010e8:	7100641f 	cmp	w0, #0x19
  4010ec:	540000a8 	b.hi	401100 <strtol+0xd0>  // b.pmore
  4010f0:	5100dc60 	sub	w0, w3, #0x37
  4010f4:	6b02001f 	cmp	w0, w2
  4010f8:	54fffdcb 	b.lt	4010b0 <strtol+0x80>  // b.tstop
  4010fc:	d503201f 	nop
  401100:	9b047d00 	mul	x0, x8, x4
  401104:	b4000041 	cbz	x1, 40110c <strtol+0xdc>
  401108:	f9000025 	str	x5, [x1]
  40110c:	d65f03c0 	ret
  401110:	7100405f 	cmp	w2, #0x10
  401114:	54fffc01 	b.ne	401094 <strtol+0x64>  // b.any
  401118:	7100c07f 	cmp	w3, #0x30
  40111c:	54fffbc1 	b.ne	401094 <strtol+0x64>  // b.any
  401120:	394004a0 	ldrb	w0, [x5, #1]
  401124:	121a7800 	and	w0, w0, #0xffffffdf
  401128:	12001c00 	and	w0, w0, #0xff
  40112c:	7101601f 	cmp	w0, #0x58
  401130:	54fffb41 	b.ne	401098 <strtol+0x68>  // b.any
  401134:	394008a3 	ldrb	w3, [x5, #2]
  401138:	910008a5 	add	x5, x5, #0x2
  40113c:	17ffffd6 	b	401094 <strtol+0x64>
  401140:	910004a5 	add	x5, x5, #0x1
  401144:	d2800028 	mov	x8, #0x1                   	// #1
  401148:	17ffffce 	b	401080 <strtol+0x50>
  40114c:	394004a3 	ldrb	w3, [x5, #1]
  401150:	121a7860 	and	w0, w3, #0xffffffdf
  401154:	12001c00 	and	w0, w0, #0xff
  401158:	7101601f 	cmp	w0, #0x58
  40115c:	54000121 	b.ne	401180 <strtol+0x150>  // b.any
  401160:	394008a3 	ldrb	w3, [x5, #2]
  401164:	52800202 	mov	w2, #0x10                  	// #16
  401168:	910008a5 	add	x5, x5, #0x2
  40116c:	17ffffca 	b	401094 <strtol+0x64>
  401170:	b4000041 	cbz	x1, 401178 <strtol+0x148>
  401174:	f900003f 	str	xzr, [x1]
  401178:	d2800000 	mov	x0, #0x0                   	// #0
  40117c:	d65f03c0 	ret
  401180:	910004a5 	add	x5, x5, #0x1
  401184:	52800102 	mov	w2, #0x8                   	// #8
  401188:	17ffffc3 	b	401094 <strtol+0x64>
  40118c:	d2800000 	mov	x0, #0x0                   	// #0
  401190:	17ffffdd 	b	401104 <strtol+0xd4>
  401194:	d503201f 	nop
  401198:	d503201f 	nop
  40119c:	d503201f 	nop

00000000004011a0 <__isoc23_strtol>:
  4011a0:	17ffffa4 	b	401030 <strtol>
  4011a4:	d503201f 	nop
  4011a8:	d503201f 	nop
  4011ac:	d503201f 	nop

00000000004011b0 <memcpy>:
  4011b0:	f100001f 	cmp	x0, #0x0
  4011b4:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  4011b8:	54000120 	b.eq	4011dc <memcpy+0x2c>  // b.none
  4011bc:	b4000102 	cbz	x2, 4011dc <memcpy+0x2c>
  4011c0:	d2800003 	mov	x3, #0x0                   	// #0
  4011c4:	d503201f 	nop
  4011c8:	38636824 	ldrb	w4, [x1, x3]
  4011cc:	38236804 	strb	w4, [x0, x3]
  4011d0:	91000463 	add	x3, x3, #0x1
  4011d4:	eb03005f 	cmp	x2, x3
  4011d8:	54ffff81 	b.ne	4011c8 <memcpy+0x18>  // b.any
  4011dc:	d65f03c0 	ret

00000000004011e0 <__memcpy_chk>:
  4011e0:	17fffff4 	b	4011b0 <memcpy>
  4011e4:	d503201f 	nop
  4011e8:	d503201f 	nop
  4011ec:	d503201f 	nop

00000000004011f0 <memset>:
  4011f0:	b40000e0 	cbz	x0, 40120c <memset+0x1c>
  4011f4:	b40000c2 	cbz	x2, 40120c <memset+0x1c>
  4011f8:	aa0003e3 	mov	x3, x0
  4011fc:	8b020002 	add	x2, x0, x2
  401200:	38001461 	strb	w1, [x3], #1
  401204:	eb02007f 	cmp	x3, x2
  401208:	54ffffc1 	b.ne	401200 <memset+0x10>  // b.any
  40120c:	d65f03c0 	ret

0000000000401210 <memcmp>:
  401210:	f100001f 	cmp	x0, #0x0
  401214:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401218:	540001a0 	b.eq	40124c <memcmp+0x3c>  // b.none
  40121c:	b4000182 	cbz	x2, 40124c <memcmp+0x3c>
  401220:	d2800003 	mov	x3, #0x0                   	// #0
  401224:	14000004 	b	401234 <memcmp+0x24>
  401228:	91000463 	add	x3, x3, #0x1
  40122c:	eb03005f 	cmp	x2, x3
  401230:	540000e0 	b.eq	40124c <memcmp+0x3c>  // b.none
  401234:	38636804 	ldrb	w4, [x0, x3]
  401238:	38636825 	ldrb	w5, [x1, x3]
  40123c:	6b05009f 	cmp	w4, w5
  401240:	54ffff40 	b.eq	401228 <memcmp+0x18>  // b.none
  401244:	4b050080 	sub	w0, w4, w5
  401248:	d65f03c0 	ret
  40124c:	52800000 	mov	w0, #0x0                   	// #0
  401250:	d65f03c0 	ret
  401254:	d503201f 	nop
  401258:	d503201f 	nop
  40125c:	d503201f 	nop

0000000000401260 <memmove>:
  401260:	f100001f 	cmp	x0, #0x0
  401264:	fa401824 	ccmp	x1, #0x0, #0x4, ne	// ne = any
  401268:	54000160 	b.eq	401294 <memmove+0x34>  // b.none
  40126c:	eb01001f 	cmp	x0, x1
  401270:	54000142 	b.cs	401298 <memmove+0x38>  // b.hs, b.nlast
  401274:	b4000102 	cbz	x2, 401294 <memmove+0x34>
  401278:	d2800003 	mov	x3, #0x0                   	// #0
  40127c:	d503201f 	nop
  401280:	38636824 	ldrb	w4, [x1, x3]
  401284:	38236804 	strb	w4, [x0, x3]
  401288:	91000463 	add	x3, x3, #0x1
  40128c:	eb03005f 	cmp	x2, x3
  401290:	54ffff81 	b.ne	401280 <memmove+0x20>  // b.any
  401294:	d65f03c0 	ret
  401298:	b4ffffe2 	cbz	x2, 401294 <memmove+0x34>
  40129c:	d1000442 	sub	x2, x2, #0x1
  4012a0:	38626823 	ldrb	w3, [x1, x2]
  4012a4:	38226803 	strb	w3, [x0, x2]
  4012a8:	17fffffc 	b	401298 <memmove+0x38>
  4012ac:	00000000 	udf	#0

00000000004012b0 <__aarch64_swp1_acq>:
  4012b0:	90000010 	adrp	x16, 401000 <strstr+0x70>
  4012b4:	394db210 	ldrb	w16, [x16, #876]
  4012b8:	34000070 	cbz	w16, 4012c4 <__aarch64_swp1_acq+0x14>
  4012bc:	38a08020 	swpab	w0, w0, [x1]
  4012c0:	d65f03c0 	ret
  4012c4:	2a0003f0 	mov	w16, w0
  4012c8:	085ffc20 	ldaxrb	w0, [x1]
  4012cc:	08117c30 	stxrb	w17, w16, [x1]
  4012d0:	35ffffd1 	cbnz	w17, 4012c8 <__aarch64_swp1_acq+0x18>
  4012d4:	d65f03c0 	ret
