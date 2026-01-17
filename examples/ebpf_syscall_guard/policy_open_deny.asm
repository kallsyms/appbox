mov64 r6, r1
ldxdw r2, [r6+0]
jne r2, 0x5, +30
ldxdw r1, [r6+8]
mov64 r2, 11
mov64 r3, r6
add64 r3, 136
call 1
jne r0, 0x0, +24
ldxb r0, [r3+0]
jne r0, 0x2e, +22
ldxb r0, [r3+1]
jne r0, 0x2f, +20
ldxb r0, [r3+2]
jne r0, 0x74, +18
ldxb r0, [r3+3]
jne r0, 0x65, +16
ldxb r0, [r3+4]
jne r0, 0x73, +14
ldxb r0, [r3+5]
jne r0, 0x74, +12
ldxb r0, [r3+6]
jne r0, 0x2e, +10
ldxb r0, [r3+7]
jne r0, 0x74, +8
ldxb r0, [r3+8]
jne r0, 0x78, +6
ldxb r0, [r3+9]
jne r0, 0x74, +4
ldxb r0, [r3+10]
jne r0, 0x0, +2
mov64 r0, 1
exit
mov64 r0, 0
exit
