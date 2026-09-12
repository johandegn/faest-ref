/*
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by Gilles Van Assche and Ronny Van Keer, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements Keccak-p[1600] in a SnP-compatible way.
Please refer to SnP-documentation.h for more details.

This implementation comes with KeccakP-1600-SnP.h in the same folder.
Please refer to LowLevel.build for the exact list of other files it must be combined with.
*/

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "brg_endian.h"
#include "load-store.h"
#include "KeccakP-1600-SnP.h"

#if defined(KeccakP1600_plain64_useLaneComplementing)
#define UseBebigokimisa
#endif

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(KeccakP1600_plain64_useSHLD)
    #define ROL64(x,N) ({ \
    register uint64_t __out; \
    register uint64_t __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((uint64_t)a) << offset) ^ (((uint64_t)a) >> (64-offset)))
#endif

#include "KeccakP-1600-64.macros"
#ifdef KeccakP1600_plain64_fullUnrolling
#define FullUnrolling
#else
#define Unrolling KeccakP1600_plain64_unrolling
#endif
#include "KeccakP-1600-unrolling.macros"
#include "SnP-Relaned.h"

static const uint64_t KeccakF1600RoundConstants[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL };

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Initialize(KeccakP1600_plain64_state *state)
{
    memset(state, 0, 200);
#ifdef KeccakP1600_plain64_useLaneComplementing
    state->A[ 1] = ~(uint64_t)0;
    state->A[ 2] = ~(uint64_t)0;
    state->A[ 8] = ~(uint64_t)0;
    state->A[12] = ~(uint64_t)0;
    state->A[17] = ~(uint64_t)0;
    state->A[20] = ~(uint64_t)0;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_AddBytesInLane(KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    uint64_t lane;
    if (length == 0)
        return;
    if (length == 1)
        lane = data[0];
    else {
        lane = 0;
        memcpy(&lane, data, length);
    }
    lane <<= offset*8;
#else
    uint64_t lane = 0;
    unsigned int i;
    for(i=0; i<length; i++)
        lane |= ((uint64_t)data[i]) << ((i+offset)*8);
#endif
    state->A[lanePosition] ^= lane;
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_AddLanes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    unsigned int i = 0;

    for( ; (i+8)<=laneCount; i+=8) {
        state->A[i+0] ^= XKCP_load64(data+(i+0)*8);
        state->A[i+1] ^= XKCP_load64(data+(i+1)*8);
        state->A[i+2] ^= XKCP_load64(data+(i+2)*8);
        state->A[i+3] ^= XKCP_load64(data+(i+3)*8);
        state->A[i+4] ^= XKCP_load64(data+(i+4)*8);
        state->A[i+5] ^= XKCP_load64(data+(i+5)*8);
        state->A[i+6] ^= XKCP_load64(data+(i+6)*8);
        state->A[i+7] ^= XKCP_load64(data+(i+7)*8);
    }
    for( ; (i+4)<=laneCount; i+=4) {
        state->A[i+0] ^= XKCP_load64(data+(i+0)*8);
        state->A[i+1] ^= XKCP_load64(data+(i+1)*8);
        state->A[i+2] ^= XKCP_load64(data+(i+2)*8);
        state->A[i+3] ^= XKCP_load64(data+(i+3)*8);
    }
    for( ; (i+2)<=laneCount; i+=2) {
        state->A[i+0] ^= XKCP_load64(data+(i+0)*8);
        state->A[i+1] ^= XKCP_load64(data+(i+1)*8);
    }
    if (i<laneCount) {
        state->A[i+0] ^= XKCP_load64(data+(i+0)*8);
    }
#else
    unsigned int i;
    const uint8_t *curData = data;
    for(i=0; i<laneCount; i++, curData+=8) {
        uint64_t lane = (uint64_t)curData[0]
            | ((uint64_t)curData[1] <<  8)
            | ((uint64_t)curData[2] << 16)
            | ((uint64_t)curData[3] << 24)
            | ((uint64_t)curData[4] << 32)
            | ((uint64_t)curData[5] << 40)
            | ((uint64_t)curData[6] << 48)
            | ((uint64_t)curData[7] << 56);
        state->A[i] ^= lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
void KeccakP1600_plain64_AddByte(KeccakP1600_plain64_state *state, unsigned char byte, unsigned int offset)
{
    uint64_t lane = byte;
    lane <<= (offset%8)*8;
    state->A[offset/8] ^= lane;
}
#endif

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_AddBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_AddBytes(state, data, offset, length, KeccakP1600_plain64_AddLanes, KeccakP1600_plain64_AddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteBytesInLane(KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#ifdef KeccakP1600_plain64_useLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20)) {
        unsigned int i;
        for(i=0; i<length; i++)
            ((unsigned char*)state)[lanePosition*8+offset+i] = ~data[i];
    }
    else
#endif
    {
        memcpy((unsigned char*)state+lanePosition*8+offset, data, length);
    }
#else
    uint64_t lane = state->A[lanePosition];
    unsigned int i;
    for(i=0; i<length; i++) {
        lane &= ~((uint64_t)0xFF << ((offset+i)*8));
#ifdef KeccakP1600_plain64_useLaneComplementing
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            lane |= (uint64_t)(data[i] ^ 0xFF) << ((offset+i)*8);
        else
#endif
            lane |= (uint64_t)data[i] << ((offset+i)*8);
    }
    state->A[lanePosition] = lane;
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteLanes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#ifdef KeccakP1600_plain64_useLaneComplementing
    unsigned int lanePosition;

    for(lanePosition=0; lanePosition<laneCount; lanePosition++)
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            state->A[lanePosition] = ~XKCP_load64(data+lanePosition*8);
        else
            state->A[lanePosition] = XKCP_load64(data+lanePosition*8);
#else
    memcpy(state, data, laneCount*8);
#endif
#else
    unsigned int lanePosition;
    const uint8_t *curData = data;
    for(lanePosition=0; lanePosition<laneCount; lanePosition++, curData+=8) {
        uint64_t lane = (uint64_t)curData[0]
            | ((uint64_t)curData[1] <<  8)
            | ((uint64_t)curData[2] << 16)
            | ((uint64_t)curData[3] << 24)
            | ((uint64_t)curData[4] << 32)
            | ((uint64_t)curData[5] << 40)
            | ((uint64_t)curData[6] << 48)
            | ((uint64_t)curData[7] << 56);
#ifdef KeccakP1600_plain64_useLaneComplementing
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            state->A[lanePosition] = ~lane;
        else
#endif
            state->A[lanePosition] = lane;
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteBytes(KeccakP1600_plain64_state *state, const unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_OverwriteBytes(state, data, offset, length, KeccakP1600_plain64_OverwriteLanes, KeccakP1600_plain64_OverwriteBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_OverwriteWithZeroes(KeccakP1600_plain64_state *state, unsigned int byteCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#ifdef KeccakP1600_plain64_useLaneComplementing
    unsigned int lanePosition;

    for(lanePosition=0; lanePosition<byteCount/8; lanePosition++)
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            state->A[lanePosition] = ~0;
        else
            state->A[lanePosition] = 0;
    if (byteCount%8 != 0) {
        lanePosition = byteCount/8;
        if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
            memset((unsigned char*)state+lanePosition*8, 0xFF, byteCount%8);
        else
            memset((unsigned char*)state+lanePosition*8, 0, byteCount%8);
    }
#else
    memset(state, 0, byteCount);
#endif
#else
    unsigned int i, j;
    for(i=0; i<byteCount; i+=8) {
        unsigned int lanePosition = i/8;
        if (i+8 <= byteCount) {
#ifdef KeccakP1600_plain64_useLaneComplementing
            if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
                state->A[lanePosition] = ~(uint64_t)0;
            else
#endif
                state->A[lanePosition] = 0;
        }
        else {
            uint64_t lane = state->A[lanePosition];
            for(j=0; j<byteCount%8; j++) {
#ifdef KeccakP1600_plain64_useLaneComplementing
                if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
                    lane |= (uint64_t)0xFF << (j*8);
                else
#endif
                    lane &= ~((uint64_t)0xFF << (j*8));
            }
            state->A[lanePosition] = lane;
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Permute_Nrounds(KeccakP1600_plain64_state *state, unsigned int nr)
{
    declareABCDE
    unsigned int i;
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    roundsN(nr)
    copyToState(stateAsLanes, A)

}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Permute_24rounds(KeccakP1600_plain64_state *state)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    rounds24
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_Permute_12rounds(KeccakP1600_plain64_state *state)
{
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;

    copyFromState(A, stateAsLanes)
    rounds12
    copyToState(stateAsLanes, A)
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractBytesInLane(const KeccakP1600_plain64_state *state, unsigned int lanePosition, unsigned char *data, unsigned int offset, unsigned int length)
{
    uint64_t lane = state->A[lanePosition];
#ifdef KeccakP1600_plain64_useLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
        lane = ~lane;
#endif
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    {
        uint64_t lane1[1];
        lane1[0] = lane;
        memcpy(data, (uint8_t*)lane1+offset, length);
    }
#else
    unsigned int i;
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        data[i] = lane & 0xFF;
        lane >>= 8;
    }
#endif
}

/* ---------------------------------------------------------------- */

#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
static void fromWordToBytes(uint8_t *bytes, const uint64_t word)
{
    unsigned int i;

    for(i=0; i<(64/8); i++)
        bytes[i] = (word >> (8*i)) & 0xFF;
}
#endif

void KeccakP1600_plain64_ExtractLanes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
    memcpy(data, state, laneCount*8);
#else
    unsigned int i;

    for(i=0; i<laneCount; i++)
        fromWordToBytes(data+(i*8), state->A[i]);
#endif
#ifdef KeccakP1600_plain64_useLaneComplementing
    if (laneCount > 1) {
        XKCP_store64(data+1*8, ~XKCP_load64(data+1*8));
        if (laneCount > 2) {
            XKCP_store64(data+2*8, ~XKCP_load64(data+2*8));
            if (laneCount > 8) {
                XKCP_store64(data+8*8, ~XKCP_load64(data+8*8));
                if (laneCount > 12) {
                    XKCP_store64(data+12*8, ~XKCP_load64(data+12*8));
                    if (laneCount > 17) {
                        XKCP_store64(data+17*8, ~XKCP_load64(data+17*8));
                        if (laneCount > 20) {
                            XKCP_store64(data+20*8, ~XKCP_load64(data+20*8));
                        }
                    }
                }
            }
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractBytes(const KeccakP1600_plain64_state *state, unsigned char *data, unsigned int offset, unsigned int length)
{
    SnP_ExtractBytes(state, data, offset, length, KeccakP1600_plain64_ExtractLanes, KeccakP1600_plain64_ExtractBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractAndAddBytesInLane(const KeccakP1600_plain64_state *state, unsigned int lanePosition, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    uint64_t lane = state->A[lanePosition];
#ifdef KeccakP1600_plain64_useLaneComplementing
    if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
        lane = ~lane;
#endif
    unsigned int i;
    lane >>= offset*8;
    for(i=0; i<length; i++) {
        output[i] = input[i] ^ (lane & 0xFF);
        lane >>= 8;
    }
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractAndAddLanes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int laneCount)
{
    unsigned int i;
#if (PLATFORM_BYTE_ORDER != IS_LITTLE_ENDIAN)
    unsigned char temp[8];
    unsigned int j;
#endif

    for(i=0; i<laneCount; i++) {
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
        XKCP_store64(output+i*8, XKCP_load64(input+i*8) ^ state->A[i]);
#else
        fromWordToBytes(temp, state->A[i]);
        for(j=0; j<8; j++)
            output[i*8+j] = input[i*8+j] ^ temp[j];
#endif
    }
#ifdef KeccakP1600_plain64_useLaneComplementing
    if (laneCount > 1) {
        XKCP_store64(output+1*8, ~XKCP_load64(output+1*8));
        if (laneCount > 2) {
            XKCP_store64(output+2*8, ~XKCP_load64(output+2*8));
            if (laneCount > 8) {
                XKCP_store64(output+8*8, ~XKCP_load64(output+8*8));
                if (laneCount > 12) {
                    XKCP_store64(output+12*8, ~XKCP_load64(output+12*8));
                    if (laneCount > 17) {
                        XKCP_store64(output+17*8, ~XKCP_load64(output+17*8));
                        if (laneCount > 20) {
                            XKCP_store64(output+20*8, ~XKCP_load64(output+20*8));
                        }
                    }
                }
            }
        }
    }
#endif
}

/* ---------------------------------------------------------------- */

void KeccakP1600_plain64_ExtractAndAddBytes(const KeccakP1600_plain64_state *state, const unsigned char *input, unsigned char *output, unsigned int offset, unsigned int length)
{
    SnP_ExtractAndAddBytes(state, input, output, offset, length, KeccakP1600_plain64_ExtractAndAddLanes, KeccakP1600_plain64_ExtractAndAddBytesInLane, 8);
}

/* ---------------------------------------------------------------- */

size_t KeccakF1600_plain64_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen)
{
    size_t originalDataByteLen = dataByteLen;
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;
    const unsigned char *inData = data;

    copyFromState(A, stateAsLanes)
    while(dataByteLen >= laneCount*8) {
        addInput(A, inData, laneCount)
        rounds24
        inData += laneCount*8;
        dataByteLen -= laneCount*8;
    }
    copyToState(stateAsLanes, A)
    return originalDataByteLen - dataByteLen;
}

/* ---------------------------------------------------------------- */

size_t KeccakP1600_12rounds_plain64_FastLoop_Absorb(KeccakP1600_plain64_state *state, unsigned int laneCount, const unsigned char *data, size_t dataByteLen)
{
    size_t originalDataByteLen = dataByteLen;
    declareABCDE
    #ifndef KeccakP1600_plain64_fullUnrolling
    unsigned int i;
    #endif
    uint64_t *stateAsLanes = state->A;
    const unsigned char *inData = data;

    copyFromState(A, stateAsLanes)
    while(dataByteLen >= laneCount*8) {
        addInput(A, inData, laneCount)
        rounds12
        inData += laneCount*8;
        dataByteLen -= laneCount*8;
    }
    copyToState(stateAsLanes, A)
    return originalDataByteLen - dataByteLen;
}
