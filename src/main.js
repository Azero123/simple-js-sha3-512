
/**
 * [js-sha3]{@link https://github.com/emn178/js-sha3}
 *
 * @version 0.8.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2015-2018
 * @license MIT
 */



/*jslint bitwise: true */
// import chi from './chi';
// import iota from './iota';
// import rhoPi from './rho-pi';
// import theta from './theta';

// const permute = () => {
//   // Intermediate variables
//   const C = new Uint32Array(10);
//   const D = new Uint32Array(10);
//   const W = new Uint32Array(2);

//   return (A) => {
//     for (let roundIndex = 0; roundIndex < 24; roundIndex++) {
//       theta({ A, C, D, W });
//       rhoPi({ A, C, W });
//       chi({ A, C });
//       iota({ A, roundIndex });
//     }
//     C.fill(0);
//     D.fill(0);
//     W.fill(0);
//   };
// };

// export default permute;

const max = Math.pow(2, 32)
const fast = typeof window === 'undefined'

function rotr(x, n) {
    return (((x >>> n) | (x << 32 - n)) >>> 0) % max
}

const utf8 = function (str) {
  var i, l = str.length,
    output = new Array(16).fill(0)
  let current = 0
  for (i = 0; i < l; i += 1) {
    const r = i % 4
    if (r === 0) {
        current = 0
    }
    if (l !== i) {
        current += str.charCodeAt(i) << +(3 - r) * 8
    }
    else {
        current += 128 << +(3 - r) * 8
    }
    output[i/4 | 0] = current
  }
  return output
}
  
//Keccak round constants
const keccak_lane_t =
{
  (keccak_lane_t) 0x0000000000000001,
  (keccak_lane_t) 0x0000000000008082,
  (keccak_lane_t) 0x800000000000808A,
  (keccak_lane_t) 0x8000000080008000,
  (keccak_lane_t) 0x000000000000808B,
  (keccak_lane_t) 0x0000000080000001,
  (keccak_lane_t) 0x8000000080008081,
  (keccak_lane_t) 0x8000000000008009,
  (keccak_lane_t) 0x000000000000008A,
  (keccak_lane_t) 0x0000000000000088,
  (keccak_lane_t) 0x0000000080008009,
  (keccak_lane_t) 0x000000008000000A,
  (keccak_lane_t) 0x000000008000808B,
  (keccak_lane_t) 0x800000000000008B,
  (keccak_lane_t) 0x8000000000008089,
  (keccak_lane_t) 0x8000000000008003,
  (keccak_lane_t) 0x8000000000008002,
  (keccak_lane_t) 0x8000000000000080,
#if (KECCAK_L >= 4)
  (keccak_lane_t) 0x000000000000800A,
  (keccak_lane_t) 0x800000008000000A,
#endif
#if (KECCAK_L >= 5)
  (keccak_lane_t) 0x8000000080008081,
  (keccak_lane_t) 0x8000000000008080,
#endif
#if (KECCAK_L >= 6)
  (keccak_lane_t) 0x0000000080000001,
  (keccak_lane_t) 0x8000000080008008
#endif
};


/**
* @brief Apply theta transformation
* @param[in,out] a State array
**/

const theta(a) =>
{
  keccak_lane_t c[5];
  keccak_lane_t d[5];

  //The effect of the theta transformation is to XOR each bit in the
  //state with the parities of two columns in the array
  c[0] = a[0][0] ^ a[1][0] ^ a[2][0] ^ a[3][0] ^ a[4][0];
  c[1] = a[0][1] ^ a[1][1] ^ a[2][1] ^ a[3][1] ^ a[4][1];
  c[2] = a[0][2] ^ a[1][2] ^ a[2][2] ^ a[3][2] ^ a[4][2];
  c[3] = a[0][3] ^ a[1][3] ^ a[2][3] ^ a[3][3] ^ a[4][3];
  c[4] = a[0][4] ^ a[1][4] ^ a[2][4] ^ a[3][4] ^ a[4][4];

  d[0] = c[4] ^ KECCAK_ROL(c[1], 1);
  d[1] = c[0] ^ KECCAK_ROL(c[2], 1);
  d[2] = c[1] ^ KECCAK_ROL(c[3], 1);
  d[3] = c[2] ^ KECCAK_ROL(c[4], 1);
  d[4] = c[3] ^ KECCAK_ROL(c[0], 1);

  a[0][0] ^= d[0];
  a[1][0] ^= d[0];
  a[2][0] ^= d[0];
  a[3][0] ^= d[0];
  a[4][0] ^= d[0];

  a[0][1] ^= d[1];
  a[1][1] ^= d[1];
  a[2][1] ^= d[1];
  a[3][1] ^= d[1];
  a[4][1] ^= d[1];

  a[0][2] ^= d[2];
  a[1][2] ^= d[2];
  a[2][2] ^= d[2];
  a[3][2] ^= d[2];
  a[4][2] ^= d[2];

  a[0][3] ^= d[3];
  a[1][3] ^= d[3];
  a[2][3] ^= d[3];
  a[3][3] ^= d[3];
  a[4][3] ^= d[3];

  a[0][4] ^= d[4];
  a[1][4] ^= d[4];
  a[2][4] ^= d[4];
  a[3][4] ^= d[4];
  a[4][4] ^= d[4];
}


/**
* @brief Apply rho transformation
* @param[in,out] a State array
**/

const rho(a) =>
{
  //The effect of the rho transformation is to rotate the bits of each lane by
  //an offset, which depends on the fixed x and y coordinates of the lane
  a[0][1] = KECCAK_ROL(a[0][1], 1   % KECCAK_W);
  a[0][2] = KECCAK_ROL(a[0][2], 190 % KECCAK_W);
  a[0][3] = KECCAK_ROL(a[0][3], 28  % KECCAK_W);
  a[0][4] = KECCAK_ROL(a[0][4], 91  % KECCAK_W);

  a[1][0] = KECCAK_ROL(a[1][0], 36  % KECCAK_W);
  a[1][1] = KECCAK_ROL(a[1][1], 300 % KECCAK_W);
  a[1][2] = KECCAK_ROL(a[1][2], 6   % KECCAK_W);
  a[1][3] = KECCAK_ROL(a[1][3], 55  % KECCAK_W);
  a[1][4] = KECCAK_ROL(a[1][4], 276 % KECCAK_W);

  a[2][0] = KECCAK_ROL(a[2][0], 3   % KECCAK_W);
  a[2][1] = KECCAK_ROL(a[2][1], 10  % KECCAK_W);
  a[2][2] = KECCAK_ROL(a[2][2], 171 % KECCAK_W);
  a[2][3] = KECCAK_ROL(a[2][3], 153 % KECCAK_W);
  a[2][4] = KECCAK_ROL(a[2][4], 231 % KECCAK_W);

  a[3][0] = KECCAK_ROL(a[3][0], 105 % KECCAK_W);
  a[3][1] = KECCAK_ROL(a[3][1], 45  % KECCAK_W);
  a[3][2] = KECCAK_ROL(a[3][2], 15  % KECCAK_W);
  a[3][3] = KECCAK_ROL(a[3][3], 21  % KECCAK_W);
  a[3][4] = KECCAK_ROL(a[3][4], 136 % KECCAK_W);

  a[4][0] = KECCAK_ROL(a[4][0], 210 % KECCAK_W);
  a[4][1] = KECCAK_ROL(a[4][1], 66  % KECCAK_W);
  a[4][2] = KECCAK_ROL(a[4][2], 253 % KECCAK_W);
  a[4][3] = KECCAK_ROL(a[4][3], 120 % KECCAK_W);
  a[4][4] = KECCAK_ROL(a[4][4], 78  % KECCAK_W);
}


/**
* @brief Apply pi transformation
* @param[in,out] a State array
**/

const pi(a) =>
{
  const temp;

  //The effect of the pi transformation is to rearrange the
  //positions of the lanes
  temp = a[0][1];
  a[0][1] = a[1][1];
  a[1][1] = a[1][4];
  a[1][4] = a[4][2];
  a[4][2] = a[2][4];
  a[2][4] = a[4][0];
  a[4][0] = a[0][2];
  a[0][2] = a[2][2];
  a[2][2] = a[2][3];
  a[2][3] = a[3][4];
  a[3][4] = a[4][3];
  a[4][3] = a[3][0];
  a[3][0] = a[0][4];
  a[0][4] = a[4][4];
  a[4][4] = a[4][1];
  a[4][1] = a[1][3];
  a[1][3] = a[3][1];
  a[3][1] = a[1][0];
  a[1][0] = a[0][3];
  a[0][3] = a[3][3];
  a[3][3] = a[3][2];
  a[3][2] = a[2][1];
  a[2][1] = a[1][2];
  a[1][2] = a[2][0];
  a[2][0] = temp;
}


/**
* @brief Apply chi transformation
* @param[in,out] a State array
**/

const chi(a) =>
{
  const temp1;
  const temp2;

  //The effect of the chi transformation is to XOR each bit with
  //a non linear function of two other bits in its row
  temp1 = a[0][0];
  temp2 = a[0][1];
  a[0][0] ^= (2**33-1) ^ a[0][1] & a[0][2];
  a[0][1] ^= (2**33-1) ^ a[0][2] & a[0][3];
  a[0][2] ^= (2**33-1) ^ a[0][3] & a[0][4];
  a[0][3] ^= (2**33-1) ^ a[0][4] & temp1;
  a[0][4] ^= (2**33-1) ^ temp1 & temp2;

  temp1 = a[1][0];
  temp2 = a[1][1];
  a[1][0] ^= (2**33-1) ^ a[1][1] & a[1][2];
  a[1][1] ^= (2**33-1) ^ a[1][2] & a[1][3];
  a[1][2] ^= (2**33-1) ^ a[1][3] & a[1][4];
  a[1][3] ^= (2**33-1) ^ a[1][4] & temp1;
  a[1][4] ^= (2**33-1) ^ temp1 & temp2;

  temp1 = a[2][0];
  temp2 = a[2][1];
  a[2][0] ^= (2**33-1) ^ a[2][1] & a[2][2];
  a[2][1] ^= (2**33-1) ^ a[2][2] & a[2][3];
  a[2][2] ^= (2**33-1) ^ a[2][3] & a[2][4];
  a[2][3] ^= (2**33-1) ^ a[2][4] & temp1;
  a[2][4] ^= (2**33-1) ^ temp1 & temp2;

  temp1 = a[3][0];
  temp2 = a[3][1];
  a[3][0] ^= (2**33-1) ^ a[3][1] & a[3][2];
  a[3][1] ^= (2**33-1) ^ a[3][2] & a[3][3];
  a[3][2] ^= (2**33-1) ^ a[3][3] & a[3][4];
  a[3][3] ^= (2**33-1) ^ a[3][4] & temp1;
  a[3][4] ^= (2**33-1) ^ temp1 & temp2;

  temp1 = a[4][0];
  temp2 = a[4][1];
  a[4][0] ^= (2**33-1) ^ a[4][1] & a[4][2];
  a[4][1] ^= (2**33-1) ^ a[4][2] & a[4][3];
  a[4][2] ^= (2**33-1) ^ a[4][3] & a[4][4];
  a[4][3] ^= (2**33-1) ^ a[4][4] & temp1;
  a[4][4] ^= (2**33-1) ^ temp1 & temp2;
}


/**
* @brief Apply iota transformation
* @param[in,out] a State array
* @param[index] round Round index
**/

static void iota(a, index)
{
  //The iota transformation is parameterized by the round index
  a[0][0] ^= rc[index];
}


/**
* @brief Initialize Keccak context
* @param[in] context Pointer to the Keccak context to initialize
* @param[in] capacity Capacity of the sponge function
**/

const keccakInit = (KeccakContext *context, uint_t capacity) =>
{
  uint_t rate;

  //Clear Keccak context
  osMemset(context, 0, sizeof(KeccakContext));

  //The capacity cannot exceed the width of a Keccak-p permutation
  if(capacity >= KECCAK_B)
      return ERROR_INVALID_PARAMETER;

  //The rate depends on the capacity of the sponge function
  rate = KECCAK_B - capacity;

  //The rate must be multiple of the lane size
  if((rate % KECCAK_W) != 0)
      return ERROR_INVALID_PARAMETER;

  //Save the block size, in bytes
  context.blockSize = rate / 8;

  //Successful initialization
  return NO_ERROR;
}
  
  
 /**
  * @brief Absorb data
  * @param[in] context Pointer to the Keccak context
  * @param[in] input Pointer to the buffer being hashed
  * @param[in] length Length of the buffer
  **/
  
 const keccakAbsorb(context, input, length) =>
 {
    const i;
    const n;
    keccak_lane_t *a;
  
    //Point to the state array
    a = (keccak_lane_t *) context.a;
  
    //Absorbing phase
    while(length > 0)
    {
       //Limit the number of bytes to process at a time
       n = MIN(length, context.blockSize - context.length);
  
       //Copy the data to the buffer
       osMemcpy(context.buffer + context.length, input, n);
  
       //Number of data bytes that have been buffered
       context.length += n;
  
       //Advance the data pointer
       input = (uint8_t *) input + n;
       //Remaining bytes to process
       length -= n;
  
       //Absorb the message block by block
       if(context.length == context.blockSize)
       {
          //Absorb the current block
          for(i = 0; i < context.blockSize / sizeof(keccak_lane_t); i++)
          {
             a[i] ^= KECCAK_LETOH(context.block[i]);
          }
  
          //Apply block permutation function
          keccakPermutBlock(context);
  
          //The input buffer is empty
          context.length = 0;
       }
    }
 }
  
  
 /**
  * @brief Finish absorbing phase
  * @param[in] context Pointer to the Keccak context
  * @param[in] pad Value of the padding byte (0x01 for Keccak, 0x06 for SHA-3 and 0x1F for XOF)
  **/
  
 const keccakFinal(context, pad) =>
 {
    const i;
    const q;
    keccak_lane_t *a;
  
    //Point to the state array
    a = (keccak_lane_t *) context.a;
  
    //Compute the number of padding bytes
    q = context.blockSize - context.length;
  
    //Append padding
    osMemset(context.buffer + context.length, 0, q);
    context.buffer[context.length] |= pad;
    context.buffer[context.blockSize - 1] |= 0x80;
  
    //Absorb the final block
    for(i = 0; i < context.blockSize / sizeof(keccak_lane_t); i++)
    {
       a[i] ^= KECCAK_LETOH(context.block[i]);
    }
  
    //Apply block permutation function
    keccakPermutBlock(context);
  
    //Convert lanes to little-endian byte order
    for(i = 0; i < context.blockSize / sizeof(keccak_lane_t); i++)
    {
       a[i] = KECCAK_HTOLE(a[i]);
    }
  
    //Number of bytes available in the output buffer
    context.length = context.blockSize;
 }
  
  
 /**
  * @brief Extract data from the squeezing phase
  * @param[in] context Pointer to the Keccak context
  * @param[out] output Output string
  * @param[in] length Desired output length, in bytes
  **/
  
 const keccakSqueeze(KeccakContext *context, uint8_t *output, size_t length) =>
 {
    const i;
    const n;
    keccak_lane_t *a;
  
    //Point to the state array
    a = (keccak_lane_t *) context.a;
  
    //An arbitrary number of output bits can be squeezed out of the state
    while(length > 0)
    {
       //Check whether more data is required
       if(context.length == 0)
       {
          //Convert lanes to host byte order
          for(i = 0; i < context.blockSize / sizeof(keccak_lane_t); i++)
          {
             a[i] = KECCAK_LETOH(a[i]);
          }
  
          //Apply block permutation function
          keccakPermutBlock(context);
  
          //Convert lanes to little-endian byte order
          for(i = 0; i < context.blockSize / sizeof(keccak_lane_t); i++)
          {
             a[i] = KECCAK_HTOLE(a[i]);
          }
  
          //Number of bytes available in the output buffer
          context.length = context.blockSize;
       }
  
       //Compute the number of bytes to process at a time
       n = MIN(length, context.length);
  
       //Copy the output string
       if(output != NULL)
       {
          osMemcpy(output, context.digest + context.blockSize -
             context.length, n);
       }
  
       //Number of bytes available in the output buffer
       context.length -= n;
  
       //Advance the data pointer
       output = (uint8_t *) output + n;
       //Number of bytes that remains to be written
       length -= n;
    }
 }
  
  
 /**
  * @brief Block permutation
  * @param[in] context Pointer to the Keccak context
  **/
  
 const keccakPermutBlock(context) =>
 {
    let i;
  
    //Each round consists of a sequence of five transformations,
    //which are called the step mappings
    for(i = 0; i < KECCAK_NR; i++)
    {
       //Apply theta step mapping
       theta(context.a);
       //Apply rho step mapping
       rho(context.a);
       //Apply pi step mapping
       pi(context.a);
       //Apply chi step mapping
       chi(context.a);
       //Apply iota step mapping
       iota(context.a, i);
    }
 }

/**
* @brief Initialize SHA3-512 message digest context
* @param[in] context Pointer to the SHA3-512 context to initialize
**/

const sha3_512Init(context) =>
{
    //The capacity of the sponge is twice the digest length
    keccakInit(context, 2 * 512);
}


/**
* @brief Update the SHA3-512 context with a portion of the message being hashed
* @param[in] context Pointer to the SHA3-512 context
* @param[in] data Pointer to the buffer being hashed
* @param[in] length Length of the buffer
**/

const sha3_512Update(context, data, length) =>
{
    //Absorb the input data
    keccakAbsorb(context, data, length);
}


/**
* @brief Finish the SHA3-512 message digest
* @param[in] context Pointer to the SHA3-512 context
* @param[out] digest Calculated digest (optional parameter)
**/

void sha3_512Final(context, digest)
{
    //Finish absorbing phase (padding byte is 0x06 for SHA-3)
    keccakFinal(context, KECCAK_SHA3_PAD);
    //Extract data from the squeezing phase
    keccakSqueeze(context, digest, SHA3_512_DIGEST_SIZE);
}
  
module.exports = m => { 
    
    // //SHA3-512 object identifier (2.16.840.1.101.3.4.2.10)
    // const uint8_t sha3_512Oid[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A};
    
    // //Common interface for hash algorithms
    // const HashAlgo sha3_512HashAlgo =
    // {
    //     "SHA3-512",
    //     sha3_512Oid,
    //     sizeof(sha3_512Oid),
    //     sizeof(Sha3_512Context),
    //     SHA3_512_BLOCK_SIZE,
    //     SHA3_512_DIGEST_SIZE,
    //     SHA3_512_MIN_PAD_SIZE,
    //     FALSE,
    //     (HashAlgoCompute) sha3_512Compute,
    //     (HashAlgoInit) sha3_512Init,
    //     (HashAlgoUpdate) sha3_512Update,
    //     (HashAlgoFinal) sha3_512Final,
    //     NULL
    // };
    
    
    // /**
    // * @brief Digest a message using SHA3-512
    // * @param[in] data Pointer to the message being hashed
    // * @param[in] length Length of the message
    // * @param[out] digest Pointer to the calculated digest
    // * @return Error code
    // **/
    
    // error_t sha3_512Compute(const void *data, size_t length, uint8_t *digest)
    // {
      let context;
  
      //Allocate a memory buffer to hold the SHA3-512 context
      context = Sha3_512Context
      //Failed to allocate memory?
      if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
  
      //Initialize the SHA3-512 context
      sha3_512Init(context);
      //Digest the message
      sha3_512Update(context, data, length);
      //Finalize the SHA3-512 message digest
      sha3_512Final(context, digest);
  
      //Free previously allocated memory
      cryptoFreeMem(context);
      //Successful processing
      return NO_ERROR;
    // }
    
    // #endif

}