#include <stdint.h>
#include "aes.h"

constexpr uint8_t AES::S_BOX[];
constexpr uint8_t AES::INVERSE_S_BOX[];
constexpr uint8_t AES::R_CON[];


void AES::KeyExpansion(uint8_t* roundKey, uint8_t* key) {
  uint8_t tmp[4];

  for (uint8_t i = 0; i < Nk; i++) {
    ((uint32_t*)roundKey)[i] = ((uint32_t*)key)[i];
  }

  for (uint8_t i = Nk; i < Nb*(Nr+1); i++) {
    *((uint32_t*)tmp) = ((uint32_t*)roundKey)[i-1];
    if (i % Nk == 0) {
      RotWord(tmp);
      SubWord(tmp);
      tmp[0] ^= R_CON[i/Nk];
    } else if (i % Nk == 4) {
      SubWord(tmp);
    }
    ((uint32_t*)roundKey)[i] = ((uint32_t*)roundKey)[i-Nk] ^ *((uint32_t*)tmp);
  }
}


void AES::RotWord(uint8_t *word) {
  uint8_t tmp = word[0];
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = tmp;
}


void AES::SubWord(uint8_t *word) {
  word[0] = S_BOX[word[0]];
  word[1] = S_BOX[word[1]];
  word[2] = S_BOX[word[2]];
  word[3] = S_BOX[word[3]];
}


void AES::AddRoundKey(uint8_t round, State* s, uint8_t* roundKey) {
  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < 4; j++) {
      (*s)[i][j] ^= roundKey[(round*Nb*4)+(i * Nb)+j];
    }
  }
}


void AES::SubBytes(State* s) {
  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < 4; j++) {
      (*s)[j][i] = S_BOX[(*s)[j][i]];
    }
  }
}


void AES::ShiftRows(State* s) {
  uint8_t tmp = (*s)[0][1];
  (*s)[0][1] = (*s)[1][1];
  (*s)[1][1] = (*s)[2][1];
  (*s)[2][1] = (*s)[3][1];
  (*s)[3][1] = tmp;

  tmp = (*s)[0][2];
  (*s)[0][2] = (*s)[2][2];
  (*s)[2][2] = tmp;

  tmp = (*s)[1][2];
  (*s)[1][2] = (*s)[3][2];
  (*s)[3][2] = tmp;

  tmp = (*s)[0][3];
  (*s)[0][3] = (*s)[3][3];
  (*s)[3][3] = (*s)[2][3];
  (*s)[2][3] = (*s)[1][3];
  (*s)[1][3] = tmp;
}


uint8_t AES::xtime(uint8_t x) {
  return ((x<<1)^(((x>>7)&1)*0x1b));
}


void AES::MixColumns(State* s) {
  uint8_t x;
  uint8_t y;
  uint8_t z;
  for (uint8_t i = 0; i < 4; i++) {
    z = (*s)[i][0];

    x = (*s)[i][0];
    x ^= (*s)[i][1];
    x ^= (*s)[i][2];
    x ^= (*s)[i][3];

    y = (*s)[i][0];
    y ^= (*s)[i][1];
    y = xtime(y);
    (*s)[i][0] ^= y ^ x ;

    y = (*s)[i][1] ^ (*s)[i][2];
    y = xtime(y);
    (*s)[i][1] ^= y ^ x;

    y = (*s)[i][2] ^ (*s)[i][3];
    y = xtime(y);
    (*s)[i][2] ^= y ^ x;

    y = (*s)[i][3] ^ z;
    y = xtime(y);
    (*s)[i][3] ^= y ^ x ;
  }
}


uint8_t AES::Multiply(uint8_t a, uint8_t b) {
  uint8_t tmp = (b&1)*a;
  tmp ^= (b>>1 & 1)*xtime(a);
  tmp ^= (b>>2 & 1)*xtime(xtime(a));
  tmp ^= (b>>3 & 1)*xtime(xtime(xtime(a)));
  tmp ^= (b>>4 & 1)*xtime(xtime(xtime(xtime(a))));
  return tmp;
}


void AES::InvMixColumns(State* s) {
  uint8_t tmp[4];
  for (uint8_t i = 0; i < 4; ++i)
  {

    tmp[0] = (*s)[i][0];
    tmp[1] = (*s)[i][1];
    tmp[2] = (*s)[i][2];
    tmp[3] = (*s)[i][3];

    (*s)[i][0] = Multiply(tmp[0], 0x0e);
    (*s)[i][0] ^= Multiply(tmp[1], 0x0b);
    (*s)[i][0] ^= Multiply(tmp[2], 0x0d);
    (*s)[i][0] ^= Multiply(tmp[3], 0x09);

    (*s)[i][1] = Multiply(tmp[0], 0x09);
    (*s)[i][1] ^= Multiply(tmp[1], 0x0e);
    (*s)[i][1] ^= Multiply(tmp[2], 0x0b);
    (*s)[i][1] ^= Multiply(tmp[3], 0x0d);

    (*s)[i][2] = Multiply(tmp[0], 0x0d);
    (*s)[i][2] ^= Multiply(tmp[1], 0x09);
    (*s)[i][2] ^= Multiply(tmp[2], 0x0e);
    (*s)[i][2] ^= Multiply(tmp[3], 0x0b);

    (*s)[i][3] = Multiply(tmp[0], 0x0b);
    (*s)[i][3] ^= Multiply(tmp[1], 0x0d);
    (*s)[i][3] ^= Multiply(tmp[2], 0x09);
    (*s)[i][3] ^= Multiply(tmp[3], 0x0e);
  }
}


void AES::InvSubBytes(State* s) {
  for (uint8_t i = 0; i < 4; i++) {
    for (uint8_t j = 0; j < 4; j++) {
      (*s)[j][i] = INVERSE_S_BOX[(*s)[j][i]];
    }
  }
}


void AES::InvShiftRows(State* s) {
  uint8_t tmp = (*s)[3][1];
  (*s)[3][1] = (*s)[2][1];
  (*s)[2][1] = (*s)[1][1];
  (*s)[1][1] = (*s)[0][1];
  (*s)[0][1] = tmp;

  tmp = (*s)[0][2];
  (*s)[0][2] = (*s)[2][2];
  (*s)[2][2] = tmp;

  tmp = (*s)[1][2];
  (*s)[1][2] = (*s)[3][2];
  (*s)[3][2] = tmp;

  tmp = (*s)[0][3];
  (*s)[0][3] = (*s)[1][3];
  (*s)[1][3] = (*s)[2][3];
  (*s)[2][3] = (*s)[3][3];
  (*s)[3][3] = tmp;
}


void AES::Cipher(State* s, uint8_t* roundKey) {
  uint8_t round = 0;
  AddRoundKey(0, s, roundKey);
  for (round = 1; round < Nr; round++) {
    SubBytes(s);
    ShiftRows(s);
    MixColumns(s);
    AddRoundKey(round, s, roundKey);
  }
  SubBytes(s);
  ShiftRows(s);
  AddRoundKey(Nr, s, roundKey);
}


void AES::InvCipher(State* s, uint8_t* RoundKey) {
  uint8_t round = Nr-1;
  AddRoundKey(Nr, s, RoundKey);
  while (round > 0)
  {
    InvShiftRows(s);
    InvSubBytes(s);
    AddRoundKey(round, s, RoundKey);
    InvMixColumns(s);
    round--;
  }
  InvShiftRows(s);
  InvSubBytes(s);
  AddRoundKey(0, s, RoundKey);
}


void AES::encryptECB(uint8_t* buf) {
  Cipher((State*)buf, RoundKey);
}


void AES::decryptECB(uint8_t* buf) {
  InvCipher((State*)buf, RoundKey);
}