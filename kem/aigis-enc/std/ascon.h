#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>

typedef struct {
  uint64_t x[5];
} ascon_state_t;

typedef struct {
  ascon_state_t s;       // Ascon的内部状态（5个64位字）
  uint32_t counter;      // 用于状态更新的计数器
  uint8_t phase;         // 0: 未初始化, 1: 已吸收, 2: 挤压中
} ascon_kdf_ctx;

#endif /* ASCON_H_ */
