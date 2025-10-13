// SPDX-License-Identifier: MPL-2.0
#pragma once

#include <stdint.h>
#include <stdbool.h>

void fut_test_plan(uint16_t count);
void fut_test_pass(void);
void fut_test_fail(uint16_t code);
bool fut_tests_completed(void);
