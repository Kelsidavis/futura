/* apple_gpio.h - Apple GPIO Controller C FFI Header
 *
 * Copyright (c) 2025 Kelsi Davis
 * Licensed under the MPL v2.0 — see LICENSE for details.
 */

#ifndef __FUTURA_APPLE_GPIO_H__
#define __FUTURA_APPLE_GPIO_H__

#include <stdint.h>

typedef struct AppleGpio AppleGpio;

AppleGpio *rust_gpio_init(uint64_t base, uint32_t npins);
void rust_gpio_free(AppleGpio *gpio);
void rust_gpio_set_direction(AppleGpio *gpio, uint32_t pin, int32_t output);
int32_t rust_gpio_get_direction(const AppleGpio *gpio, uint32_t pin);
void rust_gpio_set_output(const AppleGpio *gpio, uint32_t pin, int32_t high);
void rust_gpio_toggle(const AppleGpio *gpio, uint32_t pin);
int32_t rust_gpio_get_input(const AppleGpio *gpio, uint32_t pin);
void rust_gpio_set_pull(const AppleGpio *gpio, uint32_t pin, uint32_t pull);
uint32_t rust_gpio_get_pull(const AppleGpio *gpio, uint32_t pin);
void rust_gpio_configure_irq(const AppleGpio *gpio, uint32_t pin, uint32_t mode);
void rust_gpio_enable_irq(const AppleGpio *gpio, uint32_t pin);
void rust_gpio_disable_irq(const AppleGpio *gpio, uint32_t pin);
void rust_gpio_clear_irq(const AppleGpio *gpio, uint32_t pin);
int32_t rust_gpio_irq_pending(const AppleGpio *gpio, uint32_t pin);
void rust_gpio_handle_irq(AppleGpio *gpio);
uint32_t rust_gpio_npins(const AppleGpio *gpio);

#endif /* __FUTURA_APPLE_GPIO_H__ */
