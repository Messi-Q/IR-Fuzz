/* EVMC: Ethereum Client-VM Connector API.
 * Copyright 2018 The EVMC Authors.
 * Licensed under the Apache License, Version 2.0. See the LICENSE file.
 */

#pragma once

#include <evmc/evmc.h>
#include <evmc/utils.h>

/**
 * Creates EVMC Example VM.
 */
EVMC_EXPORT struct evmc_instance* evmc_create_example_vm(void);
