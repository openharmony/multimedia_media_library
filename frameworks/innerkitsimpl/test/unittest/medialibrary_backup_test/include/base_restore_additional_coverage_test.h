/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#ifndef BASE_RESTORE_ADDITIONAL_COVERAGE_TEST_H
#define BASE_RESTORE_ADDITIONAL_COVERAGE_TEST_H

#include "gtest/gtest.h"

namespace OHOS {
namespace Media {
class BaseRestoreAdditionalCoverageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};
} // namespace Media
} // namespace OHOS

#endif // BASE_RESTORE_ADDITIONAL_COVERAGE_TEST_H
