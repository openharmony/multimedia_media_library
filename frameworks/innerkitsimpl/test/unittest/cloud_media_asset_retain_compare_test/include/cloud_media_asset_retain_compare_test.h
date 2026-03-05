/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef FRAMEWORKS_SERVICES_MEDIALIBRARY_CLOUD_MEDIA_ASSET_RETAIN_COMPARE_TEST_H
#define FRAMEWORKS_SERVICES_MEDIALIBRARY_CLOUD_MEDIA_ASSET_RETAIN_COMPARE_TEST_H

#include <gtest/gtest.h>

namespace OHOS {
namespace Media {
class CloudMediaAssetRetainCompareTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
} // namespace Media
} // namespace OHOS

#endif // FRAMEWORKS_SERVICES_MEDIALIBRARY_CLOUD_MEDIA_ASSET_RETAIN_COMPARE_TEST_H
