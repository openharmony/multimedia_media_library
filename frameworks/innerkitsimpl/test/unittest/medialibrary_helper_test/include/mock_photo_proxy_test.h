/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOCK_PHOTO_PROXY_TEST_H
#define MOCK_PHOTO_PROXY_TEST_H

#include "gmock/gmock.h"

#include "photo_proxy_test.h"

namespace OHOS {
namespace Media {
class MockPhotoProxyTest : public PhotoProxyTest {
public:
    MockPhotoProxyTest() {};
    ~MockPhotoProxyTest() {};

    MOCK_METHOD0(GetDisplayName, std::string());
    MOCK_METHOD0(GetExtension, std::string());
    MOCK_METHOD0(GetPhotoId, std::string());
    MOCK_METHOD0(GetDeferredProcType, DeferredProcType());
    MOCK_METHOD0(GetWidth, int32_t());
    MOCK_METHOD0(GetHeight, int32_t());
    MOCK_METHOD0(GetFileDataAddr, void*());
    MOCK_METHOD0(GetFileSize, size_t());
    MOCK_METHOD0(GetFormat, PhotoFormat());
    MOCK_METHOD0(GetPhotoQuality, PhotoQuality());
    MOCK_METHOD0(Release, void());
};
} // Media
} // OHOS
#endif // MOCK_PHOTO_PROXY_TEST_H